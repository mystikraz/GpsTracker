"""Minimal security-focused FastAPI authentication surface for Phase B."""

from __future__ import annotations

import asyncio
import html
import json
import logging
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

from fastapi import FastAPI, HTTPException, Query, Request, Response
from fastapi.openapi.utils import get_openapi
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy import and_, exists, select, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from .auth_security import (
    AuthenticationError, LoginPreSessionStore, has_recent_reauthentication, random_token, require_csrf, require_session, token_hash,
    revoke_all_sessions, write_audit,
)
from .auth_service import AuthService, GENERIC_LOGIN_ERROR
from .csrf import COOKIE_NAME, clear_cookie_header, cookie_header, validate_origin
from .db.models import AuditEvent, Device, DeviceVehicleAssignment, MembershipGroupScope, Organization, OrganizationInvitation, OrganizationMembership, Position, Session, User, UserGroup, Vehicle, VehicleGroupMembership, VehicleLatestState
from .vehicle_colors import next_vehicle_color
from .db.tenant import organization_transaction, set_user_context
from .authorization import Action, Assurance, Resource, Role, authorize
from .org_service import OrganizationError, accept_invitation, change_membership_role, create_group, create_invitation, membership_for, principal_for, resend_invitation, revoke_invitation, set_membership_status
from .db.provisioning import provision_postgres_device, rotate_postgres_device_secret
from .email_provider import EmailDeliveryError, EmailProvider
from .ingestion.auth import SecretProtector


LOGIN_CSRF_COOKIE = "__Host-fleet_login"
GENERIC_RESET_MESSAGE = "if the account exists, reset instructions will be provided"
logger = logging.getLogger(__name__)


class LoginBody(BaseModel):
    email: str
    password: str
    csrf_token: str
    pre_session: str | None = None


class BootstrapOwnerBody(BaseModel):
    email: str = Field(min_length=3, max_length=320)
    password: str = Field(min_length=12, max_length=1024)


class PasswordChangeBody(BaseModel):
    current_password: str
    new_password: str
    csrf_token: str


class ResetRequestBody(BaseModel):
    email: str


class ResetConsumeBody(BaseModel):
    token: str
    new_password: str


class ReauthBody(BaseModel):
    password: str
    purpose: str = Field(min_length=1, max_length=64)
    csrf_token: str


class InvitationBody(BaseModel):
    role: str
    email: str | None = None


class AcceptInvitationBody(BaseModel):
    token: str
    password: str


class RoleBody(BaseModel):
    role: str
    csrf_token: str


class GroupBody(BaseModel):
    name: str = Field(min_length=1, max_length=128)


class VehicleBody(BaseModel):
    name: str = Field(min_length=1, max_length=256)
    plate_number: str | None = None


class GroupScopeBody(BaseModel):
    group_ids: list[UUID]
    csrf_token: str


class OrganizationSettingsBody(BaseModel):
    name: str = Field(min_length=1, max_length=256)
    timezone: str = Field(min_length=1, max_length=64)
    position_retention_months: int = Field(ge=1, le=120)
    raw_retention_days: int = Field(ge=1, le=3650)


class OrganizationCreateBody(BaseModel):
    name: str = Field(min_length=1, max_length=256)
    timezone: str = Field(default="Asia/Kathmandu", min_length=1, max_length=64)


class AuthApp:
    def __init__(self, sessions: async_sessionmaker[AsyncSession], auth: AuthService, *, manual_links: bool = False, email_provider: EmailProvider | None = None, public_base_url: str = "", secret_protector: SecretProtector | None = None, auth_pepper: bytes = b"", offline_after_seconds: int = 300, moving_speed_kmh: float = 1.0, sse_max_streams: int = 16) -> None:
        self.sessions = sessions
        self.auth = auth
        self.manual_links = manual_links
        self.email_provider = email_provider
        self.public_base_url = public_base_url.rstrip("/")
        self.secret_protector = secret_protector
        self.auth_pepper = auth_pepper
        self.login_csrf = LoginPreSessionStore()
        self.offline_after_seconds = offline_after_seconds
        self.moving_speed_kmh = moving_speed_kmh
        self.sse_max_streams = sse_max_streams
        self._sse_lock = asyncio.Lock()
        self._active_sse_streams = 0

    def build(self) -> FastAPI:
        app = FastAPI(
            title="GPS Tracker API",
            summary="Fleet, vehicle, device, and position APIs for GPS Tracker mobile clients.",
            description=(
                "Use the session cookie returned by `/api/v1/auth/login` for authenticated requests. "
                "State-changing requests must also send the CSRF token from `/api/v1/auth/csrf` in "
                "the `X-CSRF-Token` header. The OpenAPI document is available at `/api/openapi.json`."
            ),
            version="1.0.0",
            docs_url="/api/docs",
            redoc_url="/api/redoc",
            openapi_url="/api/openapi.json",
            openapi_tags=[
                {"name": "authentication", "description": "Login, session, password, and account recovery flows."},
                {"name": "organizations", "description": "Organization settings, members, groups, invitations, and audit events."},
                {"name": "fleet", "description": "Vehicles, live state, positions, history, and streaming updates."},
                {"name": "devices", "description": "Tracker device provisioning, assignment, and secret rotation."},
            ],
        )

        def custom_openapi():
            if app.openapi_schema:
                return app.openapi_schema
            schema = get_openapi(
                title=app.title,
                version=app.version,
                summary=app.summary,
                description=app.description,
                routes=app.routes,
                tags=app.openapi_tags,
            )
            schema.setdefault("components", {}).setdefault("securitySchemes", {})["SessionCookie"] = {
                "type": "apiKey",
                "in": "cookie",
                "name": COOKIE_NAME,
                "description": "HttpOnly session cookie returned by the login endpoint.",
            }
            public_paths = {
                "/api/v1/auth/login/csrf",
                "/api/v1/auth/login",
                "/api/v1/auth/bootstrap/status",
                "/api/v1/auth/bootstrap-owner",
                "/api/v1/auth/reset/request",
                "/api/v1/auth/reset/consume",
                "/api/v1/auth/invitations/accept",
            }
            for path, operations in schema.get("paths", {}).items():
                for method, operation in operations.items():
                    if method == "parameters" or not isinstance(operation, dict):
                        continue
                    if path not in public_paths:
                        operation["security"] = [{"SessionCookie": []}]
                    if "tags" not in operation:
                        if path.startswith("/api/v1/auth/"):
                            operation["tags"] = ["authentication"]
                        elif "/devices" in path:
                            operation["tags"] = ["devices"]
                        elif any(part in path for part in ("/vehicles", "/positions")):
                            operation["tags"] = ["fleet"]
                        else:
                            operation["tags"] = ["organizations"]
            app.openapi_schema = schema
            return app.openapi_schema

        app.openapi = custom_openapi

        @app.middleware("http")
        async def security_headers(request: Request, call_next):
            response = await call_next(request)
            response.headers["Cache-Control"] = response.headers.get("Cache-Control", "no-store")
            response.headers["Referrer-Policy"] = "no-referrer"
            response.headers["X-Content-Type-Options"] = "nosniff"
            if request.url.path.startswith(("/api/docs", "/api/redoc")):
                response.headers["Content-Security-Policy"] = (
                    "default-src 'self'; "
                    "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
                    "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
                    "img-src 'self' data: https://fastapi.tiangolo.com; "
                    "connect-src 'self'; frame-ancestors 'none'; object-src 'none'"
                )
            else:
                response.headers["Content-Security-Policy"] = "default-src 'self'; frame-ancestors 'none'"
            return response

        def request_id(request: Request) -> str:
            return request.headers.get("X-Request-ID", str(uuid4()))[:128]

        async def current(request: Request) -> tuple[Session, User]:
            raw = request.cookies.get(COOKIE_NAME)
            if not raw:
                raise HTTPException(status_code=401, detail="authentication required")
            async with self.sessions() as session:
                try:
                    record, user = await require_session(session, raw)
                    session.expunge(record)
                    session.expunge(user)
                    return record, user
                except AuthenticationError:
                    raise HTTPException(status_code=401, detail="authentication required")

        @app.get("/api/v1/orgs")
        async def my_organizations(request: Request):
            _, user = await current(request)
            async with self.sessions() as session:
                async with session.begin():
                    await set_user_context(session, user.id)
                    rows = await session.execute(select(OrganizationMembership.organization_id, OrganizationMembership.role).where(OrganizationMembership.user_id == user.id, OrganizationMembership.status == "active"))
                    return [{"organization_id": str(row[0]), "role": row[1]} for row in rows]

        @app.post("/api/v1/orgs")
        async def organization_create(body: OrganizationCreateBody, request: Request):
            record, user = await current(request)
            await csrf_request(request, record)
            now = datetime.now(UTC)
            async with self.sessions() as session:
                async with session.begin():
                    await set_user_context(session, user.id)
                    organization = Organization(
                        name=body.name.strip(),
                        timezone=body.timezone.strip(),
                        position_retention_months=12,
                        raw_retention_days=30,
                        created_at=now,
                    )
                    session.add(organization)
                    await session.flush()
                    await session.execute(text("SELECT set_config('app.organization_id', :organization_id, true)"), {"organization_id": str(organization.id)})
                    session.add(OrganizationMembership(organization_id=organization.id, user_id=user.id, role=Role.OWNER.value, status="active", group_scope_mode="all", created_at=now))
                    await write_audit(session, action="organization.create", result="success", request_id=request_id(request), actor_user_id=user.id, organization_id=organization.id)
                    return {"organization_id": str(organization.id), "role": Role.OWNER.value}

        async def csrf_request(request: Request, record: Session) -> None:
            host = request.headers.get("host", "")
            try:
                validate_origin(origin=request.headers.get("origin"), host=host)
                require_csrf(record, request.headers.get("X-CSRF-Token"))
            except (ValueError, AuthenticationError):
                raise HTTPException(status_code=403, detail="request rejected")

        @app.get("/api/v1/auth/login/csrf")
        async def login_csrf(response: Response):
            pre_session, token = self.login_csrf.issue()
            response.headers["Set-Cookie"] = f"{LOGIN_CSRF_COOKIE}={pre_session}; Max-Age=600; Path=/; HttpOnly; Secure; SameSite=Lax"
            return {"csrf_token": token}

        @app.post("/api/v1/auth/login")
        async def login(body: LoginBody, request: Request, response: Response):
            try:
                cookie = request.cookies.get(LOGIN_CSRF_COOKIE)
                if not cookie or (body.pre_session is not None and cookie != body.pre_session):
                    raise AuthenticationError("request rejected")
                self.login_csrf.consume(cookie, body.csrf_token)
                ticket = await self.auth.login(body.email, body.password, ip=request.client.host if request.client else "unknown", user_agent=request.headers.get("user-agent"), request_id=request_id(request))
            except AuthenticationError as error:
                detail = GENERIC_LOGIN_ERROR if str(error) == GENERIC_LOGIN_ERROR else "request rejected"
                raise HTTPException(status_code=401, detail=detail)
            response.headers["Set-Cookie"] = cookie_header(ticket.raw_id, max_age=43200)
            response.headers["X-CSRF-Token"] = ticket.csrf_token
            response.headers["Cache-Control"] = "no-store"
            return {"user_id": str(ticket.user_id)}

        @app.get("/api/v1/auth/bootstrap/status")
        async def bootstrap_status():
            async with self.sessions() as session:
                available = await session.scalar(select(User.id).limit(1)) is None
            return {"available": available}

        @app.post("/api/v1/auth/bootstrap-owner")
        async def bootstrap_owner(body: BootstrapOwnerBody, request: Request, response: Response):
            try:
                cookie = request.cookies.get(LOGIN_CSRF_COOKIE)
                if not cookie or not body.email.strip():
                    raise AuthenticationError("request rejected")
                self.login_csrf.consume(cookie, request.headers.get("X-CSRF-Token", ""))
                ticket = await self.auth.bootstrap_owner(
                    body.email,
                    body.password,
                    ip=request.client.host if request.client else "unknown",
                    user_agent=request.headers.get("user-agent"),
                    request_id=request_id(request),
                )
            except AuthenticationError as error:
                if str(error) == "bootstrap already completed":
                    raise HTTPException(status_code=409, detail="first account already created")
                raise HTTPException(status_code=400, detail="account creation rejected")
            except ValueError:
                raise HTTPException(status_code=400, detail="password does not meet policy")
            response.headers["Set-Cookie"] = cookie_header(ticket.raw_id, max_age=8 * 60 * 60)
            response.headers["X-CSRF-Token"] = ticket.csrf_token
            response.headers["Cache-Control"] = "no-store"
            return {"user_id": str(ticket.user_id)}

        @app.post("/api/v1/auth/logout")
        async def logout(request: Request, response: Response):
            record, user = await current(request)
            await csrf_request(request, record)
            await self.auth.logout(request.cookies[COOKIE_NAME], request_id=request_id(request), ip=request.client.host if request.client else None)
            response.headers["Set-Cookie"] = clear_cookie_header()
            return {"ok": True}

        @app.get("/api/v1/auth/me")
        async def me(request: Request):
            _, user = await current(request)
            return {"user_id": str(user.id), "email": user.email, "status": user.status}

        @app.get("/api/v1/auth/csrf")
        async def session_csrf(request: Request, response: Response):
            record, _ = await current(request)
            token = random_token()
            async with self.sessions() as session:
                async with session.begin():
                    stored = await session.get(Session, record.id)
                    if stored is None:
                        raise HTTPException(status_code=401, detail="authentication required")
                    stored.csrf_token_hash = token_hash(token)
            response.headers["X-CSRF-Token"] = token
            return {"csrf_token": token}

        @app.post("/api/v1/auth/password/change")
        async def change_password(body: PasswordChangeBody, request: Request, response: Response):
            record, _ = await current(request)
            await csrf_request(request, record)
            try:
                ticket = await self.auth.change_password(request.cookies[COOKIE_NAME], body.current_password, body.new_password, request_id=request_id(request))
            except AuthenticationError:
                raise HTTPException(status_code=400, detail="password change rejected")
            response.headers["Set-Cookie"] = cookie_header(ticket.raw_id, max_age=43200)
            response.headers["X-CSRF-Token"] = ticket.csrf_token
            return {"ok": True}

        @app.post("/api/v1/auth/reset/request")
        async def reset_request(body: ResetRequestBody, request: Request, response: Response):
            token = None
            async with self.sessions() as session:
                user = await session.scalar(select(User).where(User.email == body.email.strip().casefold()))
            if user is not None and self.manual_links:
                token = await self.auth.issue_reset_token(user.id, request_id=request_id(request))
            elif user is not None and self.email_provider is not None and user.email:
                token = await self.auth.issue_reset_token(user.id, request_id=request_id(request))
                link = f"{self.public_base_url}/reset-password#{token}"
                try:
                    await asyncio.to_thread(
                        self.email_provider.send,
                        recipient=user.email,
                        subject="Reset your FleetTracker password",
                        body=(
                            "<p>We received a request to reset your FleetTracker password.</p>"
                            f"<p><a href=\"{html.escape(link, quote=True)}\">Reset your password</a></p>"
                            "<p>This link expires in one hour and can only be used once.</p>"
                        ),
                    )
                except EmailDeliveryError:
                    logger.exception("password reset email delivery failed")
            response.headers["Cache-Control"] = "no-store"
            result = {"message": GENERIC_RESET_MESSAGE}
            if token is not None:
                result["reset_token"] = token
            return result

        @app.post("/api/v1/auth/reset/consume")
        async def reset_consume(body: ResetConsumeBody, request: Request, response: Response):
            try:
                await self.auth.consume_reset_token(body.token, body.new_password, request_id=request_id(request))
            except AuthenticationError:
                raise HTTPException(status_code=400, detail="reset request rejected")
            response.headers["Cache-Control"] = "no-store"
            return {"ok": True}

        @app.get("/api/v1/auth/sessions")
        async def sessions_list(request: Request):
            _, user = await current(request)
            async with self.sessions() as session:
                rows = await session.scalars(select(Session).where(Session.user_id == user.id, Session.revoked_at.is_(None)))
                return [{"id": str(row.id), "created_at": row.created_at, "last_seen_at": row.last_seen_at} for row in rows]

        @app.post("/api/v1/auth/sessions/{session_id}/revoke")
        async def sessions_revoke(session_id: UUID, request: Request):
            record, user = await current(request)
            await csrf_request(request, record)
            async with self.sessions() as session:
                async with session.begin():
                    target = await session.scalar(select(Session).where(Session.id == session_id, Session.user_id == user.id))
                    if target is None:
                        raise HTTPException(status_code=404, detail="not found")
                    target.revoked_at = datetime.now(UTC)
                    target.revoke_reason = "user_revoke"
                    await write_audit(session, action="session.revoke", result="success", request_id=request_id(request), actor_user_id=user.id, target_id=str(session_id))
            return {"ok": True}

        @app.post("/api/v1/auth/reauthenticate")
        async def reauthenticate(body: ReauthBody, request: Request):
            record, _ = await current(request)
            await csrf_request(request, record)
            await self.auth.reauthenticate(request.cookies[COOKIE_NAME], body.password, purpose=body.purpose, request_id=request_id(request))
            return {"ok": True}

        async def org_principal(request: Request, org_id: UUID) -> tuple[Session, User, object]:
            record, user = await current(request)
            assurance = Assurance.RECENT_REAUTHENTICATION if has_recent_reauthentication(record) else Assurance.PASSWORD
            async with self.sessions() as session:
                membership = await membership_for(session, user_id=user.id, organization_id=org_id)
                if membership is None:
                    raise HTTPException(status_code=404, detail="not found")
                principal = await principal_for(session, user_id=user.id, organization_id=org_id, assurance=assurance)
            return record, user, principal

        def denied() -> HTTPException:
            return HTTPException(status_code=404, detail="not found")

        @app.get("/api/v1/orgs/{org_id}")
        async def organization_detail(org_id: UUID, request: Request):
            _, _, principal = await org_principal(request, org_id)
            if not authorize(principal, Action.VIEW_ORGANIZATION, Resource(org_id)):
                raise denied()
            async with self.sessions() as session:
                async with organization_transaction(session, org_id):
                    organization = await session.scalar(select(Organization).where(Organization.id == org_id))
                    if organization is None:
                        raise denied()
                    return {"id": str(organization.id), "name": organization.name, "timezone": organization.timezone, "position_retention_months": organization.position_retention_months, "raw_retention_days": organization.raw_retention_days}

        @app.patch("/api/v1/orgs/{org_id}/settings")
        async def organization_settings(org_id: UUID, body: OrganizationSettingsBody, request: Request):
            record, user, principal = await org_principal(request, org_id)
            await csrf_request(request, record)
            if not authorize(principal, Action.UPDATE_ORGANIZATION_SETTINGS, Resource(org_id)):
                raise denied()
            async with self.sessions() as session:
                async with organization_transaction(session, org_id):
                    organization = await session.scalar(select(Organization).where(Organization.id == org_id))
                    if organization is None:
                        raise denied()
                    organization.name = body.name
                    organization.timezone = body.timezone
                    organization.position_retention_months = body.position_retention_months
                    organization.raw_retention_days = body.raw_retention_days
                    await write_audit(session, action="organization.settings_update", result="success", request_id=request_id(request), actor_user_id=user.id, organization_id=org_id)
            return {"ok": True}

        @app.get("/api/v1/orgs/{org_id}/audit")
        async def audit_events(org_id: UUID, request: Request):
            _, _, principal = await org_principal(request, org_id)
            if not authorize(principal, Action.READ_AUDIT_LOG, Resource(org_id)):
                raise denied()
            async with self.sessions() as session:
                async with organization_transaction(session, org_id):
                    rows = await session.scalars(select(AuditEvent).where(AuditEvent.organization_id == org_id).order_by(AuditEvent.occurred_at.desc()).limit(500))
                    return [{"id": row.id, "occurred_at": row.occurred_at, "action": row.action, "result": row.result, "target_type": row.target_type, "target_id": row.target_id, "metadata": row.metadata_json} for row in rows]

        async def vehicle_in_scope(session: AsyncSession, *, org_id: UUID, user_id: UUID, vehicle_id: UUID) -> bool:
            membership_id = select(OrganizationMembership.id).where(OrganizationMembership.user_id == user_id, OrganizationMembership.organization_id == org_id).scalar_subquery()
            return await session.scalar(select(VehicleGroupMembership.vehicle_id).join(MembershipGroupScope, and_(MembershipGroupScope.group_id == VehicleGroupMembership.group_id, MembershipGroupScope.organization_id == org_id)).where(VehicleGroupMembership.vehicle_id == vehicle_id, MembershipGroupScope.membership_id == membership_id).limit(1)) is not None

        @app.get("/api/v1/orgs/{org_id}/members")
        async def members(org_id: UUID, request: Request):
            record, user, principal = await org_principal(request, org_id)
            if not authorize(principal, Action.VIEW_MEMBERS, Resource(org_id)):
                raise denied()
            async with self.sessions() as session:
                async with organization_transaction(session, org_id):
                    rows = await session.execute(select(OrganizationMembership, User.email).join(User, User.id == OrganizationMembership.user_id).where(OrganizationMembership.organization_id == org_id))
                    return [{"user_id": str(row[0].user_id), "email": row[1], "role": row[0].role, "status": row[0].status, "group_scope_mode": row[0].group_scope_mode} for row in rows]

        @app.post("/api/v1/orgs/{org_id}/invitations")
        async def invite(org_id: UUID, body: InvitationBody, request: Request):
            record, user, _ = await org_principal(request, org_id)
            if self.email_provider is not None and not body.email:
                raise HTTPException(status_code=400, detail="email is required for email invitations")
            try:
                role = Role(body.role)
                assurance = Assurance.RECENT_REAUTHENTICATION if has_recent_reauthentication(record) else Assurance.PASSWORD
                token = await create_invitation(self.sessions, actor=user.id, organization_id=org_id, role=role, email=body.email, assurance=assurance, request_id=request_id(request))
            except (ValueError, OrganizationError):
                raise denied()
            if self.email_provider is not None and body.email:
                link = f"{self.public_base_url}/accept-invitation#{token}"
                try:
                    await asyncio.to_thread(
                        self.email_provider.send,
                        recipient=body.email,
                        subject="You’re invited to FleetTracker",
                        body=(
                            "<p>You’ve been invited to join a FleetTracker organization.</p>"
                            f"<p><a href=\"{html.escape(link, quote=True)}\">Accept the invitation</a></p>"
                            "<p>This invitation expires in two days.</p>"
                        ),
                    )
                except EmailDeliveryError:
                    logger.exception("organization invitation email delivery failed")
                    raise HTTPException(status_code=502, detail="invitation email could not be sent")
            response = {"created": True}
            if self.manual_links:
                response["invite_token"] = token
            return Response(content=__import__("json").dumps(response), media_type="application/json", headers={"Cache-Control": "no-store"})

        @app.get("/api/v1/orgs/{org_id}/invitations")
        async def invitations(org_id: UUID, request: Request):
            _, _, principal = await org_principal(request, org_id)
            if not authorize(principal, Action.VIEW_MEMBERS, Resource(org_id)):
                raise denied()
            async with self.sessions() as session:
                async with organization_transaction(session, org_id):
                    rows = await session.scalars(select(OrganizationInvitation).where(OrganizationInvitation.organization_id == org_id).order_by(OrganizationInvitation.created_at.desc()).limit(500))
                    return [{"id": str(row.id), "email": row.email, "role": row.role, "expires_at": row.expires_at, "accepted_at": row.accepted_at, "revoked_at": row.revoked_at} for row in rows]

        @app.post("/api/v1/auth/invitations/accept")
        async def accept(body: AcceptInvitationBody, request: Request):
            existing = None
            raw = request.cookies.get(COOKIE_NAME)
            if raw:
                async with self.sessions() as session:
                    try:
                        _, user = await require_session(session, raw)
                        existing = user.id
                    except AuthenticationError:
                        existing = None
            try:
                user_id = await accept_invitation(self.sessions, self.auth.passwords, token=body.token, password=body.password, existing_user_id=existing, request_id=request_id(request))
            except (OrganizationError, AuthenticationError):
                raise HTTPException(status_code=400, detail="invitation rejected")
            return {"user_id": str(user_id)}

        @app.post("/api/v1/orgs/{org_id}/invitations/{invitation_id}/revoke")
        async def invitation_revoke(org_id: UUID, invitation_id: UUID, request: Request):
            record, user, _ = await org_principal(request, org_id)
            await csrf_request(request, record)
            assurance = Assurance.RECENT_REAUTHENTICATION if has_recent_reauthentication(record) else Assurance.PASSWORD
            try:
                await revoke_invitation(self.sessions, actor=user.id, organization_id=org_id, invitation_id=invitation_id, assurance=assurance, request_id=request_id(request))
            except OrganizationError:
                raise denied()
            return {"ok": True}

        @app.post("/api/v1/orgs/{org_id}/invitations/{invitation_id}/resend")
        async def invitation_resend(org_id: UUID, invitation_id: UUID, request: Request, response: Response):
            record, user, _ = await org_principal(request, org_id)
            await csrf_request(request, record)
            assurance = Assurance.RECENT_REAUTHENTICATION if has_recent_reauthentication(record) else Assurance.PASSWORD
            try:
                replacement_id, token = await resend_invitation(self.sessions, actor=user.id, organization_id=org_id, invitation_id=invitation_id, assurance=assurance, request_id=request_id(request))
            except OrganizationError:
                raise denied()
            result = {"invitation_id": str(replacement_id)}
            if self.manual_links:
                result["invite_token"] = token
            response.headers["Cache-Control"] = "no-store"
            return result

        @app.post("/api/v1/orgs/{org_id}/members/{target_user_id}/reset")
        async def member_reset(org_id: UUID, target_user_id: UUID, request: Request, response: Response):
            record, user, principal = await org_principal(request, org_id)
            await csrf_request(request, record)
            assurance = Assurance.RECENT_REAUTHENTICATION if has_recent_reauthentication(record) else Assurance.PASSWORD
            async with self.sessions() as session:
                target = await session.scalar(select(OrganizationMembership).where(OrganizationMembership.organization_id == org_id, OrganizationMembership.user_id == target_user_id))
            if target is None:
                raise denied()
            action = Action.ADMIN_RESET_OWNER_ADMIN if target.role in {Role.OWNER.value, Role.ADMIN.value} else Action.ADMIN_RESET_DISPATCHER_VIEWER
            if not authorize(principal, action, Resource(org_id, target_role=Role(target.role))):
                raise denied()
            token = await self.auth.issue_reset_token(target_user_id, request_id=request_id(request))
            response.headers["Cache-Control"] = "no-store"
            return {"reset_token": token} if self.manual_links else {"created": True}

        @app.patch("/api/v1/orgs/{org_id}/members/{target_user_id}/role")
        async def member_role(org_id: UUID, target_user_id: UUID, body: RoleBody, request: Request, response: Response):
            record, user, _ = await org_principal(request, org_id)
            await csrf_request(request, record)
            try:
                role = Role(body.role)
                assurance = Assurance.RECENT_REAUTHENTICATION if has_recent_reauthentication(record) else Assurance.PASSWORD
                await change_membership_role(self.sessions, actor=user.id, organization_id=org_id, target_user=target_user_id, role=role, assurance=assurance, request_id=request_id(request))
                ticket = await self.auth.rotate_after_privilege_change(request.cookies[COOKIE_NAME], request_id=request_id(request))
            except (ValueError, OrganizationError):
                raise denied()
            response.headers["Set-Cookie"] = cookie_header(ticket.raw_id, max_age=43200)
            response.headers["X-CSRF-Token"] = ticket.csrf_token
            return {"ok": True}

        @app.post("/api/v1/orgs/{org_id}/members/{target_user_id}/{status}")
        async def member_status(org_id: UUID, target_user_id: UUID, status: str, request: Request):
            record, user, _ = await org_principal(request, org_id)
            await csrf_request(request, record)
            try:
                assurance = Assurance.RECENT_REAUTHENTICATION if has_recent_reauthentication(record) else Assurance.PASSWORD
                await set_membership_status(self.sessions, actor=user.id, organization_id=org_id, target_user=target_user_id, status=status, assurance=assurance, request_id=request_id(request))
            except OrganizationError:
                raise denied()
            return {"ok": True}

        @app.delete("/api/v1/orgs/{org_id}/data")
        async def organization_data_delete(org_id: UUID, request: Request):
            record, user, principal = await org_principal(request, org_id)
            await csrf_request(request, record)
            if not authorize(principal, Action.DELETE_ORGANIZATION_DATA, Resource(org_id)):
                raise denied()
            async with self.sessions() as session:
                async with organization_transaction(session, org_id):
                    await session.execute(text("SELECT fleet_delete_organization_data(:organization_id)"), {"organization_id": org_id})
                    await write_audit(session, action="organization.data_delete", result="success", request_id=request_id(request), actor_user_id=user.id, organization_id=org_id)
            return {"ok": True}

        @app.get("/api/v1/orgs/{org_id}/groups")
        async def groups(org_id: UUID, request: Request):
            _, _, principal = await org_principal(request, org_id)
            if not authorize(principal, Action.MANAGE_GROUPS, Resource(org_id)) and principal.role not in {Role.DISPATCHER, Role.VIEWER}:
                raise denied()
            async with self.sessions() as session:
                async with organization_transaction(session, org_id):
                    rows = await session.scalars(select(UserGroup).where(UserGroup.organization_id == org_id))
                    return [{"id": str(row.id), "name": row.name} for row in rows]

        @app.post("/api/v1/orgs/{org_id}/groups")
        async def group_create(org_id: UUID, body: GroupBody, request: Request):
            record, user, _ = await org_principal(request, org_id)
            await csrf_request(request, record)
            try:
                assurance = Assurance.RECENT_REAUTHENTICATION if has_recent_reauthentication(record) else Assurance.PASSWORD
                group_id = await create_group(self.sessions, actor=user.id, organization_id=org_id, name=body.name, assurance=assurance, request_id=request_id(request))
            except OrganizationError:
                raise denied()
            return {"id": str(group_id), "name": body.name}

        @app.delete("/api/v1/orgs/{org_id}/groups/{group_id}")
        async def group_delete(org_id: UUID, group_id: UUID, request: Request):
            record, user, principal = await org_principal(request, org_id)
            await csrf_request(request, record)
            if not authorize(principal, Action.MANAGE_GROUPS, Resource(org_id)):
                raise denied()
            async with self.sessions() as session:
                async with organization_transaction(session, org_id):
                    group = await session.scalar(select(UserGroup).where(UserGroup.id == group_id, UserGroup.organization_id == org_id))
                    if group is None:
                        raise denied()
                    await session.delete(group)
                    await write_audit(session, action="group.delete", result="success", request_id=request_id(request), actor_user_id=user.id, organization_id=org_id, target_id=str(group_id))
            return {"ok": True}

        @app.post("/api/v1/orgs/{org_id}/groups/{group_id}/vehicles/{vehicle_id}")
        async def group_vehicle_assign(org_id: UUID, group_id: UUID, vehicle_id: UUID, request: Request):
            record, user, principal = await org_principal(request, org_id)
            await csrf_request(request, record)
            if not authorize(principal, Action.ASSIGN_VEHICLES_TO_GROUPS, Resource(org_id)):
                raise denied()
            async with self.sessions() as session:
                async with organization_transaction(session, org_id):
                    group = await session.scalar(select(UserGroup).where(UserGroup.id == group_id, UserGroup.organization_id == org_id))
                    vehicle = await session.scalar(select(Vehicle).where(Vehicle.id == vehicle_id, Vehicle.organization_id == org_id))
                    if group is None or vehicle is None:
                        raise denied()
                    session.add(VehicleGroupMembership(organization_id=org_id, group_id=group_id, vehicle_id=vehicle_id))
                    await write_audit(session, action="group.vehicle_assign", result="success", request_id=request_id(request), actor_user_id=user.id, organization_id=org_id, target_id=str(vehicle_id))
            return {"ok": True}

        @app.put("/api/v1/orgs/{org_id}/members/{target_user_id}/groups")
        async def member_scope(org_id: UUID, target_user_id: UUID, body: GroupScopeBody, request: Request):
            record, user, principal = await org_principal(request, org_id)
            await csrf_request(request, record)
            if not authorize(principal, Action.SET_MEMBER_GROUP_SCOPE, Resource(org_id)):
                raise denied()
            async with self.sessions() as session:
                async with organization_transaction(session, org_id):
                    membership = await session.scalar(select(OrganizationMembership).where(OrganizationMembership.organization_id == org_id, OrganizationMembership.user_id == target_user_id))
                    if membership is None:
                        raise denied()
                    valid_groups = set(await session.scalars(select(UserGroup.id).where(UserGroup.organization_id == org_id, UserGroup.id.in_(body.group_ids))))
                    if valid_groups != set(body.group_ids):
                        raise denied()
                    await session.execute(delete(MembershipGroupScope).where(MembershipGroupScope.organization_id == org_id, MembershipGroupScope.membership_id == membership.id))
                    membership.group_scope_mode = "restricted" if body.group_ids else "all"
                    session.add_all([MembershipGroupScope(organization_id=org_id, membership_id=membership.id, group_id=group_id) for group_id in body.group_ids])
                    await write_audit(session, action="membership.group_scope", result="success", request_id=request_id(request), actor_user_id=user.id, organization_id=org_id, target_id=str(target_user_id), metadata={"role": membership.role})
            return {"ok": True, "group_scope_mode": "restricted" if body.group_ids else "all"}

        @app.get("/api/v1/orgs/{org_id}/vehicles")
        async def vehicles(org_id: UUID, request: Request):
            _, user, principal = await org_principal(request, org_id)
            if not authorize(principal, Action.VIEW_VEHICLES, Resource(org_id, group_id=UUID(int=0) if principal.group_scope_mode == "all" else None)):
                raise denied()
            async with self.sessions() as session:
                async with organization_transaction(session, org_id):
                    query = select(Vehicle).where(Vehicle.organization_id == org_id)
                    if principal.group_scope_mode == "restricted":
                        query = query.where(exists(select(VehicleGroupMembership.vehicle_id).join(MembershipGroupScope, and_(MembershipGroupScope.group_id == VehicleGroupMembership.group_id, MembershipGroupScope.organization_id == org_id)).where(VehicleGroupMembership.vehicle_id == Vehicle.id, MembershipGroupScope.membership_id == select(OrganizationMembership.id).where(OrganizationMembership.user_id == user.id, OrganizationMembership.organization_id == org_id).scalar_subquery())))
                    rows = await session.scalars(query)
                    return [{"id": str(row.id), "name": row.name, "plate_number": row.plate_number, "color": row.color} for row in rows]

        @app.post("/api/v1/orgs/{org_id}/vehicles")
        async def vehicle_create(org_id: UUID, body: VehicleBody, request: Request):
            record, user, principal = await org_principal(request, org_id)
            await csrf_request(request, record)
            if not authorize(principal, Action.CREATE_VEHICLE, Resource(org_id)):
                raise denied()
            async with self.sessions() as session:
                async with organization_transaction(session, org_id):
                    used_colors = set(await session.scalars(select(Vehicle.color).where(Vehicle.organization_id == org_id)))
                    vehicle = Vehicle(organization_id=org_id, name=body.name, plate_number=body.plate_number, color=next_vehicle_color(used_colors), created_at=datetime.now(UTC))
                    session.add(vehicle)
                    await session.flush()
                    await write_audit(session, action="vehicle.create", result="success", request_id=request_id(request), actor_user_id=user.id, organization_id=org_id, target_id=str(vehicle.id))
                    return {"id": str(vehicle.id), "color": vehicle.color}

        @app.get("/api/v1/orgs/{org_id}/vehicles/{vehicle_id}")
        async def vehicle_get(org_id: UUID, vehicle_id: UUID, request: Request):
            _, user, principal = await org_principal(request, org_id)
            if not authorize(principal, Action.VIEW_VEHICLES, Resource(org_id, group_id=UUID(int=0) if principal.group_scope_mode == "all" else None)):
                raise denied()
            async with self.sessions() as session:
                async with organization_transaction(session, org_id):
                    vehicle = await session.scalar(select(Vehicle).where(Vehicle.id == vehicle_id, Vehicle.organization_id == org_id))
                    if vehicle is None:
                        raise denied()
                    if principal.group_scope_mode == "restricted":
                        if not await vehicle_in_scope(session, org_id=org_id, user_id=user.id, vehicle_id=vehicle_id):
                            raise denied()
                    return {"id": str(vehicle.id), "name": vehicle.name, "plate_number": vehicle.plate_number, "color": vehicle.color}

        @app.patch("/api/v1/orgs/{org_id}/vehicles/{vehicle_id}")
        async def vehicle_update(org_id: UUID, vehicle_id: UUID, body: VehicleBody, request: Request):
            record, user, principal = await org_principal(request, org_id)
            await csrf_request(request, record)
            if not authorize(principal, Action.UPDATE_VEHICLE, Resource(org_id, group_id=UUID(int=0) if principal.group_scope_mode == "all" else None)):
                raise denied()
            async with self.sessions() as session:
                async with organization_transaction(session, org_id):
                    vehicle = await session.scalar(select(Vehicle).where(Vehicle.id == vehicle_id, Vehicle.organization_id == org_id))
                    if vehicle is None:
                        raise denied()
                    if principal.group_scope_mode == "restricted" and not await vehicle_in_scope(session, org_id=org_id, user_id=user.id, vehicle_id=vehicle_id):
                        raise denied()
                    vehicle.name = body.name
                    vehicle.plate_number = body.plate_number
                    await write_audit(session, action="vehicle.update", result="success", request_id=request_id(request), actor_user_id=user.id, organization_id=org_id, target_id=str(vehicle_id))
            return {"ok": True}

        @app.delete("/api/v1/orgs/{org_id}/vehicles/{vehicle_id}")
        async def vehicle_delete(org_id: UUID, vehicle_id: UUID, request: Request):
            record, user, principal = await org_principal(request, org_id)
            await csrf_request(request, record)
            if not authorize(principal, Action.DELETE_VEHICLE, Resource(org_id, group_id=UUID(int=0) if principal.group_scope_mode == "all" else None)):
                raise denied()
            async with self.sessions() as session:
                async with organization_transaction(session, org_id):
                    vehicle = await session.scalar(select(Vehicle).where(Vehicle.id == vehicle_id, Vehicle.organization_id == org_id))
                    if vehicle is None:
                        raise denied()
                    if principal.group_scope_mode == "restricted" and not await vehicle_in_scope(session, org_id=org_id, user_id=user.id, vehicle_id=vehicle_id):
                        raise denied()
                    await session.delete(vehicle)
                    await write_audit(session, action="vehicle.delete", result="success", request_id=request_id(request), actor_user_id=user.id, organization_id=org_id, target_id=str(vehicle_id))
            return {"ok": True}

        @app.get("/api/v1/orgs/{org_id}/devices")
        async def devices(org_id: UUID, request: Request):
            _, user, principal = await org_principal(request, org_id)
            if not authorize(principal, Action.VIEW_DEVICES, Resource(org_id, group_id=UUID(int=0) if principal.group_scope_mode == "all" else None)):
                raise denied()
            async with self.sessions() as session:
                async with organization_transaction(session, org_id):
                    query = select(Device, DeviceVehicleAssignment.vehicle_id).join(DeviceVehicleAssignment, and_(DeviceVehicleAssignment.device_id == Device.id, DeviceVehicleAssignment.organization_id == org_id, DeviceVehicleAssignment.effective_to.is_(None))).where(Device.organization_id == org_id, Device.active.is_(True))
                    if principal.group_scope_mode == "restricted":
                        scoped = select(VehicleGroupMembership.vehicle_id).join(MembershipGroupScope, and_(MembershipGroupScope.group_id == VehicleGroupMembership.group_id, MembershipGroupScope.organization_id == org_id)).where(MembershipGroupScope.membership_id == select(OrganizationMembership.id).where(OrganizationMembership.user_id == user.id, OrganizationMembership.organization_id == org_id).scalar_subquery())
                        query = query.where(DeviceVehicleAssignment.vehicle_id.in_(scoped))
                    rows = await session.execute(query)
                    return [{"id": str(row[0].id), "terminal_id": row[0].terminal_id, "vehicle_id": str(row[1])} for row in rows]

        @app.get("/api/v1/orgs/{org_id}/positions")
        async def positions(org_id: UUID, request: Request):
            _, user, principal = await org_principal(request, org_id)
            if not authorize(principal, Action.VIEW_POSITIONS, Resource(org_id, group_id=UUID(int=0) if principal.group_scope_mode == "all" else None)):
                raise denied()
            async with self.sessions() as session:
                async with organization_transaction(session, org_id):
                    query = select(Position).where(Position.organization_id == org_id).order_by(Position.gps_timestamp.desc()).limit(1000)
                    if principal.group_scope_mode == "restricted":
                        scoped = select(VehicleGroupMembership.vehicle_id).join(MembershipGroupScope, and_(MembershipGroupScope.group_id == VehicleGroupMembership.group_id, MembershipGroupScope.organization_id == org_id)).where(MembershipGroupScope.membership_id == select(OrganizationMembership.id).where(OrganizationMembership.user_id == user.id, OrganizationMembership.organization_id == org_id).scalar_subquery())
                        query = query.where(Position.vehicle_id.in_(scoped))
                    rows = await session.scalars(query)
                    return [{"id": row.id, "vehicle_id": str(row.vehicle_id), "gps_timestamp": row.gps_timestamp, "latitude": row.latitude, "longitude": row.longitude} for row in rows]

        def latest_status(row: VehicleLatestState, now: datetime) -> str:
            if row.last_authenticated_message_at is None or now - row.last_authenticated_message_at > timedelta(seconds=self.offline_after_seconds):
                return "offline"
            if row.last_position_at is None or row.latitude is None or row.longitude is None:
                return "no_fix"
            return "moving" if (row.speed_kmh or 0) >= self.moving_speed_kmh else "stopped"

        def latest_payload(row: VehicleLatestState, vehicle: Vehicle, device: Device | None, now: datetime) -> dict[str, object]:
            return {
                "vehicle_id": str(row.vehicle_id),
                "vehicle_name": vehicle.name,
                "plate_number": vehicle.plate_number,
                "color": vehicle.color,
                "device_id": str(row.device_id),
                "terminal_id": device.terminal_id if device is not None else None,
                "status": latest_status(row, now),
                "last_authenticated_message_at": row.last_authenticated_message_at,
                "last_position_at": row.last_position_at,
                "gps_timestamp": row.gps_timestamp,
                "latitude": row.latitude,
                "longitude": row.longitude,
                "speed_kmh": row.speed_kmh,
                "course": row.course,
                "updated_at": row.updated_at,
            }

        async def latest_rows(session: AsyncSession, *, org_id: UUID, user_id: UUID, restricted: bool, after: datetime | None = None, after_vehicle_id: UUID | None = None):
            query = select(VehicleLatestState, Vehicle, Device).join(
                Vehicle,
                and_(Vehicle.organization_id == org_id, Vehicle.id == VehicleLatestState.vehicle_id),
            ).outerjoin(
                Device,
                and_(Device.organization_id == org_id, Device.id == VehicleLatestState.device_id),
            ).where(VehicleLatestState.organization_id == org_id)
            if after is not None:
                query = query.where(
                    (VehicleLatestState.updated_at > after)
                    | ((VehicleLatestState.updated_at == after) & (VehicleLatestState.vehicle_id > (after_vehicle_id or UUID(int=0))))
                )
            if restricted:
                membership_id = select(OrganizationMembership.id).where(
                    OrganizationMembership.user_id == user_id,
                    OrganizationMembership.organization_id == org_id,
                ).scalar_subquery()
                query = query.where(exists(select(VehicleGroupMembership.vehicle_id).join(
                    MembershipGroupScope,
                    and_(MembershipGroupScope.group_id == VehicleGroupMembership.group_id, MembershipGroupScope.organization_id == org_id),
                ).where(VehicleGroupMembership.vehicle_id == VehicleLatestState.vehicle_id, MembershipGroupScope.membership_id == membership_id)))
            return await session.execute(query.order_by(VehicleLatestState.updated_at, VehicleLatestState.vehicle_id).limit(500))

        @app.get("/api/v1/orgs/{org_id}/vehicles/latest-state")
        async def vehicles_latest_state(org_id: UUID, request: Request):
            _, user, principal = await org_principal(request, org_id)
            if not authorize(principal, Action.VIEW_VEHICLES, Resource(org_id, group_id=UUID(int=0))):
                raise denied()
            async with self.sessions() as session:
                async with organization_transaction(session, org_id):
                    rows = await latest_rows(session, org_id=org_id, user_id=user.id, restricted=principal.group_scope_mode == "restricted")
                    now = datetime.now(UTC)
                    return [latest_payload(row, vehicle, device, now) for row, vehicle, device in rows]

        @app.get("/api/v1/orgs/{org_id}/vehicles/{vehicle_id}/latest-state")
        async def vehicle_latest_state(org_id: UUID, vehicle_id: UUID, request: Request):
            _, user, principal = await org_principal(request, org_id)
            if not authorize(principal, Action.VIEW_VEHICLES, Resource(org_id, group_id=UUID(int=0))):
                raise denied()
            async with self.sessions() as session:
                async with organization_transaction(session, org_id):
                    vehicle = await session.scalar(select(Vehicle).where(Vehicle.organization_id == org_id, Vehicle.id == vehicle_id))
                    if vehicle is None or (principal.group_scope_mode == "restricted" and not await vehicle_in_scope(session, org_id=org_id, user_id=user.id, vehicle_id=vehicle_id)):
                        raise denied()
                    row = await session.scalar(select(VehicleLatestState).where(VehicleLatestState.organization_id == org_id, VehicleLatestState.vehicle_id == vehicle_id))
                    if row is None:
                        raise denied()
                    device = await session.scalar(select(Device).where(Device.organization_id == org_id, Device.id == row.device_id))
                    return latest_payload(row, vehicle, device, datetime.now(UTC))

        @app.get("/api/v1/orgs/{org_id}/vehicles/{vehicle_id}/history")
        async def vehicle_history(
            org_id: UUID,
            vehicle_id: UUID,
            request: Request,
            from_: datetime = Query(alias="from"),
            to: datetime = Query(),
            cursor: datetime | None = Query(default=None),
            limit: int = Query(default=500, ge=1, le=500),
        ):
            _, user, principal = await org_principal(request, org_id)
            if not authorize(principal, Action.VIEW_POSITIONS, Resource(org_id, group_id=UUID(int=0))):
                raise denied()
            from_ = from_.astimezone(UTC)
            to = to.astimezone(UTC)
            if to <= from_ or to - from_ > timedelta(days=31):
                raise HTTPException(status_code=422, detail="history range rejected")
            async with self.sessions() as session:
                async with organization_transaction(session, org_id):
                    vehicle = await session.scalar(select(Vehicle).where(Vehicle.organization_id == org_id, Vehicle.id == vehicle_id))
                    if vehicle is None or (principal.group_scope_mode == "restricted" and not await vehicle_in_scope(session, org_id=org_id, user_id=user.id, vehicle_id=vehicle_id)):
                        raise denied()
                    query = select(Position).where(
                        Position.organization_id == org_id,
                        Position.vehicle_id == vehicle_id,
                        Position.gps_timestamp >= from_,
                        Position.gps_timestamp < to,
                    )
                    if cursor is not None:
                        query = query.where(Position.gps_timestamp > cursor.astimezone(UTC))
                    rows = list(await session.scalars(query.order_by(Position.gps_timestamp).limit(limit * 4 + 1)))
                    has_more = len(rows) > limit * 4
                    if has_more:
                        rows = rows[: limit * 4]
                    if len(rows) > limit:
                        stride = max(1, (len(rows) + limit - 1) // limit)
                        rows = rows[::stride]
                    next_cursor = rows[-1].gps_timestamp if has_more and rows else None
                    return {
                        "vehicle_id": str(vehicle_id),
                        "from": from_,
                        "to": to,
                        "downsampled": len(rows) < limit * 4,
                        "next_cursor": next_cursor,
                        "points": [{"id": row.id, "gps_timestamp": row.gps_timestamp, "latitude": row.latitude, "longitude": row.longitude, "speed_kmh": row.speed_kmh, "course": row.course} for row in rows],
                    }

        @app.get("/api/v1/orgs/{org_id}/vehicles/stream")
        async def vehicle_stream(org_id: UUID, request: Request):
            _, _, principal = await org_principal(request, org_id)
            if not authorize(principal, Action.VIEW_VEHICLES, Resource(org_id, group_id=UUID(int=0))):
                raise denied()
            async with self._sse_lock:
                if self._active_sse_streams >= self.sse_max_streams:
                    raise HTTPException(status_code=503, detail="live updates unavailable")
                self._active_sse_streams += 1

            raw_cursor = request.headers.get("last-event-id")
            cursor_time = None
            cursor_vehicle = None
            if raw_cursor:
                try:
                    cursor_value, cursor_id = raw_cursor.split("|", 1)
                    cursor_time = datetime.fromisoformat(cursor_value).astimezone(UTC)
                    cursor_vehicle = UUID(cursor_id)
                except (ValueError, TypeError):
                    cursor_time = None

            async def events():
                nonlocal cursor_time, cursor_vehicle
                try:
                    while True:
                        if await request.is_disconnected():
                            break
                        try:
                            _, user, current_principal = await org_principal(request, org_id)
                        except HTTPException:
                            break
                        async with self.sessions() as session:
                            async with organization_transaction(session, org_id):
                                rows = await latest_rows(session, org_id=org_id, user_id=user.id, restricted=current_principal.group_scope_mode == "restricted", after=cursor_time, after_vehicle_id=cursor_vehicle)
                                now = datetime.now(UTC)
                                for row, vehicle, device in rows:
                                    cursor_time = row.updated_at
                                    cursor_vehicle = row.vehicle_id
                                    event_id = f"{row.updated_at.isoformat()}|{row.vehicle_id}"
                                    payload = json.dumps(latest_payload(row, vehicle, device, now), default=str, separators=(",", ":"))
                                    yield f"id: {event_id}\nevent: vehicle-state\ndata: {payload}\n\n"
                        yield ": heartbeat\n\n"
                        await asyncio.sleep(1.5)
                finally:
                    async with self._sse_lock:
                        self._active_sse_streams -= 1

            return StreamingResponse(events(), media_type="text/event-stream", headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"})

        @app.post("/api/v1/orgs/{org_id}/devices")
        async def device_provision(org_id: UUID, body: dict, request: Request, response: Response):
            record, user, principal = await org_principal(request, org_id)
            await csrf_request(request, record)
            if self.secret_protector is None or not authorize(principal, Action.PROVISION_DEVICE, Resource(org_id)):
                raise denied()
            try:
                device_id, auth_code = await provision_postgres_device(self.sessions, organization_id=str(org_id), vehicle_id=str(UUID(body["vehicle_id"])), terminal_id=str(body["terminal_id"]), secret_protector=self.secret_protector, auth_code=str(body["auth_code"]) if body.get("auth_code") else None, auth_pepper=self.auth_pepper)
            except (KeyError, ValueError):
                raise denied()
            await _audit_request(self.sessions, action="device.provision", user_id=user.id, org_id=org_id, request_id=request_id(request))
            response.headers["Cache-Control"] = "no-store"
            return {"device_id": device_id, "auth_code": auth_code}

        @app.post("/api/v1/orgs/{org_id}/devices/{device_id}/rotate-secret")
        async def device_rotate(org_id: UUID, device_id: UUID, body: dict, request: Request, response: Response):
            record, user, principal = await org_principal(request, org_id)
            await csrf_request(request, record)
            if self.secret_protector is None or not authorize(principal, Action.ROTATE_DEVICE_SECRET, Resource(org_id)):
                raise denied()
            async with self.sessions() as session:
                terminal = await session.scalar(select(Device.terminal_id).where(Device.id == device_id, Device.organization_id == org_id))
            if terminal is None:
                raise denied()
            try:
                await rotate_postgres_device_secret(self.sessions, terminal_id=terminal, secret_protector=self.secret_protector, auth_code=str(body["auth_code"]), auth_pepper=self.auth_pepper)
            except (KeyError, ValueError):
                raise denied()
            await _audit_request(self.sessions, action="device.secret_rotate", user_id=user.id, org_id=org_id, request_id=request_id(request), target_id=str(device_id))
            response.headers["Cache-Control"] = "no-store"
            return {"ok": True}

        @app.post("/api/v1/orgs/{org_id}/devices/{device_id}/assign")
        async def device_assign(org_id: UUID, device_id: UUID, body: dict, request: Request):
            record, user, principal = await org_principal(request, org_id)
            await csrf_request(request, record)
            if not authorize(principal, Action.ASSIGN_DEVICE, Resource(org_id)):
                raise denied()
            try:
                vehicle_id = UUID(str(body["vehicle_id"]))
            except (KeyError, ValueError):
                raise denied()
            async with self.sessions() as session:
                async with organization_transaction(session, org_id):
                    device = await session.scalar(select(Device).where(Device.id == device_id, Device.organization_id == org_id))
                    vehicle = await session.scalar(select(Vehicle).where(Vehicle.id == vehicle_id, Vehicle.organization_id == org_id))
                    if device is None or vehicle is None:
                        raise denied()
                    now = datetime.now(UTC)
                    current_assignment = await session.scalar(
                        select(DeviceVehicleAssignment).where(
                            DeviceVehicleAssignment.organization_id == org_id,
                            DeviceVehicleAssignment.device_id == device_id,
                            DeviceVehicleAssignment.effective_to.is_(None),
                        )
                    )
                    if current_assignment is not None and current_assignment.vehicle_id == vehicle_id:
                        return {"ok": True}
                    if current_assignment is not None:
                        current_assignment.effective_to = now
                        await session.flush()
                    session.add(DeviceVehicleAssignment(organization_id=org_id, device_id=device_id, vehicle_id=vehicle_id, effective_from=now))
                    await write_audit(session, action="device.assign", result="success", request_id=request_id(request), actor_user_id=user.id, organization_id=org_id, target_id=str(device_id))
            return {"ok": True}

        @app.delete("/api/v1/orgs/{org_id}/devices/{device_id}")
        async def device_delete(org_id: UUID, device_id: UUID, request: Request):
            record, user, principal = await org_principal(request, org_id)
            await csrf_request(request, record)
            if not authorize(principal, Action.DELETE_DEVICE, Resource(org_id)):
                raise denied()
            async with self.sessions() as session:
                async with organization_transaction(session, org_id):
                    device = await session.scalar(select(Device).where(Device.id == device_id, Device.organization_id == org_id, Device.active.is_(True)))
                    if device is None:
                        raise denied()
                    assignment = await session.scalar(
                        select(DeviceVehicleAssignment).where(
                            DeviceVehicleAssignment.device_id == device_id,
                            DeviceVehicleAssignment.organization_id == org_id,
                            DeviceVehicleAssignment.effective_to.is_(None),
                        )
                    )
                    if assignment is not None:
                        assignment.effective_to = datetime.now(UTC)
                    device.active = False
                    await write_audit(session, action="device.delete", result="success", request_id=request_id(request), actor_user_id=user.id, organization_id=org_id, target_id=str(device_id))
            return {"ok": True}

        # Starlette matches routes in registration order. These literal paths
        # must precede the single-segment vehicle detail route so that
        # ``latest-state`` and ``stream`` are not parsed as UUIDs.
        literal_vehicle_paths = {
            f"/api/v1/orgs/{{org_id}}/vehicles/latest-state",
            f"/api/v1/orgs/{{org_id}}/vehicles/stream",
        }
        literal_routes = [route for route in app.router.routes if getattr(route, "path", None) in literal_vehicle_paths]
        app.router.routes[:] = [route for route in app.router.routes if route not in literal_routes]
        detail_index = next((index for index, route in enumerate(app.router.routes) if getattr(route, "path", None) == "/api/v1/orgs/{org_id}/vehicles/{vehicle_id}"), len(app.router.routes))
        for route in reversed(literal_routes):
            app.router.routes.insert(detail_index, route)
        return app


async def _audit_request(sessions, *, action: str, user_id: UUID, org_id: UUID, request_id: str, target_id: str | None = None) -> None:
    async with sessions() as session:
        async with session.begin():
            await write_audit(session, action=action, result="success", request_id=request_id, actor_user_id=user_id, organization_id=org_id, target_id=target_id)


def create_app(sessions: async_sessionmaker[AsyncSession], auth: AuthService, *, manual_links: bool = False, email_provider: EmailProvider | None = None, public_base_url: str = "", secret_protector: SecretProtector | None = None, auth_pepper: bytes = b"", offline_after_seconds: int = 300, moving_speed_kmh: float = 1.0, sse_max_streams: int = 16) -> FastAPI:
    return AuthApp(sessions, auth, manual_links=manual_links, email_provider=email_provider, public_base_url=public_base_url, secret_protector=secret_protector, auth_pepper=auth_pepper, offline_after_seconds=offline_after_seconds, moving_speed_kmh=moving_speed_kmh, sse_max_streams=sse_max_streams).build()

