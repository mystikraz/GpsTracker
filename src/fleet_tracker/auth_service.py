"""Database-backed password authentication workflows."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

from sqlalchemy import select, text, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from .auth_security import (
    DEFAULT_ABSOLUTE_SECONDS, DEFAULT_IDLE_SECONDS, LOCKOUT_SECONDS,
    MAX_FAILED_LOGINS, AuthenticationError, PasswordService, ProcessRateLimiter,
    SessionTicket, create_session, random_token, revoke_all_sessions,
    require_session, rotate_session, token_hash, write_audit,
)
from .db.models import Organization, OrganizationMembership, PasswordToken, Session, User


GENERIC_LOGIN_ERROR = "invalid email or password"


class AuthService:
    def __init__(
        self,
        sessions: async_sessionmaker[AsyncSession],
        *,
        passwords: PasswordService | None = None,
        limiter: ProcessRateLimiter | None = None,
        lockout_seconds: int = LOCKOUT_SECONDS,
    ) -> None:
        self.sessions = sessions
        self.passwords = passwords or PasswordService()
        self.limiter = limiter or ProcessRateLimiter()
        self.lockout_seconds = lockout_seconds
        self._dummy_hash: str | None = None

    async def _dummy(self) -> str:
        if self._dummy_hash is None:
            self._dummy_hash = await self.passwords.hash("dummy-password-not-for-login")
        return self._dummy_hash

    async def bootstrap_owner(self, email: str, password: str, *, ip: str | None, user_agent: str | None, request_id: str) -> SessionTicket:
        normalized = email.strip().casefold()
        password_hash = await self.passwords.hash(password)
        async with self.sessions() as session:
            async with session.begin():
                await session.execute(
                    text("SELECT pg_advisory_xact_lock(hashtextextended(:lock_name, 0))"),
                    {"lock_name": "fleet_tracker.bootstrap_owner"},
                )
                if await session.scalar(select(User.id).limit(1)) is not None:
                    raise AuthenticationError("bootstrap already completed")
                now = datetime.now(UTC)
                user = User(email=normalized, password_hash=password_hash, created_at=now, updated_at=now, password_changed_at=now)
                organization = Organization(name="My organization", timezone="Asia/Kathmandu", position_retention_months=12, raw_retention_days=30, created_at=now)
                session.add(organization)
                await session.flush()
                session.add(user)
                await session.flush()
                await session.execute(
                    text("SELECT set_config('app.organization_id', :organization_id, true)"),
                    {"organization_id": str(organization.id)},
                )
                session.add(OrganizationMembership(organization_id=organization.id, user_id=user.id, role="owner", status="active", group_scope_mode="all", created_at=now))
                ticket = await create_session(session, user=user, ip_address=ip, user_agent_redacted=user_agent, idle_seconds=900, absolute_seconds=8 * 60 * 60)
                await write_audit(session, action="bootstrap.owner_created", result="success", request_id=request_id, actor_user_id=user.id, organization_id=organization.id, ip_address=ip, user_agent_redacted=user_agent)
                return ticket

    async def login(self, email: str, password: str, *, ip: str, user_agent: str | None, request_id: str) -> SessionTicket:
        normalized = email.strip().casefold()
        async with self.sessions() as session:
            async with session.begin():
                user = await session.scalar(select(User).where(User.email == normalized))
                if user is None:
                    await self.passwords.verify(await self._dummy(), password)
                    await write_audit(session, action="login.failure", result="failure", request_id=request_id, ip_address=ip, user_agent_redacted=user_agent)
                    raise AuthenticationError(GENERIC_LOGIN_ERROR)
                now = datetime.now(UTC)
                throttled = not self.limiter.allow(ip=ip, account=normalized)
                locked = user.locked_until is not None and user.locked_until > now
                valid = False if throttled or locked else await self.passwords.verify(user.password_hash, password)
                if not valid:
                    user.failed_login_count += 1
                    if user.failed_login_count >= MAX_FAILED_LOGINS:
                        user.locked_until = now + timedelta(seconds=self.lockout_seconds)
                        await write_audit(session, action="lockout", result="failure", request_id=request_id, actor_user_id=user.id, ip_address=ip, user_agent_redacted=user_agent)
                    await write_audit(session, action="login.failure", result="failure", request_id=request_id, actor_user_id=user.id, ip_address=ip, user_agent_redacted=user_agent)
                    raise AuthenticationError(GENERIC_LOGIN_ERROR)
                user.failed_login_count = 0
                user.locked_until = None
                admin = await session.scalar(select(OrganizationMembership.role).where(OrganizationMembership.user_id == user.id, OrganizationMembership.status == "active", OrganizationMembership.role.in_(("owner", "admin"))).limit(1))
                idle = 900 if admin else DEFAULT_IDLE_SECONDS
                absolute = 8 * 60 * 60 if admin else DEFAULT_ABSOLUTE_SECONDS
                ticket = await create_session(session, user=user, ip_address=ip, user_agent_redacted=user_agent, idle_seconds=idle, absolute_seconds=absolute)
                await write_audit(session, action="login.success", result="success", request_id=request_id, actor_user_id=user.id, ip_address=ip, user_agent_redacted=user_agent)
                return ticket

    async def logout(self, raw_session_id: str, *, request_id: str, ip: str | None = None) -> None:
        async with self.sessions() as session:
            async with session.begin():
                record, user = await require_session(session, raw_session_id)
                record.revoked_at = datetime.now(UTC)
                record.revoke_reason = "logout"
                await write_audit(session, action="logout", result="success", request_id=request_id, actor_user_id=user.id, ip_address=ip)

    async def change_password(self, raw_session_id: str, current_password: str, new_password: str, *, request_id: str) -> SessionTicket:
        async with self.sessions() as session:
            async with session.begin():
                record, user = await require_session(session, raw_session_id)
                if not await self.passwords.verify(user.password_hash, current_password):
                    await write_audit(session, action="password.change", result="failure", request_id=request_id, actor_user_id=user.id)
                    raise AuthenticationError("password change rejected")
                new_hash = await self.passwords.hash(new_password)
                user.password_hash = new_hash
                user.password_changed_at = datetime.now(UTC)
                await revoke_all_sessions(session, user.id, "password_change")
                ticket = await create_session(session, user=user, ip_address=record.ip_address, user_agent_redacted=record.user_agent_redacted)
                await write_audit(session, action="password.change", result="success", request_id=request_id, actor_user_id=user.id)
                return ticket

    async def reauthenticate(self, raw_session_id: str, password: str, *, purpose: str, request_id: str) -> None:
        async with self.sessions() as session:
            async with session.begin():
                record, user = await require_session(session, raw_session_id)
                if not await self.passwords.verify(user.password_hash, password):
                    await write_audit(session, action="reauthentication", result="failure", request_id=request_id, actor_user_id=user.id, metadata={"reason": purpose})
                    raise AuthenticationError("reauthentication failed")
                record.last_reauthenticated_at = datetime.now(UTC)
                await write_audit(session, action="reauthentication", result="success", request_id=request_id, actor_user_id=user.id, metadata={"reason": purpose})

    async def rotate_after_privilege_change(self, raw_session_id: str, *, request_id: str) -> SessionTicket:
        async with self.sessions() as session:
            async with session.begin():
                record, user = await require_session(session, raw_session_id)
                ticket = await rotate_session(session, record, user, reason="privilege_change")
                await write_audit(session, action="session.rotate", result="success", request_id=request_id, actor_user_id=user.id, metadata={"reason": "privilege_change"})
                return ticket

    async def issue_reset_token(self, user_id: UUID, *, request_id: str) -> str:
        token = random_token()
        async with self.sessions() as session:
            async with session.begin():
                await session.execute(text("SELECT set_config('app.user_id', :user_id, true)"), {"user_id": str(user_id)})
                session.add(PasswordToken(user_id=user_id, token_hash=token_hash(token), expires_at=datetime.now(UTC) + timedelta(hours=1), created_at=datetime.now(UTC)))
                await write_audit(session, action="password.reset.request", result="success", request_id=request_id, actor_user_id=user_id, metadata={"channel": "manual"})
        return token

    async def consume_reset_token(self, token: str, new_password: str, *, request_id: str) -> None:
        async with self.sessions() as session:
            async with session.begin():
                await session.execute(text("SELECT set_config('app.reset_token', :token, true)"), {"token": token})
                record = await session.scalar(select(PasswordToken).where(PasswordToken.token_hash == token_hash(token), PasswordToken.consumed_at.is_(None)).with_for_update())
                if record is None or record.expires_at <= datetime.now(UTC):
                    raise AuthenticationError("reset request rejected")
                user = await session.get(User, record.user_id)
                if user is None:
                    raise AuthenticationError("reset request rejected")
                await session.execute(text("SELECT set_config('app.user_id', :user_id, true)"), {"user_id": str(user.id)})
                user.password_hash = await self.passwords.hash(new_password)
                user.password_changed_at = datetime.now(UTC)
                user.failed_login_count = 0
                user.locked_until = None
                record.consumed_at = datetime.now(UTC)
                await revoke_all_sessions(session, user.id, "password_reset")
                await write_audit(session, action="password.reset", result="success", request_id=request_id, actor_user_id=user.id)

