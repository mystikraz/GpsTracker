"""Organization invitations, memberships, and group-scope operations."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

from sqlalchemy import delete, select, text, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from .auth_security import AuthenticationError, PasswordService, random_token, token_hash, write_audit
from .authorization import Action, Assurance, Principal, Resource, Role, authorize
from .db.models import (
    Device, DeviceVehicleAssignment, MembershipGroupScope, OrganizationInvitation,
    OrganizationMembership, User, UserGroup, Vehicle, VehicleGroupMembership,
)


class OrganizationError(Exception):
    pass


def _role(value: str) -> Role:
    try:
        return Role(value)
    except ValueError as error:
        raise OrganizationError("invalid role") from error


async def membership_for(session: AsyncSession, *, user_id: UUID, organization_id: UUID) -> OrganizationMembership | None:
    return await session.scalar(select(OrganizationMembership).where(
        OrganizationMembership.user_id == user_id,
        OrganizationMembership.organization_id == organization_id,
        OrganizationMembership.status == "active",
    ))


async def principal_for(session: AsyncSession, *, user_id: UUID, organization_id: UUID, assurance: Assurance = Assurance.PASSWORD) -> Principal:
    membership = await membership_for(session, user_id=user_id, organization_id=organization_id)
    if membership is None:
        raise OrganizationError("not found")
    return Principal(user_id, organization_id, _role(membership.role), group_scope_mode=membership.group_scope_mode, assurance=assurance)


async def create_invitation(
    sessions: async_sessionmaker[AsyncSession], *, actor: UUID, organization_id: UUID,
    role: Role, email: str | None, assurance: Assurance, request_id: str,
) -> str:
    token = random_token()
    async with sessions() as session:
        async with session.begin():
            await session.execute(text("SELECT pg_advisory_xact_lock(hashtextextended(:organization_id, 0))"), {"organization_id": str(organization_id)})
            principal = await principal_for(session, user_id=actor, organization_id=organization_id, assurance=assurance)
            action = Action.INVITE_ADMIN if role is Role.ADMIN else Action.INVITE_DISPATCHER_VIEWER
            if role is Role.OWNER:
                action = Action.INVITE_OWNER
            if not authorize(principal, action, Resource(organization_id, target_role=role)):
                await write_audit(session, action="invitation.create", result="denied", request_id=request_id, actor_user_id=actor, organization_id=organization_id)
                raise OrganizationError("not found")
            record = OrganizationInvitation(organization_id=organization_id, email=email.casefold() if email else None, role=role.value, token_hash=token_hash(token), expires_at=datetime.now(UTC) + timedelta(days=2), invited_by=actor, created_at=datetime.now(UTC))
            session.add(record)
            await write_audit(session, action="invitation.create", result="success", request_id=request_id, actor_user_id=actor, organization_id=organization_id, metadata={"role": role.value, "channel": "manual"})
    return token


async def accept_invitation(
    sessions: async_sessionmaker[AsyncSession], passwords: PasswordService, *, token: str,
    password: str, existing_user_id: UUID | None, request_id: str,
) -> UUID:
    async with sessions() as session:
        async with session.begin():
            invite = await session.scalar(select(OrganizationInvitation).where(OrganizationInvitation.token_hash == token_hash(token), OrganizationInvitation.accepted_at.is_(None), OrganizationInvitation.revoked_at.is_(None)).with_for_update())
            if invite is None or invite.expires_at <= datetime.now(UTC):
                raise OrganizationError("invitation rejected")
            user = await session.get(User, existing_user_id) if existing_user_id else None
            if user is not None and invite.email and user.email.casefold() != invite.email.casefold():
                raise OrganizationError("invitation rejected")
            if user is None:
                if not invite.email:
                    raise OrganizationError("invitation requires an email")
                user = User(email=invite.email, password_hash=await passwords.hash(password), created_at=datetime.now(UTC), updated_at=datetime.now(UTC), password_changed_at=datetime.now(UTC))
                session.add(user)
                await session.flush()
            elif existing_user_id is not None:
                user.password_hash = await passwords.hash(password)
                user.password_changed_at = datetime.now(UTC)
            membership = OrganizationMembership(organization_id=invite.organization_id, user_id=user.id, role=invite.role, status="active", group_scope_mode="all", created_at=datetime.now(UTC))
            session.add(membership)
            invite.accepted_at = datetime.now(UTC)
            await write_audit(session, action="invitation.accept", result="success", request_id=request_id, actor_user_id=user.id, organization_id=invite.organization_id)
            return user.id


async def revoke_invitation(sessions: async_sessionmaker[AsyncSession], *, actor: UUID, organization_id: UUID, invitation_id: UUID, assurance: Assurance, request_id: str) -> None:
    async with sessions() as session:
        async with session.begin():
            await session.execute(text("SELECT pg_advisory_xact_lock(hashtextextended(:organization_id, 0))"), {"organization_id": str(organization_id)})
            principal = await principal_for(session, user_id=actor, organization_id=organization_id, assurance=assurance)
            if not authorize(principal, Action.INVITE_DISPATCHER_VIEWER, Resource(organization_id)):
                raise OrganizationError("not found")
            invite = await session.scalar(select(OrganizationInvitation).where(OrganizationInvitation.id == invitation_id, OrganizationInvitation.organization_id == organization_id, OrganizationInvitation.accepted_at.is_(None), OrganizationInvitation.revoked_at.is_(None)))
            if invite is None:
                raise OrganizationError("not found")
            invite.revoked_at = datetime.now(UTC)
            await write_audit(session, action="invitation.revoke", result="success", request_id=request_id, actor_user_id=actor, organization_id=organization_id, target_id=str(invitation_id))


async def resend_invitation(sessions: async_sessionmaker[AsyncSession], *, actor: UUID, organization_id: UUID, invitation_id: UUID, assurance: Assurance, request_id: str) -> tuple[UUID, str]:
    async with sessions() as session:
        async with session.begin():
            principal = await principal_for(session, user_id=actor, organization_id=organization_id, assurance=assurance)
            invite = await session.scalar(select(OrganizationInvitation).where(OrganizationInvitation.id == invitation_id, OrganizationInvitation.organization_id == organization_id, OrganizationInvitation.accepted_at.is_(None), OrganizationInvitation.revoked_at.is_(None)))
            if invite is None or not authorize(principal, Action.INVITE_DISPATCHER_VIEWER if invite.role != Role.ADMIN.value else Action.INVITE_ADMIN, Resource(organization_id, target_role=_role(invite.role))):
                raise OrganizationError("not found")
            invite.revoked_at = datetime.now(UTC)
            token = random_token()
            replacement = OrganizationInvitation(organization_id=organization_id, email=invite.email, role=invite.role, token_hash=token_hash(token), expires_at=datetime.now(UTC) + timedelta(days=2), invited_by=actor, created_at=datetime.now(UTC))
            session.add(replacement)
            await session.flush()
            await write_audit(session, action="invitation.resend", result="success", request_id=request_id, actor_user_id=actor, organization_id=organization_id, target_id=str(replacement.id), metadata={"role": invite.role, "channel": "manual"})
            return replacement.id, token


async def change_membership_role(sessions: async_sessionmaker[AsyncSession], *, actor: UUID, organization_id: UUID, target_user: UUID, role: Role, assurance: Assurance, request_id: str) -> None:
    async with sessions() as session:
        async with session.begin():
            await session.execute(text("SELECT pg_advisory_xact_lock(hashtextextended(:organization_id, 0))"), {"organization_id": str(organization_id)})
            principal = await principal_for(session, user_id=actor, organization_id=organization_id, assurance=assurance)
            target = await session.scalar(select(OrganizationMembership).where(OrganizationMembership.organization_id == organization_id, OrganizationMembership.user_id == target_user).with_for_update())
            if target is None or target.status != "active" or not authorize(principal, Action.CHANGE_OWNER_ROLE if target.role == Role.OWNER.value or role is Role.OWNER else Action.CHANGE_NON_OWNER_ROLE, Resource(organization_id, target_role=_role(target.role), target_is_last_owner=False)):
                raise OrganizationError("not found")
            if target.role == Role.OWNER.value and role is not Role.OWNER:
                owners = await session.scalar(select(OrganizationMembership).where(OrganizationMembership.organization_id == organization_id, OrganizationMembership.role == Role.OWNER.value, OrganizationMembership.status == "active").with_for_update())
                count = await session.scalar(select(OrganizationMembership.id).where(OrganizationMembership.organization_id == organization_id, OrganizationMembership.role == Role.OWNER.value, OrganizationMembership.status == "active", OrganizationMembership.id != target.id).limit(1))
                if count is None:
                    raise OrganizationError("last owner protected")
            target.role = role.value
            await write_audit(session, action="membership.role_change", result="success", request_id=request_id, actor_user_id=actor, organization_id=organization_id, target_id=str(target_user), metadata={"role": role.value})


async def set_membership_status(sessions: async_sessionmaker[AsyncSession], *, actor: UUID, organization_id: UUID, target_user: UUID, status: str, assurance: Assurance, request_id: str) -> None:
    if status not in {"active", "suspended", "removed"}:
        raise OrganizationError("invalid status")
    async with sessions() as session:
        async with session.begin():
            await session.execute(text("SELECT pg_advisory_xact_lock(hashtextextended(:organization_id, 0))"), {"organization_id": str(organization_id)})
            principal = await principal_for(session, user_id=actor, organization_id=organization_id, assurance=assurance)
            target = await session.scalar(select(OrganizationMembership).where(OrganizationMembership.organization_id == organization_id, OrganizationMembership.user_id == target_user).with_for_update())
            if target is None or target.status != "active":
                raise OrganizationError("not found")
            action = Action.SUSPEND_REMOVE_OWNER if target.role == Role.OWNER.value else Action.SUSPEND_REMOVE_NON_OWNER
            if not authorize(principal, action, Resource(organization_id, target_role=_role(target.role), target_is_last_owner=False)):
                raise OrganizationError("not found")
            if target.role == Role.OWNER.value and status != "active":
                other = await session.scalar(select(OrganizationMembership.id).where(OrganizationMembership.organization_id == organization_id, OrganizationMembership.role == Role.OWNER.value, OrganizationMembership.status == "active", OrganizationMembership.id != target.id).with_for_update().limit(1))
                if other is None:
                    raise OrganizationError("last owner protected")
            target.status = status
            await write_audit(session, action=f"membership.{status}", result="success", request_id=request_id, actor_user_id=actor, organization_id=organization_id, target_id=str(target_user))


async def create_group(sessions: async_sessionmaker[AsyncSession], *, actor: UUID, organization_id: UUID, name: str, assurance: Assurance, request_id: str) -> UUID:
    async with sessions() as session:
        async with session.begin():
            principal = await principal_for(session, user_id=actor, organization_id=organization_id, assurance=assurance)
            if not authorize(principal, Action.MANAGE_GROUPS, Resource(organization_id)):
                raise OrganizationError("not found")
            group = UserGroup(organization_id=organization_id, name=name, created_at=datetime.now(UTC))
            session.add(group)
            await session.flush()
            await write_audit(session, action="group.create", result="success", request_id=request_id, actor_user_id=actor, organization_id=organization_id, target_id=str(group.id))
            return group.id

