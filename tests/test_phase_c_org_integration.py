from __future__ import annotations

import asyncio
import os
import unittest
from datetime import UTC, datetime
from uuid import uuid4

from sqlalchemy import select

from fleet_tracker.auth_security import PasswordService, create_session
from fleet_tracker.authorization import Assurance, Role
from fleet_tracker.db.engine import create_engine_and_session_factory
from fleet_tracker.db.models import Organization, OrganizationMembership, Session, User
from fleet_tracker.org_service import OrganizationError, accept_invitation, change_membership_role, create_invitation, set_membership_status


DATABASE_URL = os.environ.get("TEST_DATABASE_URL", "")


@unittest.skipUnless(os.environ.get("RUN_POSTGRES_TESTS") == "1" and DATABASE_URL, "requires disposable PostgreSQL")
class PhaseCOrganizationTests(unittest.TestCase):
    def test_invitation_accept_role_lifecycle_last_owner_and_session_revoke(self) -> None:
        async def run() -> None:
            engine, sessions = create_engine_and_session_factory(DATABASE_URL)
            passwords = PasswordService(max_concurrency=1)
            try:
                now = datetime.now(UTC)
                async with sessions() as db:
                    async with db.begin():
                        owner = User(email=f"owner-{uuid4()}@example.invalid", password_hash=await passwords.hash("owner password correct"), created_at=now, updated_at=now, password_changed_at=now)
                        org = Organization(name="Phase C", timezone="UTC", position_retention_months=12, raw_retention_days=30, created_at=now)
                        db.add_all([owner, org])
                        await db.flush()
                        db.add(OrganizationMembership(organization_id=org.id, user_id=owner.id, role="owner", status="active", group_scope_mode="all", created_at=now))
                token = await create_invitation(sessions, actor=owner.id, organization_id=org.id, role=Role.VIEWER, email=f"member-{uuid4()}@example.invalid", assurance=Assurance.RECENT_REAUTHENTICATION, request_id=str(uuid4()))
                member_id = await accept_invitation(sessions, passwords, token=token, password="member password correct", existing_user_id=None, request_id=str(uuid4()))
                async with sessions() as db:
                    async with db.begin():
                        member = await db.scalar(select(User).where(User.id == member_id))
                        ticket = await create_session(db, user=member, ip_address="192.0.2.10", user_agent_redacted="test")
                await change_membership_role(sessions, actor=owner.id, organization_id=org.id, target_user=member_id, role=Role.DISPATCHER, assurance=Assurance.RECENT_REAUTHENTICATION, request_id=str(uuid4()))
                await set_membership_status(sessions, actor=owner.id, organization_id=org.id, target_user=member_id, status="suspended", assurance=Assurance.RECENT_REAUTHENTICATION, request_id=str(uuid4()))
                async with sessions() as db:
                    revoked = await db.scalar(select(Session.revoked_at).where(Session.id == ticket.session_id))
                    self.assertIsNotNone(revoked)
                with self.assertRaises(OrganizationError):
                    await set_membership_status(sessions, actor=owner.id, organization_id=org.id, target_user=owner.id, status="suspended", assurance=Assurance.RECENT_REAUTHENTICATION, request_id=str(uuid4()))
            finally:
                await engine.dispose()

        asyncio.run(run())

