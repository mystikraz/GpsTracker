from __future__ import annotations

import asyncio
import os
import unittest
from datetime import UTC, datetime
from uuid import uuid4

from sqlalchemy import select

from fleet_tracker.auth_security import PasswordService
from fleet_tracker.authorization import Assurance
from fleet_tracker.db.engine import create_engine_and_session_factory
from fleet_tracker.db.models import Organization, OrganizationMembership, User
from fleet_tracker.org_service import OrganizationError, set_membership_status


DATABASE_URL = os.environ.get("TEST_DATABASE_URL", "")


@unittest.skipUnless(os.environ.get("RUN_POSTGRES_TESTS") == "1" and DATABASE_URL, "requires disposable PostgreSQL")
class LastOwnerConcurrencyTests(unittest.TestCase):
    def test_simultaneous_owner_suspend_requests_have_one_success_and_one_owner_remains(self) -> None:
        async def run() -> None:
            engine, sessions = create_engine_and_session_factory(DATABASE_URL)
            try:
                now = datetime.now(UTC)
                async with sessions() as db:
                    async with db.begin():
                        password_hash = await PasswordService().hash("owner concurrency password")
                        owner = User(email=f"owner-a-{uuid4()}@example.invalid", password_hash=password_hash, created_at=now, updated_at=now, password_changed_at=now)
                        other = User(email=f"owner-b-{uuid4()}@example.invalid", password_hash=password_hash, created_at=now, updated_at=now, password_changed_at=now)
                        org = Organization(name="Concurrent owners", timezone="UTC", position_retention_months=12, raw_retention_days=30, created_at=now)
                        db.add_all([owner, other, org])
                        await db.flush()
                        db.add_all([
                            OrganizationMembership(organization_id=org.id, user_id=owner.id, role="owner", status="active", group_scope_mode="all", created_at=now),
                            OrganizationMembership(organization_id=org.id, user_id=other.id, role="owner", status="active", group_scope_mode="all", created_at=now),
                        ])
                async def suspend() -> bool:
                    try:
                        await set_membership_status(sessions, actor=owner.id, organization_id=org.id, target_user=other.id, status="suspended", assurance=Assurance.RECENT_REAUTHENTICATION, request_id=str(uuid4()))
                        return True
                    except OrganizationError:
                        return False
                results = await asyncio.gather(suspend(), suspend())
                self.assertEqual(sum(results), 1)
                async with sessions() as db:
                    count = await db.scalar(select(OrganizationMembership.id).where(OrganizationMembership.organization_id == org.id, OrganizationMembership.role == "owner", OrganizationMembership.status == "active").limit(2))
                    self.assertIsNotNone(count)
            finally:
                await engine.dispose()
        asyncio.run(run())

