from __future__ import annotations

import asyncio
import os
import unittest
from datetime import UTC, datetime, timedelta
from uuid import uuid4

from sqlalchemy import select

from fleet_tracker.auth_security import AuthenticationError, PasswordService, create_session, require_csrf, require_session
from fleet_tracker.auth_service import AuthService
from fleet_tracker.db.engine import create_engine_and_session_factory
from fleet_tracker.db.models import Organization, OrganizationMembership, User


DATABASE_URL = os.environ.get("TEST_DATABASE_URL", "")


@unittest.skipUnless(os.environ.get("RUN_POSTGRES_TESTS") == "1" and DATABASE_URL, "requires disposable PostgreSQL")
class PhaseBAuthIntegrationTests(unittest.TestCase):
    def test_idle_and_absolute_expiry(self) -> None:
        async def run() -> None:
            engine, sessions = create_engine_and_session_factory(DATABASE_URL)
            try:
                async with sessions() as db:
                    async with db.begin():
                        now = datetime.now(UTC)
                        user = User(email=f"expiry-{uuid4()}@example.invalid", password_hash=await PasswordService().hash("expiry password correct"), created_at=now, updated_at=now, password_changed_at=now)
                        db.add(user)
                        await db.flush()
                        idle = await create_session(db, user=user, ip_address=None, user_agent_redacted=None, idle_seconds=1, absolute_seconds=100)
                        absolute = await create_session(db, user=user, ip_address=None, user_agent_redacted=None, idle_seconds=100, absolute_seconds=1)
                    with self.assertRaises(AuthenticationError):
                        async with sessions() as check:
                            await require_session(check, idle.raw_id, now=datetime.now(UTC) + timedelta(seconds=2))
                    with self.assertRaises(AuthenticationError):
                        async with sessions() as check:
                            await require_session(check, absolute.raw_id, now=datetime.now(UTC) + timedelta(seconds=2))
            finally:
                await engine.dispose()

        asyncio.run(run())

    def test_privilege_change_rotation_rejects_old_session(self) -> None:
        async def run() -> None:
            engine, sessions = create_engine_and_session_factory(DATABASE_URL)
            try:
                service = AuthService(sessions, passwords=PasswordService(max_concurrency=1))
                async with sessions() as db:
                    async with db.begin():
                        now = datetime.now(UTC)
                        user = User(email=f"rotation-{uuid4()}@example.invalid", password_hash=await service.passwords.hash("rotation password correct"), created_at=now, updated_at=now, password_changed_at=now)
                        db.add(user)
                        await db.flush()
                        ticket = await create_session(db, user=user, ip_address=None, user_agent_redacted=None)
                rotated = await service.rotate_after_privilege_change(ticket.raw_id, request_id=str(uuid4()))
                self.assertNotEqual(ticket.raw_id, rotated.raw_id)
                async with sessions() as db:
                    with self.assertRaises(AuthenticationError):
                        await require_session(db, ticket.raw_id)
            finally:
                await engine.dispose()
        asyncio.run(run())

    def test_login_session_rotation_csrf_lockout_and_reset(self) -> None:
        async def run() -> None:
            engine, sessions = create_engine_and_session_factory(DATABASE_URL)
            try:
                email = f"phase-b-{uuid4()}@example.invalid"
                password_service = PasswordService(max_concurrency=1)
                password_hash = await password_service.hash("correct horse battery staple")
                async with sessions() as db:
                    async with db.begin():
                        now = datetime.now(UTC)
                        user = User(email=email, password_hash=password_hash, created_at=now, updated_at=now, password_changed_at=now)
                        org = Organization(name="Phase B", timezone="UTC", position_retention_months=12, raw_retention_days=30, created_at=now)
                        db.add_all([user, org])
                        await db.flush()
                        db.add(OrganizationMembership(organization_id=org.id, user_id=user.id, role="owner", status="active", group_scope_mode="all", created_at=now))
                auth = AuthService(sessions, passwords=password_service)
                first = await auth.login(email, "correct horse battery staple", ip="192.0.2.1", user_agent="test", request_id=str(uuid4()))
                async with sessions() as db:
                    async with db.begin():
                        record, _ = await require_session(db, first.raw_id)
                        require_csrf(record, first.csrf_token)
                        with self.assertRaises(AuthenticationError):
                            require_csrf(record, "wrong")
                changed = await auth.change_password(first.raw_id, "correct horse battery staple", "new correct horse password", request_id=str(uuid4()))
                self.assertNotEqual(first.raw_id, changed.raw_id)
                with self.assertRaises(AuthenticationError):
                    await auth.login(email, "correct horse battery staple", ip="192.0.2.1", user_agent="test", request_id=str(uuid4()))
                reset = await auth.issue_reset_token(user.id, request_id=str(uuid4()))
                await auth.consume_reset_token(reset, "reset correct horse password", request_id=str(uuid4()))
                with self.assertRaises(AuthenticationError):
                    await auth.consume_reset_token(reset, "another correct horse password", request_id=str(uuid4()))
                async with sessions() as db:
                    with self.assertRaises(AuthenticationError):
                        await require_session(db, changed.raw_id)
                logged = await auth.login(email, "reset correct horse password", ip="192.0.2.2", user_agent="test", request_id=str(uuid4()))
                self.assertTrue(logged.raw_id)
            finally:
                await engine.dispose()

        asyncio.run(run())

