from __future__ import annotations

import asyncio
import os
import unittest
from datetime import UTC, datetime
from uuid import uuid4

import httpx
from sqlalchemy import select

from fleet_tracker.auth_security import PasswordService
from fleet_tracker.auth_service import AuthService
from fleet_tracker.db.engine import create_engine_and_session_factory
from fleet_tracker.db.models import Organization, OrganizationMembership, User
from fleet_tracker.http_api import create_app


DATABASE_URL = os.environ.get("TEST_DATABASE_URL", "")


@unittest.skipUnless(os.environ.get("RUN_POSTGRES_TESTS") == "1" and DATABASE_URL, "requires disposable PostgreSQL")
class PhaseBHttpTests(unittest.TestCase):
    def test_auth_endpoints_cookie_csrf_login_csrf_and_generic_errors(self) -> None:
        async def run() -> None:
            engine, sessions = create_engine_and_session_factory(DATABASE_URL)
            try:
                email = f"http-{uuid4()}@example.invalid"
                password = "correct horse battery staple"
                hasher = PasswordService(max_concurrency=1)
                now = datetime.now(UTC)
                async with sessions() as db:
                    async with db.begin():
                        user = User(email=email, password_hash=await hasher.hash(password), created_at=now, updated_at=now, password_changed_at=now)
                        org = Organization(name="HTTP", timezone="UTC", position_retention_months=12, raw_retention_days=30, created_at=now)
                        db.add_all([user, org])
                        await db.flush()
                        db.add(OrganizationMembership(organization_id=org.id, user_id=user.id, role="owner", status="active", group_scope_mode="all", created_at=now))
                app = create_app(sessions, AuthService(sessions, passwords=hasher), manual_links=True)
                transport = httpx.ASGITransport(app=app)
                async with httpx.AsyncClient(transport=transport, base_url="https://fleet.example.invalid") as client:
                    csrf = await client.get("/api/v1/auth/login/csrf", headers={"host": "fleet.example.invalid"})
                    self.assertEqual(csrf.status_code, 200)
                    set_cookie = csrf.headers["set-cookie"]
                    self.assertIn("__Host-fleet_login=", set_cookie)
                    for flag in ("HttpOnly", "Secure", "SameSite=Lax", "Path=/"):
                        self.assertIn(flag, set_cookie)
                    self.assertNotIn("Domain=", set_cookie)
                    pre_session = client.cookies.get("__Host-fleet_login")
                    body = {"email": email, "password": password, "csrf_token": csrf.json()["csrf_token"], "pre_session": pre_session}
                    logged = await client.post("/api/v1/auth/login", json=body, headers={"host": "fleet.example.invalid"})
                    self.assertEqual(logged.status_code, 200)
                    auth_cookie = logged.headers["set-cookie"]
                    self.assertIn("__Host-fleet_session=", auth_cookie)
                    for flag in ("HttpOnly", "Secure", "SameSite=Lax", "Path=/"):
                        self.assertIn(flag, auth_cookie)
                    self.assertNotIn("Domain=", auth_cookie)
                    me = await client.get("/api/v1/auth/me", headers={"host": "fleet.example.invalid"})
                    self.assertEqual(me.status_code, 200)
                    bad = await client.post("/api/v1/auth/logout", headers={"host": "fleet.example.invalid", "origin": "https://fleet.example.invalid"})
                    self.assertEqual(bad.status_code, 403)
                    self.assertEqual(bad.json(), {"detail": "request rejected"})
                    wrong = await client.get("/api/v1/auth/login/csrf", headers={"host": "fleet.example.invalid"})
                    unknown = await client.post("/api/v1/auth/login", json={"email": "missing@example.invalid", "password": "wrong password", "csrf_token": wrong.json()["csrf_token"], "pre_session": client.cookies.get("__Host-fleet_login")}, headers={"host": "fleet.example.invalid"})
                    self.assertEqual(unknown.json(), {"detail": "invalid email or password"})
                    reset = await client.post("/api/v1/auth/reset/request", json={"email": email}, headers={"host": "fleet.example.invalid"})
                    self.assertEqual(reset.status_code, 200)
                    self.assertEqual(reset.headers["cache-control"], "no-store")
                    self.assertIn("reset_token", reset.json())
                    self.assertNotIn(reset.json()["reset_token"], reset.headers.get("location", ""))
            finally:
                await engine.dispose()

        asyncio.run(run())

