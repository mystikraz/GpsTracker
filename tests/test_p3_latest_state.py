from __future__ import annotations

import asyncio
import os
import unittest
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import httpx
from sqlalchemy import text

from fleet_tracker.auth_security import PasswordService, create_session
from fleet_tracker.auth_service import AuthService
from fleet_tracker.db.engine import create_engine_and_session_factory
from fleet_tracker.db.models import Organization, OrganizationMembership, User, Vehicle
from fleet_tracker.http_api import create_app


DATABASE_URL = os.environ.get("TEST_DATABASE_URL", "")


@unittest.skipUnless(os.environ.get("RUN_POSTGRES_TESTS") == "1" and DATABASE_URL, "requires disposable PostgreSQL")
class P3LatestStateHttpTests(unittest.TestCase):
    def test_latest_history_and_literal_routes(self) -> None:
        async def run() -> None:
            engine, sessions = create_engine_and_session_factory(DATABASE_URL)
            passwords = PasswordService(max_concurrency=1)
            now = datetime.now(UTC)
            email = f"p3-{uuid4()}@example.invalid"
            password = "correct horse battery staple"
            org_id = uuid4()
            vehicle_id = uuid4()
            device_id = uuid4()
            try:
                async with sessions() as db:
                    async with db.begin():
                        user = User(email=email, password_hash=await passwords.hash(password), created_at=now, updated_at=now, password_changed_at=now)
                        org = Organization(id=org_id, name="P3", timezone="UTC", position_retention_months=12, raw_retention_days=30, created_at=now)
                        vehicle = Vehicle(id=vehicle_id, organization_id=org_id, name="Unit 1", plate_number="P3", created_at=now)
                        db.add_all([user, org, vehicle])
                        await db.flush()
                        db.add(OrganizationMembership(organization_id=org_id, user_id=user.id, role="owner", status="active", group_scope_mode="all", created_at=now))
                        await db.execute(text("""
                            INSERT INTO devices (id, organization_id, terminal_id, auth_secret_hash, auth_secret_ciphertext, created_at, secret_rotated_at)
                            VALUES (:id, :org, :terminal, decode('61','hex'), decode('61','hex'), :now, :now)
                        """), {"id": device_id, "org": org_id, "terminal": f"{uuid4().int % 10**12:012d}", "now": now})
                        await db.execute(text("""
                            INSERT INTO device_vehicle_assignments (organization_id, device_id, vehicle_id, effective_from)
                            VALUES (:org, :device, :vehicle, :now)
                        """), {"org": org_id, "device": device_id, "vehicle": vehicle_id, "now": now - timedelta(minutes=1)})
                        await db.execute(text("""
                            INSERT INTO raw_messages (organization_id, device_id, received_at, message_id, terminal_serial, raw_frame, body, authenticated, parser_status, created_at)
                            VALUES (:org, :device, :received, 258, 1, decode('00','hex'), decode('00','hex'), true, 'authenticated', :now)
                        """), {"org": org_id, "device": device_id, "received": now, "now": now})
                        await db.execute(text("""
                            INSERT INTO positions (id, gps_timestamp, organization_id, device_id, vehicle_id, received_at, latitude, longitude, location, altitude_m, speed_kmh, course, alarm, status, extras)
                            VALUES (nextval('positions_id_seq'), :gps, :org, :device, :vehicle, :received, 27.7, 85.3, ST_SetSRID(ST_MakePoint(85.3, 27.7), 4326)::geography, 10, 12.5, 90, 0, 1, '{}'::jsonb)
                        """), {"gps": now - timedelta(seconds=5), "org": org_id, "device": device_id, "vehicle": vehicle_id, "received": now})
                        ticket = await create_session(db, user=user, ip_address="192.0.2.5", user_agent_redacted="test")

                app = create_app(sessions, AuthService(sessions, passwords=passwords))
                transport = httpx.ASGITransport(app=app)
                async with httpx.AsyncClient(transport=transport, base_url="https://fleet.example.invalid") as client:
                    client.cookies.set("__Host-fleet_session", ticket.raw_id)
                    latest = await client.get(f"/api/v1/orgs/{org_id}/vehicles/latest-state", headers={"host": "fleet.example.invalid"})
                    self.assertEqual(latest.status_code, 200)
                    self.assertEqual(latest.json()[0]["status"], "moving")
                    detail = await client.get(f"/api/v1/orgs/{org_id}/vehicles/{vehicle_id}/latest-state", headers={"host": "fleet.example.invalid"})
                    self.assertEqual(detail.status_code, 200)
                    history = await client.get(
                        f"/api/v1/orgs/{org_id}/vehicles/{vehicle_id}/history",
                        params={"from": (now - timedelta(hours=1)).isoformat(), "to": now.isoformat()},
                        headers={"host": "fleet.example.invalid"},
                    )
                    self.assertEqual(history.status_code, 200)
                    self.assertEqual(len(history.json()["points"]), 1)
            finally:
                await engine.dispose()

        asyncio.run(run())

