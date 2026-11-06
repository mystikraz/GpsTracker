"""Opt-in PostgreSQL integration coverage for the P1 transaction boundary.

Run only after ``docker compose up`` and ``alembic upgrade head`` with:

    RUN_POSTGRES_TESTS=1 TEST_DATABASE_URL=... python -m unittest tests.test_postgres_integration

The default local suite skips this module because the repository may be used
without a running database.
"""

from __future__ import annotations

import asyncio
import json
import os
import time
import unittest
from datetime import datetime, timezone
from pathlib import Path
from uuid import UUID, uuid4


if not os.environ.get("RUN_POSTGRES_TESTS"):
    raise unittest.SkipTest("set RUN_POSTGRES_TESTS=1 to run PostgreSQL integration tests")

TEST_DATABASE_URL = os.environ.get("TEST_DATABASE_URL")
if not TEST_DATABASE_URL:
    raise unittest.SkipTest("set TEST_DATABASE_URL to a disposable/test database; production URLs are refused")
if os.environ.get("DATABASE_URL") and os.environ["DATABASE_URL"] != TEST_DATABASE_URL:
    raise RuntimeError("DATABASE_URL differs from TEST_DATABASE_URL; refusing a non-test integration target")

try:
    from sqlalchemy import delete, func, select, text
    from sqlalchemy.exc import IntegrityError
except ImportError as error:  # pragma: no cover - exercised only in minimal environments
    raise unittest.SkipTest(f"database dependencies unavailable: {error}") from error

from fleet_tracker.db.engine import create_engine_and_session_factory
from fleet_tracker.db.ingestion_store import PostgresIngestionStore
from fleet_tracker.db.models import DeviceVehicleAssignment, Organization, Position, Vehicle
from fleet_tracker.db.provisioning import provision_postgres_device
from fleet_tracker.ingestion.auth import AesGcmSecretProtector, DeviceAuthenticator
from fleet_tracker.ingestion.processor import ConnectionState, MessageProcessor
from fleet_tracker.protocol.jt808 import AUTHENTICATION_MESSAGE_ID, decode_frame, encode_frame


FIXTURES = json.loads((Path(__file__).parents[1] / "jt808_fixtures.json").read_text())
BY_NAME = {fixture["name"]: fixture for fixture in FIXTURES["fixtures"]}


class PostgreSQLIngestionTests(unittest.TestCase):
    def test_fixture_replay_is_persisted_and_deduplicated(self) -> None:
        asyncio.run(self._run())

    async def _run(self) -> None:
        database_url = TEST_DATABASE_URL
        engine, sessions = create_engine_and_session_factory(database_url)
        organization_id = uuid4()
        vehicle_id = uuid4()
        device_id: str | None = None
        try:
            async with sessions() as session:
                async with session.begin():
                    session.add(
                        Organization(
                            id=organization_id,
                            name="P1 integration",
                            timezone="Asia/Kathmandu",
                            position_retention_months=12,
                            raw_retention_days=30,
                            created_at=datetime.now(timezone.utc),
                        )
                    )
                    session.add(
                        Vehicle(
                            id=vehicle_id,
                            organization_id=organization_id,
                            name="Integration vehicle",
                            created_at=datetime.now(timezone.utc),
                        )
                    )

            protector = AesGcmSecretProtector(b"k" * 32)
            device_id, _ = await provision_postgres_device(
                sessions,
                organization_id=str(organization_id),
                vehicle_id=str(vehicle_id),
                terminal_id="999900001234",
                secret_protector=protector,
                auth_code="12345678901",
                auth_pepper=b"pepper",
            )
            store = PostgresIngestionStore(sessions, protector, auth_pepper=b"pepper")
            processor = MessageProcessor(DeviceAuthenticator(store, protector, pepper=b"pepper"), store)
            state = ConnectionState()
            received_at = datetime(2026, 11, 6, 7, 0, tzinfo=timezone.utc)

            frames = [
                decode_frame(bytes.fromhex(BY_NAME["registration"]["frame_hex"])),
                decode_frame(encode_frame(AUTHENTICATION_MESSAGE_ID, "999900001234", 1, b"12345678901")),
                decode_frame(bytes.fromhex(BY_NAME["position_fix_serial12"]["frame_hex"])),
                decode_frame(bytes.fromhex(BY_NAME["batch_0704_serial3"]["frame_hex"])),
            ]
            for frame in frames:
                await processor.process(frame, state, received_at=received_at)

            async with sessions() as session:
                count = await session.scalar(
                    select(func.count())
                    .select_from(Position)
                    .where(Position.device_id == UUID(device_id))
                )
                self.assertEqual(count, 5)

            async with sessions() as session:
                async with session.begin():
                    async with session.begin_nested():
                        session.add(
                            DeviceVehicleAssignment(
                                organization_id=organization_id,
                                device_id=UUID(device_id),
                                vehicle_id=vehicle_id,
                                effective_from=datetime(2026, 11, 6, 8, 0, tzinfo=timezone.utc),
                                effective_to=datetime(2026, 12, 1, tzinfo=timezone.utc),
                            )
                        )
                        with self.assertRaises(IntegrityError):
                            await session.flush()

                    await session.execute(
                        text(
                            "UPDATE device_vehicle_assignments SET effective_to = :end "
                            "WHERE device_id = :device_id AND effective_to IS NULL"
                        ),
                        {"end": datetime(2026, 12, 1, tzinfo=timezone.utc), "device_id": UUID(device_id)},
                    )
                    session.add(
                        DeviceVehicleAssignment(
                            organization_id=organization_id,
                            device_id=UUID(device_id),
                            vehicle_id=vehicle_id,
                            effective_from=datetime(2026, 12, 1, tzinfo=timezone.utc),
                            effective_to=datetime(2027, 1, 1, tzinfo=timezone.utc),
                        )
                    )
                    await session.flush()

            async with sessions() as session:
                async with session.begin():
                    await session.execute(
                        text(
                            "INSERT INTO positions (gps_timestamp, organization_id, device_id, vehicle_id, "
                            "received_at, latitude, longitude, location, altitude_m, speed_kmh, course, alarm, "
                            "status, extras) VALUES "
                            "(:gps, :org, :device, :vehicle, :received, 27.68, 85.33, "
                            "ST_SetSRID(ST_MakePoint(85.33, 27.68), 4326)::geography, 0, 0, 0, 0, 0, '{}'::jsonb)"
                        ),
                        {
                            "gps": datetime(2025, 9, 1, tzinfo=timezone.utc),
                            "org": organization_id,
                            "device": UUID(device_id),
                            "vehicle": vehicle_id,
                            "received": datetime(2026, 11, 6, tzinfo=timezone.utc),
                        },
                    )
                    await session.execute(
                        text(
                            "INSERT INTO positions (gps_timestamp, organization_id, device_id, vehicle_id, "
                            "received_at, latitude, longitude, location, altitude_m, speed_kmh, course, alarm, "
                            "status, extras) VALUES "
                            "(:gps, :org, :device, :vehicle, :received, 27.68, 85.33, "
                            "ST_SetSRID(ST_MakePoint(85.33, 27.68), 4326)::geography, 0, 0, 0, 0, 0, '{}'::jsonb)"
                        ),
                        {
                            "gps": datetime(2026, 11, 5, tzinfo=timezone.utc),
                            "org": organization_id,
                            "device": UUID(device_id),
                            "vehicle": vehicle_id,
                            "received": datetime(2026, 11, 6, tzinfo=timezone.utc),
                        },
                    )
                    await session.execute(
                        text(
                            "INSERT INTO positions (gps_timestamp, organization_id, device_id, vehicle_id, "
                            "received_at, latitude, longitude, location, altitude_m, speed_kmh, course, alarm, "
                            "status, extras) VALUES "
                            "(:gps, :org, :device, :vehicle, :received, 27.68, 85.33, "
                            "ST_SetSRID(ST_MakePoint(85.33, 27.68), 4326)::geography, 0, 0, 0, 0, 0, '{}'::jsonb)"
                        ),
                        {
                            "gps": datetime(2099, 1, 1, tzinfo=timezone.utc),
                            "org": organization_id,
                            "device": UUID(device_id),
                            "vehicle": vehicle_id,
                            "received": datetime(2026, 11, 6, tzinfo=timezone.utc),
                        },
                    )

            maintenance_store = PostgresIngestionStore(sessions, protector, auth_pepper=b"pepper")
            first_maintenance = maintenance_store.maintain_partitions
            result_one = await first_maintenance(
                now=datetime(2026, 11, 30, 23, 59, tzinfo=timezone.utc), months_ahead=2
            )
            result_two = await first_maintenance(
                now=datetime(2026, 11, 30, 23, 59, tzinfo=timezone.utc), months_ahead=2
            )
            self.assertEqual(result_one["partitions_created"], 3)
            self.assertEqual(result_two["partitions_created"], 3)
            self.assertEqual(result_one["default_rows"], 2)
            self.assertEqual(result_two["default_rows"], 1)
            self.assertEqual(result_one["positions_deleted"], 1)
            with self.assertLogs("fleet_tracker.maintenance", level="WARNING") as logs:
                await first_maintenance(
                    now=datetime(2026, 11, 30, 23, 59, tzinfo=timezone.utc), months_ahead=0
                )
            self.assertTrue(any("positions_default_nonempty" in message for message in logs.output))

            async with sessions() as session:
                old_count = await session.scalar(
                    text("SELECT count(*) FROM positions WHERE gps_timestamp = '2025-09-01T00:00:00Z'")
                )
                recent_count = await session.scalar(
                    text("SELECT count(*) FROM positions WHERE gps_timestamp = '2026-11-05T00:00:00Z'")
                )
                self.assertEqual(old_count, 0)
                self.assertEqual(recent_count, 1)

            maintenance = await PostgresIngestionStore(sessions, protector, auth_pepper=b"pepper").maintain_partitions(
                now=datetime(2026, 11, 6, 7, 0, tzinfo=timezone.utc), months_ahead=2
            )
            self.assertEqual(maintenance["partitions_created"], 3)
        finally:
            async with sessions() as session:
                async with session.begin():
                    await session.execute(delete(Organization).where(Organization.id == organization_id))
            await engine.dispose()

    def test_first_query_allows_neon_cold_start(self) -> None:
        async def check() -> None:
            engine, sessions = create_engine_and_session_factory(TEST_DATABASE_URL)
            try:
                async with sessions() as session:
                    await asyncio.wait_for(session.execute(text("SELECT 1")), timeout=30)
            finally:
                await engine.dispose()

        started = time.monotonic()
        asyncio.run(check())
        self.assertLess(time.monotonic() - started, 30)


if __name__ == "__main__":
    unittest.main()
