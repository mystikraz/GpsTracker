"""Opt-in PostgreSQL integration coverage for the P1 transaction boundary.

Run only after ``docker compose up`` and ``alembic upgrade head`` with:

    RUN_POSTGRES_TESTS=1 DATABASE_URL=... python -m unittest tests.test_postgres_integration

The default local suite skips this module because the repository may be used
without a running database.
"""

from __future__ import annotations

import asyncio
import json
import os
import unittest
from datetime import datetime, timezone
from pathlib import Path
from uuid import UUID, uuid4


if not os.environ.get("RUN_POSTGRES_TESTS"):
    raise unittest.SkipTest("set RUN_POSTGRES_TESTS=1 to run PostgreSQL integration tests")

try:
    from sqlalchemy import delete, func, select
except ImportError as error:  # pragma: no cover - exercised only in minimal environments
    raise unittest.SkipTest(f"database dependencies unavailable: {error}") from error

from fleet_tracker.db.engine import create_engine_and_session_factory
from fleet_tracker.db.ingestion_store import PostgresIngestionStore
from fleet_tracker.db.models import Organization, Position, Vehicle
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
        database_url = os.environ["DATABASE_URL"]
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
                terminal_id="071604184647",
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
                decode_frame(encode_frame(AUTHENTICATION_MESSAGE_ID, "071604184647", 1, b"12345678901")),
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
        finally:
            async with sessions() as session:
                async with session.begin():
                    await session.execute(delete(Organization).where(Organization.id == organization_id))
            await engine.dispose()


if __name__ == "__main__":
    unittest.main()
