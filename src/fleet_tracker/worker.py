"""P1 maintenance worker; later phases add durable alert/trip consumers here."""

from __future__ import annotations

import asyncio
import logging

from fleet_tracker.config import Settings
from fleet_tracker.db.engine import create_engine_and_session_factory
from fleet_tracker.db.ingestion_store import PostgresIngestionStore
from fleet_tracker.ingestion.auth import AesGcmSecretProtector


logger = logging.getLogger("fleet_tracker.worker")


async def run() -> None:
    settings = Settings.from_env()
    engine, sessions = create_engine_and_session_factory(settings.database_url)
    store = PostgresIngestionStore(
        sessions,
        AesGcmSecretProtector(settings.device_secret_key),
        auth_pepper=settings.device_auth_pepper,
    )
    try:
        while True:
            deleted = await store.purge_expired_raw_messages()
            logger.info("raw_message_retention deleted=%s", deleted)
            await asyncio.sleep(3600)
    finally:
        await engine.dispose()


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    asyncio.run(run())


if __name__ == "__main__":
    main()
