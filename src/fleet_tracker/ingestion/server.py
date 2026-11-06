"""Production TCP ingestion service entrypoint."""

from __future__ import annotations

import asyncio
import logging

from fleet_tracker.config import Settings
from fleet_tracker.db.engine import create_engine_and_session_factory
from fleet_tracker.db.ingestion_store import PostgresIngestionStore

from .auth import AesGcmSecretProtector, DeviceAuthenticator
from .processor import MessageProcessor
from .transport import ConnectionLimiter, serve_client


logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger("fleet_tracker.ingestion")


async def run() -> None:
    settings = Settings.from_env()
    engine, session_factory = create_engine_and_session_factory(settings.database_url)
    protector = AesGcmSecretProtector(settings.device_secret_key)
    store = PostgresIngestionStore(
        session_factory,
        protector,
        auth_pepper=settings.device_auth_pepper,
    )
    processor = MessageProcessor(DeviceAuthenticator(store, protector, pepper=settings.device_auth_pepper), store)
    limiter = ConnectionLimiter(
        max_connections=settings.max_connections,
        max_connections_per_ip=settings.max_connections_per_ip,
        attempts_per_minute=settings.auth_attempts_per_minute,
    )

    async def client_connected(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        await serve_client(
            reader,
            writer,
            processor,
            limiter=limiter,
            max_frame_size=settings.frame_max_bytes,
            max_buffer_size=settings.frame_buffer_max_bytes,
            idle_timeout_seconds=settings.idle_timeout_seconds,
        )

    server = await asyncio.start_server(client_connected, settings.tracker_host, settings.tracker_port)
    addresses = ", ".join(str(sock.getsockname()) for sock in server.sockets or [])
    logger.info("tracker_ingestion_started addresses=%s", addresses)
    try:
        async with server:
            await server.serve_forever()
    finally:
        await engine.dispose()


def main() -> None:
    asyncio.run(run())


if __name__ == "__main__":
    main()
