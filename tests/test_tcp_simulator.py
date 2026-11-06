from __future__ import annotations

import asyncio
import json
import unittest
from datetime import timezone
from pathlib import Path

from fleet_tracker.ingestion.auth import DeviceAuthenticator, PlaintextSecretProtector, provision_device
from fleet_tracker.ingestion.processor import ConnectionState, InMemoryIngestionStore, MessageProcessor
from fleet_tracker.ingestion.transport import ConnectionLimiter, serve_client
from fleet_tracker.protocol.jt808 import FrameStreamParser, decode_frame


FIXTURES = json.loads((Path(__file__).parents[1] / "jt808_fixtures.json").read_text())
BY_NAME = {fixture["name"]: fixture for fixture in FIXTURES["fixtures"]}
DEVICE = "999900001234"


async def read_frame(reader: asyncio.StreamReader) -> object:
    parser = FrameStreamParser()
    while True:
        data = await reader.read(128)
        if not data:
            raise AssertionError("tracker server closed before sending a response")
        frames = parser.feed(data)
        if frames:
            return frames[0]


class SimulatedTrackerTests(unittest.TestCase):
    def test_connection_limiter_caps_ip_and_global_connections(self) -> None:
        async def check() -> None:
            limiter = ConnectionLimiter(max_connections=1, max_connections_per_ip=1, attempts_per_minute=3)
            self.assertTrue(await limiter.acquire("192.0.2.1"))
            self.assertFalse(await limiter.acquire("192.0.2.1"))
            self.assertFalse(await limiter.acquire("192.0.2.2"))
            await limiter.release("192.0.2.1")
            self.assertTrue(await limiter.acquire("192.0.2.2"))

        asyncio.run(check())

    def test_fixture_replay_over_tcp_and_reconnect_authentication(self) -> None:
        asyncio.run(self._run_fixture_replay())

    async def _run_fixture_replay(self) -> None:
        store = InMemoryIngestionStore()
        await provision_device(
            store,
            terminal_id=DEVICE,
            organization_id="org-1",
            vehicle_id="vehicle-1",
            secret_protector=PlaintextSecretProtector(),
            auth_code="58392017406",
        )
        processor = MessageProcessor(
            DeviceAuthenticator(store, PlaintextSecretProtector()),
            store,
        )

        async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            await serve_client(reader, writer, processor, idle_timeout_seconds=5)

        server = await asyncio.start_server(handler, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            writer.write(bytes.fromhex(BY_NAME["registration"]["frame_hex"]))
            await writer.drain()
            registration_response = await read_frame(reader)
            self.assertEqual(registration_response.header.message_id, 0x8100)

            writer.write(bytes.fromhex(BY_NAME["auth_serial1_captured"]["frame_hex"]))
            await writer.drain()
            auth_response = await read_frame(reader)
            self.assertEqual(auth_response.header.message_id, 0x8001)

            for name in ("position_no_fix", "position_fix_serial12", "batch_0704_serial3"):
                writer.write(bytes.fromhex(BY_NAME[name]["frame_hex"]))
                await writer.drain()
                response = await read_frame(reader)
                self.assertEqual(response.header.message_id, 0x8001)
            writer.close()
            await writer.wait_closed()

            reconnect_reader, reconnect_writer = await asyncio.open_connection("127.0.0.1", port)
            reconnect_writer.write(bytes.fromhex(BY_NAME["auth_serial1_captured"]["frame_hex"]))
            await reconnect_writer.drain()
            reconnect_response = await read_frame(reconnect_reader)
            self.assertEqual(reconnect_response.header.message_id, 0x8001)
            reconnect_writer.close()
            await reconnect_writer.wait_closed()
        finally:
            server.close()
            await server.wait_closed()

        self.assertEqual(len(store.positions), 5)
        self.assertEqual(len(store.raw_messages), 6)


if __name__ == "__main__":
    unittest.main()
