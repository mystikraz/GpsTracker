from __future__ import annotations

import asyncio
import json
import unittest
from datetime import datetime, timezone
from pathlib import Path

from fleet_tracker.ingestion.auth import (
    DeviceAuthenticator,
    PlaintextSecretProtector,
    generate_auth_code,
    provision_device,
)
from fleet_tracker.ingestion.processor import ConnectionState, InMemoryIngestionStore, MessageProcessor
from fleet_tracker.protocol.jt808 import decode_frame, encode_frame


FIXTURES = json.loads((Path(__file__).parents[1] / "jt808_fixtures.json").read_text())
BY_NAME = {fixture["name"]: fixture for fixture in FIXTURES["fixtures"]}
DEVICE = "071604184647"
FIXED_NOW = datetime(2026, 11, 6, 7, 0, tzinfo=timezone.utc)


class IngestionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.store = InMemoryIngestionStore()
        self.protector = PlaintextSecretProtector()
        self.secret = "71604184647"
        asyncio.run(
            provision_device(
                self.store,
                terminal_id=DEVICE,
                organization_id="org-1",
                vehicle_id="vehicle-1",
                secret_protector=self.protector,
                auth_code=self.secret,
            )
        )
        self.processor = MessageProcessor(DeviceAuthenticator(self.store, self.protector), self.store)

    def process(self, name: str, state: ConnectionState) -> object:
        frame = decode_frame(bytes.fromhex(BY_NAME[name]["frame_hex"]))
        return asyncio.run(self.processor.process(frame, state, received_at=FIXED_NOW))

    def test_registration_and_reconnect_authentication(self) -> None:
        first_state = ConnectionState()
        registration = self.process("registration", first_state)
        self.assertTrue(registration.accepted)
        registration_response = decode_frame(registration.responses[0])
        self.assertEqual(registration_response.header.message_id, 0x8100)
        self.assertEqual(registration_response.body[3:], self.secret.encode("ascii"))

        reconnect_state = ConnectionState()
        authenticated = self.process("auth_serial1_captured", reconnect_state)
        self.assertTrue(authenticated.authenticated)
        self.assertFalse(authenticated.close_connection)
        self.assertEqual(len(self.store.raw_messages), 2)

    def test_unknown_or_wrong_authentication_is_closed_without_storage(self) -> None:
        unknown = InMemoryIngestionStore()
        processor = MessageProcessor(DeviceAuthenticator(unknown, self.protector), unknown)
        state = ConnectionState()
        frame = decode_frame(bytes.fromhex(BY_NAME["auth_serial1_captured"]["frame_hex"]))
        result = asyncio.run(processor.process(frame, state, received_at=FIXED_NOW))
        self.assertTrue(result.close_connection)
        self.assertEqual(unknown.raw_messages, [])

    def test_positions_ignore_no_fix_and_deduplicate_by_gps_timestamp(self) -> None:
        state = ConnectionState()
        self.process("auth_serial1_captured", state)
        no_fix = self.process("position_no_fix", state)
        self.assertEqual(no_fix.stored_positions, 0)
        self.assertEqual(len(self.store.positions), 0)

        first = self.process("position_fix_serial12", state)
        duplicate = self.process("position_fix_serial12", state)
        self.assertEqual(first.stored_positions, 1)
        self.assertEqual(duplicate.stored_positions, 0)
        self.assertEqual(len(self.store.positions), 1)

    def test_batch_positions_and_vendor_messages_are_accepted_after_auth(self) -> None:
        state = ConnectionState()
        self.process("auth_serial1_captured", state)
        batch = self.process("batch_0704_serial3", state)
        replay = self.process("batch_0704_serial3", state)
        vendor = self.process("vendor_1107_info", state)
        self.assertEqual(batch.stored_positions, 4)
        self.assertEqual(replay.stored_positions, 0)
        self.assertEqual(vendor.parser_status, "vendor_or_unknown")
        self.assertEqual(len(self.store.positions), 4)

    def test_generated_secret_differs_from_observed_serial_code(self) -> None:
        code = generate_auth_code(DEVICE)
        self.assertEqual(len(code), 11)
        self.assertTrue(code.isascii() and code.isdecimal())
        self.assertNotEqual(code, DEVICE.lstrip("0"))

    def test_alternate_code_is_issued_and_verified(self) -> None:
        alternate_store = InMemoryIngestionStore()
        alternate = "12345678901"
        asyncio.run(
            provision_device(
                alternate_store,
                terminal_id=DEVICE,
                organization_id="org-1",
                vehicle_id="vehicle-1",
                secret_protector=self.protector,
                auth_code=alternate,
            )
        )
        processor = MessageProcessor(
            DeviceAuthenticator(alternate_store, self.protector),
            alternate_store,
        )
        registration_state = ConnectionState()
        registration = decode_frame(bytes.fromhex(BY_NAME["registration"]["frame_hex"]))
        registration_result = asyncio.run(processor.process(registration, registration_state, received_at=FIXED_NOW))
        registration_response = decode_frame(registration_result.responses[0])
        self.assertEqual(registration_response.body[3:], alternate.encode("ascii"))

        auth_state = ConnectionState()
        auth = decode_frame(encode_frame(0x0102, DEVICE, 1, alternate.encode("ascii")))
        auth_result = asyncio.run(processor.process(auth, auth_state, received_at=FIXED_NOW))
        self.assertTrue(auth_result.authenticated)


if __name__ == "__main__":
    unittest.main()
