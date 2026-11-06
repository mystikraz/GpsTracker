from __future__ import annotations

import asyncio
import hashlib
import inspect
import json
import unittest
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

from fleet_tracker.ingestion.auth import (
    DeviceAuthenticator,
    PlaintextSecretProtector,
    generate_auth_code,
    provision_device,
)
from fleet_tracker.ingestion.processor import ConnectionState, InMemoryIngestionStore, MessageProcessor
from fleet_tracker.ingestion.processor import AuthenticatedConnectionRegistry
from fleet_tracker.db.partitions import partition_month_starts
from fleet_tracker.protocol.jt808 import decode_frame, encode_frame


FIXTURES = json.loads((Path(__file__).parents[1] / "jt808_fixtures.json").read_text())
BY_NAME = {fixture["name"]: fixture for fixture in FIXTURES["fixtures"]}
DEVICE = "999900001234"
FIXED_NOW = datetime(2026, 11, 6, 7, 0, tzinfo=timezone.utc)


class IngestionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.store = InMemoryIngestionStore()
        self.protector = PlaintextSecretProtector()
        self.secret = "58392017406"
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

    def test_registration_and_auth_raw_messages_redact_bodies_and_frames(self) -> None:
        state = ConnectionState()
        registration_frame = decode_frame(bytes.fromhex(BY_NAME["registration"]["frame_hex"]))
        auth_frame = decode_frame(bytes.fromhex(BY_NAME["auth_serial1_captured"]["frame_hex"]))
        self.process("registration", state)
        self.process("auth_serial1_captured", state)
        for stored, original in zip(self.store.raw_messages, (registration_frame, auth_frame)):
            self.assertEqual(stored.body, b"")
            self.assertNotIn(self.secret.encode("ascii"), stored.raw_frame)
            self.assertEqual(stored.redacted_body_length, len(original.body))
            self.assertEqual(stored.redacted_body_hash, hashlib.sha256(original.body).digest())

    def test_ingestion_logs_do_not_contain_auth_code(self) -> None:
        from fleet_tracker.ingestion import transport

        with self.assertLogs(transport.logger, level="INFO") as logs:
            transport.logger.info(
                "ingestion_message_accepted source_ip=%s terminal_id=%s "
                "message_id=0x%04x parser_status=%s stored_positions=%s",
                "192.0.2.1",
                DEVICE,
                0x0102,
                "authenticated",
                0,
            )
            transport.logger.error(
                "message_persistence_failed source_ip=%s terminal_id=%s message_id=0x%04x",
                "192.0.2.1",
                DEVICE,
                0x0102,
            )
        self.assertNotIn(self.secret, "\n".join(logs.output))
        self.assertNotIn("logger.exception", inspect.getsource(transport.serve_client))

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

    def test_one_authenticated_connection_rejects_conflict_and_records_ips(self) -> None:
        registry = AuthenticatedConnectionRegistry()
        processor = MessageProcessor(
            DeviceAuthenticator(self.store, self.protector), self.store, connection_registry=registry
        )
        first = ConnectionState()
        second = ConnectionState()
        auth = decode_frame(bytes.fromhex(BY_NAME["auth_serial1_captured"]["frame_hex"]))
        self.assertTrue(asyncio.run(processor.process(auth, first, source_ip="192.0.2.10")).authenticated)
        conflict = asyncio.run(processor.process(auth, second, source_ip="192.0.2.11"))
        self.assertTrue(conflict.close_connection)
        self.assertEqual(conflict.parser_status, "authenticated_connection_conflict")

    def test_one_authenticated_connection_replacement_invalidates_old_state(self) -> None:
        registry = AuthenticatedConnectionRegistry(idle_seconds=0)
        processor = MessageProcessor(
            DeviceAuthenticator(self.store, self.protector), self.store, connection_registry=registry
        )
        first = ConnectionState()
        second = ConnectionState()
        closed = []

        async def close_old() -> None:
            closed.append(True)

        first.close_callback = close_old
        auth = decode_frame(bytes.fromhex(BY_NAME["auth_serial1_captured"]["frame_hex"]))
        asyncio.run(processor.process(auth, first, source_ip="192.0.2.10"))
        first.last_activity -= 1
        result = asyncio.run(processor.process(auth, second, source_ip="192.0.2.11"))
        self.assertTrue(result.authenticated)
        self.assertFalse(first.active)
        self.assertEqual(closed, [True])

    def test_auth_failure_for_provisioned_device_returns_failure_ack(self) -> None:
        state = ConnectionState()
        bad = decode_frame(encode_frame(0x0102, DEVICE, 99, b"00000000000"))
        result = asyncio.run(self.processor.process(bad, state, source_ip="192.0.2.30"))
        response = decode_frame(result.responses[0])
        self.assertEqual(response.header.message_id, 0x8001)
        self.assertEqual(response.body[-1], 1)
        self.assertTrue(result.close_connection)

    def test_persistence_failure_emits_no_ack_and_retry_preserves_data(self) -> None:
        class FailOnceStore(InMemoryIngestionStore):
            def __init__(self) -> None:
                super().__init__()
                self.failed = False

            async def record_message(self, **kwargs):
                if not self.failed:
                    self.failed = True
                    raise RuntimeError("simulated database failure")
                return await super().record_message(**kwargs)

        store = FailOnceStore()
        asyncio.run(
            provision_device(
                store,
                terminal_id=DEVICE,
                organization_id="org-1",
                vehicle_id="vehicle-1",
                secret_protector=self.protector,
                auth_code=self.secret,
            )
        )
        processor = MessageProcessor(DeviceAuthenticator(store, self.protector), store)
        state = ConnectionState()
        auth = decode_frame(bytes.fromhex(BY_NAME["auth_serial1_captured"]["frame_hex"]))
        with self.assertRaises(RuntimeError):
            asyncio.run(processor.process(auth, state, received_at=FIXED_NOW))
        self.assertEqual(store.raw_messages, [])
        retry = asyncio.run(processor.process(auth, state, received_at=FIXED_NOW))
        self.assertEqual(len(retry.responses), 1)
        self.assertEqual(len(store.raw_messages), 1)

    def test_subpackages_are_rejected_explicitly(self) -> None:
        state = ConnectionState()
        self.process("auth_serial1_captured", state)
        frame = decode_frame(bytes.fromhex(BY_NAME["heartbeat"]["frame_hex"]))
        subpackage_header = replace(
            frame.header,
            body_properties=frame.header.body_properties | 0x2000,
            has_subpackage=True,
        )
        result = asyncio.run(
            self.processor.process(replace(frame, header=subpackage_header), state, source_ip="192.0.2.20")
        )
        self.assertTrue(result.close_connection)
        self.assertEqual(result.parser_status, "subpackage_unsupported")

    def test_partition_clock_crosses_year_boundary(self) -> None:
        starts = partition_month_starts(
            now=datetime(2026, 12, 31, 23, 59, tzinfo=timezone.utc), months_ahead=3
        )
        self.assertEqual(
            [value.strftime("%Y-%m-%d") for value in starts],
            ["2026-12-01", "2027-01-01", "2027-02-01", "2027-03-01"],
        )


if __name__ == "__main__":
    unittest.main()
