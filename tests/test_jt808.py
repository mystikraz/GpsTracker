from __future__ import annotations

import json
import unittest
from datetime import timezone
from pathlib import Path

from fleet_tracker.protocol.jt808 import (
    BATCH_POSITION_MESSAGE_ID,
    GENERAL_RESPONSE_MESSAGE_ID,
    POSITION_MESSAGE_ID,
    REGISTRATION_MESSAGE_ID,
    REGISTRATION_RESPONSE_MESSAGE_ID,
    FrameStreamParser,
    InvalidChecksum,
    InvalidFrameLength,
    JT808Error,
    decode_frame,
    decode_positions_batch,
    encode_general_response,
    encode_registration_response,
    parse_position,
)


FIXTURES = json.loads((Path(__file__).parents[1] / "jt808_fixtures.json").read_text())
BY_NAME = {fixture["name"]: fixture for fixture in FIXTURES["fixtures"]}


class JT808FixtureTests(unittest.TestCase):
    def test_exact_captured_auth_frames_decode(self) -> None:
        for frame_hex in FIXTURES["captured_auth_frames_exact"]:
            with self.subTest(frame_hex=frame_hex):
                frame = decode_frame(bytes.fromhex(frame_hex))
                self.assertEqual(frame.header.message_id, 0x0102)
                self.assertEqual(frame.header.terminal_id, "999900001234")
                self.assertEqual(frame.body, b"58392017406")

    def test_registration_decodes_with_body_and_header(self) -> None:
        frame = decode_frame(bytes.fromhex(BY_NAME["registration"]["frame_hex"]))
        self.assertEqual(frame.header.message_id, REGISTRATION_MESSAGE_ID)
        self.assertEqual(frame.header.serial, 29)
        self.assertEqual(frame.header.body_length, len(frame.body))
        self.assertEqual(frame.header.body_length, 46)
        self.assertEqual(frame.header.terminal_id, "999900001234")

    def test_position_fixtures_match_expected(self) -> None:
        for name in ("position_no_fix", "position_fix_serial12", "position_fix_serial20", "position_fix_serial21"):
            with self.subTest(name=name):
                fixture = BY_NAME[name]
                frame = decode_frame(bytes.fromhex(fixture["frame_hex"]))
                self.assertEqual(frame.header.message_id, POSITION_MESSAGE_ID)
                position = parse_position(frame.body)
                expected = fixture["expected"]["positions"][0]
                self.assertIs(position.gps_fix, expected["fix"])
                self.assertAlmostEqual(position.latitude, expected["lat"])
                self.assertAlmostEqual(position.longitude, expected["lon"])
                self.assertAlmostEqual(position.speed_kmh, expected["speed_kmh"])
                self.assertEqual(position.course, expected["course"])
                self.assertEqual(position.gps_timestamp.isoformat(), expected["utc"])
                self.assertEqual(position.gps_timestamp.tzinfo, timezone.utc)

    def test_batch_fixtures_decode_all_positions(self) -> None:
        for name in ("batch_0704_serial3", "batch_0704_serial13"):
            with self.subTest(name=name):
                fixture = BY_NAME[name]
                frame = decode_frame(bytes.fromhex(fixture["frame_hex"]))
                self.assertEqual(frame.header.message_id, BATCH_POSITION_MESSAGE_ID)
                count, item_type, positions = decode_positions_batch(frame.body)
                self.assertEqual(count, fixture["expected"]["count"])
                self.assertEqual(count, 4)
                self.assertEqual(item_type, 1)
                self.assertEqual(len(positions), count)
                for position, expected in zip(positions, fixture["expected"]["positions"]):
                    self.assertTrue(position.gps_fix)
                    self.assertAlmostEqual(position.latitude, expected["lat"])
                    self.assertAlmostEqual(position.longitude, expected["lon"])
                    self.assertEqual(position.course, expected["course"])
                    self.assertEqual(position.gps_timestamp.isoformat(), expected["utc"])

    def test_signed_altitude_and_extra_tlvs_are_preserved(self) -> None:
        frame = decode_frame(bytes.fromhex(BY_NAME["batch_0704_serial13"]["frame_hex"]))
        _, _, positions = decode_positions_batch(frame.body)
        self.assertEqual(positions[0].altitude_m, -239)
        self.assertTrue(positions[0].tlvs)

    def test_parser_handles_noise_split_reads_and_two_frames(self) -> None:
        fixture = bytes.fromhex(BY_NAME["auth_serial1_captured"]["frame_hex"])
        parser = FrameStreamParser()
        self.assertEqual(parser.feed(b"\x00\xff" + fixture[:7]), [])
        frames = parser.feed(fixture[7:] + fixture)
        self.assertEqual(len(frames), 2)
        self.assertTrue(all(frame.header.message_id == 0x0102 for frame in frames))
        self.assertEqual(parser.errors, [])

    def test_parser_rejects_invalid_complete_frames_but_continues(self) -> None:
        negative = {case["name"]: case for case in FIXTURES["negative_fixtures"]}
        parser = FrameStreamParser()
        self.assertEqual(parser.feed(bytes.fromhex(negative["bad_checksum"]["frame_hex"])), [])
        self.assertIsInstance(parser.errors[-1], InvalidChecksum)

        self.assertEqual(parser.feed(bytes.fromhex(negative["body_length_mismatch"]["frame_hex"])), [])
        self.assertIsInstance(parser.errors[-1], InvalidFrameLength)

        valid = bytes.fromhex(BY_NAME["heartbeat"]["frame_hex"])
        self.assertEqual(parser.feed(valid)[0].header.message_id, 0x0002)

    def test_parser_keeps_truncated_frame_until_end_flag(self) -> None:
        truncated = bytes.fromhex(
            next(case for case in FIXTURES["negative_fixtures"] if case["name"] == "truncated_no_end_flag")["frame_hex"]
        )
        parser = FrameStreamParser()
        self.assertEqual(parser.feed(truncated), [])
        self.assertEqual(parser.errors, [])
        frames = parser.feed(b"\x7e")
        self.assertEqual(len(frames), 1)
        self.assertEqual(frames[0].header.message_id, 0x0102)
        self.assertEqual(parser.errors, [])

    def test_invalid_escape_is_rejected(self) -> None:
        invalid = next(case for case in FIXTURES["negative_fixtures"] if case["name"] == "bad_escape_7d03")
        parser = FrameStreamParser()
        self.assertEqual(parser.feed(bytes.fromhex(invalid["frame_hex"])), [])
        self.assertIsInstance(parser.errors[-1], JT808Error)

    def test_response_builders_round_trip(self) -> None:
        registration = encode_registration_response("999900001234", 1, 29, "12345678901")
        registration_frame = decode_frame(registration)
        self.assertEqual(registration_frame.header.message_id, REGISTRATION_RESPONSE_MESSAGE_ID)
        self.assertEqual(registration_frame.body, b"\x00\x1d\x00" + b"12345678901")

        general = encode_general_response("999900001234", 2, 36, 0x0002)
        general_frame = decode_frame(general)
        self.assertEqual(general_frame.header.message_id, GENERAL_RESPONSE_MESSAGE_ID)
        self.assertEqual(general_frame.body, b"\x00$\x00\x02\x00")


if __name__ == "__main__":
    unittest.main()
