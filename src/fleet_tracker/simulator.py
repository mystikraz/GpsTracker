"""Replay the checked-in PG07 fixtures against a running TCP listener."""

from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path

from fleet_tracker.protocol.jt808 import (
    AUTHENTICATION_MESSAGE_ID,
    FrameStreamParser,
    JT808Error,
    decode_frame,
    encode_frame,
)


FIXTURE_PATH = Path(__file__).parents[2] / "jt808_fixtures.json"


async def _read_frame(reader: asyncio.StreamReader) -> object:
    parser = FrameStreamParser()
    while True:
        chunk = await reader.read(512)
        if not chunk:
            raise ConnectionError("server closed before a response")
        frames = parser.feed(chunk)
        if frames:
            return frames[0]


async def _send_and_expect(
    writer: asyncio.StreamWriter,
    reader: asyncio.StreamReader,
    frame: bytes,
    *,
    chunk_size: int,
) -> object:
    for index in range(0, len(frame), chunk_size):
        writer.write(frame[index : index + chunk_size])
        await writer.drain()
        await asyncio.sleep(0)
    return await _read_frame(reader)


async def replay(args: argparse.Namespace) -> None:
    fixture_data = json.loads(args.fixture.read_text())
    fixtures = {fixture["name"]: fixture for fixture in fixture_data["fixtures"]}
    terminal_id = args.terminal_id

    reader, writer = await asyncio.open_connection(args.host, args.port)
    try:
        registration = bytes.fromhex(fixtures["registration"]["frame_hex"])
        registration_response = await _send_and_expect(
            writer,
            reader,
            registration,
            chunk_size=args.chunk_size,
        )
        if registration_response.header.message_id != 0x8100:
            raise JT808Error("expected 0x8100 registration response")
        auth_code = registration_response.body[3:].decode("ascii")
        auth = encode_frame(AUTHENTICATION_MESSAGE_ID, terminal_id, 1, auth_code.encode("ascii"))
        auth_response = await _send_and_expect(writer, reader, auth, chunk_size=args.chunk_size)
        if auth_response.header.message_id != 0x8001:
            raise JT808Error("expected 0x8001 authentication response")

        for name in args.messages:
            response = await _send_and_expect(
                writer,
                reader,
                bytes.fromhex(fixtures[name]["frame_hex"]),
                chunk_size=args.chunk_size,
            )
            if response.header.message_id != 0x8001:
                raise JT808Error(f"expected 0x8001 response for {name}")
            print(f"replayed={name}")
    finally:
        writer.close()
        await writer.wait_closed()

    if args.reconnect:
        reader, writer = await asyncio.open_connection(args.host, args.port)
        try:
            auth = encode_frame(AUTHENTICATION_MESSAGE_ID, terminal_id, 1, auth_code.encode("ascii"))
            response = await _send_and_expect(writer, reader, auth, chunk_size=args.chunk_size)
            if response.header.message_id != 0x8001:
                raise JT808Error("expected direct reconnect authentication response")
            print("reconnected=0102-only")
        finally:
            writer.close()
            await writer.wait_closed()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="fleet-tracker-replay")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8881)
    parser.add_argument("--terminal-id", default="999900001234")
    parser.add_argument("--fixture", type=Path, default=FIXTURE_PATH)
    parser.add_argument("--chunk-size", type=int, default=17)
    parser.add_argument("--reconnect", action="store_true")
    parser.add_argument(
        "messages",
        nargs="*",
        default=["heartbeat", "position_no_fix", "position_fix_serial12", "batch_0704_serial3", "vendor_1107_info"],
    )
    return parser


def main() -> None:
    args = build_parser().parse_args()
    if args.chunk_size < 1:
        raise SystemExit("--chunk-size must be positive")
    asyncio.run(replay(args))


if __name__ == "__main__":
    main()
