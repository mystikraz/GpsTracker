"""Strict, dependency-free JT/T 808 framing and location decoding.

This module deliberately has no database, network, or application-authentication
dependencies.  It can therefore be used by unit tests, the TCP listener, and a
fixture-replaying tracker client without changing behavior between environments.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
START_END_FLAG = 0x7E
ESCAPE_FLAG = 0x7D
ESCAPED_END_FLAG = b"\x7d\x02"
ESCAPED_ESCAPE_FLAG = b"\x7d\x01"

REGISTRATION_MESSAGE_ID = 0x0100
AUTHENTICATION_MESSAGE_ID = 0x0102
HEARTBEAT_MESSAGE_ID = 0x0002
POSITION_MESSAGE_ID = 0x0200
BATCH_POSITION_MESSAGE_ID = 0x0704
GENERAL_RESPONSE_MESSAGE_ID = 0x8001
REGISTRATION_RESPONSE_MESSAGE_ID = 0x8100

HEADER_LENGTH = 12
SUBPACKAGE_HEADER_LENGTH = 16
MAX_BODY_LENGTH = 0x03FF
UTC_PLUS_EIGHT = timezone(timedelta(hours=8))
UTC = timezone.utc


class JT808Error(ValueError):
    """Base class for malformed or unsupported JT/T 808 data."""


class InvalidEscape(JT808Error):
    """The byte-stuffed payload contains an invalid escape sequence."""


class InvalidChecksum(JT808Error):
    """The frame checksum does not match the header and body."""


class InvalidFrameLength(JT808Error):
    """The declared body length does not match the frame."""


class UnsupportedMessage(JT808Error):
    """A valid frame uses a feature this implementation cannot decode."""


class FrameTooLarge(JT808Error):
    """The stream buffer exceeded its configured safety limit."""


@dataclass(frozen=True, slots=True)
class JT808Header:
    message_id: int
    body_properties: int
    body_length: int
    terminal_id: str
    serial: int
    encryption_type: int
    has_subpackage: bool
    package_total: int | None = None
    package_number: int | None = None


@dataclass(frozen=True, slots=True)
class JT808Frame:
    header: JT808Header
    body: bytes
    checksum: int
    raw_frame: bytes


@dataclass(frozen=True, slots=True)
class JT808Tlv:
    tag: int
    value: bytes


@dataclass(frozen=True, slots=True)
class Position:
    alarm: int
    status: int
    latitude: float
    longitude: float
    altitude_m: int
    speed_kmh: float
    course: int
    gps_timestamp: datetime
    gps_fix: bool
    south: bool
    west: bool
    tlvs: tuple[JT808Tlv, ...]
    extra_raw: bytes


def _bcd_decode(data: bytes) -> str:
    digits: list[str] = []
    for value in data:
        high, low = value >> 4, value & 0x0F
        if high > 9 or low > 9:
            raise JT808Error(f"invalid BCD byte 0x{value:02x}")
        digits.extend((str(high), str(low)))
    return "".join(digits)


def _bcd_encode(digits: str) -> bytes:
    if len(digits) % 2 or not digits.isascii() or not digits.isdecimal():
        raise JT808Error("BCD value must contain an even number of ASCII digits")
    return bytes((int(digits[i : i + 2], 10) // 10 << 4) | (int(digits[i : i + 2], 10) % 10) for i in range(0, len(digits), 2))


def _terminal_id_bytes(terminal_id: str) -> bytes:
    if len(terminal_id) != 12 or not terminal_id.isascii() or not terminal_id.isdecimal():
        raise JT808Error("terminal ID must be exactly 12 ASCII digits")
    return _bcd_encode(terminal_id)


def _checksum(data: bytes) -> int:
    value = 0
    for byte in data:
        value ^= byte
    return value


def escape(data: bytes) -> bytes:
    """Apply JT/T 808 byte stuffing."""

    return data.replace(b"\x7d", ESCAPED_ESCAPE_FLAG).replace(b"\x7e", ESCAPED_END_FLAG)


def unescape(data: bytes) -> bytes:
    """Remove JT/T 808 byte stuffing and reject malformed escapes."""

    output = bytearray()
    index = 0
    while index < len(data):
        byte = data[index]
        if byte != ESCAPE_FLAG:
            output.append(byte)
            index += 1
            continue

        if index + 1 >= len(data):
            raise InvalidEscape("trailing escape byte")
        escaped = data[index + 1]
        if escaped == 0x01:
            output.append(ESCAPE_FLAG)
        elif escaped == 0x02:
            output.append(START_END_FLAG)
        else:
            raise InvalidEscape(f"invalid escape sequence 0x7d{escaped:02x}")
        index += 2
    return bytes(output)


def decode_frame(frame: bytes) -> JT808Frame:
    """Decode one complete framed JT/T 808 message."""

    if len(frame) < 3 or frame[0] != START_END_FLAG or frame[-1] != START_END_FLAG:
        raise JT808Error("frame must have 0x7e start and end flags")

    payload = unescape(frame[1:-1])
    if len(payload) < HEADER_LENGTH + 1:
        raise InvalidFrameLength("frame is shorter than the JT/T 808 header")

    message_id = int.from_bytes(payload[0:2], "big")
    body_properties = int.from_bytes(payload[2:4], "big")
    body_length = body_properties & MAX_BODY_LENGTH
    encryption_type = (body_properties >> 10) & 0x07
    has_subpackage = bool(body_properties & 0x2000)
    header_length = SUBPACKAGE_HEADER_LENGTH if has_subpackage else HEADER_LENGTH
    if encryption_type:
        raise UnsupportedMessage(f"encrypted body type {encryption_type} is unsupported")

    expected_length = header_length + body_length + 1
    if len(payload) != expected_length:
        raise InvalidFrameLength(
            f"declared body length {body_length} does not match payload length {len(payload)}"
        )

    expected_checksum = _checksum(payload[:-1])
    checksum = payload[-1]
    if checksum != expected_checksum:
        raise InvalidChecksum(f"expected 0x{expected_checksum:02x}, got 0x{checksum:02x}")

    terminal_id = _bcd_decode(payload[4:10])
    serial = int.from_bytes(payload[10:12], "big")
    package_total: int | None = None
    package_number: int | None = None
    if has_subpackage:
        package_total = int.from_bytes(payload[12:14], "big")
        package_number = int.from_bytes(payload[14:16], "big")

    header = JT808Header(
        message_id=message_id,
        body_properties=body_properties,
        body_length=body_length,
        terminal_id=terminal_id,
        serial=serial,
        encryption_type=encryption_type,
        has_subpackage=has_subpackage,
        package_total=package_total,
        package_number=package_number,
    )
    return JT808Frame(
        header=header,
        body=payload[header_length:-1],
        checksum=checksum,
        raw_frame=bytes(frame),
    )


class FrameStreamParser:
    """Extract and validate frames from arbitrary TCP chunks.

    Invalid complete frames are discarded and exposed through ``errors`` so one
    bad packet does not terminate a connection. An incomplete frame remains
    buffered until its end flag arrives or the configured limit is exceeded.
    """

    def __init__(self, *, max_frame_size: int = 4096, max_buffer_size: int = 8192) -> None:
        if max_frame_size < 32 or max_buffer_size < max_frame_size:
            raise ValueError("buffer limits are too small")
        self.max_frame_size = max_frame_size
        self.max_buffer_size = max_buffer_size
        self._buffer = bytearray()
        self.errors: list[JT808Error] = []

    def _record_error(self, error: JT808Error) -> None:
        if len(self.errors) >= 32:
            del self.errors[0]
        self.errors.append(error)

    def feed(self, data: bytes) -> list[JT808Frame]:
        if not data:
            return []
        self._buffer.extend(data)

        frames: list[JT808Frame] = []
        while self._buffer:
            start = self._buffer.find(bytes((START_END_FLAG,)))
            if start < 0:
                self._buffer.clear()
                break
            if start:
                del self._buffer[:start]

            end = self._buffer.find(bytes((START_END_FLAG,)), 1)
            if end < 0:
                if len(self._buffer) > self.max_frame_size:
                    self._buffer.clear()
                    error = FrameTooLarge("incomplete JT/T 808 frame exceeded limit")
                    self._record_error(error)
                    raise error
                break

            frame = bytes(self._buffer[: end + 1])
            del self._buffer[: end + 1]
            if len(frame) <= 2:
                continue
            if len(frame) > self.max_frame_size:
                error = FrameTooLarge("JT/T 808 frame exceeded limit")
                self._record_error(error)
                continue
            try:
                frames.append(decode_frame(frame))
            except JT808Error as error:
                self._record_error(error)
        if len(self._buffer) > self.max_buffer_size:
            self._buffer.clear()
            error = FrameTooLarge("TCP receive buffer exceeded limit")
            self._record_error(error)
            raise error
        return frames


def _decode_device_timestamp(raw: bytes) -> datetime:
    if len(raw) != 6:
        raise JT808Error("position timestamp must be six BCD bytes")
    digits = _bcd_decode(raw)
    try:
        local_time = datetime.strptime(digits, "%y%m%d%H%M%S").replace(tzinfo=UTC_PLUS_EIGHT)
    except ValueError as error:
        raise JT808Error(f"invalid device timestamp {digits}") from error
    return local_time.astimezone(UTC)


def _decode_tlvs(data: bytes) -> tuple[tuple[JT808Tlv, ...], bytes]:
    tlvs: list[JT808Tlv] = []
    index = 0
    while index + 2 <= len(data):
        tag = data[index]
        length = data[index + 1]
        end = index + 2 + length
        if end > len(data):
            return tuple(tlvs), data[index:]
        tlvs.append(JT808Tlv(tag=tag, value=data[index + 2 : end]))
        index = end
    return tuple(tlvs), data[index:]


def parse_position(body: bytes) -> Position:
    """Decode a 0x0200 location body.

    A no-fix body is returned with ``gps_fix=False`` so callers can update the
    authenticated-device heartbeat state without persisting it as a position.
    """

    if len(body) < 28:
        raise JT808Error("position body must contain at least 28 bytes")

    alarm = int.from_bytes(body[0:4], "big")
    status = int.from_bytes(body[4:8], "big")
    gps_fix = bool(status & 0x02)
    south = bool(status & 0x04)
    west = bool(status & 0x08)

    latitude = int.from_bytes(body[8:12], "big") / 1_000_000
    longitude = int.from_bytes(body[12:16], "big") / 1_000_000
    if south:
        latitude = -latitude
    if west:
        longitude = -longitude
    if gps_fix and not (-90 <= latitude <= 90 and -180 <= longitude <= 180):
        raise JT808Error("position coordinates are out of range")

    altitude_m = int.from_bytes(body[16:18], "big", signed=True)
    speed_kmh = int.from_bytes(body[18:20], "big") / 10
    course = int.from_bytes(body[20:22], "big")
    gps_timestamp = _decode_device_timestamp(body[22:28])
    tlvs, extra_raw = _decode_tlvs(body[28:])
    return Position(
        alarm=alarm,
        status=status,
        latitude=latitude,
        longitude=longitude,
        altitude_m=altitude_m,
        speed_kmh=speed_kmh,
        course=course,
        gps_timestamp=gps_timestamp,
        gps_fix=gps_fix,
        south=south,
        west=west,
        tlvs=tlvs,
        extra_raw=extra_raw,
    )


def decode_positions_batch(body: bytes) -> tuple[int, int, tuple[Position, ...]]:
    """Decode a 0x0704 body into ``(count, item_type, positions)``."""

    if len(body) < 3:
        raise JT808Error("batch body must contain count and item type")
    count = int.from_bytes(body[0:2], "big")
    item_type = body[2]
    index = 3
    positions: list[Position] = []
    for item_index in range(count):
        if index + 2 > len(body):
            raise JT808Error(f"batch ends before item {item_index}")
        length = int.from_bytes(body[index : index + 2], "big")
        index += 2
        if index + length > len(body):
            raise JT808Error(f"batch item {item_index} exceeds body length")
        positions.append(parse_position(body[index : index + length]))
        index += length
    if index != len(body):
        raise JT808Error("batch contains trailing bytes")
    return count, item_type, tuple(positions)


def encode_frame(message_id: int, terminal_id: str, serial: int, body: bytes = b"") -> bytes:
    """Build a valid, unescaped JT/T 808 frame."""

    if not 0 <= message_id <= 0xFFFF:
        raise JT808Error("message ID must fit in two bytes")
    if not 0 <= serial <= 0xFFFF:
        raise JT808Error("message serial must fit in two bytes")
    if len(body) > MAX_BODY_LENGTH:
        raise JT808Error("body exceeds the supported JT/T 808 body limit")
    header = (
        message_id.to_bytes(2, "big")
        + len(body).to_bytes(2, "big")
        + _terminal_id_bytes(terminal_id)
        + serial.to_bytes(2, "big")
    )
    payload = header + body
    return bytes((START_END_FLAG,)) + escape(payload + bytes((_checksum(payload),))) + bytes((START_END_FLAG,))


def encode_general_response(
    terminal_id: str,
    server_serial: int,
    request_serial: int,
    request_message_id: int,
    result: int = 0,
) -> bytes:
    body = request_serial.to_bytes(2, "big") + request_message_id.to_bytes(2, "big") + bytes((result,))
    return encode_frame(GENERAL_RESPONSE_MESSAGE_ID, terminal_id, server_serial, body)


def encode_registration_response(
    terminal_id: str,
    server_serial: int,
    request_serial: int,
    auth_code: str,
    result: int = 0,
) -> bytes:
    if len(auth_code) != 11 or not auth_code.isascii() or not auth_code.isdecimal():
        raise JT808Error("authentication code must be 11 ASCII digits")
    body = request_serial.to_bytes(2, "big") + bytes((result,)) + auth_code.encode("ascii")
    return encode_frame(REGISTRATION_RESPONSE_MESSAGE_ID, terminal_id, server_serial, body)
