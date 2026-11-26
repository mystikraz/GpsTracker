"""Authenticated JT/T 808 message processing with a testable store boundary."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import logging
import time
from collections.abc import Awaitable, Callable
from uuid import uuid4
from typing import Protocol

from fleet_tracker.protocol.jt808 import (
    AUTHENTICATION_MESSAGE_ID,
    BATCH_POSITION_MESSAGE_ID,
    HEARTBEAT_MESSAGE_ID,
    POSITION_MESSAGE_ID,
    REGISTRATION_MESSAGE_ID,
    JT808Error,
    JT808Frame,
    Position,
    decode_positions_batch,
    encode_general_response,
    encode_registration_response,
    encode_frame,
    parse_position,
)

from .auth import DeviceAuthenticator, DeviceRecord, InMemoryDeviceRepository

logger = logging.getLogger("fleet_tracker.ingestion")


@dataclass(slots=True)
class ConnectionState:
    terminal_id: str | None = None
    device: DeviceRecord | None = None
    authenticated: bool = False
    server_serial: int = 0
    connection_id: str = field(default_factory=lambda: str(uuid4()))
    source_ip: str = "unknown"
    active: bool = True
    last_activity: float = field(default_factory=time.monotonic)
    last_position_write: float | None = None
    close_callback: Callable[[], Awaitable[None]] | None = None

    def next_server_serial(self) -> int:
        self.server_serial = (self.server_serial + 1) & 0xFFFF
        return self.server_serial


@dataclass(frozen=True, slots=True)
class RawMessageRecord:
    terminal_id: str
    message_id: int
    terminal_serial: int
    raw_frame: bytes
    body: bytes
    received_at: datetime
    authenticated: bool
    parser_status: str
    redacted_body_length: int | None = None
    redacted_body_hash: bytes | None = None


@dataclass(frozen=True, slots=True)
class StoredPosition:
    terminal_id: str
    organization_id: str
    vehicle_id: str
    position: Position
    received_at: datetime


class IngestionStore(Protocol):
    async def record_message(
        self,
        *,
        device: DeviceRecord,
        frame: JT808Frame,
        received_at: datetime,
        authenticated: bool,
        positions: tuple[Position, ...],
        parser_status: str,
    ) -> int: ...


class InMemoryIngestionStore(InMemoryDeviceRepository):
    """Deterministic store used by protocol and simulated-tracker tests."""

    def __init__(self) -> None:
        super().__init__()
        self.raw_messages: list[RawMessageRecord] = []
        self.positions: list[StoredPosition] = []
        self.last_authenticated_message: dict[str, datetime] = {}

    async def record_message(
        self,
        *,
        device: DeviceRecord,
        frame: JT808Frame,
        received_at: datetime,
        authenticated: bool,
        positions: tuple[Position, ...],
        parser_status: str,
    ) -> int:
        sensitive = frame.header.message_id in {REGISTRATION_MESSAGE_ID, AUTHENTICATION_MESSAGE_ID}
        stored_body = b"" if sensitive else frame.body
        stored_frame = (
            encode_frame(frame.header.message_id, frame.header.terminal_id, frame.header.serial, b"")
            if sensitive
            else frame.raw_frame
        )
        self.raw_messages.append(
            RawMessageRecord(
                terminal_id=device.terminal_id,
                message_id=frame.header.message_id,
                terminal_serial=frame.header.serial,
                raw_frame=stored_frame,
                body=stored_body,
                received_at=received_at,
                authenticated=authenticated,
                parser_status=parser_status,
                redacted_body_length=len(frame.body) if sensitive else None,
                redacted_body_hash=hashlib.sha256(frame.body).digest() if sensitive else None,
            )
        )
        if authenticated:
            self.last_authenticated_message[device.terminal_id] = received_at

        inserted = 0
        existing = {(item.terminal_id, item.position.gps_timestamp) for item in self.positions}
        for position in positions:
            key = (device.terminal_id, position.gps_timestamp)
            if key in existing:
                continue
            self.positions.append(
                StoredPosition(
                    terminal_id=device.terminal_id,
                    organization_id=device.organization_id,
                    vehicle_id=device.vehicle_id,
                    position=position,
                    received_at=received_at,
                )
            )
            existing.add(key)
            inserted += 1
        return inserted


@dataclass(frozen=True, slots=True)
class ProcessResult:
    responses: tuple[bytes, ...] = ()
    accepted: bool = False
    authenticated: bool = False
    close_connection: bool = False
    stored_positions: int = 0
    parser_status: str = "rejected"


class AuthenticatedConnectionRegistry:
    """Enforce one authenticated TCP connection per terminal."""

    def __init__(self, *, idle_seconds: float = 60.0) -> None:
        if idle_seconds < 0:
            raise ValueError("idle_seconds must be non-negative")
        self.idle_seconds = idle_seconds
        self._connections: dict[str, ConnectionState] = {}

    async def claim(self, terminal_id: str, state: ConnectionState, source_ip: str) -> bool:
        current = self._connections.get(terminal_id)
        if current is not None and current is not state and current.active:
            idle = time.monotonic() - current.last_activity
            logger.warning(
                "authenticated_connection_conflict terminal_id=%s old_source_ip=%s "
                "new_source_ip=%s idle_seconds=%.3f action=%s",
                terminal_id,
                current.source_ip,
                source_ip,
                idle,
                "replace" if idle > self.idle_seconds else "reject",
            )
            if idle <= self.idle_seconds:
                return False
            if current.close_callback is not None:
                await current.close_callback()
            current.active = False
        state.connection_id = state.connection_id or str(uuid4())
        state.source_ip = source_ip
        state.active = True
        self._connections[terminal_id] = state
        return True

    def release(self, state: ConnectionState) -> None:
        if state.terminal_id and self._connections.get(state.terminal_id) is state:
            self._connections.pop(state.terminal_id, None)


class MessageProcessor:
    def __init__(
        self,
        authenticator: DeviceAuthenticator,
        store: IngestionStore,
        *,
        connection_registry: AuthenticatedConnectionRegistry | None = None,
        position_min_interval_seconds: float = 0,
    ) -> None:
        if not 0 <= position_min_interval_seconds < float('inf'):
            raise ValueError("position_min_interval_seconds must be finite and non-negative")
        self.authenticator = authenticator
        self.store = store
        self.connection_registry = connection_registry
        self.position_min_interval_seconds = position_min_interval_seconds

    async def process(
        self,
        frame: JT808Frame,
        state: ConnectionState,
        *,
        received_at: datetime | None = None,
        source_ip: str = "unknown",
    ) -> ProcessResult:
        received_at = received_at or datetime.now(timezone.utc)
        state.last_activity = time.monotonic()
        if not state.active:
            return ProcessResult(close_connection=True, parser_status="connection_replaced")
        terminal_id = frame.header.terminal_id
        if state.terminal_id is not None and state.terminal_id != terminal_id:
            return ProcessResult(close_connection=True, parser_status="terminal_changed")

        if frame.header.has_subpackage:
            logger.warning(
                "unsupported_subpackage terminal_id=%s message_id=0x%04x source_ip=%s",
                terminal_id,
                frame.header.message_id,
                source_ip,
            )
            return ProcessResult(close_connection=True, parser_status="subpackage_unsupported")

        if frame.header.message_id == REGISTRATION_MESSAGE_ID:
            logger.info(
                "jt808_registration_received source_ip=%s terminal_id=%s "
                "request_serial=%s body_length=%s",
                source_ip,
                terminal_id,
                frame.header.serial,
                len(frame.body),
            )
            registration = await self.authenticator.registration_code(terminal_id)
            if registration is None:
                logger.warning(
                    "jt808_registration_rejected source_ip=%s terminal_id=%s "
                    "request_serial=%s reason=unknown_device",
                    source_ip,
                    terminal_id,
                    frame.header.serial,
                )
                return ProcessResult(close_connection=True, parser_status="unknown_device")
            device, auth_code = registration
            state.terminal_id = terminal_id
            state.device = device
            state.authenticated = False
            inserted = await self.store.record_message(
                device=device,
                frame=frame,
                received_at=received_at,
                authenticated=False,
                positions=(),
                parser_status="registration",
            )
            del inserted
            response = encode_registration_response(
                terminal_id,
                state.next_server_serial(),
                frame.header.serial,
                auth_code,
            )
            logger.info(
                "jt808_registration_response source_ip=%s terminal_id=%s "
                "request_serial=%s server_serial=%s response_message_id=0x8100 "
                "result=0 auth_code_length=%s",
                source_ip,
                terminal_id,
                frame.header.serial,
                state.server_serial,
                len(auth_code),
            )
            return ProcessResult(
                responses=(response,),
                accepted=True,
                authenticated=False,
                parser_status="registration",
            )

        if frame.header.message_id == AUTHENTICATION_MESSAGE_ID:
            try:
                auth_code = frame.body.decode("ascii")
            except UnicodeDecodeError:
                auth_code = ""
            logger.info(
                "jt808_authentication_received source_ip=%s terminal_id=%s "
                "request_serial=%s auth_code_length=%s",
                source_ip,
                terminal_id,
                frame.header.serial,
                len(auth_code),
            )
            provisioned_device = await self.authenticator.lookup(terminal_id)
            device = await self.authenticator.authenticate(terminal_id, auth_code)
            if device is None:
                if provisioned_device is None:
                    logger.warning(
                        "jt808_authentication_rejected source_ip=%s terminal_id=%s "
                        "request_serial=%s reason=unknown_device",
                        source_ip,
                        terminal_id,
                        frame.header.serial,
                    )
                    return ProcessResult(close_connection=True, parser_status="authentication_failed")
                response = encode_general_response(
                    terminal_id,
                    state.next_server_serial(),
                    frame.header.serial,
                    frame.header.message_id,
                    result=1,
                )
                logger.warning(
                    "jt808_authentication_rejected source_ip=%s terminal_id=%s "
                    "request_serial=%s server_serial=%s response_message_id=0x8001 "
                    "result=1 reason=code_mismatch",
                    source_ip,
                    terminal_id,
                    frame.header.serial,
                    state.server_serial,
                )
                return ProcessResult(
                    responses=(response,),
                    close_connection=True,
                    parser_status="authentication_failed",
                )
            if self.connection_registry and not await self.connection_registry.claim(terminal_id, state, source_ip):
                return ProcessResult(close_connection=True, parser_status="authenticated_connection_conflict")
            state.terminal_id = terminal_id
            state.device = device
            state.authenticated = True
            await self.store.record_message(
                device=device,
                frame=frame,
                received_at=received_at,
                authenticated=True,
                positions=(),
                parser_status="authenticated",
            )
            response = encode_general_response(
                terminal_id,
                state.next_server_serial(),
                frame.header.serial,
                frame.header.message_id,
            )
            logger.info(
                "jt808_authentication_accepted source_ip=%s terminal_id=%s "
                "request_serial=%s server_serial=%s response_message_id=0x8001 result=0",
                source_ip,
                terminal_id,
                frame.header.serial,
                state.server_serial,
            )
            return ProcessResult(
                responses=(response,),
                accepted=True,
                authenticated=True,
                parser_status="authenticated",
            )

        if not state.authenticated or state.device is None:
            return ProcessResult(close_connection=True, parser_status="unauthenticated_message")

        positions: tuple[Position, ...] = ()
        parser_status = "accepted"
        result_code = 0
        try:
            if frame.header.message_id == POSITION_MESSAGE_ID:
                position = parse_position(frame.body)
                positions = (position,) if position.gps_fix else ()
                parser_status = "position_fix" if position.gps_fix else "position_no_fix"
            elif frame.header.message_id == BATCH_POSITION_MESSAGE_ID:
                _, _, decoded_positions = decode_positions_batch(frame.body)
                positions = tuple(position for position in decoded_positions if position.gps_fix)
                parser_status = "batch_positions"
            elif frame.header.message_id == HEARTBEAT_MESSAGE_ID:
                parser_status = "heartbeat"
            else:
                parser_status = "vendor_or_unknown"
        except JT808Error as error:
            parser_status = f"parse_error:{type(error).__name__}"
            result_code = 1

        # Sampling deliberately drops the whole ordinary live position frame,
        # including its raw record and outbox event. Alarms and historical batches
        # are never sampled. Only acknowledge after a prior successful write.
        now = time.monotonic()
        if (frame.header.message_id == POSITION_MESSAGE_ID and positions
                and not positions[0].alarm and state.last_position_write is not None
                and now - state.last_position_write < self.position_min_interval_seconds):
            response = encode_general_response(terminal_id, state.next_server_serial(),
                                               frame.header.serial, frame.header.message_id)
            return ProcessResult(responses=(response,), accepted=True, authenticated=True,
                                 parser_status="position_sampled")

        stored_positions = await self.store.record_message(
            device=state.device,
            frame=frame,
            received_at=received_at,
            authenticated=True,
            positions=positions,
            parser_status=parser_status,
        )
        if frame.header.message_id == POSITION_MESSAGE_ID and positions:
            state.last_position_write = time.monotonic()
        response = encode_general_response(
            terminal_id,
            state.next_server_serial(),
            frame.header.serial,
            frame.header.message_id,
            result=result_code,
        )
        return ProcessResult(
            responses=(response,),
            accepted=True,
            authenticated=True,
            stored_positions=stored_positions,
            parser_status=parser_status,
        )
