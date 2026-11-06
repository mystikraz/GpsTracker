"""Authenticated JT/T 808 message processing with a testable store boundary."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
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
    parse_position,
)

from .auth import DeviceAuthenticator, DeviceRecord, InMemoryDeviceRepository


@dataclass(slots=True)
class ConnectionState:
    terminal_id: str | None = None
    device: DeviceRecord | None = None
    authenticated: bool = False
    server_serial: int = 0

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
        self.raw_messages.append(
            RawMessageRecord(
                terminal_id=device.terminal_id,
                message_id=frame.header.message_id,
                terminal_serial=frame.header.serial,
                raw_frame=frame.raw_frame,
                body=frame.body,
                received_at=received_at,
                authenticated=authenticated,
                parser_status=parser_status,
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


class MessageProcessor:
    def __init__(self, authenticator: DeviceAuthenticator, store: IngestionStore) -> None:
        self.authenticator = authenticator
        self.store = store

    async def process(
        self,
        frame: JT808Frame,
        state: ConnectionState,
        *,
        received_at: datetime | None = None,
    ) -> ProcessResult:
        received_at = received_at or datetime.now(timezone.utc)
        terminal_id = frame.header.terminal_id
        if state.terminal_id is not None and state.terminal_id != terminal_id:
            return ProcessResult(close_connection=True, parser_status="terminal_changed")

        if frame.header.message_id == REGISTRATION_MESSAGE_ID:
            registration = await self.authenticator.registration_code(terminal_id)
            if registration is None:
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
            device = await self.authenticator.authenticate(terminal_id, auth_code)
            if device is None:
                return ProcessResult(close_connection=True, parser_status="authentication_failed")
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

        stored_positions = await self.store.record_message(
            device=state.device,
            frame=frame,
            received_at=received_at,
            authenticated=True,
            positions=positions,
            parser_status=parser_status,
        )
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
