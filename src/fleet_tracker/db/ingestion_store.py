"""PostgreSQL transaction boundary for authenticated JT/T 808 ingestion."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from uuid import UUID

from sqlalchemy import or_, select, text, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from fleet_tracker.ingestion.auth import DeviceRecord, DeviceRepository, SecretProtector
from fleet_tracker.protocol.jt808 import JT808Frame, Position

from .models import Device, DeviceVehicleAssignment, RawMessage


UTC = timezone.utc


def _position_extras(position: Position) -> dict[str, object]:
    return {
        "tlvs": [{"tag": tlv.tag, "value_hex": tlv.value.hex()} for tlv in position.tlvs],
        "trailing_hex": position.extra_raw.hex(),
    }


class PostgresIngestionStore(DeviceRepository):
    """Store implementation used by the independently restartable TCP service."""

    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        secret_protector: SecretProtector,
        *,
        auth_pepper: bytes = b"",
    ) -> None:
        self.session_factory = session_factory
        self.secret_protector = secret_protector
        self.auth_pepper = auth_pepper

    async def get_device(self, terminal_id: str) -> DeviceRecord | None:
        now = datetime.now(UTC)
        async with self.session_factory() as session:
            device = await session.scalar(
                select(Device).where(Device.terminal_id == terminal_id, Device.active.is_(True))
            )
            if device is None:
                return None
            assignment = await session.scalar(
                select(DeviceVehicleAssignment)
                .where(
                    DeviceVehicleAssignment.device_id == device.id,
                    DeviceVehicleAssignment.organization_id == device.organization_id,
                    DeviceVehicleAssignment.effective_from <= now,
                    or_(
                        DeviceVehicleAssignment.effective_to.is_(None),
                        DeviceVehicleAssignment.effective_to > now,
                    ),
                )
                .order_by(DeviceVehicleAssignment.effective_from.desc())
                .limit(1)
            )
            if assignment is None:
                return None
            return DeviceRecord(
                terminal_id=device.terminal_id,
                organization_id=str(device.organization_id),
                vehicle_id=str(assignment.vehicle_id),
                auth_secret_hash=device.auth_secret_hash,
                auth_secret_ciphertext=device.auth_secret_ciphertext,
                database_id=str(device.id),
                active=device.active,
            )

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
        if device.database_id is None:
            raise ValueError("persistent device records require database_id")
        organization_id = UUID(device.organization_id)
        device_id = UUID(device.database_id)
        vehicle_id = UUID(device.vehicle_id)
        received_at = received_at.astimezone(UTC)
        frame_hash = hashlib.sha256(device.terminal_id.encode("ascii") + frame.raw_frame).hexdigest()
        inserted_positions = 0
        position_payload: list[dict[str, object]] = []

        async with self.session_factory() as session:
            async with session.begin():
                raw_message = RawMessage(
                    organization_id=organization_id,
                    device_id=device_id,
                    received_at=received_at,
                    message_id=frame.header.message_id,
                    terminal_serial=frame.header.serial,
                    raw_frame=frame.raw_frame,
                    body=frame.body,
                    authenticated=authenticated,
                    parser_status=parser_status,
                    created_at=received_at,
                )
                session.add(raw_message)
                await session.flush()

                for position in positions:
                    gps_timestamp = position.gps_timestamp.astimezone(UTC)
                    params = {
                        "gps_timestamp": gps_timestamp,
                        "organization_id": organization_id,
                        "device_id": device_id,
                        "vehicle_id": vehicle_id,
                        "received_at": received_at,
                        "latitude": position.latitude,
                        "longitude": position.longitude,
                        "altitude_m": position.altitude_m,
                        "speed_kmh": position.speed_kmh,
                        "course": position.course,
                        "alarm": position.alarm,
                        "status": position.status,
                        "extras": json.dumps(_position_extras(position)),
                        "raw_message_id": raw_message.id,
                    }
                    result = await session.execute(
                        text(
                            """
                            INSERT INTO positions (
                                gps_timestamp, organization_id, device_id, vehicle_id,
                                received_at, latitude, longitude, location, altitude_m,
                                speed_kmh, course, alarm, status, extras, raw_message_id
                            ) VALUES (
                                :gps_timestamp, :organization_id, :device_id, :vehicle_id,
                                :received_at, :latitude, :longitude,
                                ST_SetSRID(ST_MakePoint(:longitude, :latitude), 4326)::geography,
                                :altitude_m, :speed_kmh, :course, :alarm, :status,
                                CAST(:extras AS jsonb), :raw_message_id
                            )
                            ON CONFLICT DO NOTHING
                            RETURNING id
                            """
                        ),
                        params,
                    )
                    inserted_id = result.scalar_one_or_none()
                    if inserted_id is not None:
                        inserted_positions += 1
                        position_payload.append(
                            {
                                "position_id": inserted_id,
                                "gps_timestamp": gps_timestamp.isoformat(),
                                "latitude": position.latitude,
                                "longitude": position.longitude,
                                "speed_kmh": position.speed_kmh,
                                "course": position.course,
                            }
                        )

                if authenticated:
                    values: dict[str, object] = {"last_authenticated_message_at": received_at}
                    if position_payload:
                        values["last_position_at"] = max(
                            datetime.fromisoformat(item["gps_timestamp"]) for item in position_payload
                        )
                    await session.execute(update(Device).where(Device.id == device_id).values(**values))

                payload = {
                    "terminal_id": device.terminal_id,
                    "message_id": frame.header.message_id,
                    "terminal_serial": frame.header.serial,
                    "received_at": received_at.isoformat(),
                    "raw_message_id": raw_message.id,
                    "positions": position_payload,
                    "parser_status": parser_status,
                }
                await session.execute(
                    text(
                        """
                        INSERT INTO outbox_events (
                            organization_id, event_type, aggregate_type, aggregate_id,
                            idempotency_key, payload, created_at, available_at
                        ) VALUES (
                            :organization_id, 'telemetry.message.accepted', 'device',
                            :aggregate_id, :idempotency_key, CAST(:payload AS jsonb),
                            :created_at, :available_at
                        )
                        ON CONFLICT (idempotency_key) DO NOTHING
                        """
                    ),
                    {
                        "organization_id": organization_id,
                        "aggregate_id": device.terminal_id,
                        "idempotency_key": frame_hash,
                        "payload": json.dumps(payload),
                        "created_at": received_at,
                        "available_at": received_at,
                    },
                )
        return inserted_positions

    async def purge_expired_raw_messages(self, *, now: datetime | None = None) -> int:
        """Delete raw frames according to each organization's configured policy."""

        now = (now or datetime.now(UTC)).astimezone(UTC)
        async with self.session_factory() as session:
            async with session.begin():
                result = await session.execute(
                    text(
                        """
                        DELETE FROM raw_messages AS raw
                        USING organizations AS org
                        WHERE raw.organization_id = org.id
                          AND raw.received_at < (
                              CAST(:now AS timestamptz)
                              - (org.raw_retention_days * INTERVAL '1 day')
                          )
                        """
                    ),
                    {"now": now},
                )
                return result.rowcount
