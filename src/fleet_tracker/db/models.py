"""SQLAlchemy metadata for the P1 PostgreSQL schema."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from geoalchemy2 import Geography
from sqlalchemy import BigInteger, Boolean, DateTime, ForeignKey, Integer, LargeBinary, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class Organization(Base):
    __tablename__ = "organizations"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(Text, nullable=False)
    timezone: Mapped[str] = mapped_column(String(64), nullable=False, default="Asia/Kathmandu")
    position_retention_months: Mapped[int] = mapped_column(Integer, nullable=False, default=12)
    raw_retention_days: Mapped[int] = mapped_column(Integer, nullable=False, default=30)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class Vehicle(Base):
    __tablename__ = "vehicles"
    __table_args__ = (UniqueConstraint("organization_id", "id", name="uq_vehicles_org_id"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    name: Mapped[str] = mapped_column(Text, nullable=False)
    plate_number: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class Device(Base):
    __tablename__ = "devices"
    __table_args__ = (
        UniqueConstraint("organization_id", "id", name="uq_devices_org_id"),
        UniqueConstraint("terminal_id", name="uq_devices_terminal_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    terminal_id: Mapped[str] = mapped_column(String(12), nullable=False)
    auth_secret_hash: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    auth_secret_ciphertext: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    last_authenticated_message_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_position_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    secret_rotated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class DeviceVehicleAssignment(Base):
    __tablename__ = "device_vehicle_assignments"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    device_id: Mapped[uuid.UUID] = mapped_column(nullable=False)
    vehicle_id: Mapped[uuid.UUID] = mapped_column(nullable=False)
    effective_from: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    effective_to: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class RawMessage(Base):
    __tablename__ = "raw_messages"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    organization_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    device_id: Mapped[uuid.UUID] = mapped_column(nullable=False)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    message_id: Mapped[int] = mapped_column(Integer, nullable=False)
    terminal_serial: Mapped[int] = mapped_column(Integer, nullable=False)
    raw_frame: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    body: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    redacted_body_length: Mapped[int | None] = mapped_column(Integer)
    redacted_body_hash: Mapped[bytes | None] = mapped_column(LargeBinary)
    authenticated: Mapped[bool] = mapped_column(Boolean, nullable=False)
    parser_status: Mapped[str] = mapped_column(String(64), nullable=False)
    parse_error: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class Position(Base):
    __tablename__ = "positions"
    __table_args__ = {"postgresql_partition_by": "RANGE (gps_timestamp)"}

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    gps_timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), primary_key=True)
    organization_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    device_id: Mapped[uuid.UUID] = mapped_column(nullable=False)
    vehicle_id: Mapped[uuid.UUID] = mapped_column(nullable=False)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    latitude: Mapped[float] = mapped_column(nullable=False)
    longitude: Mapped[float] = mapped_column(nullable=False)
    location: Mapped[Any] = mapped_column(Geography(geometry_type="POINT", srid=4326), nullable=False)
    altitude_m: Mapped[int] = mapped_column(Integer, nullable=False)
    speed_kmh: Mapped[float] = mapped_column(nullable=False)
    course: Mapped[int] = mapped_column(Integer, nullable=False)
    alarm: Mapped[int] = mapped_column(Integer, nullable=False)
    status: Mapped[int] = mapped_column(BigInteger, nullable=False)
    extras: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    raw_message_id: Mapped[int | None] = mapped_column(nullable=True)


class OutboxEvent(Base):
    __tablename__ = "outbox_events"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    organization_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    event_type: Mapped[str] = mapped_column(String(128), nullable=False)
    aggregate_type: Mapped[str] = mapped_column(String(64), nullable=False)
    aggregate_id: Mapped[str] = mapped_column(String(128), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(256), nullable=False, unique=True)
    payload: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    available_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    claimed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    processed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
