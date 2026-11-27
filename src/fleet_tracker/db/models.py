"""SQLAlchemy metadata for the P1 PostgreSQL schema."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from geoalchemy2 import Geography
from sqlalchemy import BigInteger, Boolean, DateTime, ForeignKey, Integer, LargeBinary, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import CITEXT, JSONB, UUID
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


class User(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email: Mapped[str | None] = mapped_column(CITEXT, unique=True)
    password_hash: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="active")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    password_changed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    failed_login_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class OrganizationMembership(Base):
    __tablename__ = "organization_memberships"
    __table_args__ = (UniqueConstraint("organization_id", "user_id", name="uq_membership_org_user"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    role: Mapped[str] = mapped_column(String(16), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="active")
    group_scope_mode: Mapped[str] = mapped_column(String(16), nullable=False, default="all")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    suspended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    removed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class OrganizationInvitation(Base):
    __tablename__ = "organization_invitations"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    email: Mapped[str | None] = mapped_column(CITEXT)
    role: Mapped[str] = mapped_column(String(16), nullable=False)
    token_hash: Mapped[bytes] = mapped_column(LargeBinary, nullable=False, unique=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    accepted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    invited_by: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class UserGroup(Base):
    __tablename__ = "user_groups"
    __table_args__ = (UniqueConstraint("organization_id", "name", name="uq_user_groups_org_name"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    name: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class VehicleGroupMembership(Base):
    __tablename__ = "vehicle_group_memberships"

    organization_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), primary_key=True)
    group_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("user_groups.id", ondelete="CASCADE"), primary_key=True)
    vehicle_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("vehicles.id", ondelete="CASCADE"), primary_key=True)


class MembershipGroupScope(Base):
    __tablename__ = "membership_group_scopes"

    organization_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), primary_key=True)
    membership_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organization_memberships.id", ondelete="CASCADE"), primary_key=True)
    group_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("user_groups.id", ondelete="CASCADE"), primary_key=True)


class Session(Base):
    __tablename__ = "sessions"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    session_hash: Mapped[bytes] = mapped_column(LargeBinary, nullable=False, unique=True)
    csrf_token_hash: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    idle_expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    absolute_expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    rotated_from_hash: Mapped[bytes | None] = mapped_column(LargeBinary)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoke_reason: Mapped[str | None] = mapped_column(String(64))
    last_reauthenticated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    ip_address: Mapped[str | None] = mapped_column(String(64))
    user_agent_redacted: Mapped[str | None] = mapped_column(Text)


class PasswordToken(Base):
    __tablename__ = "password_tokens"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    token_hash: Mapped[bytes] = mapped_column(LargeBinary, nullable=False, unique=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class Reauthentication(Base):
    __tablename__ = "reauthentications"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    session_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("sessions.id", ondelete="CASCADE"), nullable=False)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    completed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    purpose: Mapped[str] = mapped_column(String(64), nullable=False)


class AuditEvent(Base):
    __tablename__ = "audit_events"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    # Audit references intentionally do not cascade or SET NULL: those would
    # mutate append-only audit rows during user/organization deletion.
    actor_user_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id"))
    organization_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("organizations.id"))
    action: Mapped[str] = mapped_column(String(128), nullable=False)
    target_type: Mapped[str] = mapped_column(String(64), nullable=False)
    target_id: Mapped[str | None] = mapped_column(String(128))
    result: Mapped[str] = mapped_column(String(16), nullable=False)
    ip_address: Mapped[str | None] = mapped_column(String(64))
    user_agent_redacted: Mapped[str | None] = mapped_column(Text)
    request_id: Mapped[str] = mapped_column(String(128), nullable=False)
    metadata_json: Mapped[dict[str, Any]] = mapped_column("metadata", JSONB, nullable=False, default=dict)


class Vehicle(Base):
    __tablename__ = "vehicles"
    __table_args__ = (UniqueConstraint("organization_id", "id", name="uq_vehicles_org_id"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    name: Mapped[str] = mapped_column(Text, nullable=False)
    plate_number: Mapped[str | None] = mapped_column(Text)
    color: Mapped[str] = mapped_column(String(7), nullable=False, server_default="#0f766e")
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


class VehicleLatestState(Base):
    __tablename__ = "vehicle_latest_state"

    organization_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True)
    vehicle_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True)
    device_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    last_authenticated_message_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_position_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    gps_timestamp: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    latitude: Mapped[float | None] = mapped_column()
    longitude: Mapped[float | None] = mapped_column()
    speed_kmh: Mapped[float | None] = mapped_column()
    course: Mapped[int | None] = mapped_column()
    status: Mapped[int | None] = mapped_column(BigInteger)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


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
