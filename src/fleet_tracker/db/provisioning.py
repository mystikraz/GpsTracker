"""P1 device provisioning transaction."""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from fleet_tracker.ingestion.auth import (
    SecretProtector,
    generate_auth_code,
    hash_auth_code,
    validate_auth_code,
    validate_terminal_id,
)

from .models import Device, DeviceVehicleAssignment, Organization, Vehicle


async def provision_postgres_device(
    session_factory: async_sessionmaker[AsyncSession],
    *,
    organization_id: str,
    vehicle_id: str,
    terminal_id: str,
    secret_protector: SecretProtector,
    auth_code: str | None = None,
    auth_pepper: bytes = b"",
) -> tuple[str, str]:
    """Create a provisioned device and active vehicle assignment.

    Returns ``(device_id, auth_code)``. Callers must avoid logging the second
    value; it is returned solely so the bootstrap operator can handle it
    according to the deployment procedure.
    """

    terminal_id = validate_terminal_id(terminal_id)
    organization_uuid = UUID(organization_id)
    vehicle_uuid = UUID(vehicle_id)
    auth_code = validate_auth_code(auth_code) if auth_code is not None else generate_auth_code(terminal_id)
    now = datetime.now(timezone.utc)

    async with session_factory() as session:
        async with session.begin():
            organization = await session.scalar(select(Organization).where(Organization.id == organization_uuid))
            vehicle = await session.scalar(
                select(Vehicle).where(Vehicle.id == vehicle_uuid, Vehicle.organization_id == organization_uuid)
            )
            if organization is None or vehicle is None:
                raise ValueError("organization and vehicle must exist in the same tenant")
            if await session.scalar(select(Device).where(Device.terminal_id == terminal_id)) is not None:
                raise ValueError("terminal ID is already provisioned")

            device = Device(
                organization_id=organization_uuid,
                terminal_id=terminal_id,
                auth_secret_hash=hash_auth_code(auth_code, auth_pepper),
                auth_secret_ciphertext=secret_protector.encrypt(
                    auth_code,
                    associated_data=terminal_id.encode("ascii"),
                ),
                active=True,
                created_at=now,
                secret_rotated_at=now,
            )
            session.add(device)
            await session.flush()
            session.add(
                DeviceVehicleAssignment(
                    organization_id=organization_uuid,
                    device_id=device.id,
                    vehicle_id=vehicle_uuid,
                    effective_from=now,
                )
            )
            return str(device.id), auth_code


async def rotate_postgres_device_secret(
    session_factory: async_sessionmaker[AsyncSession],
    *,
    terminal_id: str,
    secret_protector: SecretProtector,
    auth_code: str,
    auth_pepper: bytes = b"",
) -> None:
    """Replace a device auth secret after a canary has validated the new code."""

    terminal_id = validate_terminal_id(terminal_id)
    auth_code = validate_auth_code(auth_code)
    now = datetime.now(timezone.utc)
    async with session_factory() as session:
        async with session.begin():
            device = await session.scalar(select(Device).where(Device.terminal_id == terminal_id))
            if device is None:
                raise ValueError("terminal ID is not provisioned")
            device.auth_secret_hash = hash_auth_code(auth_code, auth_pepper)
            device.auth_secret_ciphertext = secret_protector.encrypt(
                auth_code, associated_data=terminal_id.encode("ascii")
            )
            device.secret_rotated_at = now
