"""Small operational CLI for P1 local setup and device provisioning."""

from __future__ import annotations

import argparse
import asyncio
import base64
import os
from datetime import datetime, timezone
from uuid import UUID

from sqlalchemy import select

from fleet_tracker.db.engine import create_engine_and_session_factory
from fleet_tracker.db.models import Organization, Vehicle
from fleet_tracker.db.provisioning import provision_postgres_device
from fleet_tracker.ingestion.auth import AesGcmSecretProtector


def _decode_secret(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _database_url(args: argparse.Namespace) -> str:
    return args.database_url or os.environ.get("DIRECT_DATABASE_URL") or os.environ.get("DATABASE_URL") or ""


def _protector(args: argparse.Namespace) -> AesGcmSecretProtector:
    value = args.secret_key_b64 or os.environ.get("DEVICE_SECRET_KEY_B64")
    if not value:
        raise SystemExit("DEVICE_SECRET_KEY_B64 or --secret-key-b64 is required")
    return AesGcmSecretProtector(_decode_secret(value))


async def _create_organization(args: argparse.Namespace) -> None:
    engine, sessions = create_engine_and_session_factory(_database_url(args))
    try:
        async with sessions() as session:
            async with session.begin():
                organization = Organization(
                    name=args.name,
                    timezone=args.timezone,
                    position_retention_months=12,
                    raw_retention_days=30,
                    created_at=datetime.now(timezone.utc),
                )
                session.add(organization)
                await session.flush()
                print(organization.id)
    finally:
        await engine.dispose()


async def _create_vehicle(args: argparse.Namespace) -> None:
    organization_id = UUID(args.org_id)
    engine, sessions = create_engine_and_session_factory(_database_url(args))
    try:
        async with sessions() as session:
            async with session.begin():
                organization = await session.scalar(select(Organization).where(Organization.id == organization_id))
                if organization is None:
                    raise SystemExit("organization not found")
                vehicle = Vehicle(
                    organization_id=organization_id,
                    name=args.name,
                    plate_number=args.plate,
                    created_at=datetime.now(timezone.utc),
                )
                session.add(vehicle)
                await session.flush()
                print(vehicle.id)
    finally:
        await engine.dispose()


async def _provision_device(args: argparse.Namespace) -> None:
    pepper_value = args.auth_pepper_b64 or os.environ.get("DEVICE_AUTH_PEPPER_B64", "")
    auth_pepper = _decode_secret(pepper_value) if pepper_value else b""
    engine, sessions = create_engine_and_session_factory(_database_url(args))
    try:
        device_id, auth_code = await provision_postgres_device(
            sessions,
            organization_id=args.org_id,
            vehicle_id=args.vehicle_id,
            terminal_id=args.terminal_id,
            secret_protector=_protector(args),
            auth_code=args.auth_code,
            auth_pepper=auth_pepper,
        )
        print(f"device_id={device_id}")
        if args.print_auth_code:
            print(f"auth_code={auth_code}")
    finally:
        await engine.dispose()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="fleet-tracker")
    parser.add_argument("--database-url", default=None)
    subparsers = parser.add_subparsers(dest="command", required=True)

    organization = subparsers.add_parser("create-organization")
    organization.add_argument("--name", required=True)
    organization.add_argument("--timezone", default="Asia/Kathmandu")

    vehicle = subparsers.add_parser("create-vehicle")
    vehicle.add_argument("--org-id", required=True)
    vehicle.add_argument("--name", required=True)
    vehicle.add_argument("--plate", default=None)

    device = subparsers.add_parser("provision-device")
    device.add_argument("--org-id", required=True)
    device.add_argument("--vehicle-id", required=True)
    device.add_argument("--terminal-id", required=True)
    device.add_argument("--auth-code", default=None, help="Only for controlled migration/hardware tests")
    device.add_argument("--secret-key-b64", default=None)
    device.add_argument("--auth-pepper-b64", default=None)
    device.add_argument("--print-auth-code", action="store_true")
    return parser


def main() -> None:
    args = build_parser().parse_args()
    if args.command == "create-organization":
        asyncio.run(_create_organization(args))
    elif args.command == "create-vehicle":
        asyncio.run(_create_vehicle(args))
    elif args.command == "provision-device":
        asyncio.run(_provision_device(args))


if __name__ == "__main__":
    main()
