"""Small operational CLI for P1 local setup and device provisioning."""

from __future__ import annotations

import argparse
import asyncio
import base64
import os
import getpass
import re
import sys
import subprocess
from datetime import datetime, timezone
from uuid import UUID

from sqlalchemy import select, text

from fleet_tracker.db.engine import create_engine_and_session_factory
from fleet_tracker.db.models import Organization, Vehicle
from fleet_tracker.db.provisioning import provision_postgres_device, rotate_postgres_device_secret
from fleet_tracker.ingestion.auth import AesGcmSecretProtector


class SecretSafeArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        safe_message = re.sub(r"\b\d{11}\b", "<redacted>", message)
        super().error(safe_message)


def _decode_secret(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _database_url(args: argparse.Namespace) -> str:
    return args.database_url or os.environ.get("DIRECT_DATABASE_URL") or os.environ.get("DATABASE_URL") or ""


def _protector(args: argparse.Namespace) -> AesGcmSecretProtector:
    value = args.secret_key_b64 or os.environ.get("DEVICE_SECRET_KEY_B64")
    if not value:
        raise SystemExit("DEVICE_SECRET_KEY_B64 or --secret-key-b64 is required")
    return AesGcmSecretProtector(_decode_secret(value))


def _read_secret(env_name: str, prompt: str) -> str:
    value = os.environ.get(env_name)
    if value:
        return value
    if sys.stdin.isatty():
        return getpass.getpass(prompt)
    return sys.stdin.readline().strip()


def _run_migrations(confirm_production: bool, revision: str) -> None:
    if confirm_production:
        os.environ["MIGRATION_CONFIRM_PRODUCTION"] = "1"
    subprocess.run(["alembic", "upgrade", revision], check=True)


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
    initial_auth_code = _read_secret("INITIAL_AUTH_CODE", "Initial device auth code: ") if args.initial_auth_code else None
    engine, sessions = create_engine_and_session_factory(_database_url(args))
    try:
        device_id, auth_code = await provision_postgres_device(
            sessions,
            organization_id=args.org_id,
            vehicle_id=args.vehicle_id,
            terminal_id=args.terminal_id,
            secret_protector=_protector(args),
            auth_code=initial_auth_code,
            auth_pepper=auth_pepper,
        )
        print(f"device_id={device_id}")
        del auth_code
    finally:
        await engine.dispose()


async def _healthcheck(args: argparse.Namespace) -> None:
    engine, sessions = create_engine_and_session_factory(_database_url(args))
    try:
        async with sessions() as session:
            await session.execute(select(Organization).limit(1))
            version = await session.scalar(text("SELECT version_num FROM alembic_version"))
            if not version:
                raise SystemExit("database migrations are not applied")
    finally:
        await engine.dispose()


async def _rotate_device(args: argparse.Namespace) -> None:
    pepper_value = args.auth_pepper_b64 or os.environ.get("DEVICE_AUTH_PEPPER_B64", "")
    auth_pepper = _decode_secret(pepper_value) if pepper_value else b""
    engine, sessions = create_engine_and_session_factory(_database_url(args))
    auth_code = _read_secret("DEVICE_AUTH_CODE", "New device auth code: ")
    try:
        await rotate_postgres_device_secret(
            sessions,
            terminal_id=args.terminal_id,
            secret_protector=_protector(args),
            auth_code=auth_code,
            auth_pepper=auth_pepper,
        )
        print(f"rotated_terminal_id={args.terminal_id}")
    finally:
        await engine.dispose()


def build_parser() -> argparse.ArgumentParser:
    parser = SecretSafeArgumentParser(prog="fleet-tracker")
    parser.add_argument("--database-url", default=None)
    subparsers = parser.add_subparsers(dest="command", required=True, parser_class=SecretSafeArgumentParser)

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
    device.add_argument(
        "--initial-auth-code",
        action="store_true",
        help="read the explicit initial code from INITIAL_AUTH_CODE or stdin",
    )
    device.add_argument("--secret-key-b64", default=None)
    device.add_argument("--auth-pepper-b64", default=None)
    subparsers.add_parser("healthcheck", help="verify database connectivity and migration state")
    rotate = subparsers.add_parser("rotate-device-secret", help="rotate an already-provisioned device code")
    rotate.add_argument("--terminal-id", required=True)
    rotate.add_argument("--auth-code", action="store_true", required=True, help="read the new code from DEVICE_AUTH_CODE or stdin")
    rotate.add_argument("--secret-key-b64", default=None)
    rotate.add_argument("--auth-pepper-b64", default=None)
    migrate = subparsers.add_parser("migrate", help="apply migrations with a fail-closed target")
    migrate.add_argument("--confirm-production", action="store_true")
    migrate.add_argument("--revision", default="head")
    return parser


def main() -> None:
    args = build_parser().parse_args()
    if args.command == "create-organization":
        asyncio.run(_create_organization(args))
    elif args.command == "create-vehicle":
        asyncio.run(_create_vehicle(args))
    elif args.command == "provision-device":
        asyncio.run(_provision_device(args))
    elif args.command == "healthcheck":
        asyncio.run(_healthcheck(args))
    elif args.command == "rotate-device-secret":
        asyncio.run(_rotate_device(args))
    elif args.command == "migrate":
        _run_migrations(args.confirm_production, args.revision)


if __name__ == "__main__":
    main()
