"""Environment-backed service configuration."""

from __future__ import annotations

import base64
import os
from dataclasses import dataclass

from dotenv import load_dotenv


def _secret_bytes(name: str, *, required: bool = True) -> bytes:
    value = os.environ.get(name)
    if not value:
        if required:
            raise RuntimeError(f"{name} must be set")
        return b""
    try:
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except ValueError as error:
        raise RuntimeError(f"{name} must be URL-safe base64") from error


@dataclass(frozen=True, slots=True)
class Settings:
    database_url: str
    tracker_host: str = "0.0.0.0"
    tracker_port: int = 8881
    frame_max_bytes: int = 4096
    frame_buffer_max_bytes: int = 8192
    idle_timeout_seconds: int = 180
    max_connections: int = 256
    max_connections_per_ip: int = 8
    auth_attempts_per_minute: int = 20
    authenticated_connection_idle_seconds: float = 60.0
    position_min_interval_seconds: float = 0.0
    device_secret_key: bytes = b""
    device_auth_pepper: bytes = b""

    @classmethod
    def from_env(cls, database_env: str = "DATABASE_URL") -> "Settings":
        # Explicit process environment values win; .env is a local-development
        # convenience and is not used to override values injected by Compose.
        load_dotenv()
        database_url = os.environ.get(database_env) or os.environ.get("DATABASE_URL")
        if not database_url:
            raise RuntimeError(f"{database_env} must be set")
        return cls(
            database_url=database_url,
            tracker_host=os.environ.get("TRACKER_HOST", "0.0.0.0"),
            tracker_port=int(os.environ.get("TRACKER_PORT", "8881")),
            frame_max_bytes=int(os.environ.get("FRAME_MAX_BYTES", "4096")),
            frame_buffer_max_bytes=int(os.environ.get("FRAME_BUFFER_MAX_BYTES", "8192")),
            idle_timeout_seconds=int(os.environ.get("IDLE_TIMEOUT_SECONDS", "180")),
            max_connections=int(os.environ.get("MAX_CONNECTIONS", "256")),
            max_connections_per_ip=int(os.environ.get("MAX_CONNECTIONS_PER_IP", "8")),
            auth_attempts_per_minute=int(os.environ.get("AUTH_ATTEMPTS_PER_MINUTE", "20")),
            authenticated_connection_idle_seconds=float(
                os.environ.get("AUTHENTICATED_CONNECTION_IDLE_SECONDS", "60")
            ),
            position_min_interval_seconds=float(os.environ.get("POSITION_MIN_INTERVAL_SECONDS", "0")),
            device_secret_key=_secret_bytes("DEVICE_SECRET_KEY_B64"),
            device_auth_pepper=_secret_bytes("DEVICE_AUTH_PEPPER_B64"),
        )
