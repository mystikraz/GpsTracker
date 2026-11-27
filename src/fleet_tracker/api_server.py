"""Production HTTP API entrypoint for the same-origin web application."""

from __future__ import annotations

import base64
import os

from dotenv import load_dotenv
import uvicorn

from .auth_service import AuthService
from .auth_security import PasswordService
from .config import Settings
from .db.engine import create_engine_and_session_factory
from .email_provider import ResendProvider
from .http_api import create_app
from .ingestion.auth import AesGcmSecretProtector


def _decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def build_app():
    load_dotenv()
    database_url = os.environ.get("FLEET_API_DATABASE_URL") or os.environ.get("DATABASE_URL")
    if not database_url:
        raise RuntimeError("FLEET_API_DATABASE_URL must be set")
    # Settings is shared with the TCP/worker entrypoints and historically
    # reads DATABASE_URL. Populate it internally from the API-specific value;
    # callers do not need to expose a generic DATABASE_URL in .env.
    os.environ.setdefault("DATABASE_URL", database_url)
    settings = Settings.from_env()
    # Device authentication hashes must use the same pepper as the TCP
    # ingestion service.  Keep this explicitly device-scoped so UI
    # provisioning and tracker authentication cannot drift apart.
    auth_pepper_value = os.environ.get("DEVICE_AUTH_PEPPER_B64")
    if not auth_pepper_value:
        raise RuntimeError("DEVICE_AUTH_PEPPER_B64 must be set")
    engine, sessions = create_engine_and_session_factory(database_url)
    passwords = PasswordService(
        breached_password_file=os.environ.get("PASSWORD_BREACHED_LIST_PATH"),
        max_concurrency=int(os.environ.get("PASSWORD_HASH_MAX_CONCURRENCY", "2")),
    )
    email_provider = None
    email_mode = os.environ.get("EMAIL_PROVIDER", "manual-link").strip().lower()
    if email_mode == "resend":
        resend_key = os.environ.get("RESEND_API_KEY", "").strip()
        email_from = os.environ.get("EMAIL_FROM", "").strip()
        public_base_url = os.environ.get("PUBLIC_BASE_URL", "").strip().rstrip("/")
        if not resend_key or not email_from or not public_base_url:
            raise RuntimeError("RESEND_API_KEY, EMAIL_FROM, and PUBLIC_BASE_URL must be set when EMAIL_PROVIDER=resend")
        email_provider = ResendProvider(api_key=resend_key, sender=email_from)
    elif email_mode != "manual-link":
        raise RuntimeError("EMAIL_PROVIDER must be manual-link or resend")
    app = create_app(
        sessions,
        AuthService(sessions, passwords=passwords),
        manual_links=email_mode == "manual-link",
        email_provider=email_provider,
        public_base_url=os.environ.get("PUBLIC_BASE_URL", "").strip().rstrip("/"),
        secret_protector=AesGcmSecretProtector(settings.device_secret_key),
        auth_pepper=_decode(auth_pepper_value),
        offline_after_seconds=int(os.environ.get("VEHICLE_OFFLINE_AFTER_SECONDS", "300")),
        moving_speed_kmh=float(os.environ.get("VEHICLE_MOVING_SPEED_KMH", "1")),
        sse_max_streams=int(os.environ.get("SSE_MAX_STREAMS", "16")),
    )

    @app.on_event("shutdown")
    async def dispose_engine() -> None:
        await engine.dispose()

    return app


app = build_app()


def main() -> None:
    uvicorn.run(app, host=os.environ.get("API_HOST", "0.0.0.0"), port=int(os.environ.get("API_PORT", "8000")), log_level="info")


if __name__ == "__main__":
    main()
