"""Cookie-session CSRF and origin checks."""

from __future__ import annotations

from urllib.parse import urlparse


class CsrfError(ValueError):
    pass


COOKIE_NAME = "__Host-fleet_session"


def validate_origin(*, origin: str | None, host: str, expected_scheme: str = "https") -> None:
    if not origin:
        raise CsrfError("origin required")
    parsed = urlparse(origin)
    if parsed.scheme != expected_scheme or parsed.netloc != host:
        raise CsrfError("origin rejected")


def cookie_header(raw_id: str, *, max_age: int) -> str:
    return f"{COOKIE_NAME}={raw_id}; Max-Age={max_age}; Path=/; HttpOnly; Secure; SameSite=Lax"


def clear_cookie_header() -> str:
    return f"{COOKIE_NAME}=; Max-Age=0; Path=/; HttpOnly; Secure; SameSite=Lax"

