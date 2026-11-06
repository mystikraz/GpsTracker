"""Fail-closed target selection for Alembic migrations."""

from __future__ import annotations

from collections.abc import Mapping
from urllib.parse import urlsplit


def migration_database_url(environ: Mapping[str, str]) -> tuple[str, str]:
    """Return ``(url, mode)`` and refuse ambiguous or pooled migration targets."""

    test_url = environ.get("TEST_DATABASE_URL", "").strip()
    if test_url:
        url, mode = test_url, "test"
    else:
        if environ.get("MIGRATION_CONFIRM_PRODUCTION") != "1":
            raise RuntimeError(
                "refusing migration: set TEST_DATABASE_URL for a test target "
                "or run the migration wrapper with --confirm-production"
            )
        url, mode = environ.get("DIRECT_DATABASE_URL", "").strip(), "production"
        if not url:
            raise RuntimeError("refusing production migration: DIRECT_DATABASE_URL must be set")

    parsed = urlsplit(url)
    if not parsed.hostname:
        raise RuntimeError("refusing migration: database URL has no hostname")
    if "-pooler." in parsed.hostname or "pooler" in parsed.hostname:
        raise RuntimeError("refusing migration: use a direct, non-pooled database URL")
    return url, mode
