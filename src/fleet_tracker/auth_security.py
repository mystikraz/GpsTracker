"""Phase B password, session, CSRF, throttling, and token primitives."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import os
import secrets
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Iterable
from uuid import UUID

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from sqlalchemy import delete, select, text, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from .db.models import AuditEvent, PasswordToken, Session, User


MIN_PASSWORD_LENGTH = 12
DEFAULT_IDLE_SECONDS = 30 * 60
DEFAULT_ABSOLUTE_SECONDS = 12 * 60 * 60
OWNER_ADMIN_IDLE_SECONDS = 15 * 60
OWNER_ADMIN_ABSOLUTE_SECONDS = 8 * 60 * 60
DEFAULT_REAUTH_SECONDS = 10 * 60
LOCKOUT_SECONDS = 15 * 60
MAX_FAILED_LOGINS = 8


class AuthenticationError(Exception):
    """Safe, generic authentication failure."""


class PasswordPolicyError(ValueError):
    pass


def _load_breached_passwords(path: str | None = None) -> frozenset[str]:
    candidates = [Path(path)] if path else [Path("config/common-passwords.txt")]
    found: set[str] = set()
    for candidate in candidates:
        if candidate.is_file():
            found.update(line.strip().casefold() for line in candidate.read_text(encoding="utf-8").splitlines() if line.strip())
    found.update({"password", "password123", "password123456", "123456789012", "qwertyuiop", "letmein12345"})
    return frozenset(found)


class PasswordService:
    """Argon2id with bounded CPU concurrency; never logs password material."""

    def __init__(self, *, breached_password_file: str | None = None, max_concurrency: int = 2) -> None:
        if max_concurrency < 1:
            raise ValueError("max_concurrency must be positive")
        self.hasher = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=1)
        self._semaphore = asyncio.Semaphore(max_concurrency)
        self.breached = _load_breached_passwords(breached_password_file)

    def validate(self, password: str) -> None:
        if len(password) < MIN_PASSWORD_LENGTH:
            raise PasswordPolicyError("password does not meet policy")
        if password.casefold() in self.breached:
            raise PasswordPolicyError("password does not meet policy")

    async def hash(self, password: str) -> str:
        self.validate(password)
        async with self._semaphore:
            return await asyncio.to_thread(self.hasher.hash, password)

    async def verify(self, encoded: str, password: str) -> bool:
        async with self._semaphore:
            try:
                return await asyncio.to_thread(self.hasher.verify, encoded, password)
            except (VerifyMismatchError, VerificationError, InvalidHashError):
                return False


def random_token() -> str:
    return secrets.token_urlsafe(32)


def token_hash(token: str) -> bytes:
    return hashlib.sha256(token.encode("ascii")).digest()


def constant_time_equal(left: bytes, right: bytes) -> bool:
    return hmac.compare_digest(left, right)


@dataclass(frozen=True, slots=True)
class SessionTicket:
    raw_id: str
    csrf_token: str
    session_id: UUID
    user_id: UUID


def _now() -> datetime:
    return datetime.now(UTC)


class ProcessRateLimiter:
    """Single-instance limiter; deployment must remain one API process."""

    def __init__(self, *, per_ip: int = 20, per_account: int = 10, window_seconds: int = 60) -> None:
        self.per_ip = per_ip
        self.per_account = per_account
        self.window_seconds = window_seconds
        self._events: dict[str, deque[float]] = defaultdict(deque)

    def allow(self, *, ip: str, account: str) -> bool:
        now = time.monotonic()
        allowed = True
        for key, limit in ((f"ip:{ip}", self.per_ip), (f"account:{account.casefold()}", self.per_account)):
            events = self._events[key]
            while events and now - events[0] >= self.window_seconds:
                events.popleft()
            if len(events) >= limit:
                allowed = False
            else:
                events.append(now)
        return allowed


class LoginPreSessionStore:
    """Short-lived login CSRF token store; bounded to the single API process."""

    def __init__(self, ttl_seconds: int = 600) -> None:
        self.ttl_seconds = ttl_seconds
        self._tokens: dict[str, tuple[bytes, float]] = {}

    def issue(self) -> tuple[str, str]:
        session_id = secrets.token_urlsafe(24)
        token = secrets.token_urlsafe(32)
        self._tokens[session_id] = (token_hash(token), time.monotonic() + self.ttl_seconds)
        return session_id, token

    def consume(self, session_id: str, token: str) -> None:
        record = self._tokens.pop(session_id, None)
        if record is None or record[1] < time.monotonic() or not constant_time_equal(record[0], token_hash(token)):
            raise AuthenticationError("request rejected")


async def create_session(
    session: AsyncSession,
    *,
    user: User,
    ip_address: str | None,
    user_agent_redacted: str | None,
    idle_seconds: int = DEFAULT_IDLE_SECONDS,
    absolute_seconds: int = DEFAULT_ABSOLUTE_SECONDS,
) -> SessionTicket:
    now = _now()
    raw_id = secrets.token_urlsafe(32)
    csrf = secrets.token_urlsafe(32)
    record = Session(
        user_id=user.id,
        session_hash=token_hash(raw_id),
        csrf_token_hash=token_hash(csrf),
        created_at=now,
        last_seen_at=now,
        idle_expires_at=now + timedelta(seconds=idle_seconds),
        absolute_expires_at=now + timedelta(seconds=absolute_seconds),
        ip_address=ip_address,
        user_agent_redacted=user_agent_redacted,
    )
    await session.execute(text("SELECT set_config('app.user_id', :user_id, true)"), {"user_id": str(user.id)})
    session.add(record)
    await session.flush()
    return SessionTicket(raw_id, csrf, record.id, user.id)


async def require_session(
    session: AsyncSession, raw_id: str, *, now: datetime | None = None
) -> tuple[Session, User]:
    now = now or _now()
    await session.execute(text("SELECT set_config('app.session_id', :session_id, true)"), {"session_id": raw_id})
    record = await session.scalar(select(Session).where(Session.session_hash == token_hash(raw_id)))
    if record is None or record.revoked_at is not None or record.idle_expires_at <= now or record.absolute_expires_at <= now:
        raise AuthenticationError("authentication failed")
    user = await session.get(User, record.user_id)
    if user is None or user.status != "active":
        raise AuthenticationError("authentication failed")
    record.last_seen_at = now
    return record, user


def require_csrf(record: Session, supplied_token: str | None) -> None:
    if not supplied_token or not constant_time_equal(record.csrf_token_hash, token_hash(supplied_token)):
        raise AuthenticationError("request rejected")


def has_recent_reauthentication(record: Session, *, window_seconds: int = DEFAULT_REAUTH_SECONDS) -> bool:
    return record.last_reauthenticated_at is not None and record.last_reauthenticated_at >= _now() - timedelta(seconds=window_seconds)


async def revoke_session(session: AsyncSession, record: Session, reason: str) -> None:
    record.revoked_at = _now()
    record.revoke_reason = reason


async def revoke_all_sessions(session: AsyncSession, user_id: UUID, reason: str) -> None:
    await session.execute(
        update(Session).where(Session.user_id == user_id, Session.revoked_at.is_(None)).values(
            revoked_at=_now(), revoke_reason=reason
        )
    )


async def rotate_session(
    session: AsyncSession, record: Session, user: User, *, reason: str
) -> SessionTicket:
    await revoke_session(session, record, reason)
    return await create_session(session, user=user, ip_address=record.ip_address, user_agent_redacted=record.user_agent_redacted)


async def write_audit(
    session: AsyncSession,
    *,
    action: str,
    result: str,
    request_id: str,
    actor_user_id: UUID | None = None,
    organization_id: UUID | None = None,
    target_type: str = "account",
    target_id: str | None = None,
    ip_address: str | None = None,
    user_agent_redacted: str | None = None,
    metadata: dict[str, str | int | bool] | None = None,
) -> None:
    allowed = {"reason", "method", "role", "session_count", "channel"}
    safe_metadata = {key: value for key, value in (metadata or {}).items() if key in allowed}
    session.add(AuditEvent(
        occurred_at=_now(), actor_user_id=actor_user_id, organization_id=organization_id, action=action,
        target_type=target_type, target_id=target_id, result=result,
        ip_address=ip_address, user_agent_redacted=user_agent_redacted,
        request_id=request_id, metadata_json=safe_metadata,
    ))

