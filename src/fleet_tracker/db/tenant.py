"""Transaction-local organization context for pooled PostgreSQL connections."""

from __future__ import annotations

from contextlib import asynccontextmanager
from collections.abc import AsyncIterator
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession


TENANT_CONTEXT_SQL = text("SELECT set_config('app.organization_id', :organization_id, true)")
USER_CONTEXT_SQL = text("SELECT set_config('app.user_id', :user_id, true)")


@asynccontextmanager
async def organization_transaction(
    session: AsyncSession, organization_id: UUID
) -> AsyncIterator[AsyncSession]:
    """Begin a transaction and set a transaction-local tenant setting.

    The explicit guard prevents a caller from accidentally changing the tenant
    context in an already-active transaction.
    """

    try:
        validated_organization_id = UUID(str(organization_id))
    except (TypeError, ValueError) as error:
        raise ValueError("organization_id must be a valid UUID") from error
    if session.in_transaction():
        raise RuntimeError("organization_transaction requires an idle session")
    async with session.begin():
        await session.execute(
            TENANT_CONTEXT_SQL,
            {"organization_id": str(validated_organization_id)},
        )
        yield session


async def set_user_context(session: AsyncSession, user_id: UUID | str) -> None:
    """Set a validated transaction-local user context for membership lookup."""

    try:
        validated_user_id = UUID(str(user_id))
    except (TypeError, ValueError) as error:
        raise ValueError("user_id must be a valid UUID") from error
    if not session.in_transaction():
        raise RuntimeError("set_user_context requires an active transaction")
    await session.execute(USER_CONTEXT_SQL, {"user_id": str(validated_user_id)})
