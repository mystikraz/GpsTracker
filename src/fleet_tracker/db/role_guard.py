"""Fail-closed checks for the API database role."""

from __future__ import annotations

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession


API_ROLE_CHECK_SQL = text(
    """
    SELECT r.rolname, r.rolsuper, r.rolcreaterole, r.rolbypassrls,
           EXISTS (
               SELECT 1 FROM pg_database AS d
               WHERE d.datname = current_database() AND d.datdba = r.oid
           ) AS database_owner,
           EXISTS (
               SELECT 1 FROM pg_class AS c
               JOIN pg_namespace AS n ON n.oid = c.relnamespace
               WHERE c.relowner = r.oid AND n.nspname = 'public'
                 AND c.relname IN ('organizations', 'vehicles', 'positions')
           ) AS tenant_table_owner
    FROM pg_roles AS r
    WHERE r.rolname = current_user
    """
)


async def assert_safe_api_role(session: AsyncSession) -> None:
    """Reject API startup under owner, superuser, CREATEROLE, or BYPASSRLS."""

    row = (await session.execute(API_ROLE_CHECK_SQL)).mappings().one()
    if (
        row["rolsuper"]
        or row["rolcreaterole"]
        or row["rolbypassrls"]
        or row["database_owner"]
        or row["tenant_table_owner"]
    ):
        raise RuntimeError("API database role must not be owner, superuser, CREATEROLE, or BYPASSRLS")
