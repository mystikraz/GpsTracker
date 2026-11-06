"""Database engine construction kept separate from service entrypoints."""

from __future__ import annotations

from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine


def async_database_url(database_url: str) -> str:
    if not database_url.startswith(("postgresql://", "postgres://")):
        return database_url
    parsed = urlsplit(database_url)
    query = parse_qsl(parsed.query, keep_blank_values=True)
    normalized_query: list[tuple[str, str]] = []
    for key, value in query:
        # asyncpg does not expose libpq's channel_binding keyword. Neon still
        # uses TLS through sslmode=require, which is converted below.
        if key == "channel_binding":
            continue
        normalized_query.append(("ssl" if key == "sslmode" else key, value))
    return urlunsplit(
        (
            "postgresql+asyncpg",
            parsed.netloc,
            parsed.path,
            urlencode(normalized_query),
            parsed.fragment,
        )
    )


def create_engine_and_session_factory(
    database_url: str,
) -> tuple[AsyncEngine, async_sessionmaker[AsyncSession]]:
    # Neon pooled endpoints use PgBouncer transaction pooling. The application
    # pool remains deliberately small because each service has its own pool.
    # Disabling SQLAlchemy's prepared-statement cache avoids coupling a client
    # connection to a particular backend connection through the pooler.
    is_neon_pooler = "-pooler." in database_url
    engine = create_async_engine(
        async_database_url(database_url),
        pool_pre_ping=True,
        pool_size=5,
        max_overflow=5,
        connect_args={"prepared_statement_cache_size": 0} if is_neon_pooler else {},
    )
    return engine, async_sessionmaker(engine, expire_on_commit=False)
