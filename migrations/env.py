from __future__ import annotations

import os

from alembic import context
from sqlalchemy import engine_from_config, pool

from fleet_tracker.db.models import Base


config = context.config
target_metadata = Base.metadata


def run_migrations_offline() -> None:
    database_url = os.environ.get(
        "DIRECT_DATABASE_URL",
        os.environ.get("DATABASE_URL", config.get_main_option("sqlalchemy.url")),
    )
    context.configure(url=database_url, target_metadata=target_metadata, literal_binds=True, dialect_opts={"paramstyle": "named"})
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    database_url = os.environ.get("DIRECT_DATABASE_URL") or os.environ.get("DATABASE_URL")
    configuration = config.get_section(config.config_ini_section) or {}
    if database_url:
        if database_url.startswith("postgresql://"):
            database_url = "postgresql+psycopg://" + database_url.removeprefix("postgresql://")
        elif database_url.startswith("postgres://"):
            database_url = "postgresql+psycopg://" + database_url.removeprefix("postgres://")
        configuration["sqlalchemy.url"] = database_url.replace("%", "%%")
    connectable = engine_from_config(configuration, prefix="sqlalchemy.", poolclass=pool.NullPool)
    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
