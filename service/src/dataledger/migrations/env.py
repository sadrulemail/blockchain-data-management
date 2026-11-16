"""Alembic environment. Runs against the connection handed over by ``dataledger.db.migrate`` or, from the Alembic
command line, against ``DATALEDGER_DATABASE_URL``."""

from __future__ import annotations

from alembic import context
from sqlalchemy import Connection, engine_from_config, pool

from dataledger.config import get_settings
from dataledger.db import metadata

config = context.config


def _run(connection: Connection) -> None:
    context.configure(
        connection=connection,
        target_metadata=metadata,
        render_as_batch=connection.dialect.name == "sqlite",  # SQLite alters tables by copying them
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_offline() -> None:
    context.configure(
        url=config.get_main_option("sqlalchemy.url") or get_settings().database_url,
        target_metadata=metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def run_online() -> None:
    connection = config.attributes.get("connection")
    if connection is not None:
        _run(connection)
        return
    section = config.get_section(config.config_ini_section, {})
    section.setdefault("sqlalchemy.url", get_settings().database_url)
    engine = engine_from_config(section, prefix="sqlalchemy.", poolclass=pool.NullPool)
    with engine.connect() as conn:
        _run(conn)
        conn.commit()


if context.is_offline_mode():
    run_offline()
else:
    run_online()
