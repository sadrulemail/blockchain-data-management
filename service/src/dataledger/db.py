"""Read models built from chain events plus the service's own object and document tables.

Chain events are the source of truth; every table filled by the indexer can be dropped and rebuilt by
replaying logs from the deployment block. ``objects`` and ``documents`` are owned by the service.

The schema is versioned with Alembic (``dataledger/migrations``). Change a table here, then add a revision with
``uv run alembic -c src/dataledger/migrations/alembic.ini revision --autogenerate -m "..."``; a test fails when the
migrations and these definitions drift apart.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Any

from sqlalchemy import (
    BigInteger,
    Boolean,
    Column,
    Connection,
    Engine,
    Index,
    Integer,
    LargeBinary,
    MetaData,
    String,
    Table,
    Text,
    UniqueConstraint,
    create_engine,
    event,
    inspect,
    text,
)

if TYPE_CHECKING:
    from alembic.config import Config

metadata = MetaData()

HASH = String(66)
ADDRESS = String(42)

indexer_state = Table(
    "indexer_state",
    metadata,
    Column("key", String(64), primary_key=True),
    Column("value", String(255), nullable=False),
)

datasets = Table(
    "datasets",
    metadata,
    Column("dataset_id", Integer, primary_key=True, autoincrement=False),
    Column("name", String(64), nullable=False),
    Column("owner", ADDRESS, nullable=False),
    Column("pending_owner", ADDRESS),
    Column("classification", Integer, nullable=False),
    Column("schema_hash", HASH, nullable=False),
    Column("metadata_uri", Text, nullable=False),
    Column("archived", Boolean, nullable=False, default=False),
    Column("version_count", Integer, nullable=False, default=0),
    Column("access_count", Integer, nullable=False, default=0),
    Column("created_at", BigInteger, nullable=False),
    Column("created_block", BigInteger, nullable=False),
)

versions = Table(
    "versions",
    metadata,
    Column("dataset_id", Integer, primary_key=True),
    Column("version", Integer, primary_key=True),
    Column("merkle_root", HASH, nullable=False),
    Column("content_hash", HASH, nullable=False),
    Column("schema_hash", HASH),
    Column("record_count", BigInteger, nullable=False),
    Column("storage_uri", Text, nullable=False),
    Column("committer", ADDRESS, nullable=False),
    Column("status", Integer, nullable=False),
    Column("status_reason", Text),
    Column("committed_at", BigInteger, nullable=False),
    Column("block_number", BigInteger, nullable=False),
    Column("tx_hash", HASH, nullable=False),
)

lineage = Table(
    "lineage",
    metadata,
    Column("dataset_id", Integer, primary_key=True),
    Column("version", Integer, primary_key=True),
    Column("parent_dataset_id", Integer, primary_key=True),
    Column("parent_version", Integer, primary_key=True),
)

stewards = Table(
    "stewards",
    metadata,
    Column("dataset_id", Integer, primary_key=True),
    Column("account", ADDRESS, primary_key=True),
    Column("enabled", Boolean, nullable=False),
)

grants = Table(
    "grants",
    metadata,
    Column("dataset_id", Integer, primary_key=True),
    Column("grantee", ADDRESS, primary_key=True),
    Column("granted_by", ADDRESS, nullable=False),
    Column("purpose_hash", HASH, nullable=False),
    Column("purpose", Text),
    Column("granted_at", BigInteger, nullable=False),
    Column("expires_at", BigInteger, nullable=False),
    Column("revoked", Boolean, nullable=False, default=False),
)

access_requests = Table(
    "access_requests",
    metadata,
    Column("request_id", Integer, primary_key=True, autoincrement=False),
    Column("dataset_id", Integer, nullable=False),
    Column("requester", ADDRESS, nullable=False),
    Column("purpose", Text, nullable=False),
    Column("purpose_hash", HASH, nullable=False),
    Column("status", String(16), nullable=False),
    Column("requested_at", BigInteger, nullable=False),
    Column("decided_by", ADDRESS),
    Column("decided_at", BigInteger),
    Column("reason", Text),
)

attestations = Table(
    "attestations",
    metadata,
    Column("dataset_id", Integer, primary_key=True),
    Column("version", Integer, primary_key=True),
    Column("auditor", ADDRESS, primary_key=True),
    Column("score_bps", Integer, nullable=False),
    Column("passed", Boolean, nullable=False),
    Column("report_hash", HASH, nullable=False),
    Column("report_uri", Text, nullable=False),
    Column("attested_at", BigInteger, nullable=False),
    Column("tx_hash", HASH, nullable=False),
)

access_log = Table(
    "access_log",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("dataset_id", Integer, nullable=False),
    Column("version", Integer, nullable=False),
    Column("accessor", ADDRESS, nullable=False),
    Column("receipt_hash", HASH, nullable=False),
    Column("accessed_at", BigInteger, nullable=False),
    Column("block_number", BigInteger, nullable=False),
    Column("tx_hash", HASH, nullable=False),
)

audit_events = Table(
    "audit_events",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("source", String(16), nullable=False),  # chain | gateway
    Column("contract", String(32)),
    Column("event", String(48), nullable=False),
    Column("dataset_id", Integer),
    Column("version", Integer),
    Column("actor", ADDRESS),
    Column("summary", Text, nullable=False),
    Column("details", Text, nullable=False),
    Column("occurred_at", BigInteger, nullable=False),
    Column("block_number", BigInteger),
    Column("tx_hash", HASH),
    Column("log_index", Integer),
    UniqueConstraint("tx_hash", "log_index", name="uq_audit_log_position"),
)

objects = Table(
    "objects",
    metadata,
    Column("object_id", String(64), primary_key=True),
    Column("dataset_id", Integer, nullable=False),
    Column("content_hash", HASH, nullable=False),
    Column("merkle_root", HASH, nullable=False),
    Column("schema_hash", HASH, nullable=False),
    Column("schema_document", HASH, nullable=False),
    Column("record_count", BigInteger, nullable=False),
    Column("size_bytes", BigInteger, nullable=False),
    Column("file_name", String(255), nullable=False),
    Column("kek_id", String(32)),
    Column("wrapped_key", LargeBinary),
    Column("uploaded_by", ADDRESS, nullable=False),
    Column("uploaded_at", BigInteger, nullable=False),
    Column("anchored_version", Integer),
    Column("state", String(16), nullable=False),  # staged | anchored | mismatch | shredded
    Column("shredded_at", BigInteger),
)

documents = Table(
    "documents",
    metadata,
    Column("doc_hash", HASH, primary_key=True),
    Column("kind", String(32), nullable=False),
    Column("body", Text, nullable=False),
    Column("created_by", ADDRESS, nullable=False),
    Column("created_at", BigInteger, nullable=False),
)

# Secondary indexes for the console and API filters (revision 0002).
Index("ix_lineage_parent", lineage.c.parent_dataset_id, lineage.c.parent_version)
Index("ix_access_requests_dataset", access_requests.c.dataset_id)
Index("ix_access_requests_status", access_requests.c.status)
Index("ix_access_log_dataset", access_log.c.dataset_id)
Index("ix_audit_events_dataset", audit_events.c.dataset_id)
Index("ix_objects_dataset", objects.c.dataset_id)

INDEXED_TABLES = (
    datasets,
    versions,
    lineage,
    stewards,
    grants,
    access_requests,
    attestations,
    access_log,
)


def make_engine(url: str) -> Engine:
    if url.startswith("sqlite:///"):
        db_path = url.removeprefix("sqlite:///")
        if db_path and db_path != ":memory:":
            Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        engine = create_engine(url, connect_args={"check_same_thread": False, "timeout": 30})

        @event.listens_for(engine, "connect")
        def _sqlite_pragmas(dbapi_conn: Any, _record: Any) -> None:  # pragma: no cover - driver hook
            cur = dbapi_conn.cursor()
            cur.execute("PRAGMA journal_mode=WAL")
            cur.execute("PRAGMA synchronous=NORMAL")
            cur.close()

        return engine
    return create_engine(url, pool_pre_ping=True)


BASELINE_REVISION = "0001"
MIGRATION_LOCK_KEY = 0x646C_6D69  # "dlmi"


def alembic_config(engine: Engine | None = None) -> Config:
    from alembic.config import Config

    cfg = Config()
    cfg.set_main_option("script_location", "dataledger:migrations")
    if engine is not None:
        cfg.set_main_option("sqlalchemy.url", engine.url.render_as_string(hide_password=False).replace("%", "%%"))
    return cfg


def migrate(engine: Engine, revision: str = "head") -> str | None:
    """Upgrades the schema and returns the revision it ends on.

    A database created by 1.0.0 (tables, no ``alembic_version``) is stamped with the baseline first, because
    revision 0001 is exactly that schema.
    """
    from alembic import command
    from alembic.runtime.migration import MigrationContext

    cfg = alembic_config(engine)
    with engine.begin() as conn:
        if conn.dialect.name == "postgresql":
            # Several pods may start at once (init containers); the first migrates, the rest wait and find head.
            conn.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": MIGRATION_LOCK_KEY})
        cfg.attributes["connection"] = conn
        tables = set(inspect(conn).get_table_names())
        if "datasets" in tables and "alembic_version" not in tables:
            command.stamp(cfg, BASELINE_REVISION)
        command.upgrade(cfg, revision)
        return MigrationContext.configure(conn).get_current_revision()


def init_db(engine: Engine) -> None:
    migrate(engine)


def dialect_insert(conn: Connection, table: Table) -> Any:
    """INSERT that supports ON CONFLICT on both SQLite and PostgreSQL."""
    if conn.dialect.name == "postgresql":
        from sqlalchemy.dialects.postgresql import insert as pg_insert

        return pg_insert(table)
    from sqlalchemy.dialects.sqlite import insert as sqlite_insert

    return sqlite_insert(table)
