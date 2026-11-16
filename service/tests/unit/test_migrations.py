"""Alembic revisions build exactly the schema defined in db.py, upgrade a 1.0.0 database and run backwards."""

import sqlalchemy as sa
from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.runtime.migration import MigrationContext

from dataledger import db


def test_migrations_match_the_table_definitions():
    engine = db.make_engine("sqlite:///:memory:")
    assert db.migrate(engine) == "0002"
    with engine.connect() as conn:
        diff = compare_metadata(MigrationContext.configure(conn), db.metadata)
    engine.dispose()
    assert diff == [], f"add an Alembic revision for: {diff}"


def test_release_1_0_database_is_stamped_and_upgraded(tmp_path):
    engine = db.make_engine(f"sqlite:///{(tmp_path / 'legacy.db').as_posix()}")
    legacy = sa.MetaData()
    for table in db.metadata.sorted_tables:
        table.to_metadata(legacy).indexes.clear()
    legacy.create_all(engine)  # what 1.0.0 did on start
    with engine.begin() as conn:
        conn.execute(db.indexer_state.insert().values(key="cursor_block", value="42"))

    assert db.migrate(engine) == "0002"
    with engine.connect() as conn:
        assert conn.execute(sa.select(db.indexer_state.c.value)).scalar() == "42"
        assert {i["name"] for i in sa.inspect(conn).get_indexes("objects")} == {"ix_objects_dataset"}
    engine.dispose()


def test_downgrade_to_baseline_and_back(tmp_path):
    engine = db.make_engine(f"sqlite:///{(tmp_path / 'cycle.db').as_posix()}")
    db.migrate(engine)
    cfg = db.alembic_config(engine)
    with engine.begin() as conn:
        cfg.attributes["connection"] = conn
        command.downgrade(cfg, "0001")
        assert sa.inspect(conn).get_indexes("access_log") == []
    assert db.migrate(engine) == "0002"
    engine.dispose()
