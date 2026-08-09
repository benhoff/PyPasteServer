from __future__ import annotations

import pytest
from alembic import command
from alembic.script import ScriptDirectory
from alembic.util.exc import CommandError
from sqlalchemy import create_engine, inspect, text

from server_app.migrations import alembic_config


def test_fresh_database_uses_single_sync_baseline(tmp_path) -> None:
    engine = create_engine(f"sqlite:///{tmp_path / 'sync.db'}")
    config = alembic_config()

    revisions = list(ScriptDirectory.from_config(config).walk_revisions())
    assert [revision.revision for revision in revisions] == ["0001_sync_baseline"]

    with engine.begin() as connection:
        config.attributes["connection"] = connection
        command.upgrade(config, "head")

    assert set(inspect(engine).get_table_names()) == {
        "alembic_version",
        "users",
        "sync_user_state",
        "sync_events",
        "paired_devices",
    }
    with engine.connect() as connection:
        assert connection.scalar(text("SELECT version_num FROM alembic_version")) == (
            "0001_sync_baseline"
        )
    assert {column["name"] for column in inspect(engine).get_columns("users")} == {
        "id",
        "username",
    }
    engine.dispose()


def test_retired_migration_history_is_rejected(tmp_path) -> None:
    engine = create_engine(f"sqlite:///{tmp_path / 'retired.db'}")
    with engine.begin() as connection:
        connection.execute(
            text("CREATE TABLE alembic_version (version_num VARCHAR(32))")
        )
        connection.execute(
            text("INSERT INTO alembic_version VALUES ('0005_sync_retention')")
        )

    config = alembic_config()
    with engine.begin() as connection:
        config.attributes["connection"] = connection
        with pytest.raises(CommandError, match="0005_sync_retention"):
            command.upgrade(config, "head")
    engine.dispose()
