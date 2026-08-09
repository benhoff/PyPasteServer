from __future__ import annotations

from alembic import command
from sqlalchemy import create_engine, inspect, select, text

from server_app.migrations import alembic_config
from server_app.models import SyncUserState


def test_migrations_remove_legacy_clipboard_and_seed_existing_users(tmp_path) -> None:
    engine = create_engine(f"sqlite:///{tmp_path / 'legacy.db'}")

    config = alembic_config()
    with engine.begin() as connection:
        config.attributes["connection"] = connection
        command.upgrade(config, "0001_legacy_baseline")
        connection.execute(
            text(
                "INSERT INTO users "
                "(id, username, email, hashed_password, email_authenticated) "
                "VALUES (7, 'legacy', 'legacy@example.test', 'unused', 1)"
            )
        )
        connection.execute(
            text(
                "INSERT INTO clipboards "
                "(id, ciphertext, nonce, tag, owner_id) "
                "VALUES (1, 'retired', 'nonce', 'tag', 7)"
            )
        )

    with engine.begin() as connection:
        config.attributes["connection"] = connection
        command.upgrade(config, "head")

    table_names = set(inspect(engine).get_table_names())
    assert {
        "alembic_version",
        "users",
        "tokens",
        "sync_user_state",
        "sync_events",
        "sync_device_cursors",
        "paired_devices",
    }.issubset(table_names)
    assert "clipboards" not in table_names
    assert "clipboard_metadata" not in table_names
    with engine.connect() as connection:
        state = connection.execute(
            select(SyncUserState).where(SyncUserState.user_id == 7)
        ).one()
        assert state.next_server_sequence == 1
        assert state.earliest_retained_sequence == 1
    engine.dispose()
