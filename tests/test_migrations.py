from __future__ import annotations

from alembic import command
from sqlalchemy import create_engine, inspect, select

from server_app.migrations import alembic_config
from server_app.models import Clipboard, ClipboardMetadata, SyncUserState, Token, User


def test_migrations_adopt_legacy_schema_and_seed_existing_users(tmp_path) -> None:
    engine = create_engine(f"sqlite:///{tmp_path / 'legacy.db'}")
    legacy_tables = [
        User.__table__,
        Clipboard.__table__,
        ClipboardMetadata.__table__,
        Token.__table__,
    ]
    User.metadata.create_all(engine, tables=legacy_tables)
    with engine.begin() as connection:
        connection.execute(
            User.__table__.insert(),
            {
                "id": 7,
                "username": "legacy",
                "email": "legacy@example.test",
                "hashed_password": "unused",
                "email_authenticated": True,
            },
        )

    config = alembic_config()
    with engine.begin() as connection:
        config.attributes["connection"] = connection
        command.upgrade(config, "head")

    assert {
        "alembic_version",
        "users",
        "clipboards",
        "clipboard_metadata",
        "tokens",
        "sync_user_state",
        "sync_events",
        "sync_device_cursors",
    }.issubset(inspect(engine).get_table_names())
    with engine.connect() as connection:
        state = connection.execute(
            select(SyncUserState).where(SyncUserState.user_id == 7)
        ).one()
        assert state.next_server_sequence == 1
    engine.dispose()
