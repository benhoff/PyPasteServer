"""Add the durable sync-v1 event log and device cursors.

Revision ID: 0002_sync_v1
Revises: 0001_legacy_baseline
"""

from __future__ import annotations

from datetime import UTC, datetime

import sqlalchemy as sa
from alembic import op

revision = "0002_sync_v1"
down_revision = "0001_legacy_baseline"
branch_labels = None
depends_on = None


def _table_names() -> set[str]:
    return set(sa.inspect(op.get_bind()).get_table_names())


def upgrade() -> None:
    tables = _table_names()
    if "sync_user_state" not in tables:
        op.create_table(
            "sync_user_state",
            sa.Column("user_id", sa.Integer(), nullable=False),
            sa.Column("next_server_sequence", sa.BigInteger(), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
            sa.CheckConstraint(
                "next_server_sequence >= 1", name="ck_sync_user_state_next_positive"
            ),
            sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
            sa.PrimaryKeyConstraint("user_id"),
        )

    if "sync_events" not in tables:
        op.create_table(
            "sync_events",
            sa.Column(
                "id",
                sa.BigInteger().with_variant(sa.Integer(), "sqlite"),
                nullable=False,
            ),
            sa.Column("user_id", sa.Integer(), nullable=False),
            sa.Column("server_sequence", sa.BigInteger(), nullable=False),
            sa.Column("message_id", sa.String(length=36), nullable=False),
            sa.Column("sender_device_id", sa.String(length=255), nullable=False),
            sa.Column("protocol_version", sa.Integer(), nullable=False),
            sa.Column("algorithm", sa.String(length=64), nullable=False),
            sa.Column("nonce", sa.LargeBinary(), nullable=False),
            sa.Column("ciphertext", sa.LargeBinary(), nullable=False),
            sa.Column("tag", sa.LargeBinary(), nullable=False),
            sa.Column("accepted_at", sa.DateTime(timezone=True), nullable=False),
            sa.CheckConstraint(
                "protocol_version = 1", name="ck_sync_events_protocol_v1"
            ),
            sa.CheckConstraint(
                "server_sequence >= 1", name="ck_sync_events_sequence_positive"
            ),
            sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
            sa.PrimaryKeyConstraint("id"),
            sa.UniqueConstraint(
                "user_id", "message_id", name="uq_sync_events_user_message"
            ),
            sa.UniqueConstraint(
                "user_id", "server_sequence", name="uq_sync_events_user_sequence"
            ),
        )
        op.create_index(
            "ix_sync_events_user_id", "sync_events", ["user_id"], unique=False
        )

    if "sync_device_cursors" not in tables:
        op.create_table(
            "sync_device_cursors",
            sa.Column("user_id", sa.Integer(), nullable=False),
            sa.Column("device_id", sa.String(length=255), nullable=False),
            sa.Column("processed_server_sequence", sa.BigInteger(), nullable=False),
            sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
            sa.CheckConstraint(
                "processed_server_sequence >= 0",
                name="ck_sync_device_cursor_nonnegative",
            ),
            sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
            sa.PrimaryKeyConstraint("user_id", "device_id"),
        )

    # Existing accounts receive an allocator row without changing any legacy
    # clipboard data.  This is also safe when adopting a manually-created sync
    # table during a staged rollout.
    connection = op.get_bind()
    user_ids = set(connection.execute(sa.text("SELECT id FROM users")).scalars())
    state_ids = set(
        connection.execute(sa.text("SELECT user_id FROM sync_user_state")).scalars()
    )
    now = datetime.now(UTC)
    missing_states = [
        {
            "user_id": user_id,
            "next_server_sequence": 1,
            "created_at": now,
            "updated_at": now,
        }
        for user_id in user_ids - state_ids
    ]
    if missing_states:
        state_table = sa.table(
            "sync_user_state",
            sa.column("user_id", sa.Integer()),
            sa.column("next_server_sequence", sa.BigInteger()),
            sa.column("created_at", sa.DateTime(timezone=True)),
            sa.column("updated_at", sa.DateTime(timezone=True)),
        )
        connection.execute(sa.insert(state_table), missing_states)


def downgrade() -> None:
    op.drop_table("sync_device_cursors")
    op.drop_index("ix_sync_events_user_id", table_name="sync_events")
    op.drop_table("sync_events")
    op.drop_table("sync_user_state")
