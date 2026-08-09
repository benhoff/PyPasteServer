"""Create the clean-break Noise sync schema.

Revision ID: 0001_sync_baseline
Revises: None
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0001_sync_baseline"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("username", sa.String(length=150), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_users_id", "users", ["id"], unique=False)
    op.create_index("ix_users_username", "users", ["username"], unique=True)

    op.create_table(
        "sync_user_state",
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("next_server_sequence", sa.BigInteger(), nullable=False),
        sa.Column("earliest_retained_sequence", sa.BigInteger(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "next_server_sequence >= 1", name="ck_sync_user_state_next_positive"
        ),
        sa.CheckConstraint(
            "earliest_retained_sequence >= 1",
            name="ck_sync_user_state_retained_positive",
        ),
        sa.CheckConstraint(
            "earliest_retained_sequence <= next_server_sequence",
            name="ck_sync_user_state_retained_before_next",
        ),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("user_id"),
    )

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
        sa.CheckConstraint("protocol_version = 1", name="ck_sync_events_protocol_v1"),
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
    op.create_index("ix_sync_events_user_id", "sync_events", ["user_id"], unique=False)

    op.create_table(
        "paired_devices",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("pairing_id", sa.String(length=36), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("device_name", sa.String(length=255), nullable=False),
        sa.Column("psk", sa.LargeBinary(length=32), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_paired_devices_pairing_id",
        "paired_devices",
        ["pairing_id"],
        unique=True,
    )
    op.create_index(
        "ix_paired_devices_user_id", "paired_devices", ["user_id"], unique=False
    )
