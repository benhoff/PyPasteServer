"""Remove the retired single-value clipboard tables.

Revision ID: 0003_remove_legacy_clipboard
Revises: 0002_sync_v1
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0003_remove_legacy_clipboard"
down_revision = "0002_sync_v1"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.drop_table("clipboard_metadata")
    op.drop_table("clipboards")


def downgrade() -> None:
    op.create_table(
        "clipboards",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("ciphertext", sa.Text(), nullable=False),
        sa.Column("nonce", sa.String(length=255), nullable=False),
        sa.Column("tag", sa.String(length=255), nullable=False),
        sa.Column("owner_id", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(["owner_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("owner_id"),
    )
    op.create_index("ix_clipboards_id", "clipboards", ["id"], unique=False)
    op.create_table(
        "clipboard_metadata",
        sa.Column("clipboard_id", sa.Integer(), nullable=False),
        sa.Column("ts_ns", sa.BigInteger(), nullable=True),
        sa.Column("uid", sa.Integer(), nullable=True),
        sa.Column("pid", sa.Integer(), nullable=True),
        sa.Column("comm", sa.String(length=255), nullable=True),
        sa.ForeignKeyConstraint(["clipboard_id"], ["clipboards.id"]),
        sa.PrimaryKeyConstraint("clipboard_id"),
    )
