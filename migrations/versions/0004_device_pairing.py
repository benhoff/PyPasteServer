"""Add per-device Noise PSK credentials.

Revision ID: 0004_device_pairing
Revises: 0003_remove_legacy_clipboard
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0004_device_pairing"
down_revision = "0003_remove_legacy_clipboard"
branch_labels = None
depends_on = None


def upgrade() -> None:
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
        sa.UniqueConstraint("pairing_id"),
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


def downgrade() -> None:
    op.drop_index("ix_paired_devices_user_id", table_name="paired_devices")
    op.drop_index("ix_paired_devices_pairing_id", table_name="paired_devices")
    op.drop_table("paired_devices")
