"""Create or adopt the legacy clipboard schema.

Revision ID: 0001_legacy_baseline
Revises: None
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0001_legacy_baseline"
down_revision = None
branch_labels = None
depends_on = None


def _table_names() -> set[str]:
    return set(sa.inspect(op.get_bind()).get_table_names())


def _index_names(table_name: str) -> set[str]:
    return {
        index["name"] for index in sa.inspect(op.get_bind()).get_indexes(table_name)
    }


def upgrade() -> None:
    tables = _table_names()

    if "users" not in tables:
        op.create_table(
            "users",
            sa.Column("id", sa.Integer(), nullable=False),
            sa.Column("username", sa.String(length=150), nullable=False),
            sa.Column("email", sa.String(length=255), nullable=False),
            sa.Column("hashed_password", sa.String(length=255), nullable=False),
            sa.Column("email_authenticated", sa.Boolean(), nullable=False),
            sa.PrimaryKeyConstraint("id"),
            sa.UniqueConstraint("email"),
            sa.UniqueConstraint("username"),
        )
        op.create_index("ix_users_id", "users", ["id"], unique=False)
        op.create_index("ix_users_username", "users", ["username"], unique=True)
    else:
        indexes = _index_names("users")
        if "ix_users_id" not in indexes:
            op.create_index("ix_users_id", "users", ["id"], unique=False)
        if "ix_users_username" not in indexes:
            op.create_index("ix_users_username", "users", ["username"], unique=True)

    tables = _table_names()
    if "clipboards" not in tables:
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

    if "clipboard_metadata" not in tables:
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

    if "tokens" not in tables:
        op.create_table(
            "tokens",
            sa.Column("id", sa.Integer(), nullable=False),
            sa.Column("token", sa.String(length=512), nullable=False),
            sa.Column("jti", sa.String(length=36), nullable=False),
            sa.Column("created_at", sa.DateTime(), nullable=False),
            sa.Column("user_id", sa.Integer(), nullable=False),
            sa.ForeignKeyConstraint(["user_id"], ["users.id"]),
            sa.PrimaryKeyConstraint("id"),
            sa.UniqueConstraint("jti"),
            sa.UniqueConstraint("token"),
        )
        op.create_index("ix_tokens_id", "tokens", ["id"], unique=False)


def downgrade() -> None:
    # This revision may have adopted a pre-existing deployment.  Removing
    # legacy user data automatically would therefore be unsafe.
    pass
