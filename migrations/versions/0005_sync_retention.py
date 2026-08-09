"""Track the earliest retained sync sequence for lossy replay.

Revision ID: 0005_sync_retention
Revises: 0004_device_pairing
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0005_sync_retention"
down_revision = "0004_device_pairing"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("sync_user_state") as batch_op:
        batch_op.add_column(
            sa.Column(
                "earliest_retained_sequence",
                sa.BigInteger(),
                nullable=False,
                server_default="1",
            )
        )

    # Existing version-1 logs are contiguous. Preserve their actual replay
    # floor, or the allocator's next sequence when the account has no events.
    connection = op.get_bind()
    connection.execute(
        sa.text(
            "UPDATE sync_user_state "
            "SET earliest_retained_sequence = COALESCE("
            "  (SELECT MIN(sync_events.server_sequence) "
            "   FROM sync_events "
            "   WHERE sync_events.user_id = sync_user_state.user_id), "
            "  next_server_sequence"
            ")"
        )
    )

    with op.batch_alter_table("sync_user_state") as batch_op:
        batch_op.create_check_constraint(
            "ck_sync_user_state_retained_positive",
            "earliest_retained_sequence >= 1",
        )
        batch_op.create_check_constraint(
            "ck_sync_user_state_retained_before_next",
            "earliest_retained_sequence <= next_server_sequence",
        )


def downgrade() -> None:
    with op.batch_alter_table("sync_user_state") as batch_op:
        batch_op.drop_constraint(
            "ck_sync_user_state_retained_before_next", type_="check"
        )
        batch_op.drop_constraint("ck_sync_user_state_retained_positive", type_="check")
        batch_op.drop_column("earliest_retained_sequence")
