"""SQLAlchemy models for the clipboard and durable sync services."""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    LargeBinary,
    String,
    UniqueConstraint,
)
from sqlalchemy.orm import relationship

from .db import Base


def utc_now() -> datetime:
    return datetime.now(UTC)


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(150), unique=True, index=True, nullable=False)

    sync_state = relationship(
        "SyncUserState",
        uselist=False,
        back_populates="user",
        cascade="all, delete-orphan",
    )
    sync_events = relationship(
        "SyncEvent", back_populates="user", cascade="all, delete-orphan"
    )
    paired_devices = relationship(
        "PairedDevice", back_populates="user", cascade="all, delete-orphan"
    )


class SyncUserState(Base):
    """The row locked while allocating a user's next durable sequence."""

    __tablename__ = "sync_user_state"

    user_id = Column(
        Integer, ForeignKey("users.id", ondelete="CASCADE"), primary_key=True
    )
    next_server_sequence = Column(BigInteger, nullable=False, default=1)
    # The first sequence that may still be replayed. When no events remain it
    # equals next_server_sequence, so an expired empty prefix stays durable.
    earliest_retained_sequence = Column(BigInteger, nullable=False, default=1)
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    updated_at = Column(
        DateTime(timezone=True), default=utc_now, onupdate=utc_now, nullable=False
    )

    user = relationship("User", back_populates="sync_state")

    __table_args__ = (
        CheckConstraint(
            "next_server_sequence >= 1", name="ck_sync_user_state_next_positive"
        ),
        CheckConstraint(
            "earliest_retained_sequence >= 1",
            name="ck_sync_user_state_retained_positive",
        ),
        CheckConstraint(
            "earliest_retained_sequence <= next_server_sequence",
            name="ck_sync_user_state_retained_before_next",
        ),
    )


class SyncEvent(Base):
    """An opaque encrypted kclip event retained for replay."""

    __tablename__ = "sync_events"

    # SQLite only auto-increments a column whose concrete type is INTEGER.
    id = Column(
        BigInteger().with_variant(Integer, "sqlite"),
        primary_key=True,
        autoincrement=True,
    )
    user_id = Column(
        Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    server_sequence = Column(BigInteger, nullable=False)
    message_id = Column(String(36), nullable=False)
    sender_device_id = Column(String(255), nullable=False)
    protocol_version = Column(Integer, nullable=False)
    algorithm = Column(String(64), nullable=False)
    nonce = Column(LargeBinary, nullable=False)
    ciphertext = Column(LargeBinary, nullable=False)
    tag = Column(LargeBinary, nullable=False)
    accepted_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)

    user = relationship("User", back_populates="sync_events")

    __table_args__ = (
        UniqueConstraint(
            "user_id", "server_sequence", name="uq_sync_events_user_sequence"
        ),
        UniqueConstraint("user_id", "message_id", name="uq_sync_events_user_message"),
        CheckConstraint(
            "server_sequence >= 1", name="ck_sync_events_sequence_positive"
        ),
        CheckConstraint("protocol_version = 1", name="ck_sync_events_protocol_v1"),
    )


class PairedDevice(Base):
    """A per-device Noise PSK provisioned through the local admin CLI."""

    __tablename__ = "paired_devices"

    id = Column(Integer, primary_key=True)
    pairing_id = Column(String(36), unique=True, nullable=False, index=True)
    user_id = Column(
        Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    device_name = Column(String(255), nullable=False)
    # A Noise PSK must be available to the responder. Protect the database as
    # credential material; this value is never returned after creation.
    psk = Column(LargeBinary(32), nullable=False)
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    last_used_at = Column(DateTime(timezone=True), nullable=True)
    revoked_at = Column(DateTime(timezone=True), nullable=True)

    user = relationship("User", back_populates="paired_devices")


__all__ = [
    "PairedDevice",
    "SyncEvent",
    "SyncUserState",
    "User",
    "utc_now",
]
