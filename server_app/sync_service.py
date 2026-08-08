"""Transactional persistence operations for the sync-v1 event log."""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta

from sqlalchemy import case, func, select, update
from sqlalchemy.exc import IntegrityError, OperationalError
from sqlalchemy.orm import Session

from . import db as database
from .models import SyncDeviceCursor, SyncEvent, SyncUserState, utc_now
from .sync_protocol import PushMessage, SyncProtocolError


@dataclass(frozen=True, slots=True)
class SyncLimits:
    max_account_events: int = 0
    max_account_storage_bytes: int = 0
    rate_limit_events: int = 0
    rate_limit_window_seconds: int = 60


@dataclass(frozen=True, slots=True)
class StoredEvent:
    id: int
    user_id: int
    server_sequence: int
    message_id: str
    sender_device_id: str
    protocol_version: int
    algorithm: str
    nonce: bytes
    ciphertext: bytes
    tag: bytes
    accepted_at: datetime


@dataclass(frozen=True, slots=True)
class AcceptedEvent:
    event: StoredEvent
    duplicate: bool


def _stored_event(event: SyncEvent) -> StoredEvent:
    return StoredEvent(
        id=event.id,
        user_id=event.user_id,
        server_sequence=event.server_sequence,
        message_id=event.message_id,
        sender_device_id=event.sender_device_id,
        protocol_version=event.protocol_version,
        algorithm=event.algorithm,
        nonce=bytes(event.nonce),
        ciphertext=bytes(event.ciphertext),
        tag=bytes(event.tag),
        accepted_at=event.accepted_at,
    )


class SyncStore:
    """Synchronous SQL store used from worker threads by async endpoints."""

    def __init__(self, session_factory: Callable[[], Session] | None = None) -> None:
        self._session_factory = session_factory

    def _session(self) -> Session:
        factory = self._session_factory or database.SessionLocal
        return factory()

    def latest_sequence(self, user_id: int) -> int:
        with self._session() as session:
            latest = session.execute(
                select(func.max(SyncEvent.server_sequence)).where(
                    SyncEvent.user_id == user_id
                )
            ).scalar_one()
            return int(latest or 0)

    def events_after(
        self, user_id: int, after: int, *, through: int, limit: int
    ) -> list[StoredEvent]:
        if limit < 1:
            raise ValueError("replay batch size must be positive")
        with self._session() as session:
            events = session.execute(
                select(SyncEvent)
                .where(
                    SyncEvent.user_id == user_id,
                    SyncEvent.server_sequence > after,
                    SyncEvent.server_sequence <= through,
                )
                .order_by(SyncEvent.server_sequence.asc())
                .limit(limit)
            ).scalars()
            return [_stored_event(event) for event in events]

    def register_device(self, user_id: int, device_id: str) -> None:
        for attempt in range(3):
            with self._session() as session:
                try:
                    now = utc_now()
                    cursor = session.get(SyncDeviceCursor, (user_id, device_id))
                    if cursor is None:
                        cursor = SyncDeviceCursor(
                            user_id=user_id,
                            device_id=device_id,
                            processed_server_sequence=0,
                            first_seen_at=now,
                            last_seen_at=now,
                        )
                        session.add(cursor)
                    elif cursor.revoked_at is not None:
                        raise SyncProtocolError(
                            "permission_denied",
                            "device has been revoked",
                            close_code=1008,
                        )
                    else:
                        cursor.last_seen_at = now
                    session.commit()
                    return
                except SyncProtocolError:
                    session.rollback()
                    raise
                except (IntegrityError, OperationalError):
                    session.rollback()
            time.sleep(0.01 * (attempt + 1))
        raise SyncProtocolError(
            "server_unavailable", "could not register sync device", retryable=True
        )

    def checkpoint(self, user_id: int, device_id: str, server_sequence: int) -> int:
        with self._session() as session:
            cursor = session.get(SyncDeviceCursor, (user_id, device_id))
            if cursor is None:
                raise SyncProtocolError("permission_denied", "device is not registered")
            if cursor.revoked_at is not None:
                raise SyncProtocolError(
                    "permission_denied", "device has been revoked", close_code=1008
                )

            latest = session.execute(
                select(func.max(SyncEvent.server_sequence)).where(
                    SyncEvent.user_id == user_id
                )
            ).scalar_one()
            latest_sequence = int(latest or 0)
            if server_sequence > latest_sequence:
                raise SyncProtocolError(
                    "invalid_message", "checkpoint exceeds the latest server sequence"
                )

            stored = session.execute(
                update(SyncDeviceCursor)
                .where(
                    SyncDeviceCursor.user_id == user_id,
                    SyncDeviceCursor.device_id == device_id,
                    SyncDeviceCursor.revoked_at.is_(None),
                )
                .values(
                    processed_server_sequence=case(
                        (
                            SyncDeviceCursor.processed_server_sequence
                            < server_sequence,
                            server_sequence,
                        ),
                        else_=SyncDeviceCursor.processed_server_sequence,
                    ),
                    last_seen_at=utc_now(),
                )
                .returning(SyncDeviceCursor.processed_server_sequence)
            ).scalar_one_or_none()
            if stored is None:
                session.rollback()
                raise SyncProtocolError(
                    "permission_denied", "device is not permitted", close_code=1008
                )
            session.commit()
            return int(stored)

    def accept_event(
        self,
        *,
        user_id: int,
        device_id: str,
        push: PushMessage,
        limits: SyncLimits,
    ) -> AcceptedEvent:
        for attempt in range(5):
            try:
                return self._accept_event_once(
                    user_id=user_id,
                    device_id=device_id,
                    push=push,
                    limits=limits,
                )
            except OperationalError:
                if attempt == 4:
                    break
                time.sleep(0.01 * (attempt + 1))
        raise SyncProtocolError(
            "server_unavailable",
            "event store is temporarily unavailable",
            retryable=True,
        )

    def _accept_event_once(
        self,
        *,
        user_id: int,
        device_id: str,
        push: PushMessage,
        limits: SyncLimits,
    ) -> AcceptedEvent:
        with self._session() as session:
            self._require_device(session, user_id, device_id)
            existing = self._find_message(session, user_id, push.message_id)
            if existing is not None:
                return AcceptedEvent(_stored_event(existing), duplicate=True)

            try:
                sequence = self._allocate_sequence(session, user_id)

                # A competing retry may have committed while this transaction
                # waited for the per-user allocator row.
                existing = self._find_message(session, user_id, push.message_id)
                if existing is not None:
                    session.rollback()
                    return AcceptedEvent(_stored_event(existing), duplicate=True)

                self._enforce_limits(session, user_id, len(push.ciphertext), limits)

                event = SyncEvent(
                    user_id=user_id,
                    server_sequence=sequence,
                    message_id=push.message_id,
                    sender_device_id=device_id,
                    protocol_version=1,
                    algorithm=push.algorithm,
                    nonce=push.nonce,
                    ciphertext=push.ciphertext,
                    tag=push.tag,
                    accepted_at=utc_now(),
                )
                session.add(event)

                cursor = session.get(SyncDeviceCursor, (user_id, device_id))
                if cursor is None or cursor.revoked_at is not None:
                    raise SyncProtocolError(
                        "permission_denied", "device is not permitted", close_code=1008
                    )
                cursor.last_seen_at = utc_now()

                session.commit()
                return AcceptedEvent(_stored_event(event), duplicate=False)
            except SyncProtocolError:
                session.rollback()
                raise
            except IntegrityError as exc:
                session.rollback()
                existing = self._find_message(session, user_id, push.message_id)
                if existing is not None:
                    return AcceptedEvent(_stored_event(existing), duplicate=True)
                raise OperationalError(
                    "sync event transaction conflict", {}, exc
                ) from exc

    @staticmethod
    def _require_device(session: Session, user_id: int, device_id: str) -> None:
        cursor = session.get(SyncDeviceCursor, (user_id, device_id))
        if cursor is None or cursor.revoked_at is not None:
            raise SyncProtocolError(
                "permission_denied", "device is not permitted", close_code=1008
            )

    @staticmethod
    def _find_message(
        session: Session, user_id: int, message_id: str
    ) -> SyncEvent | None:
        return session.execute(
            select(SyncEvent).where(
                SyncEvent.user_id == user_id,
                SyncEvent.message_id == message_id,
            )
        ).scalar_one_or_none()

    @staticmethod
    def _allocate_sequence(session: Session, user_id: int) -> int:
        statement = (
            update(SyncUserState)
            .where(SyncUserState.user_id == user_id)
            .values(
                next_server_sequence=SyncUserState.next_server_sequence + 1,
                updated_at=utc_now(),
            )
            .returning(SyncUserState.next_server_sequence)
        )
        next_sequence = session.execute(statement).scalar_one_or_none()
        if next_sequence is None:
            session.add(
                SyncUserState(
                    user_id=user_id,
                    next_server_sequence=1,
                    created_at=utc_now(),
                    updated_at=utc_now(),
                )
            )
            session.flush()
            next_sequence = session.execute(statement).scalar_one()
        return int(next_sequence) - 1

    @staticmethod
    def _enforce_limits(
        session: Session,
        user_id: int,
        ciphertext_bytes: int,
        limits: SyncLimits,
    ) -> None:
        if limits.max_account_events:
            event_count = int(
                session.execute(
                    select(func.count(SyncEvent.id)).where(SyncEvent.user_id == user_id)
                ).scalar_one()
            )
            if event_count >= limits.max_account_events:
                raise SyncProtocolError(
                    "quota_exceeded", "account event quota exceeded"
                )

        if limits.max_account_storage_bytes:
            used = session.execute(
                select(
                    func.coalesce(
                        func.sum(
                            func.length(SyncEvent.nonce)
                            + func.length(SyncEvent.ciphertext)
                            + func.length(SyncEvent.tag)
                        ),
                        0,
                    )
                ).where(SyncEvent.user_id == user_id)
            ).scalar_one()
            incoming = ciphertext_bytes + 24 + 16
            if int(used or 0) + incoming > limits.max_account_storage_bytes:
                raise SyncProtocolError(
                    "quota_exceeded", "account storage quota exceeded"
                )

        if limits.rate_limit_events and limits.rate_limit_window_seconds:
            cutoff = utc_now() - timedelta(seconds=limits.rate_limit_window_seconds)
            recent = int(
                session.execute(
                    select(func.count(SyncEvent.id)).where(
                        SyncEvent.user_id == user_id,
                        SyncEvent.accepted_at >= cutoff,
                    )
                ).scalar_one()
            )
            if recent >= limits.rate_limit_events:
                raise SyncProtocolError(
                    "rate_limited", "account event rate limit exceeded", retryable=True
                )


sync_store = SyncStore()

__all__ = [
    "AcceptedEvent",
    "StoredEvent",
    "SyncLimits",
    "SyncStore",
    "sync_store",
]
