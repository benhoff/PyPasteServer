"""Transactional persistence operations for the sync-v1 event log."""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import case, delete, func, select, update
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
class RetentionPolicy:
    max_age_seconds: int = 0
    max_events: int = 0
    max_storage_bytes: int = 0

    @property
    def enabled(self) -> bool:
        return bool(self.max_age_seconds or self.max_events or self.max_storage_bytes)


@dataclass(frozen=True, slots=True)
class ReplayWindow:
    earliest_sequence: int
    latest_sequence: int


@dataclass(frozen=True, slots=True)
class PruneResult:
    deleted_events: int
    deleted_bytes: int
    earliest_sequence: int


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

    def replay_window(self, user_id: int) -> ReplayWindow:
        with self._session() as session:
            state = session.get(SyncUserState, user_id)
            if state is None:
                raise SyncProtocolError(
                    "server_unavailable",
                    "sync account state is unavailable",
                    retryable=True,
                )
            return ReplayWindow(
                earliest_sequence=int(state.earliest_retained_sequence),
                latest_sequence=int(state.next_server_sequence) - 1,
            )

    def latest_sequence(self, user_id: int) -> int:
        return self.replay_window(user_id).latest_sequence

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

            state = session.get(SyncUserState, user_id)
            if state is None:
                raise SyncProtocolError(
                    "server_unavailable",
                    "sync account state is unavailable",
                    retryable=True,
                )
            latest_sequence = int(state.next_server_sequence) - 1
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
        retention: RetentionPolicy | None = None,
    ) -> AcceptedEvent:
        for attempt in range(5):
            try:
                return self._accept_event_once(
                    user_id=user_id,
                    device_id=device_id,
                    push=push,
                    limits=limits,
                    retention=retention,
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
        retention: RetentionPolicy | None,
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

                session.flush()
                if retention is not None and retention.enabled:
                    self._prune_account_in_session(session, user_id, retention)

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

    def prune_account(self, user_id: int, policy: RetentionPolicy) -> PruneResult:
        if not policy.enabled:
            window = self.replay_window(user_id)
            return PruneResult(0, 0, window.earliest_sequence)
        for attempt in range(5):
            try:
                with self._session() as session:
                    result = self._prune_account_in_session(session, user_id, policy)
                    session.commit()
                    return result
            except OperationalError:
                if attempt == 4:
                    break
                time.sleep(0.01 * (attempt + 1))
        raise SyncProtocolError(
            "server_unavailable",
            "event retention is temporarily unavailable",
            retryable=True,
        )

    def prune_all(self, policy: RetentionPolicy) -> PruneResult:
        if not policy.enabled:
            return PruneResult(0, 0, 1)
        with self._session() as session:
            user_ids = list(session.scalars(select(SyncUserState.user_id)))

        deleted_events = 0
        deleted_bytes = 0
        earliest_sequence = 1
        for user_id in user_ids:
            result = self.prune_account(int(user_id), policy)
            deleted_events += result.deleted_events
            deleted_bytes += result.deleted_bytes
            earliest_sequence = result.earliest_sequence
        return PruneResult(deleted_events, deleted_bytes, earliest_sequence)

    @staticmethod
    def _prune_account_in_session(
        session: Session, user_id: int, policy: RetentionPolicy
    ) -> PruneResult:
        state = session.execute(
            select(SyncUserState)
            .where(SyncUserState.user_id == user_id)
            .with_for_update()
        ).scalar_one_or_none()
        if state is None:
            raise SyncProtocolError(
                "server_unavailable",
                "sync account state is unavailable",
                retryable=True,
            )

        rows = list(
            session.execute(
                select(
                    SyncEvent.server_sequence,
                    SyncEvent.accepted_at,
                    (
                        func.length(SyncEvent.nonce)
                        + func.length(SyncEvent.ciphertext)
                        + func.length(SyncEvent.tag)
                    ).label("stored_bytes"),
                )
                .where(SyncEvent.user_id == user_id)
                .order_by(SyncEvent.server_sequence.asc())
            )
        )
        if not rows:
            state.earliest_retained_sequence = int(state.next_server_sequence)
            return PruneResult(0, 0, int(state.earliest_retained_sequence))

        keep_from = 0
        if policy.max_age_seconds:
            cutoff = utc_now() - timedelta(seconds=policy.max_age_seconds)
            while keep_from < len(rows):
                accepted_at = rows[keep_from].accepted_at
                if accepted_at.tzinfo is None:
                    accepted_at = accepted_at.replace(tzinfo=UTC)
                if accepted_at >= cutoff:
                    break
                keep_from += 1

        if policy.max_events and len(rows) - keep_from > policy.max_events:
            keep_from = len(rows) - policy.max_events

        if policy.max_storage_bytes and keep_from < len(rows):
            retained_bytes = sum(int(row.stored_bytes or 0) for row in rows[keep_from:])
            # Keep at least the newest event even when an administrator sets a
            # byte limit below the maximum accepted event size.
            while (
                retained_bytes > policy.max_storage_bytes and len(rows) - keep_from > 1
            ):
                retained_bytes -= int(rows[keep_from].stored_bytes or 0)
                keep_from += 1

        if keep_from == 0:
            earliest = int(rows[0].server_sequence)
            state.earliest_retained_sequence = earliest
            return PruneResult(0, 0, earliest)

        removed = rows[:keep_from]
        cutoff_sequence = int(removed[-1].server_sequence)
        deleted_events = session.execute(
            delete(SyncEvent).where(
                SyncEvent.user_id == user_id,
                SyncEvent.server_sequence <= cutoff_sequence,
            )
        ).rowcount
        deleted_bytes = sum(int(row.stored_bytes or 0) for row in removed)
        earliest = (
            int(rows[keep_from].server_sequence)
            if keep_from < len(rows)
            else int(state.next_server_sequence)
        )
        state.earliest_retained_sequence = earliest
        return PruneResult(int(deleted_events or 0), deleted_bytes, earliest)


sync_store = SyncStore()

__all__ = [
    "AcceptedEvent",
    "PruneResult",
    "ReplayWindow",
    "RetentionPolicy",
    "StoredEvent",
    "SyncLimits",
    "SyncStore",
    "sync_store",
]
