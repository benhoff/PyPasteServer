from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import sessionmaker

from server_app.db import Base
from server_app.models import SyncDeviceCursor, SyncEvent, SyncUserState, User, utc_now
from server_app.sync_protocol import PushMessage, SyncProtocolError
from server_app.sync_service import SyncLimits, SyncStore


@pytest.fixture
def store_context(tmp_path):
    engine = create_engine(
        f"sqlite:///{tmp_path / 'sync-store.db'}",
        connect_args={"check_same_thread": False, "timeout": 30},
    )
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    with factory() as session:
        user = User(
            username="alice",
            email="alice@example.test",
            hashed_password="unused",
            email_authenticated=True,
        )
        session.add(user)
        session.flush()
        user_id = user.id
        session.add(SyncUserState(user_id=user_id, next_server_sequence=1))
        session.add(
            SyncDeviceCursor(
                user_id=user_id,
                device_id="device-a",
                processed_server_sequence=0,
            )
        )
        session.commit()
    try:
        yield SyncStore(factory), factory, user_id
    finally:
        engine.dispose()


def _push(message_id: str | None = None, byte: int = 1) -> PushMessage:
    return PushMessage(
        message_id=message_id or str(uuid4()),
        algorithm="xchacha20-poly1305",
        nonce=bytes([byte % 256]) * 24,
        ciphertext=bytes([byte % 256]),
        tag=bytes([(byte + 1) % 256]) * 16,
    )


def test_concurrent_pushes_allocate_strict_per_user_sequences(store_context) -> None:
    store, factory, user_id = store_context
    pushes = [_push(byte=index) for index in range(1, 33)]

    def accept(push: PushMessage):
        return store.accept_event(
            user_id=user_id,
            device_id="device-a",
            push=push,
            limits=SyncLimits(),
        )

    with ThreadPoolExecutor(max_workers=8) as executor:
        accepted = list(executor.map(accept, pushes))

    assert sorted(item.event.server_sequence for item in accepted) == list(range(1, 33))
    assert all(not item.duplicate for item in accepted)

    with factory() as session:
        sequences = (
            session.execute(
                select(SyncEvent.server_sequence)
                .where(SyncEvent.user_id == user_id)
                .order_by(SyncEvent.server_sequence)
            )
            .scalars()
            .all()
        )
        assert sequences == list(range(1, 33))
        assert session.get(SyncUserState, user_id).next_server_sequence == 33


def test_concurrent_duplicate_retries_reuse_one_sequence(store_context) -> None:
    store, factory, user_id = store_context
    push = _push("550e8400-e29b-41d4-a716-446655440000")

    def accept(_: int):
        return store.accept_event(
            user_id=user_id,
            device_id="device-a",
            push=push,
            limits=SyncLimits(),
        )

    with ThreadPoolExecutor(max_workers=8) as executor:
        results = list(executor.map(accept, range(16)))

    assert {result.event.server_sequence for result in results} == {1}
    assert sum(not result.duplicate for result in results) == 1
    with factory() as session:
        assert session.scalar(select(func.count(SyncEvent.id))) == 1
        assert session.get(SyncUserState, user_id).next_server_sequence == 2


def test_quota_rejection_rolls_back_sequence_and_duplicates_still_ack(
    store_context,
) -> None:
    store, _, user_id = store_context
    first_push = _push(byte=1)
    first = store.accept_event(
        user_id=user_id,
        device_id="device-a",
        push=first_push,
        limits=SyncLimits(max_account_events=1),
    )
    duplicate = store.accept_event(
        user_id=user_id,
        device_id="device-a",
        push=first_push,
        limits=SyncLimits(max_account_events=1),
    )
    assert first.event.server_sequence == duplicate.event.server_sequence == 1
    assert duplicate.duplicate

    with pytest.raises(SyncProtocolError) as error:
        store.accept_event(
            user_id=user_id,
            device_id="device-a",
            push=_push(byte=2),
            limits=SyncLimits(max_account_events=1),
        )
    assert error.value.code == "quota_exceeded"

    second = store.accept_event(
        user_id=user_id,
        device_id="device-a",
        push=_push(byte=3),
        limits=SyncLimits(),
    )
    assert second.event.server_sequence == 2


def test_storage_quota_and_rate_limit_are_durable(store_context) -> None:
    store, factory, user_id = store_context
    first = store.accept_event(
        user_id=user_id,
        device_id="device-a",
        push=_push(byte=1),
        limits=SyncLimits(
            max_account_storage_bytes=41,
            rate_limit_events=1,
            rate_limit_window_seconds=60,
        ),
    )
    assert first.event.server_sequence == 1

    with pytest.raises(SyncProtocolError) as rate_error:
        store.accept_event(
            user_id=user_id,
            device_id="device-a",
            push=_push(byte=2),
            limits=SyncLimits(rate_limit_events=1, rate_limit_window_seconds=60),
        )
    assert rate_error.value.code == "rate_limited"
    assert rate_error.value.retryable

    with pytest.raises(SyncProtocolError) as storage_error:
        store.accept_event(
            user_id=user_id,
            device_id="device-a",
            push=_push(byte=3),
            limits=SyncLimits(max_account_storage_bytes=41),
        )
    assert storage_error.value.code == "quota_exceeded"

    # Both rejected allocations rolled back, and a newly-created store can
    # replay the committed row after a process restart.
    restarted = SyncStore(factory)
    second = restarted.accept_event(
        user_id=user_id,
        device_id="device-a",
        push=_push(byte=4),
        limits=SyncLimits(),
    )
    assert second.event.server_sequence == 2
    assert restarted.events_after(user_id, 0, through=2, limit=10)[0].message_id == (
        first.event.message_id
    )


def test_revoked_device_cannot_push_or_checkpoint(store_context) -> None:
    store, factory, user_id = store_context
    with factory() as session:
        cursor = session.get(SyncDeviceCursor, (user_id, "device-a"))
        cursor.revoked_at = utc_now()
        session.commit()

    with pytest.raises(SyncProtocolError) as push_error:
        store.accept_event(
            user_id=user_id,
            device_id="device-a",
            push=_push(),
            limits=SyncLimits(),
        )
    assert push_error.value.code == "permission_denied"

    with pytest.raises(SyncProtocolError) as checkpoint_error:
        store.checkpoint(user_id, "device-a", 0)
    assert checkpoint_error.value.code == "permission_denied"


def test_checkpoint_is_monotonic_and_scoped_to_user(store_context) -> None:
    store, factory, user_id = store_context
    for index in range(1, 6):
        store.accept_event(
            user_id=user_id,
            device_id="device-a",
            push=_push(byte=index),
            limits=SyncLimits(),
        )

    with ThreadPoolExecutor(max_workers=5) as executor:
        stored = list(
            executor.map(
                lambda sequence: store.checkpoint(user_id, "device-a", sequence),
                [5, 1, 4, 2, 3],
            )
        )
    assert max(stored) == 5
    with factory() as session:
        cursor = session.get(SyncDeviceCursor, (user_id, "device-a"))
        assert cursor.processed_server_sequence == 5

    with pytest.raises(SyncProtocolError, match="latest"):
        store.checkpoint(user_id, "device-a", 6)


def test_replay_and_sequences_are_isolated_per_user(store_context) -> None:
    store, factory, user_id = store_context
    with factory() as session:
        other = User(
            username="bob",
            email="bob@example.test",
            hashed_password="unused",
            email_authenticated=True,
        )
        session.add(other)
        session.flush()
        other_id = other.id
        session.add(SyncUserState(user_id=other_id, next_server_sequence=1))
        session.add(
            SyncDeviceCursor(
                user_id=other_id,
                device_id="device-b",
                processed_server_sequence=0,
            )
        )
        session.commit()

    alice = store.accept_event(
        user_id=user_id,
        device_id="device-a",
        push=_push(byte=1),
        limits=SyncLimits(),
    )
    bob = store.accept_event(
        user_id=other_id,
        device_id="device-b",
        push=_push(byte=2),
        limits=SyncLimits(),
    )
    assert alice.event.server_sequence == bob.event.server_sequence == 1
    assert [
        event.message_id
        for event in store.events_after(user_id, 0, through=1, limit=10)
    ] == [alice.event.message_id]
    assert [
        event.message_id
        for event in store.events_after(other_id, 0, through=1, limit=10)
    ] == [bob.event.message_id]
