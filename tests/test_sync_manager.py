from __future__ import annotations

import asyncio
from datetime import UTC, datetime

import pytest

from server_app.sync_manager import SlowConsumerError, SyncConnection
from server_app.sync_service import ReplayWindow, StoredEvent


class BlockingWebSocket:
    def __init__(self) -> None:
        self.release = asyncio.Event()
        self.close_code: int | None = None

    async def send_text(self, value: str) -> None:
        await self.release.wait()

    async def close(self, code: int = 1000, reason: str = "") -> None:
        self.close_code = code


def test_outbound_queue_disconnects_slow_consumers() -> None:
    async def scenario() -> None:
        websocket = BlockingWebSocket()
        connection = SyncConnection(
            websocket=websocket,
            user_id=1,
            device_id="slow-device",
            resume_after=0,
            max_queue_bytes=90,
        )
        await connection.start()
        await connection.enqueue({"data": "x" * 40})
        await asyncio.sleep(0)

        with pytest.raises(SlowConsumerError):
            await connection.enqueue({"data": "y" * 40})
        assert connection.closed
        assert websocket.close_code == 1013

    asyncio.run(scenario())


class CollectingWebSocket:
    def __init__(self) -> None:
        self.messages: list[dict] = []

    async def send_text(self, value: str) -> None:
        import json

        self.messages.append(json.loads(value))

    async def close(self, code: int = 1000, reason: str = "") -> None:
        pass


class InMemoryStore:
    def __init__(self) -> None:
        now = datetime.now(UTC)
        self.events = [
            StoredEvent(
                id=sequence,
                user_id=1,
                server_sequence=sequence,
                message_id=f"00000000-0000-0000-0000-{sequence:012d}",
                sender_device_id="device-a",
                protocol_version=1,
                algorithm="xchacha20-poly1305",
                nonce=bytes(24),
                ciphertext=bytes([sequence]),
                tag=bytes(16),
                accepted_at=now,
            )
            for sequence in range(1, 4)
        ]

    def events_after(self, user_id: int, after: int, *, through: int, limit: int):
        return [
            event for event in self.events if after < event.server_sequence <= through
        ][:limit]

    def replay_window(self, user_id: int) -> ReplayWindow:
        return ReplayWindow(
            earliest_sequence=self.events[0].server_sequence,
            latest_sequence=self.events[-1].server_sequence,
        )


def test_live_notification_waits_behind_replay_and_deduplicates() -> None:
    async def scenario() -> None:
        websocket = CollectingWebSocket()
        connection = SyncConnection(
            websocket=websocket,
            user_id=1,
            device_id="device-a",
            resume_after=0,
            store=InMemoryStore(),
            replay_batch_size=1,
        )
        await connection.start()
        async with connection.delivery_lock:
            live_delivery = asyncio.create_task(connection.deliver_through(3))
            await connection.deliver_through_locked(2)
        await live_delivery
        await connection.deliver_through(3)  # duplicate Redis notification
        await connection.enqueue({"type": "barrier"}, wait=True)

        assert [
            message["server_sequence"]
            for message in websocket.messages
            if message["type"] == "event"
        ] == [1, 2, 3]
        await connection.close()

    asyncio.run(scenario())


def test_active_connection_skips_an_expired_prefix() -> None:
    async def scenario() -> None:
        websocket = CollectingWebSocket()
        store = InMemoryStore()
        store.events = store.events[2:]
        connection = SyncConnection(
            websocket=websocket,
            user_id=1,
            device_id="device-a",
            resume_after=0,
            store=store,
        )
        await connection.start()
        await connection.deliver_through(3)
        await connection.enqueue({"type": "barrier"}, wait=True)
        assert [message["type"] for message in websocket.messages] == [
            "history_truncated",
            "event",
            "barrier",
        ]
        assert websocket.messages[0]["earliest_sequence"] == 3
        assert websocket.messages[1]["server_sequence"] == 3
        await connection.close()

    asyncio.run(scenario())
