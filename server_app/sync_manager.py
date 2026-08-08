"""Ordered, bounded WebSocket fanout for durable sync-v1 events."""

from __future__ import annotations

import asyncio
import json
import logging
from collections import Counter
from typing import Any
from uuid import uuid4

from fastapi import WebSocket

from .async_utils import run_sync
from .config import (
    SYNC_MAX_QUEUE_BYTES,
    SYNC_REDIS_PUBLISH_TIMEOUT_SECONDS,
    SYNC_REPLAY_BATCH_SIZE,
)
from .redis_client import redis_client
from .sync_protocol import SyncProtocolError, event_message
from .sync_service import StoredEvent, SyncStore, sync_store

logger = logging.getLogger(__name__)
SYNC_REDIS_CHANNEL = "sync_events_v1"


class SlowConsumerError(RuntimeError):
    pass


class SyncMetrics:
    """Dependency-free process-local counters for logs/metrics adapters."""

    def __init__(self) -> None:
        self.counters: Counter[str] = Counter()
        self.active_connections = 0

    def increment(self, name: str, amount: int = 1) -> None:
        self.counters[name] += amount

    def snapshot(self) -> dict[str, int]:
        return {"active_connections": self.active_connections, **self.counters}


sync_metrics = SyncMetrics()


class SyncConnection:
    """One connection's serializer, backpressure budget, and replay cursor."""

    def __init__(
        self,
        *,
        websocket: WebSocket,
        user_id: int,
        device_id: str,
        resume_after: int,
        store: SyncStore | None = None,
        replay_batch_size: int = SYNC_REPLAY_BATCH_SIZE,
        max_queue_bytes: int = SYNC_MAX_QUEUE_BYTES,
    ) -> None:
        self.websocket = websocket
        self.user_id = user_id
        self.device_id = device_id
        self.connection_id = uuid4().hex
        self.last_delivered_sequence = resume_after
        self.store = store or sync_store
        self.replay_batch_size = replay_batch_size
        self.max_queue_bytes = max_queue_bytes

        self.delivery_lock = asyncio.Lock()
        self._queue: asyncio.Queue[tuple[str, int, asyncio.Future[None] | None] | None]
        self._queue = asyncio.Queue()
        self._queue_lock = asyncio.Lock()
        self._queued_bytes = 0
        self._sender_task: asyncio.Task[None] | None = None
        self._closed = False

    @property
    def closed(self) -> bool:
        return self._closed

    async def start(self) -> None:
        if self._sender_task is None:
            self._sender_task = asyncio.create_task(
                self._send_loop(), name=f"sync-send-{self.connection_id}"
            )

    async def enqueue(self, message: dict[str, Any], *, wait: bool = False) -> None:
        serialized = json.dumps(message, separators=(",", ":"), ensure_ascii=False)
        size = len(serialized.encode("utf-8"))
        waiter: asyncio.Future[None] | None = None
        if wait:
            waiter = asyncio.get_running_loop().create_future()

        overflow = False
        async with self._queue_lock:
            if self._closed:
                raise ConnectionError("sync connection is closed")
            if (
                size > self.max_queue_bytes
                or self._queued_bytes + size > self.max_queue_bytes
            ):
                overflow = True
            else:
                self._queued_bytes += size
                self._queue.put_nowait((serialized, size, waiter))

        if overflow:
            sync_metrics.increment("slow_consumer_disconnects")
            await self.close(code=1013, reason="outbound queue limit exceeded")
            raise SlowConsumerError("outbound queue limit exceeded")
        if waiter is not None:
            await waiter

    async def _send_loop(self) -> None:
        try:
            while True:
                item = await self._queue.get()
                if item is None:
                    self._queue.task_done()
                    return
                serialized, size, waiter = item
                try:
                    await self.websocket.send_text(serialized)
                except asyncio.CancelledError:
                    if waiter is not None and not waiter.done():
                        waiter.set_exception(ConnectionError("sync connection closed"))
                    raise
                except Exception as exc:
                    if waiter is not None and not waiter.done():
                        waiter.set_exception(exc)
                    raise
                else:
                    if waiter is not None and not waiter.done():
                        waiter.set_result(None)
                finally:
                    async with self._queue_lock:
                        self._queued_bytes = max(0, self._queued_bytes - size)
                    self._queue.task_done()
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.info(
                "sync connection send failed",
                extra={"user_id": self.user_id, "connection_id": self.connection_id},
            )
            await self.close(code=1011, reason="send failed", cancel_sender=False)

    async def deliver_through(self, target_sequence: int) -> None:
        async with self.delivery_lock:
            await self.deliver_through_locked(target_sequence)

    async def deliver_through_locked(self, target_sequence: int) -> None:
        """Replay through a target while the caller holds ``delivery_lock``."""

        if target_sequence <= self.last_delivered_sequence or self._closed:
            return
        if self.replay_batch_size < 1:
            raise SyncProtocolError(
                "internal_error", "invalid replay batch configuration", retryable=True
            )

        while self.last_delivered_sequence < target_sequence:
            batch = await run_sync(
                self.store.events_after,
                self.user_id,
                self.last_delivered_sequence,
                through=target_sequence,
                limit=self.replay_batch_size,
            )
            if not batch:
                raise SyncProtocolError(
                    "replay_unavailable",
                    "the requested event prefix is unavailable",
                    close_code=1011,
                )

            for event in batch:
                expected = self.last_delivered_sequence + 1
                if event.server_sequence != expected:
                    raise SyncProtocolError(
                        "replay_unavailable",
                        "the durable event log contains a sequence gap",
                        close_code=1011,
                    )
                await self.enqueue(_wire_event(event))
                self.last_delivered_sequence = event.server_sequence
                sync_metrics.increment("replay_bytes", _event_size(event))

    async def close(
        self,
        *,
        code: int = 1000,
        reason: str = "",
        cancel_sender: bool = True,
    ) -> None:
        async with self._queue_lock:
            if self._closed:
                return
            self._closed = True

        sender = self._sender_task
        if (
            cancel_sender
            and sender is not None
            and sender is not asyncio.current_task()
        ):
            sender.cancel()
            await asyncio.gather(sender, return_exceptions=True)

        async with self._queue_lock:
            while True:
                try:
                    item = self._queue.get_nowait()
                except asyncio.QueueEmpty:
                    break
                if item is not None:
                    _, _, waiter = item
                    if waiter is not None and not waiter.done():
                        waiter.set_exception(ConnectionError("sync connection closed"))
                self._queue.task_done()
            self._queued_bytes = 0

        try:
            await asyncio.wait_for(
                self.websocket.close(code=code, reason=reason[:123]), timeout=2
            )
        except Exception:
            pass


def _wire_event(event: StoredEvent) -> dict[str, Any]:
    return event_message(
        server_sequence=event.server_sequence,
        message_id=event.message_id,
        sender_device_id=event.sender_device_id,
        algorithm=event.algorithm,
        nonce=event.nonce,
        ciphertext=event.ciphertext,
        tag=event.tag,
        accepted_at=event.accepted_at,
    )


def _event_size(event: StoredEvent) -> int:
    return len(event.nonce) + len(event.ciphertext) + len(event.tag)


class SyncConnectionManager:
    def __init__(self) -> None:
        self._connections: dict[int, dict[str, SyncConnection]] = {}
        self._lock = asyncio.Lock()
        self._listener_task: asyncio.Task[None] | None = None
        self._pubsub = None

    async def add(self, connection: SyncConnection) -> None:
        async with self._lock:
            self._connections.setdefault(connection.user_id, {})[
                connection.connection_id
            ] = connection
            sync_metrics.active_connections += 1

    async def remove(self, connection: SyncConnection) -> None:
        removed = False
        async with self._lock:
            account_connections = self._connections.get(connection.user_id)
            if account_connections is not None:
                removed = (
                    account_connections.pop(connection.connection_id, None) is not None
                )
                if not account_connections:
                    self._connections.pop(connection.user_id, None)
            if removed:
                sync_metrics.active_connections = max(
                    0, sync_metrics.active_connections - 1
                )
        await connection.close()

    async def notify(self, user_id: int, server_sequence: int) -> None:
        async with self._lock:
            connections = list(self._connections.get(user_id, {}).values())
        if not connections:
            return

        results = await asyncio.gather(
            *(
                connection.deliver_through(server_sequence)
                for connection in connections
            ),
            return_exceptions=True,
        )
        for connection, result in zip(connections, results):
            if isinstance(result, Exception):
                error = (
                    result
                    if isinstance(result, SyncProtocolError)
                    else SyncProtocolError(
                        "server_unavailable",
                        "live event delivery is temporarily unavailable",
                        retryable=True,
                        close_code=1011,
                    )
                )
                if not connection.closed:
                    try:
                        await connection.enqueue(error.as_message(), wait=True)
                    except Exception:
                        pass
                    await connection.close(code=error.close_code or 1011)
                await self.remove(connection)

    async def publish(self, user_id: int, server_sequence: int) -> bool:
        notification = json.dumps(
            {"user_id": user_id, "server_sequence": server_sequence},
            separators=(",", ":"),
        )
        try:
            publish = redis_client.publish(SYNC_REDIS_CHANNEL, notification)
            await asyncio.wait_for(
                publish, timeout=max(1, SYNC_REDIS_PUBLISH_TIMEOUT_SECONDS)
            )
            return True
        except Exception:
            sync_metrics.increment("redis_notification_failures")
            logger.warning(
                "could not publish sync event notification",
                extra={"user_id": user_id, "server_sequence": server_sequence},
            )
            return False

    async def start_listening(self) -> None:
        if self._listener_task is None or self._listener_task.done():
            self._listener_task = asyncio.create_task(
                self._listen_loop(), name="sync-redis-listener"
            )

    async def _listen_loop(self) -> None:
        delay = 0.25
        while True:
            try:
                self._pubsub = redis_client.pubsub()
                await self._pubsub.subscribe(SYNC_REDIS_CHANNEL)
                delay = 0.25
                async for message in self._pubsub.listen():
                    if message.get("type") != "message":
                        continue
                    notification = _parse_notification(message.get("data"))
                    if notification is not None:
                        await self.notify(*notification)
            except asyncio.CancelledError:
                raise
            except Exception:
                sync_metrics.increment("redis_notification_failures")
                logger.warning(
                    "sync Redis listener unavailable; replay remains durable"
                )
                await asyncio.sleep(delay)
                delay = min(delay * 2, 10.0)
            finally:
                if self._pubsub is not None:
                    try:
                        await self._pubsub.aclose()
                    except AttributeError:
                        try:
                            await self._pubsub.close()
                        except Exception:
                            pass
                    except Exception:
                        pass
                    self._pubsub = None

    async def shutdown(self) -> None:
        task = self._listener_task
        self._listener_task = None
        if task is not None:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)

        async with self._lock:
            connections = [
                connection
                for account in self._connections.values()
                for connection in account.values()
            ]
            self._connections.clear()
            sync_metrics.active_connections = 0
        await asyncio.gather(
            *(
                connection.close(code=1001, reason="server shutdown")
                for connection in connections
            ),
            return_exceptions=True,
        )


def _parse_notification(data: Any) -> tuple[int, int] | None:
    try:
        if isinstance(data, bytes):
            data = data.decode("utf-8")
        message = json.loads(data)
        user_id = message["user_id"]
        server_sequence = message["server_sequence"]
        if (
            isinstance(user_id, bool)
            or not isinstance(user_id, int)
            or user_id < 1
            or isinstance(server_sequence, bool)
            or not isinstance(server_sequence, int)
            or server_sequence < 1
        ):
            return None
        return user_id, server_sequence
    except (KeyError, TypeError, ValueError, UnicodeError, json.JSONDecodeError):
        return None


sync_manager = SyncConnectionManager()

__all__ = [
    "SYNC_REDIS_CHANNEL",
    "SlowConsumerError",
    "SyncConnection",
    "SyncConnectionManager",
    "SyncMetrics",
    "sync_manager",
    "sync_metrics",
]
