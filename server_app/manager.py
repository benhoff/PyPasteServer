"""WebSocket connection manager backed by Redis pub/sub."""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Dict, List

from fastapi import WebSocket

from .redis_client import redis_client

logger = logging.getLogger(__name__)


class ConnectionManager:
    def __init__(self) -> None:
        self.active_connections: Dict[int, List[WebSocket]] = {}
        self.lock = asyncio.Lock()
        self.pubsub = None
        self.listener_task: asyncio.Task[None] | None = None

    async def connect_redis(self) -> None:
        self.pubsub = redis_client.pubsub()
        await self.pubsub.subscribe("clipboard_updates")

    async def listen_redis(self) -> None:
        delay = 0.25
        while True:
            try:
                await self.connect_redis()
                delay = 0.25
                async for message in self.pubsub.listen():
                    if message["type"] != "message":
                        continue
                    data = json.loads(message["data"])
                    user_id = data.get("user_id")
                    if not user_id:
                        continue
                    ciphertext = data.get("ciphertext")
                    nonce = data.get("nonce")
                    tag = data.get("tag")
                    if not all([ciphertext, nonce, tag]):
                        continue
                    update_message = {
                        "type": "update",
                        "ciphertext": ciphertext,
                        "nonce": nonce,
                        "tag": tag,
                    }
                    meta = data.get("meta")
                    if isinstance(meta, dict) and meta:
                        update_message["meta"] = meta
                    await self.broadcast(user_id, update_message)
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.warning("legacy Redis listener unavailable; retrying")
                await asyncio.sleep(delay)
                delay = min(delay * 2, 10.0)
            finally:
                if self.pubsub is not None:
                    try:
                        await self.pubsub.aclose()
                    except AttributeError:  # redis-py 4 compatibility
                        try:
                            await self.pubsub.close()
                        except Exception:
                            pass
                    except Exception:
                        pass
                    self.pubsub = None

    async def start_listening(self) -> None:
        if self.listener_task is None or self.listener_task.done():
            self.listener_task = asyncio.create_task(
                self.listen_redis(), name="legacy-redis-listener"
            )

    async def increment_connection_count(self, user_id: int) -> None:
        key = f"user:{user_id}:connections"
        try:
            await redis_client.incr(key)
        except Exception:
            pass

    async def decrement_connection_count(self, user_id: int) -> None:
        key = f"user:{user_id}:connections"
        try:
            current = await redis_client.decr(key)
            if current < 0:
                await redis_client.set(key, 0)
        except Exception:
            pass

    async def get_connection_count(self, user_id: int) -> int:
        key = f"user:{user_id}:connections"
        try:
            count = await redis_client.get(key)
            return int(count) if count else 0
        except Exception:
            async with self.lock:
                return len(self.active_connections.get(user_id, []))

    async def connect(self, user_id: int, websocket: WebSocket) -> None:
        await websocket.accept()
        async with self.lock:
            self.active_connections.setdefault(user_id, []).append(websocket)
        await self.increment_connection_count(user_id)
        total = await self.get_connection_count(user_id)
        print(f"User {user_id} connected. Total connections: {total}")

    async def disconnect(self, user_id: int, websocket: WebSocket) -> None:
        async with self.lock:
            connections = self.active_connections.get(user_id, [])
            if websocket in connections:
                connections.remove(websocket)
        await self.decrement_connection_count(user_id)
        total = await self.get_connection_count(user_id)
        print(f"User {user_id} disconnected. Remaining connections: {total}")
        async with self.lock:
            if not self.active_connections.get(user_id):
                self.active_connections.pop(user_id, None)

    async def broadcast(self, user_id: int, message: dict) -> None:
        async with self.lock:
            connections = list(self.active_connections.get(user_id, []))
        to_remove: List[WebSocket] = []
        for connection in connections:
            try:
                await connection.send_json(message)
            except Exception as exc:  # pragma: no cover - logging only
                print(f"Failed to send message to connection: {exc}")
                to_remove.append(connection)
        if to_remove:
            async with self.lock:
                active = self.active_connections.get(user_id, [])
                for connection in to_remove:
                    if connection in active:
                        active.remove(connection)
                        await self.decrement_connection_count(user_id)
                if not active:
                    self.active_connections.pop(user_id, None)

    async def publish_update(self, message: dict) -> None:
        try:
            await redis_client.publish("clipboard_updates", json.dumps(message))
        except Exception:
            logger.warning(
                "legacy clipboard update could not be published",
                extra={"user_id": message.get("user_id")},
            )

    async def shutdown(self) -> None:
        task = self.listener_task
        self.listener_task = None
        if task is not None:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)


manager = ConnectionManager()

__all__ = ["manager", "ConnectionManager"]
