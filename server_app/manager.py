"""WebSocket connection manager backed by Redis pub/sub."""
from __future__ import annotations

import asyncio
import json
from typing import Dict, List

from fastapi import WebSocket

from .redis_client import redis_client


class ConnectionManager:
    def __init__(self) -> None:
        self.active_connections: Dict[int, List[WebSocket]] = {}
        self.lock = asyncio.Lock()
        self.pubsub = None

    async def connect_redis(self) -> None:
        self.pubsub = redis_client.pubsub()
        await self.pubsub.subscribe("clipboard_updates")

    async def listen_redis(self) -> None:
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

    async def start_listening(self) -> None:
        await self.connect_redis()
        asyncio.create_task(self.listen_redis())

    async def increment_connection_count(self, user_id: int) -> None:
        key = f"user:{user_id}:connections"
        await redis_client.incr(key)

    async def decrement_connection_count(self, user_id: int) -> None:
        key = f"user:{user_id}:connections"
        current = await redis_client.decr(key)
        if current < 0:
            await redis_client.set(key, 0)

    async def get_connection_count(self, user_id: int) -> int:
        key = f"user:{user_id}:connections"
        count = await redis_client.get(key)
        return int(count) if count else 0

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
        await redis_client.publish("clipboard_updates", json.dumps(message))

    async def shutdown(self) -> None:
        if self.pubsub is not None:
            await self.pubsub.unsubscribe("clipboard_updates")
            await self.pubsub.close()
        await redis_client.close()


manager = ConnectionManager()

__all__ = ["manager", "ConnectionManager"]
