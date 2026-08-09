from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

import pytest
from fastapi import FastAPI
from noise.connection import NoiseConnection
from sqlalchemy import create_engine, delete, func, select
from sqlalchemy.orm import sessionmaker

from server_app import config, sync_websocket
from server_app import db as database
from server_app.models import (
    PairedDevice,
    SyncDeviceCursor,
    SyncEvent,
    SyncUserState,
    Token,
    User,
)
from server_app.noise_transport import (
    CHUNK_CONTINUES,
    CHUNK_FINAL,
    MAX_CHUNK_DATA_BYTES,
    NOISE_PROTOCOL_NAME,
    NOISE_TRANSPORT_NAME,
)
from server_app.security import create_access_token
from server_app.sync_manager import SyncConnectionManager
from server_app.sync_protocol import encode_base64url


class ASGIWebSocket:
    """Small deterministic ASGI harness that does not depend on TestClient."""

    def __init__(
        self,
        app: FastAPI,
        headers: dict[str, str] | None = None,
        *,
        scheme: str = "ws",
    ) -> None:
        self.app = app
        self.incoming: asyncio.Queue[dict[str, Any]] = asyncio.Queue()
        self.outgoing: asyncio.Queue[dict[str, Any]] = asyncio.Queue()
        self.scope = {
            "type": "websocket",
            "asgi": {"version": "3.0", "spec_version": "2.4"},
            "http_version": "1.1",
            "scheme": scheme,
            "server": ("testserver", 80),
            "client": ("testclient", 50000),
            "root_path": "",
            "path": "/sync/v1",
            "raw_path": b"/sync/v1",
            "query_string": b"",
            "headers": [
                (key.lower().encode("latin-1"), value.encode("latin-1"))
                for key, value in (headers or {}).items()
            ],
            "subprotocols": [],
            "state": {},
        }
        self.task: asyncio.Task[None] | None = None
        self.close_code: int | None = None

    async def connect(self) -> bool:
        self.task = asyncio.create_task(
            self.app(self.scope, self.incoming.get, self.outgoing.put)
        )
        await self.incoming.put({"type": "websocket.connect"})
        message = await asyncio.wait_for(self.outgoing.get(), timeout=10)
        if message["type"] == "websocket.close":
            self.close_code = message.get("code", 1000)
            await self._join()
            return False
        assert message["type"] == "websocket.accept"
        return True

    async def send_json(self, message: dict[str, Any]) -> None:
        await self.incoming.put(
            {
                "type": "websocket.receive",
                "text": json.dumps(message, separators=(",", ":")),
            }
        )

    async def send_bytes(self, message: bytes) -> None:
        await self.incoming.put({"type": "websocket.receive", "bytes": message})

    async def receive_bytes(self) -> bytes:
        message = await asyncio.wait_for(self.outgoing.get(), timeout=10)
        if message["type"] == "websocket.close":
            self.close_code = message.get("code", 1000)
            raise ConnectionError(f"WebSocket closed with {self.close_code}")
        assert message["type"] == "websocket.send"
        assert message.get("bytes") is not None
        return bytes(message["bytes"])

    async def receive_json(self) -> dict[str, Any]:
        message = await asyncio.wait_for(self.outgoing.get(), timeout=10)
        if message["type"] == "websocket.close":
            self.close_code = message.get("code", 1000)
            raise ConnectionError(f"WebSocket closed with {self.close_code}")
        assert message["type"] == "websocket.send"
        if message.get("text") is not None:
            return json.loads(message["text"])
        return json.loads(message["bytes"].decode("utf-8"))

    async def expect_close(self) -> int:
        message = await asyncio.wait_for(self.outgoing.get(), timeout=10)
        assert message["type"] == "websocket.close"
        self.close_code = message.get("code", 1000)
        await self._join()
        return self.close_code

    async def disconnect(self) -> None:
        if self.task is None or self.task.done():
            return
        await self.incoming.put({"type": "websocket.disconnect", "code": 1000})
        await self._join()

    async def _join(self) -> None:
        if self.task is not None:
            await asyncio.wait_for(self.task, timeout=10)


def _push(message_id: str | None = None, value: bytes = b"\x01") -> dict:
    return {
        "type": "push",
        "protocol_version": 1,
        "message_id": message_id or str(uuid4()),
        "algorithm": "xchacha20-poly1305",
        "nonce": encode_base64url(bytes([9]) * 24),
        "ciphertext": encode_base64url(value),
        "tag": encode_base64url(bytes(16)),
        # The endpoint must ignore this and use the authenticated hello device.
        "sender_device_id": "untrusted-body-value",
        "unknown_future_field": {"safe": True},
    }


@pytest.fixture
def websocket_context(tmp_path, monkeypatch):
    engine = create_engine(
        f"sqlite:///{tmp_path / 'websocket.db'}",
        connect_args={"check_same_thread": False, "timeout": 30},
    )
    database.Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    monkeypatch.setattr(database, "SessionLocal", factory)
    monkeypatch.setattr(config, "SYNC_ENABLED", True)
    monkeypatch.setattr(config, "SYNC_REQUIRE_TLS", False)
    monkeypatch.setattr(config, "SYNC_ALLOW_LEGACY_BEARER", True)
    monkeypatch.setattr(config, "SYNC_ALLOW_QUERY_TOKEN", False)
    monkeypatch.setattr(config, "SYNC_RATE_LIMIT_EVENTS", 0)
    monkeypatch.setattr(config, "SYNC_MAX_INVALID_MESSAGES", 3)

    manager = SyncConnectionManager()

    async def publish_without_redis(user_id: int, server_sequence: int) -> bool:
        return False

    monkeypatch.setattr(manager, "publish", publish_without_redis)
    monkeypatch.setattr(sync_websocket, "sync_manager", manager)

    tokens: dict[str, str] = {}
    with factory() as session:
        for username in ("alice", "bob"):
            user = User(
                username=username,
                email=f"{username}@example.test",
                hashed_password="unused",
                email_authenticated=True,
            )
            session.add(user)
            session.flush()
            session.add(SyncUserState(user_id=user.id, next_server_sequence=1))
            session.commit()
            tokens[username] = create_access_token(
                {"sub": username, "user_id": user.id}, session
            )

    app = FastAPI()
    app.include_router(sync_websocket.router)
    try:
        yield app, factory, tokens, manager
    finally:
        engine.dispose()


def _headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _hello(device_id: str, resume_after: int = 0, **extra) -> dict:
    return {
        "type": "hello",
        "protocol_version": 1,
        "device_id": device_id,
        "resume_after": resume_after,
        **extra,
    }


class NoiseTestClient:
    def __init__(self, psk: bytes) -> None:
        self.noise = NoiseConnection.from_name(NOISE_PROTOCOL_NAME)
        self.noise.set_as_initiator()
        self.noise.set_psks(psk)
        self.noise.start_handshake()

    async def handshake(self, socket: ASGIWebSocket) -> None:
        await socket.send_bytes(bytes(self.noise.write_message()))
        self.noise.read_message(await socket.receive_bytes())

    async def send_json(
        self, socket: ASGIWebSocket, message: dict[str, Any]
    ) -> list[bytes]:
        data = json.dumps(message, separators=(",", ":")).encode()
        chunks = [
            data[offset : offset + MAX_CHUNK_DATA_BYTES]
            for offset in range(0, len(data), MAX_CHUNK_DATA_BYTES)
        ]
        ciphertexts = []
        for index, chunk in enumerate(chunks):
            flag = CHUNK_FINAL if index == len(chunks) - 1 else CHUNK_CONTINUES
            ciphertext = self.noise.encrypt(bytes([flag]) + chunk)
            ciphertexts.append(ciphertext)
            await socket.send_bytes(ciphertext)
        return ciphertexts

    async def receive_json(self, socket: ASGIWebSocket) -> dict[str, Any]:
        assembled = bytearray()
        while True:
            plaintext = self.noise.decrypt(await socket.receive_bytes())
            assert plaintext[0] in {CHUNK_CONTINUES, CHUNK_FINAL}
            assembled.extend(plaintext[1:])
            if plaintext[0] == CHUNK_FINAL:
                return json.loads(assembled)


def test_push_retry_replay_checkpoint_and_user_isolation(websocket_context) -> None:
    app, factory, tokens, _ = websocket_context
    message_id = "550e8400-e29b-41d4-a716-446655440000"

    async def scenario() -> dict[str, Any]:
        first = ASGIWebSocket(app, _headers(tokens["alice"]))
        assert await first.connect()
        await first.send_json(_hello("device-a", future_field="ignored"))
        ready = await first.receive_json()
        assert ready["type"] == "ready"
        assert ready["latest_sequence"] == 0
        assert ready["replay_from"] == 1

        await first.send_json(_push(message_id))
        assert await first.receive_json() == {
            "type": "push_ack",
            "message_id": message_id,
            "server_sequence": 1,
            "duplicate": False,
        }
        event = await first.receive_json()
        assert event["type"] == "event"
        assert event["server_sequence"] == 1
        assert event["sender_device_id"] == "device-a"
        assert "user_id" not in event
        await first.disconnect()

        replay = ASGIWebSocket(app, _headers(tokens["alice"]))
        assert await replay.connect()
        await replay.send_json(_hello("device-a", resume_after=0))
        assert (await replay.receive_json())["latest_sequence"] == 1
        assert await replay.receive_json() == event

        await replay.send_json(_push(message_id, value=b"different retry body"))
        duplicate_ack = await replay.receive_json()
        assert duplicate_ack["duplicate"] is True
        assert duplicate_ack["server_sequence"] == 1

        await replay.send_json({"type": "checkpoint", "server_sequence": 1})
        await replay.send_json(_push(value=b"\x02"))
        assert (await replay.receive_json())["server_sequence"] == 2
        assert (await replay.receive_json())["server_sequence"] == 2
        await replay.send_json({"type": "checkpoint", "server_sequence": 0})
        # A following valid operation establishes that both checkpoints ran.
        await replay.send_json(_push(value=b"\x03"))
        assert (await replay.receive_json())["server_sequence"] == 3
        assert (await replay.receive_json())["server_sequence"] == 3
        await replay.disconnect()

        resumed = ASGIWebSocket(app, _headers(tokens["alice"]))
        assert await resumed.connect()
        await resumed.send_json(_hello("device-c", resume_after=1))
        assert (await resumed.receive_json())["latest_sequence"] == 3
        assert (await resumed.receive_json())["server_sequence"] == 2
        assert (await resumed.receive_json())["server_sequence"] == 3
        await resumed.disconnect()

        isolated = ASGIWebSocket(app, _headers(tokens["bob"]))
        assert await isolated.connect()
        await isolated.send_json(_hello("device-b"))
        assert (await isolated.receive_json())["latest_sequence"] == 0
        await isolated.disconnect()
        return event

    event = asyncio.run(scenario())

    with factory() as session:
        alice = session.scalar(select(User).where(User.username == "alice"))
        cursor = session.get(SyncDeviceCursor, (alice.id, "device-a"))
        assert cursor.processed_server_sequence == 1
        assert (
            session.scalar(
                select(func.count(SyncEvent.id)).where(SyncEvent.user_id == alice.id)
            )
            == 3
        )
        stored = session.scalar(
            select(SyncEvent).where(SyncEvent.message_id == message_id)
        )
        assert stored.ciphertext == b"\x01"
        assert event["ciphertext"] == encode_base64url(stored.ciphertext)


def test_authentication_happens_before_accept(websocket_context) -> None:
    app, factory, tokens, _ = websocket_context

    async def scenario() -> None:
        missing = ASGIWebSocket(app)
        assert not await missing.connect()
        assert missing.close_code == 1008

        invalid = ASGIWebSocket(app, _headers("not-a-valid-token"))
        assert not await invalid.connect()
        assert invalid.close_code == 1008

        with factory() as session:
            session.execute(delete(Token).where(Token.token == tokens["bob"]))
            session.commit()
        revoked = ASGIWebSocket(app, _headers(tokens["bob"]))
        assert not await revoked.connect()
        assert revoked.close_code == 1008

    asyncio.run(scenario())


def test_noise_pairing_authenticates_and_encrypts_every_application_frame(
    websocket_context, monkeypatch
) -> None:
    app, factory, _, _ = websocket_context
    pairing_id = "eb6b89c3-6a6f-45fa-8da7-b74ea00bbfd5"
    psk = bytes(range(32))
    with factory() as session:
        alice = session.scalar(select(User).where(User.username == "alice"))
        session.add(
            PairedDevice(
                pairing_id=pairing_id,
                user_id=alice.id,
                device_name="paired-laptop",
                psk=psk,
            )
        )
        session.commit()

    # Pairing mode remains safe over ws:// and does not need the legacy bearer
    # compatibility switch.
    monkeypatch.setattr(config, "SYNC_ALLOW_LEGACY_BEARER", False)
    monkeypatch.setattr(config, "SYNC_REQUIRE_TLS", True)

    async def scenario() -> None:
        socket = ASGIWebSocket(
            app,
            {
                "X-Kclip-Transport": NOISE_TRANSPORT_NAME,
                "X-Kclip-Pairing-ID": pairing_id,
            },
        )
        assert await socket.connect()
        client = NoiseTestClient(psk)
        await client.handshake(socket)
        hello_ciphertexts = await client.send_json(socket, _hello("paired-device"))
        assert all(b'"type":"hello"' not in item for item in hello_ciphertexts)
        ready = await client.receive_json(socket)
        assert ready["type"] == "ready"

        # Cross the Noise maximum-message boundary in both directions.
        await client.send_json(
            socket, _push(value=bytes([7]) * (MAX_CHUNK_DATA_BYTES * 2))
        )
        assert (await client.receive_json(socket))["type"] == "push_ack"
        assert (await client.receive_json(socket))["type"] == "event"
        await socket.disconnect()

    asyncio.run(scenario())
    with factory() as session:
        device = session.scalar(
            select(PairedDevice).where(PairedDevice.pairing_id == pairing_id)
        )
        assert device.last_used_at is not None


def test_revoked_pairing_is_rejected_before_accept(websocket_context) -> None:
    app, factory, _, _ = websocket_context
    pairing_id = "bc7855f5-d611-426f-92c7-b529e29bd874"
    with factory() as session:
        alice = session.scalar(select(User).where(User.username == "alice"))
        session.add(
            PairedDevice(
                pairing_id=pairing_id,
                user_id=alice.id,
                device_name="revoked-device",
                psk=bytes(32),
                revoked_at=datetime.now(UTC),
            )
        )
        session.commit()

    async def scenario() -> None:
        socket = ASGIWebSocket(
            app,
            {
                "X-Kclip-Transport": NOISE_TRANSPORT_NAME,
                "X-Kclip-Pairing-ID": pairing_id,
            },
        )
        assert not await socket.connect()
        assert socket.close_code == 1008

    asyncio.run(scenario())


def test_live_fanout_reaches_same_account_only(websocket_context) -> None:
    app, _, tokens, _ = websocket_context

    async def ready_socket(username: str, device_id: str) -> ASGIWebSocket:
        socket = ASGIWebSocket(app, _headers(tokens[username]))
        assert await socket.connect()
        await socket.send_json(_hello(device_id))
        assert (await socket.receive_json())["type"] == "ready"
        return socket

    async def scenario() -> None:
        first = await ready_socket("alice", "device-a")
        second = await ready_socket("alice", "device-b")
        isolated = await ready_socket("bob", "device-c")

        push = _push()
        await first.send_json(push)
        acknowledgement = await first.receive_json()
        first_event = await first.receive_json()
        second_event = await second.receive_json()

        assert acknowledgement["message_id"] == push["message_id"]
        assert first_event == second_event
        assert second_event["sender_device_id"] == "device-a"
        await asyncio.sleep(0.05)
        assert isolated.outgoing.empty()

        await first.disconnect()
        await second.disconnect()
        await isolated.disconnect()

    asyncio.run(scenario())


def test_tls_requirement_uses_trusted_asgi_scheme(
    websocket_context, monkeypatch
) -> None:
    app, _, tokens, _ = websocket_context
    monkeypatch.setattr(config, "SYNC_REQUIRE_TLS", True)

    async def scenario() -> None:
        insecure = ASGIWebSocket(app, _headers(tokens["alice"]))
        assert not await insecure.connect()
        assert insecure.close_code == 1008

        secure = ASGIWebSocket(app, _headers(tokens["alice"]), scheme="wss")
        assert await secure.connect()
        await secure.disconnect()

    asyncio.run(scenario())


@pytest.mark.parametrize(
    ("first_message", "expected_code"),
    [
        (_push("550e8400-e29b-41d4-a716-446655440000"), "invalid_message"),
        (
            {
                "type": "hello",
                "protocol_version": 99,
                "device_id": "device-a",
                "resume_after": 0,
            },
            "protocol_mismatch",
        ),
    ],
)
def test_hello_is_required_and_versioned(
    websocket_context, first_message: dict, expected_code: str
) -> None:
    app, _, tokens, _ = websocket_context

    async def scenario() -> None:
        socket = ASGIWebSocket(app, _headers(tokens["alice"]))
        assert await socket.connect()
        await socket.send_json(first_message)
        error = await socket.receive_json()
        assert error["type"] == "error"
        assert error["code"] == expected_code
        assert await socket.expect_close() in {1002, 1009}

    asyncio.run(scenario())


def test_invalid_messages_are_structured_and_repeated_hello_is_rejected(
    websocket_context,
) -> None:
    app, _, tokens, _ = websocket_context

    async def scenario() -> None:
        socket = ASGIWebSocket(app, _headers(tokens["alice"]))
        assert await socket.connect()
        await socket.send_json(_hello("device-a"))
        assert (await socket.receive_json())["type"] == "ready"

        await socket.send_json(_hello("device-a"))
        error = await socket.receive_json()
        assert error["code"] == "invalid_message"
        assert error["retryable"] is False

        invalid_push = _push()
        invalid_push["nonce"] = "has=padding"
        await socket.send_json(invalid_push)
        error = await socket.receive_json()
        assert error["code"] == "invalid_message"
        assert error["message_id"] == invalid_push["message_id"]
        await socket.disconnect()

    asyncio.run(scenario())


def test_resume_ahead_of_durable_log_is_terminal(websocket_context) -> None:
    app, _, tokens, _ = websocket_context

    async def scenario() -> None:
        socket = ASGIWebSocket(app, _headers(tokens["alice"]))
        assert await socket.connect()
        await socket.send_json(_hello("device-a", resume_after=10))
        error = await socket.receive_json()
        assert error["code"] == "replay_unavailable"
        assert await socket.expect_close() == 1011

    asyncio.run(scenario())


def test_payload_and_exception_details_are_not_logged(
    websocket_context, monkeypatch, caplog
) -> None:
    app, _, tokens, _ = websocket_context
    secret = "never-log-this-ciphertext"

    def fail_accept_event(**kwargs):
        raise RuntimeError(secret)

    monkeypatch.setattr(sync_websocket.sync_store, "accept_event", fail_accept_event)

    async def scenario() -> None:
        socket = ASGIWebSocket(app, _headers(tokens["alice"]))
        assert await socket.connect()
        await socket.send_json(_hello("device-a"))
        assert (await socket.receive_json())["type"] == "ready"
        await socket.send_json(_push(value=secret.encode()))
        error = await socket.receive_json()
        assert error["code"] == "internal_error"
        assert await socket.expect_close() == 1011

    asyncio.run(scenario())
    assert secret not in caplog.text
