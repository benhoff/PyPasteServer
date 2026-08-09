"""Authenticated WebSocket endpoint implementing kclip sync protocol v1."""

from __future__ import annotations

import asyncio
import json
import logging
import time
from typing import Any

from fastapi import APIRouter, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.security.utils import get_authorization_scheme_param

from . import config
from . import db as database
from .async_utils import run_sync
from .noise_transport import (
    NoiseWebSocketTransport,
    PlainWebSocketTransport,
    transport_requested,
)
from .pairing import active_pairing, mark_pairing_used
from .security import decode_token
from .sync_manager import SlowConsumerError, SyncConnection, sync_manager, sync_metrics
from .sync_protocol import (
    CheckpointMessage,
    HelloMessage,
    PushMessage,
    SyncProtocolError,
    decode_json_frame,
    parse_client_message,
    push_ack_message,
    ready_message,
)
from .sync_retention import configured_retention_policy
from .sync_service import SyncLimits, sync_store

logger = logging.getLogger(__name__)
router = APIRouter()


def _bearer_token(websocket: WebSocket) -> str | None:
    scheme, credentials = get_authorization_scheme_param(
        websocket.headers.get("authorization")
    )
    if scheme.lower() == "bearer" and credentials:
        return credentials
    if config.SYNC_ALLOW_QUERY_TOKEN:
        return websocket.query_params.get("token")
    return None


def _authenticate(token: str) -> int:
    with database.SessionLocal() as session:
        user = decode_token(token, session)
        return int(user.id)


def _authenticate_pairing(pairing_id: str) -> tuple[int, bytes]:
    with database.SessionLocal() as session:
        device = active_pairing(session, pairing_id)
        if device is None:
            raise HTTPException(status_code=401, detail="Invalid pairing")
        return int(device.user_id), bytes(device.psk)


def _mark_pairing_used(pairing_id: str) -> bool:
    with database.SessionLocal() as session:
        return mark_pairing_used(session, pairing_id)


def _is_secure(websocket: WebSocket) -> bool:
    # A trusted proxy-header middleware should rewrite the ASGI scheme.  Do not
    # trust a raw X-Forwarded-Proto value supplied by an arbitrary client here.
    return websocket.url.scheme == "wss"


async def _receive_json_message(transport: Any) -> dict[str, Any]:
    text = await transport.receive_text(max_frame_bytes=config.SYNC_MAX_FRAME_BYTES)
    return decode_json_frame(text, max_frame_bytes=config.SYNC_MAX_FRAME_BYTES)


async def _send_error_before_connection(
    transport: Any, error: SyncProtocolError
) -> None:
    try:
        await transport.send_text(
            json.dumps(error.as_message(), separators=(",", ":"), ensure_ascii=False)
        )
    finally:
        await transport.close(code=error.close_code or 1002)


def _limits() -> SyncLimits:
    return SyncLimits(
        max_account_events=config.SYNC_ACCOUNT_MAX_EVENTS,
        max_account_storage_bytes=config.SYNC_ACCOUNT_MAX_STORAGE_BYTES,
        rate_limit_events=config.SYNC_RATE_LIMIT_EVENTS,
        rate_limit_window_seconds=config.SYNC_RATE_LIMIT_WINDOW_SECONDS,
    )


@router.websocket("/sync/v1")
async def sync_v1_endpoint(websocket: WebSocket) -> None:
    pairing_mode = transport_requested(websocket.headers)
    if not config.SYNC_ENABLED:
        await websocket.close(code=1008)
        return

    pairing_id: str | None = None
    psk: bytes | None = None
    if pairing_mode:
        pairing_id = websocket.headers.get("x-kclip-pairing-id")
        if not pairing_id:
            sync_metrics.increment("authentication_failures")
            await websocket.close(code=1008)
            return
        try:
            user_id, psk = await run_sync(_authenticate_pairing, pairing_id)
        except HTTPException:
            sync_metrics.increment("authentication_failures")
            await websocket.close(code=1008)
            return
        except Exception as error:
            logger.error(
                "sync authentication backend unavailable",
                extra={"error_type": type(error).__name__},
            )
            await websocket.close(code=1011)
            return
    else:
        if not config.SYNC_ALLOW_LEGACY_BEARER or (
            config.SYNC_REQUIRE_TLS and not _is_secure(websocket)
        ):
            await websocket.close(code=1008)
            return
        token = _bearer_token(websocket)
        if token is None:
            sync_metrics.increment("authentication_failures")
            await websocket.close(code=1008)
            return
        try:
            user_id = await run_sync(_authenticate, token)
        except HTTPException:
            sync_metrics.increment("authentication_failures")
            await websocket.close(code=1008)
            return
        except Exception as error:
            logger.error(
                "sync authentication backend unavailable",
                extra={"error_type": type(error).__name__},
            )
            await websocket.close(code=1011)
            return

    await websocket.accept()
    connection: SyncConnection | None = None
    transport: Any = PlainWebSocketTransport(websocket)
    try:
        if pairing_mode:
            try:
                transport = await asyncio.wait_for(
                    NoiseWebSocketTransport.handshake(websocket, psk=psk or b""),
                    timeout=max(1, config.SYNC_HELLO_TIMEOUT_SECONDS),
                )
                if not await run_sync(_mark_pairing_used, pairing_id or ""):
                    sync_metrics.increment("authentication_failures")
                    await websocket.close(code=1008)
                    return
                sync_metrics.increment("noise_sessions")
            except TimeoutError:
                sync_metrics.increment("authentication_failures")
                await websocket.close(code=1008)
                return
            except SyncProtocolError:
                sync_metrics.increment("authentication_failures")
                await websocket.close(code=1008)
                return
        try:
            first_message = await asyncio.wait_for(
                _receive_json_message(transport),
                timeout=max(1, config.SYNC_HELLO_TIMEOUT_SECONDS),
            )
            if first_message.get("type") != "hello":
                raise SyncProtocolError(
                    "invalid_message",
                    "hello must be the first client message",
                    close_code=1002,
                )
            hello = parse_client_message(
                first_message, max_event_bytes=config.SYNC_MAX_EVENT_BYTES
            )
            if not isinstance(hello, HelloMessage):
                raise SyncProtocolError(
                    "invalid_message",
                    "hello must be the first client message",
                    close_code=1002,
                )
        except TimeoutError:
            await _send_error_before_connection(
                transport,
                SyncProtocolError(
                    "invalid_message", "hello was not received in time", close_code=1002
                ),
            )
            return
        except SyncProtocolError as error:
            await _send_error_before_connection(transport, error)
            return

        await run_sync(sync_store.register_device, user_id, hello.device_id)
        connection = SyncConnection(
            websocket=transport,
            user_id=user_id,
            device_id=hello.device_id,
            resume_after=hello.resume_after,
        )
        await connection.start()

        # Register while holding the delivery lock. Redis notifications that
        # race with the replay-window read wait until ready + replay are queued.
        async with connection.delivery_lock:
            await sync_manager.add(connection)
            replay_window = await run_sync(sync_store.replay_window, user_id)
            if hello.resume_after > replay_window.latest_sequence:
                raise SyncProtocolError(
                    "replay_unavailable",
                    "resume cursor is ahead of the durable event log",
                    close_code=1011,
                )
            await connection.enqueue(
                ready_message(
                    connection_id=connection.connection_id,
                    latest_sequence=replay_window.latest_sequence,
                    earliest_sequence=replay_window.earliest_sequence,
                    resume_after=hello.resume_after,
                )
            )
            effective_resume = max(
                hello.resume_after, replay_window.earliest_sequence - 1
            )
            connection.last_delivered_sequence = effective_resume
            if effective_resume != hello.resume_after:
                sync_metrics.increment(
                    "truncated_replay_events", effective_resume - hello.resume_after
                )
            sync_metrics.increment(
                "replay_lag_events_total",
                replay_window.latest_sequence - effective_resume,
            )
            await connection.deliver_through_locked(replay_window.latest_sequence)

        invalid_messages = 0
        while not connection.closed:
            try:
                raw_message = await _receive_json_message(transport)
                message = parse_client_message(
                    raw_message, max_event_bytes=config.SYNC_MAX_EVENT_BYTES
                )
                if isinstance(message, HelloMessage):
                    raise SyncProtocolError(
                        "invalid_message", "hello has already been received"
                    )
                if isinstance(message, PushMessage):
                    await _handle_push(connection, message)
                elif isinstance(message, CheckpointMessage):
                    await run_sync(
                        sync_store.checkpoint,
                        user_id,
                        hello.device_id,
                        message.server_sequence,
                    )
                invalid_messages = 0
            except SyncProtocolError as error:
                if error.code in {"event_too_large", "rate_limited", "quota_exceeded"}:
                    sync_metrics.increment(f"{error.code}_errors")
                if error.code in {
                    "event_too_large",
                    "invalid_message",
                    "protocol_mismatch",
                }:
                    invalid_messages += 1

                should_close = error.close_code is not None or (
                    config.SYNC_MAX_INVALID_MESSAGES > 0
                    and invalid_messages >= config.SYNC_MAX_INVALID_MESSAGES
                )
                await connection.enqueue(error.as_message(), wait=should_close)
                if should_close:
                    await connection.close(code=error.close_code or 1002)
                    return
    except WebSocketDisconnect:
        pass
    except (ConnectionError, SlowConsumerError):
        pass
    except SyncProtocolError as error:
        if connection is None:
            await _send_error_before_connection(transport, error)
        elif not connection.closed:
            try:
                await connection.enqueue(error.as_message(), wait=True)
            except Exception:
                pass
            await connection.close(code=error.close_code or 1011)
    except Exception as error:
        # Exception strings from a failed SQL driver may include bound values.
        # Log only a safe category so opaque payloads can never leak here.
        logger.error(
            "sync connection failed",
            extra={"user_id": user_id, "error_type": type(error).__name__},
        )
        if connection is None:
            try:
                await _send_error_before_connection(
                    transport,
                    # This branch is reached only after accept; use the active
                    # transport so a Noise session never emits plaintext JSON.
                    SyncProtocolError(
                        "internal_error",
                        "sync service failed",
                        retryable=True,
                        close_code=1011,
                    ),
                )
            except Exception:
                pass
        elif not connection.closed:
            error = SyncProtocolError(
                "internal_error", "sync service failed", retryable=True, close_code=1011
            )
            try:
                await connection.enqueue(error.as_message(), wait=True)
            except Exception:
                pass
            await connection.close(code=1011)
    finally:
        if connection is not None:
            await sync_manager.remove(connection)


async def _handle_push(connection: SyncConnection, push: PushMessage) -> None:
    started_at = time.perf_counter()
    try:
        accepted = await run_sync(
            sync_store.accept_event,
            user_id=connection.user_id,
            device_id=connection.device_id,
            push=push,
            limits=_limits(),
            retention=configured_retention_policy(),
        )
    finally:
        sync_metrics.increment(
            "sql_commit_latency_ms_total",
            max(0, int((time.perf_counter() - started_at) * 1000)),
        )
    if accepted.duplicate:
        sync_metrics.increment("deduplicated_pushes")
    else:
        sync_metrics.increment("accepted_pushes")
        sync_metrics.increment("push_bytes", len(push.ciphertext))

    try:
        await connection.enqueue(
            push_ack_message(
                message_id=accepted.event.message_id,
                server_sequence=accepted.event.server_sequence,
                duplicate=accepted.duplicate,
            ),
            wait=True,
        )
    finally:
        if not accepted.duplicate:
            # Publish only after commit and after attempting the acknowledgement.
            # Local delivery is also attempted so a Redis outage does not affect
            # clients attached to this worker.
            await sync_manager.publish(
                accepted.event.user_id, accepted.event.server_sequence
            )
            await sync_manager.notify(
                accepted.event.user_id, accepted.event.server_sequence
            )


__all__ = ["router", "sync_v1_endpoint"]
