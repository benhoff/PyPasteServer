"""Parsing and serialization for the kclip sync-v1 wire protocol."""

from __future__ import annotations

import base64
import binascii
import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

PROTOCOL_VERSION = 1
SYNC_ALGORITHM = "xchacha20-poly1305"
NONCE_BYTES = 24
TAG_BYTES = 16
MAX_SEQUENCE = (1 << 63) - 1
ERROR_CODES = frozenset(
    {
        "invalid_message",
        "protocol_mismatch",
        "authentication_failed",
        "permission_denied",
        "event_too_large",
        "quota_exceeded",
        "rate_limited",
        "server_unavailable",
        "replay_unavailable",
        "internal_error",
    }
)

_BASE64URL_RE = re.compile(r"^[A-Za-z0-9_-]*$")


class SyncProtocolError(ValueError):
    """A safe, structured protocol error suitable for returning to a client."""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        retryable: bool = False,
        message_id: str | None = None,
        close_code: int | None = None,
    ) -> None:
        if code not in ERROR_CODES:
            raise ValueError(f"unknown sync error code: {code}")
        super().__init__(message)
        self.code = code
        self.message = message
        self.retryable = retryable
        self.message_id = message_id
        self.close_code = close_code

    def as_message(self) -> dict[str, Any]:
        message: dict[str, Any] = {
            "type": "error",
            "code": self.code,
            "message": self.message,
            "retryable": self.retryable,
        }
        if self.message_id is not None:
            message["message_id"] = self.message_id
        return message


@dataclass(frozen=True, slots=True)
class HelloMessage:
    device_id: str
    resume_after: int


@dataclass(frozen=True, slots=True)
class PushMessage:
    message_id: str
    algorithm: str
    nonce: bytes
    ciphertext: bytes
    tag: bytes


@dataclass(frozen=True, slots=True)
class CheckpointMessage:
    server_sequence: int


ClientMessage = HelloMessage | PushMessage | CheckpointMessage


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON number: {value}")


def decode_json_frame(frame: str, *, max_frame_bytes: int) -> dict[str, Any]:
    if len(frame.encode("utf-8")) > max_frame_bytes:
        raise SyncProtocolError(
            "event_too_large",
            "JSON frame exceeds the configured size limit",
            close_code=1009,
        )
    try:
        message = json.loads(frame, parse_constant=_reject_json_constant)
    except (json.JSONDecodeError, UnicodeError, ValueError) as exc:
        raise SyncProtocolError(
            "invalid_message", "message must be valid JSON"
        ) from exc
    if not isinstance(message, dict):
        raise SyncProtocolError("invalid_message", "message must be a JSON object")
    return message


def _required_int(message: dict[str, Any], field: str, *, minimum: int = 0) -> int:
    value = message.get(field)
    if isinstance(value, bool) or not isinstance(value, int):
        raise SyncProtocolError("invalid_message", f"{field} must be an integer")
    if value < minimum or value > MAX_SEQUENCE:
        raise SyncProtocolError(
            "invalid_message", f"{field} is outside the supported range"
        )
    return value


def _protocol_version(message: dict[str, Any]) -> None:
    version = message.get("protocol_version")
    if isinstance(version, bool) or not isinstance(version, int):
        raise SyncProtocolError(
            "protocol_mismatch", "protocol_version 1 is required", close_code=1002
        )
    if version != PROTOCOL_VERSION:
        raise SyncProtocolError(
            "protocol_mismatch",
            "the requested protocol version is not supported",
            close_code=1002,
        )


def _canonical_uuid(value: Any) -> str:
    if not isinstance(value, str):
        raise SyncProtocolError(
            "invalid_message", "message_id must be a canonical UUID"
        )
    try:
        parsed = UUID(value)
    except (ValueError, AttributeError) as exc:
        raise SyncProtocolError(
            "invalid_message", "message_id must be a canonical UUID"
        ) from exc
    if str(parsed) != value:
        raise SyncProtocolError(
            "invalid_message", "message_id must be a canonical lowercase UUID"
        )
    return value


def decode_base64url(value: Any, field: str) -> bytes:
    if not isinstance(value, str) or not _BASE64URL_RE.fullmatch(value):
        raise SyncProtocolError(
            "invalid_message", f"{field} must be unpadded base64url"
        )
    padding = "=" * ((4 - len(value) % 4) % 4)
    try:
        decoded = base64.b64decode(value + padding, altchars=b"-_", validate=True)
    except (binascii.Error, ValueError) as exc:
        raise SyncProtocolError(
            "invalid_message", f"{field} must be unpadded base64url"
        ) from exc
    if encode_base64url(decoded) != value:
        raise SyncProtocolError(
            "invalid_message", f"{field} must use canonical base64url encoding"
        )
    return decoded


def encode_base64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _parse_hello(message: dict[str, Any]) -> HelloMessage:
    _protocol_version(message)
    device_id = message.get("device_id")
    if (
        not isinstance(device_id, str)
        or not device_id
        or len(device_id.encode("utf-8")) > 255
    ):
        raise SyncProtocolError(
            "invalid_message",
            "device_id must be a non-empty string of at most 255 bytes",
        )
    if any(ord(character) < 0x20 for character in device_id):
        raise SyncProtocolError(
            "invalid_message", "device_id contains control characters"
        )
    return HelloMessage(
        device_id=device_id,
        resume_after=_required_int(message, "resume_after", minimum=0),
    )


def _parse_push(message: dict[str, Any], *, max_event_bytes: int) -> PushMessage:
    _protocol_version(message)
    message_id_value = message.get("message_id")
    message_id = _canonical_uuid(message_id_value)
    algorithm = message.get("algorithm")
    if algorithm != SYNC_ALGORITHM:
        raise SyncProtocolError(
            "invalid_message",
            f"algorithm must be {SYNC_ALGORITHM}",
            message_id=message_id,
        )

    try:
        nonce = decode_base64url(message.get("nonce"), "nonce")
        ciphertext = decode_base64url(message.get("ciphertext"), "ciphertext")
        tag = decode_base64url(message.get("tag"), "tag")
    except SyncProtocolError as exc:
        if exc.message_id is None:
            exc.message_id = message_id
        raise

    if len(nonce) != NONCE_BYTES:
        raise SyncProtocolError(
            "invalid_message",
            f"nonce must decode to {NONCE_BYTES} bytes",
            message_id=message_id,
        )
    if len(tag) != TAG_BYTES:
        raise SyncProtocolError(
            "invalid_message",
            f"tag must decode to {TAG_BYTES} bytes",
            message_id=message_id,
        )
    if len(ciphertext) > max_event_bytes:
        raise SyncProtocolError(
            "event_too_large",
            "ciphertext exceeds the configured event size limit",
            message_id=message_id,
        )
    return PushMessage(
        message_id=message_id,
        algorithm=algorithm,
        nonce=nonce,
        ciphertext=ciphertext,
        tag=tag,
    )


def _parse_checkpoint(message: dict[str, Any]) -> CheckpointMessage:
    return CheckpointMessage(
        server_sequence=_required_int(message, "server_sequence", minimum=0)
    )


def parse_client_message(
    message: dict[str, Any], *, max_event_bytes: int
) -> ClientMessage:
    message_type = message.get("type")
    if not isinstance(message_type, str):
        raise SyncProtocolError("invalid_message", "message type is required")

    if message_type == "hello":
        return _parse_hello(message)
    if message_type == "push":
        return _parse_push(message, max_event_bytes=max_event_bytes)
    if message_type == "checkpoint":
        return _parse_checkpoint(message)

    version = message.get("protocol_version")
    if version is not None and version != PROTOCOL_VERSION:
        raise SyncProtocolError(
            "protocol_mismatch", "unsupported protocol version", close_code=1002
        )
    raise SyncProtocolError("invalid_message", "unsupported message type")


def ready_message(
    *, connection_id: str, latest_sequence: int, resume_after: int
) -> dict[str, Any]:
    return {
        "type": "ready",
        "protocol_version": PROTOCOL_VERSION,
        "connection_id": connection_id,
        "latest_sequence": latest_sequence,
        "replay_from": resume_after + 1,
    }


def event_message(
    *,
    server_sequence: int,
    message_id: str,
    sender_device_id: str,
    algorithm: str,
    nonce: bytes,
    ciphertext: bytes,
    tag: bytes,
    accepted_at: datetime,
) -> dict[str, Any]:
    if accepted_at.tzinfo is None:
        accepted_at = accepted_at.replace(tzinfo=UTC)
    return {
        "type": "event",
        "server_sequence": server_sequence,
        "message_id": message_id,
        "sender_device_id": sender_device_id,
        "algorithm": algorithm,
        "nonce": encode_base64url(nonce),
        "ciphertext": encode_base64url(ciphertext),
        "tag": encode_base64url(tag),
        "accepted_at": int(accepted_at.timestamp() * 1000),
    }


def push_ack_message(
    *, message_id: str, server_sequence: int, duplicate: bool
) -> dict[str, Any]:
    return {
        "type": "push_ack",
        "message_id": message_id,
        "server_sequence": server_sequence,
        "duplicate": duplicate,
    }


__all__ = [
    "ERROR_CODES",
    "NONCE_BYTES",
    "PROTOCOL_VERSION",
    "SYNC_ALGORITHM",
    "TAG_BYTES",
    "CheckpointMessage",
    "ClientMessage",
    "HelloMessage",
    "PushMessage",
    "SyncProtocolError",
    "decode_base64url",
    "decode_json_frame",
    "encode_base64url",
    "event_message",
    "parse_client_message",
    "push_ack_message",
    "ready_message",
]
