"""Noise-PSK transport over binary WebSocket frames."""

from __future__ import annotations

from typing import Any

from fastapi import WebSocket, WebSocketDisconnect
from noise.connection import NoiseConnection
from noise.exceptions import NoiseHandshakeError, NoiseInvalidMessage

from .sync_protocol import SyncProtocolError

NOISE_PROTOCOL_NAME = b"Noise_NNpsk0_25519_ChaChaPoly_BLAKE2s"
NOISE_TRANSPORT_NAME = "noise-psk-v1"
NOISE_MAX_CIPHERTEXT_BYTES = 65_535
NOISE_TAG_BYTES = 16
CHUNK_HEADER_BYTES = 1
MAX_CHUNK_DATA_BYTES = NOISE_MAX_CIPHERTEXT_BYTES - NOISE_TAG_BYTES - CHUNK_HEADER_BYTES
CHUNK_CONTINUES = 0
CHUNK_FINAL = 1


async def _receive_binary(websocket: WebSocket) -> bytes:
    incoming = await websocket.receive()
    if incoming["type"] == "websocket.disconnect":
        raise WebSocketDisconnect(incoming.get("code", 1000), incoming.get("reason"))
    data = incoming.get("bytes")
    if data is None:
        raise SyncProtocolError(
            "invalid_message", "Noise transport requires binary WebSocket frames"
        )
    return bytes(data)


class PlainWebSocketTransport:
    def __init__(self, websocket: WebSocket) -> None:
        self.websocket = websocket

    async def receive_text(self, *, max_frame_bytes: int) -> str:
        incoming = await self.websocket.receive()
        if incoming["type"] == "websocket.disconnect":
            raise WebSocketDisconnect(
                incoming.get("code", 1000), incoming.get("reason")
            )
        text = incoming.get("text")
        if text is None:
            raise SyncProtocolError(
                "invalid_message", "binary WebSocket frames are not supported"
            )
        if len(text.encode("utf-8")) > max_frame_bytes:
            raise SyncProtocolError(
                "event_too_large", "WebSocket frame exceeds the configured limit"
            )
        return text

    async def send_text(self, value: str) -> None:
        await self.websocket.send_text(value)

    async def close(self, *, code: int = 1000, reason: str = "") -> None:
        await self.websocket.close(code=code, reason=reason)


class NoiseWebSocketTransport:
    def __init__(self, websocket: WebSocket, noise: NoiseConnection) -> None:
        self.websocket = websocket
        self.noise = noise

    @classmethod
    async def handshake(
        cls, websocket: WebSocket, *, psk: bytes
    ) -> NoiseWebSocketTransport:
        if len(psk) != 32:
            raise ValueError("Noise PSK must be exactly 32 bytes")
        noise = NoiseConnection.from_name(NOISE_PROTOCOL_NAME)
        noise.set_as_responder()
        noise.set_psks(psk)
        noise.start_handshake()
        try:
            first = await _receive_binary(websocket)
            noise.read_message(first)
            await websocket.send_bytes(bytes(noise.write_message()))
        except (NoiseHandshakeError, NoiseInvalidMessage, ValueError) as exc:
            raise SyncProtocolError(
                "authentication_failed", "Noise handshake failed", close_code=1008
            ) from exc
        return cls(websocket, noise)

    async def receive_text(self, *, max_frame_bytes: int) -> str:
        plaintext = bytearray()
        while True:
            ciphertext = await _receive_binary(self.websocket)
            if not ciphertext or len(ciphertext) > NOISE_MAX_CIPHERTEXT_BYTES:
                raise SyncProtocolError(
                    "invalid_message", "invalid encrypted transport frame"
                )
            try:
                chunk = bytes(self.noise.decrypt(ciphertext))
            except (NoiseHandshakeError, NoiseInvalidMessage) as exc:
                raise SyncProtocolError(
                    "authentication_failed",
                    "encrypted transport authentication failed",
                    close_code=1008,
                ) from exc
            if not chunk or chunk[0] not in {CHUNK_CONTINUES, CHUNK_FINAL}:
                raise SyncProtocolError(
                    "invalid_message", "invalid encrypted transport chunk"
                )
            plaintext.extend(chunk[1:])
            if len(plaintext) > max_frame_bytes:
                raise SyncProtocolError(
                    "event_too_large", "encrypted message exceeds the configured limit"
                )
            if chunk[0] == CHUNK_FINAL:
                try:
                    return plaintext.decode("utf-8")
                except UnicodeDecodeError as exc:
                    raise SyncProtocolError(
                        "invalid_message", "encrypted message is not UTF-8"
                    ) from exc

    async def send_text(self, value: str) -> None:
        plaintext = value.encode("utf-8")
        # JSON messages are non-empty, but this also makes the framing helper
        # well-defined for an empty string.
        chunks = [
            plaintext[offset : offset + MAX_CHUNK_DATA_BYTES]
            for offset in range(0, len(plaintext), MAX_CHUNK_DATA_BYTES)
        ] or [b""]
        for index, chunk in enumerate(chunks):
            flag = CHUNK_FINAL if index == len(chunks) - 1 else CHUNK_CONTINUES
            ciphertext = self.noise.encrypt(bytes([flag]) + chunk)
            await self.websocket.send_bytes(ciphertext)

    async def close(self, *, code: int = 1000, reason: str = "") -> None:
        await self.websocket.close(code=code, reason=reason)


def transport_requested(headers: Any) -> bool:
    return headers.get("x-kclip-transport", "").lower() == NOISE_TRANSPORT_NAME


__all__ = [
    "CHUNK_CONTINUES",
    "CHUNK_FINAL",
    "MAX_CHUNK_DATA_BYTES",
    "NOISE_PROTOCOL_NAME",
    "NOISE_TRANSPORT_NAME",
    "NoiseWebSocketTransport",
    "PlainWebSocketTransport",
    "transport_requested",
]
