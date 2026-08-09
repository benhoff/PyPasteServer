"""Pairing-code encoding and per-device credential persistence."""

from __future__ import annotations

import base64
import binascii
import json
import secrets
from dataclasses import dataclass, field
from datetime import UTC, datetime
from urllib.parse import urlsplit
from uuid import UUID, uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import PairedDevice, User

SETUP_CODE_PREFIX = "kclip-setup-v1"
PAIRING_KEY_BYTES = 32


@dataclass(frozen=True)
class PairingCredential:
    pairing_id: str
    psk: bytes = field(repr=False)


def _decode_pairing_credential(
    pairing_id: object, pairing_secret: object
) -> PairingCredential:
    if not isinstance(pairing_id, str) or not isinstance(pairing_secret, str):
        raise TypeError("invalid pairing credential")
    try:
        canonical_id = str(UUID(pairing_id))
        encoded = pairing_secret.encode("ascii")
        psk = base64.b64decode(
            encoded + b"=" * (-len(encoded) % 4),
            altchars=b"-_",
            validate=True,
        )
    except (ValueError, UnicodeError, binascii.Error) as exc:
        raise ValueError("invalid pairing credential") from exc
    canonical_secret = base64.urlsafe_b64encode(psk).rstrip(b"=").decode("ascii")
    if len(psk) != PAIRING_KEY_BYTES or canonical_secret != pairing_secret:
        raise ValueError("invalid pairing credential")
    return PairingCredential(pairing_id=canonical_id, psk=psk)


def validate_relay_url(value: str) -> str:
    if not isinstance(value, str):
        raise TypeError("invalid relay URL")
    relay_url = value.strip()
    try:
        parsed = urlsplit(relay_url)
        _ = parsed.port
    except ValueError as exc:
        raise ValueError("invalid relay URL") from exc
    if (
        parsed.scheme not in {"ws", "wss"}
        or parsed.hostname is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path != "/sync/v1"
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("relay URL must be ws:// or wss:// and end with /sync/v1")
    return relay_url


@dataclass(frozen=True)
class DeviceSetupCode:
    """Versioned client bootstrap containing routing and one device credential."""

    relay_url: str
    username: str
    device_name: str
    pairing: PairingCredential = field(repr=False)

    def encode(self) -> str:
        payload = json.dumps(
            {
                "device_name": self.device_name,
                "pairing_id": self.pairing.pairing_id,
                "pairing_secret": base64.urlsafe_b64encode(self.pairing.psk)
                .rstrip(b"=")
                .decode("ascii"),
                "relay_url": validate_relay_url(self.relay_url),
                "username": self.username,
                "version": 1,
            },
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        encoded = base64.urlsafe_b64encode(payload).rstrip(b"=").decode("ascii")
        return f"{SETUP_CODE_PREFIX}:{encoded}"

    @classmethod
    def parse(cls, value: str) -> DeviceSetupCode:
        parts = value.strip().split(":", 1)
        if len(parts) != 2 or parts[0] != SETUP_CODE_PREFIX:
            raise ValueError("invalid device setup code")
        try:
            encoded = parts[1].encode("ascii")
            payload = base64.b64decode(
                encoded + b"=" * (-len(encoded) % 4),
                altchars=b"-_",
                validate=True,
            )
            decoded = json.loads(payload)
            if not isinstance(decoded, dict) or set(decoded) != {
                "device_name",
                "pairing_id",
                "pairing_secret",
                "relay_url",
                "username",
                "version",
            }:
                raise ValueError
            if decoded["version"] != 1:
                raise ValueError
            username = decoded["username"]
            device_name = decoded["device_name"]
            if not isinstance(username, str) or not username:
                raise ValueError
            if not isinstance(device_name, str) or not device_name:
                raise ValueError
            pairing = _decode_pairing_credential(
                decoded["pairing_id"], decoded["pairing_secret"]
            )
            relay_url = validate_relay_url(decoded["relay_url"])
        except (
            binascii.Error,
            json.JSONDecodeError,
            TypeError,
            UnicodeDecodeError,
            UnicodeError,
            ValueError,
        ) as exc:
            raise ValueError("invalid device setup code") from exc
        return cls(
            relay_url=relay_url,
            username=username,
            device_name=device_name,
            pairing=pairing,
        )


def create_pairing(
    session: Session, *, user: User, device_name: str
) -> tuple[PairedDevice, PairingCredential]:
    name = device_name.strip()
    if not name or len(name) > 255:
        raise ValueError("device name must contain 1 to 255 characters")
    pairing = PairingCredential(pairing_id=str(uuid4()), psk=secrets.token_bytes(32))
    device = PairedDevice(
        pairing_id=pairing.pairing_id,
        user_id=user.id,
        device_name=name,
        psk=pairing.psk,
    )
    session.add(device)
    session.commit()
    session.refresh(device)
    return device, pairing


def active_pairing(session: Session, pairing_id: str) -> PairedDevice | None:
    try:
        canonical_id = str(UUID(pairing_id))
    except (TypeError, ValueError):
        return None
    return session.scalar(
        select(PairedDevice).where(
            PairedDevice.pairing_id == canonical_id,
            PairedDevice.revoked_at.is_(None),
        )
    )


def mark_pairing_used(session: Session, pairing_id: str) -> bool:
    device = active_pairing(session, pairing_id)
    if device is None:
        return False
    device.last_used_at = datetime.now(UTC)
    session.commit()
    return True


__all__ = [
    "PAIRING_KEY_BYTES",
    "SETUP_CODE_PREFIX",
    "DeviceSetupCode",
    "PairingCredential",
    "active_pairing",
    "create_pairing",
    "mark_pairing_used",
    "validate_relay_url",
]
