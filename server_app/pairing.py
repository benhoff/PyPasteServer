"""Pairing-code encoding and per-device credential persistence."""

from __future__ import annotations

import base64
import binascii
import secrets
from dataclasses import dataclass, field
from datetime import UTC, datetime
from uuid import UUID, uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import PairedDevice, User

PAIRING_CODE_PREFIX = "kclip-pair-v1"
PAIRING_KEY_BYTES = 32


@dataclass(frozen=True)
class PairingCode:
    pairing_id: str
    psk: bytes = field(repr=False)

    def encode(self) -> str:
        secret = base64.urlsafe_b64encode(self.psk).rstrip(b"=").decode("ascii")
        return f"{PAIRING_CODE_PREFIX}:{self.pairing_id}:{secret}"

    @classmethod
    def parse(cls, value: str) -> PairingCode:
        parts = value.strip().split(":")
        if len(parts) != 3 or parts[0] != PAIRING_CODE_PREFIX:
            raise ValueError("invalid pairing code")
        try:
            pairing_id = str(UUID(parts[1]))
            encoded = parts[2].encode("ascii")
            psk = base64.b64decode(
                encoded + b"=" * (-len(encoded) % 4),
                altchars=b"-_",
                validate=True,
            )
        except (ValueError, UnicodeError, binascii.Error) as exc:
            raise ValueError("invalid pairing code") from exc
        if len(psk) != PAIRING_KEY_BYTES:
            raise ValueError("invalid pairing code")
        return cls(pairing_id=pairing_id, psk=psk)


def create_pairing(
    session: Session, *, user: User, device_name: str
) -> tuple[PairedDevice, PairingCode]:
    name = device_name.strip()
    if not name or len(name) > 255:
        raise ValueError("device name must contain 1 to 255 characters")
    pairing = PairingCode(pairing_id=str(uuid4()), psk=secrets.token_bytes(32))
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
    "PAIRING_CODE_PREFIX",
    "PAIRING_KEY_BYTES",
    "PairingCode",
    "active_pairing",
    "create_pairing",
    "mark_pairing_used",
]
