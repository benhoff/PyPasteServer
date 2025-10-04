"""Clipboard persistence helpers."""
from __future__ import annotations

from sqlalchemy.orm import Session

from .models import Clipboard, User


def initialize_user_clipboard(db: Session, user: User) -> None:
    clipboard = Clipboard(ciphertext="", nonce="", tag="", owner_id=user.id)
    db.add(clipboard)
    db.commit()
    db.refresh(clipboard)


__all__ = ["initialize_user_clipboard"]
