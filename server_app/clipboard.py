"""Clipboard persistence helpers."""

from __future__ import annotations

from sqlalchemy.orm import Session

from .models import Clipboard, SyncUserState, User


def initialize_user_clipboard(db: Session, user: User) -> None:
    clipboard = Clipboard(ciphertext="", nonce="", tag="", owner_id=user.id)
    db.add(clipboard)
    if db.get(SyncUserState, user.id) is None:
        db.add(SyncUserState(user_id=user.id, next_server_sequence=1))
    db.commit()
    db.refresh(clipboard)


__all__ = ["initialize_user_clipboard"]
