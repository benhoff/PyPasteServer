"""FastAPI dependency helpers."""
from __future__ import annotations

from typing import Generator, Optional

from fastapi import Depends, Header, HTTPException
from sqlalchemy.orm import Session

from .db import SessionLocal
from .models import User
from .security import decode_token


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_current_user(token: Optional[str] = Header(None), db: Session = Depends(get_db)) -> User:
    if token is None:
        raise HTTPException(status_code=401, detail="Missing token")
    return decode_token(token, db)


__all__ = ["get_db", "get_current_user"]
