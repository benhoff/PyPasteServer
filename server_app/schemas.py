"""Pydantic schemas exposed by the API."""
from __future__ import annotations

from pydantic import BaseModel, EmailStr


class UserCreate(BaseModel):
    username: str
    password: str
    email: EmailStr


class ClipboardMeta(BaseModel):
    ts_ns: int | None = None
    uid: int | None = None
    pid: int | None = None
    comm: str | None = None


class ClipboardCreate(BaseModel):
    ciphertext: str
    nonce: str
    tag: str
    meta: ClipboardMeta | None = None


class ClipboardResponse(BaseModel):
    ciphertext: str
    nonce: str
    tag: str
    meta: ClipboardMeta | None = None

    class Config:
        from_attributes = True



class TokenSchema(BaseModel):
    access_token: str
    token_type: str


__all__ = [
    "UserCreate",
    "ClipboardCreate",
    "ClipboardResponse",
    "ClipboardMeta",
    "TokenSchema",
]
