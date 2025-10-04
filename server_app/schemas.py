"""Pydantic schemas exposed by the API."""
from __future__ import annotations

from pydantic import BaseModel, EmailStr


class UserCreate(BaseModel):
    username: str
    password: str
    email: EmailStr


class ClipboardCreate(BaseModel):
    ciphertext: str
    nonce: str
    tag: str


class ClipboardResponse(BaseModel):
    ciphertext: str
    nonce: str
    tag: str

    class Config:
        orm_mode = True


class TokenSchema(BaseModel):
    access_token: str
    token_type: str


__all__ = [
    "UserCreate",
    "ClipboardCreate",
    "ClipboardResponse",
    "TokenSchema",
]
