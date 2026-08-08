"""Pydantic schemas exposed by the API."""
from __future__ import annotations

from pydantic import BaseModel, EmailStr, field_validator


class UserCreate(BaseModel):
    username: str
    password: str
    email: EmailStr

    @field_validator("password")
    @classmethod
    def validate_bcrypt_length(cls, password: str) -> str:
        if not password or len(password.encode("utf-8")) > 72:
            raise ValueError("password must contain between 1 and 72 UTF-8 bytes")
        return password


class TokenSchema(BaseModel):
    access_token: str
    token_type: str


__all__ = [
    "UserCreate",
    "TokenSchema",
]
