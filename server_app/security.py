"""Authentication helpers for password hashing and JWT handling."""
from __future__ import annotations

import uuid

from fastapi import HTTPException
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy.orm import Session

from .config import JWT_ALGORITHM, JWT_SECRET
from .models import Token, User

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def create_access_token(data: dict, db: Session) -> str:
    payload = data.copy()
    jti = str(uuid.uuid4())
    payload.update({"jti": jti})
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

    token_entry = Token(token=token, jti=jti, user_id=data["user_id"])
    db.add(token_entry)
    db.commit()

    return token


def decode_token(token: str, db: Session) -> User:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except JWTError as exc:
        raise HTTPException(status_code=401, detail="Invalid token") from exc

    username: str | None = payload.get("sub")
    jti: str | None = payload.get("jti")
    if username is None or jti is None:
        raise HTTPException(status_code=401, detail="Invalid token")

    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(status_code=401, detail="Invalid user")

    token_entry = db.query(Token).filter(Token.jti == jti, Token.user_id == user.id).first()
    if not token_entry:
        raise HTTPException(status_code=401, detail="Token has been revoked or is invalid")

    return user


__all__ = [
    "get_password_hash",
    "verify_password",
    "create_access_token",
    "decode_token",
]
