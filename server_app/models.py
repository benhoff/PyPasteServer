"""SQLAlchemy models for the clipboard service."""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import BigInteger, Boolean, Column, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import relationship

from .db import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(150), unique=True, index=True, nullable=False)
    email = Column(String(255), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    email_authenticated = Column(Boolean, default=False, nullable=False)

    clipboard = relationship("Clipboard", uselist=False, back_populates="owner")
    tokens = relationship("Token", back_populates="user", cascade="all, delete-orphan")


class Clipboard(Base):
    __tablename__ = "clipboards"

    id = Column(Integer, primary_key=True, index=True)
    ciphertext = Column(Text, nullable=False)
    nonce = Column(String(255), nullable=False)
    tag = Column(String(255), nullable=False)
    owner_id = Column(Integer, ForeignKey("users.id"), unique=True, nullable=False)

    owner = relationship("User", back_populates="clipboard")
    metadata_record = relationship(
        "ClipboardMetadata",
        uselist=False,
        back_populates="clipboard",
        cascade="all, delete-orphan",
    )


class ClipboardMetadata(Base):
    __tablename__ = "clipboard_metadata"

    clipboard_id = Column(Integer, ForeignKey("clipboards.id"), primary_key=True)
    ts_ns = Column(BigInteger, nullable=True)
    uid = Column(Integer, nullable=True)
    pid = Column(Integer, nullable=True)
    comm = Column(String(255), nullable=True)

    clipboard = relationship("Clipboard", back_populates="metadata_record")


class Token(Base):
    __tablename__ = "tokens"

    id = Column(Integer, primary_key=True, index=True)
    token = Column(String(512), unique=True, nullable=False)
    jti = Column(String(36), unique=True, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)

    user = relationship("User", back_populates="tokens")


__all__ = ["User", "Clipboard", "ClipboardMetadata", "Token"]
