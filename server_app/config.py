"""Application configuration settings."""
from __future__ import annotations

import os

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./clipboard.db")
JWT_SECRET = os.getenv("JWT_SECRET", "supersecretkey")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379")

__all__ = [
    "DATABASE_URL",
    "JWT_SECRET",
    "JWT_ALGORITHM",
    "REDIS_URL",
]
