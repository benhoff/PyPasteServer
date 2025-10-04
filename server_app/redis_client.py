"""Redis client initialisation."""
from __future__ import annotations

import redis.asyncio as redis

from .config import REDIS_URL

redis_client = redis.from_url(REDIS_URL, decode_responses=True)

__all__ = ["redis_client"]
