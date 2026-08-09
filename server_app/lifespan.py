"""Application lifespan management."""

from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI

from .async_utils import run_sync, shutdown_sync_executor
from .config import RUN_DATABASE_MIGRATIONS_ON_STARTUP, validate_settings
from .migrations import run_migrations
from .redis_client import redis_client
from .sync_manager import sync_manager
from .sync_retention import sync_retention_worker


@asynccontextmanager
async def lifespan(app: FastAPI):
    validate_settings()
    if RUN_DATABASE_MIGRATIONS_ON_STARTUP:
        await run_sync(run_migrations)
    await sync_manager.start_listening()
    await sync_retention_worker.start()
    try:
        yield
    finally:
        await sync_retention_worker.shutdown()
        await sync_manager.shutdown()
        try:
            await redis_client.aclose()
        except AttributeError:  # redis-py 4 compatibility
            await redis_client.close()
        shutdown_sync_executor()


__all__ = ["lifespan"]
