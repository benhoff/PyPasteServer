"""Application lifespan management."""
from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI

from .db import Base, engine
from .manager import manager


@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine)
    await manager.start_listening()
    try:
        yield
    finally:
        await manager.shutdown()


__all__ = ["lifespan"]
