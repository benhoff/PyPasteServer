"""Application factory for the FastAPI clipboard service."""

from __future__ import annotations

from fastapi import FastAPI

from .lifespan import lifespan
from .routes import router as api_router
from .sync_websocket import router as sync_websocket_router
from .websocket import router as websocket_router


def create_app() -> FastAPI:
    app = FastAPI()
    app.include_router(api_router)
    app.include_router(websocket_router)
    app.include_router(sync_websocket_router)
    app.router.lifespan_context = lifespan
    return app


app = create_app()

__all__ = ["create_app", "app"]
