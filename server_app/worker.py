"""Gunicorn worker configuration with a transport-level frame bound."""

from __future__ import annotations

from typing import Any, ClassVar

from uvicorn.workers import UvicornWorker

from .config import SYNC_MAX_FRAME_BYTES


class SyncUvicornWorker(UvicornWorker):
    CONFIG_KWARGS: ClassVar[dict[str, Any]] = {
        **UvicornWorker.CONFIG_KWARGS,
        "ws_max_size": SYNC_MAX_FRAME_BYTES,
    }


__all__ = ["SyncUvicornWorker"]
