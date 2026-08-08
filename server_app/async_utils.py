"""Bounded executor helpers for synchronous database operations."""

from __future__ import annotations

import asyncio
import threading
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from functools import partial
from typing import Any, TypeVar

from .config import SYNC_DATABASE_WORKERS

T = TypeVar("T")
_executor: ThreadPoolExecutor | None = None
_executor_lock = threading.Lock()


def _get_executor() -> ThreadPoolExecutor:
    global _executor
    with _executor_lock:
        if _executor is None:
            _executor = ThreadPoolExecutor(
                max_workers=max(1, SYNC_DATABASE_WORKERS),
                thread_name_prefix="sync-db",
            )
        return _executor


async def run_sync(function: Callable[..., T], *args: Any, **kwargs: Any) -> T:
    """Run bounded blocking work without occupying the event-loop thread."""

    call = partial(function, *args, **kwargs)
    future = asyncio.get_running_loop().run_in_executor(_get_executor(), call)
    # The short timed wait also guarantees a bounded wake-up on runtimes where
    # a lost cross-thread selector notification would otherwise delay the
    # completion callback until the next unrelated I/O event.
    while not future.done():
        await asyncio.wait({future}, timeout=0.01)
    return future.result()


def shutdown_sync_executor() -> None:
    global _executor
    with _executor_lock:
        executor = _executor
        _executor = None
    if executor is not None:
        executor.shutdown(wait=True, cancel_futures=True)


__all__ = ["run_sync", "shutdown_sync_executor"]
