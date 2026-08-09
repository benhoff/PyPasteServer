"""Automatic cleanup for the lossy encrypted sync event buffer."""

from __future__ import annotations

import asyncio
import logging

from . import config
from .async_utils import run_sync
from .sync_service import RetentionPolicy, sync_store

logger = logging.getLogger(__name__)


def configured_retention_policy() -> RetentionPolicy:
    return RetentionPolicy(
        max_age_seconds=config.SYNC_RETENTION_MAX_AGE_SECONDS,
        max_events=config.SYNC_RETENTION_MAX_EVENTS,
        max_storage_bytes=config.SYNC_RETENTION_MAX_STORAGE_BYTES,
    )


class SyncRetentionWorker:
    def __init__(self) -> None:
        self._task: asyncio.Task[None] | None = None

    async def start(self) -> None:
        if not config.SYNC_ENABLED:
            return
        if self._task is None or self._task.done():
            self._task = asyncio.create_task(self._run(), name="sync-retention-cleanup")

    async def _run(self) -> None:
        while True:
            try:
                result = await run_sync(
                    sync_store.prune_all, configured_retention_policy()
                )
                if result.deleted_events:
                    logger.info(
                        "expired sync relay events",
                        extra={
                            "deleted_events": result.deleted_events,
                            "deleted_bytes": result.deleted_bytes,
                        },
                    )
            except asyncio.CancelledError:
                raise
            # Cleanup is maintenance work: an unexpected backend failure must
            # not terminate the worker or the application lifespan.
            except Exception as error:  # noqa: BLE001
                logger.error(
                    "sync retention cleanup failed",
                    extra={"error_type": type(error).__name__},
                )
            await asyncio.sleep(max(1, config.SYNC_RETENTION_CLEANUP_INTERVAL_SECONDS))

    async def shutdown(self) -> None:
        task = self._task
        self._task = None
        if task is not None:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)


sync_retention_worker = SyncRetentionWorker()

__all__ = [
    "SyncRetentionWorker",
    "configured_retention_policy",
    "sync_retention_worker",
]
