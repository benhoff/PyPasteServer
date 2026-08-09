"""Application configuration settings.

Settings are simple constants populated from environment variables. Sync
limits are byte counts after UTF-8/base64 decoding unless their name explicitly
contains ``FRAME``.
"""

from __future__ import annotations

import os


def _get_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _get_nonnegative_int(name: str, default: int) -> int:
    value = os.getenv(name)
    if value is None:
        return default
    parsed = int(value)
    if parsed < 0:
        raise ValueError(f"{name} must not be negative")
    return parsed


DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./clipboard.db")
REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379")

SYNC_ENABLED = _get_bool("SYNC_ENABLED", True)
RUN_DATABASE_MIGRATIONS_ON_STARTUP = _get_bool(
    "RUN_DATABASE_MIGRATIONS_ON_STARTUP", True
)

# Protocol/resource limits.  A 16 MiB JSON frame accommodates kclipd's 10 MiB
# plaintext default after base64url expansion.
SYNC_MAX_FRAME_BYTES = _get_nonnegative_int("SYNC_MAX_FRAME_BYTES", 16 * 1024 * 1024)
SYNC_MAX_EVENT_BYTES = _get_nonnegative_int("SYNC_MAX_EVENT_BYTES", 11 * 1024 * 1024)
SYNC_REPLAY_BATCH_SIZE = _get_nonnegative_int("SYNC_REPLAY_BATCH_SIZE", 500)
SYNC_MAX_QUEUE_BYTES = _get_nonnegative_int("SYNC_MAX_QUEUE_BYTES", 32 * 1024 * 1024)
SYNC_MAX_INVALID_MESSAGES = _get_nonnegative_int("SYNC_MAX_INVALID_MESSAGES", 3)
SYNC_HELLO_TIMEOUT_SECONDS = _get_nonnegative_int("SYNC_HELLO_TIMEOUT_SECONDS", 15)
SYNC_DATABASE_WORKERS = _get_nonnegative_int("SYNC_DATABASE_WORKERS", 8)

# A zero quota disables that quota.  Rate limiting is enabled by default and is
# enforced from the durable event log while sequence allocation is serialized.
SYNC_ACCOUNT_MAX_EVENTS = _get_nonnegative_int("SYNC_ACCOUNT_MAX_EVENTS", 0)
SYNC_ACCOUNT_MAX_STORAGE_BYTES = _get_nonnegative_int(
    "SYNC_ACCOUNT_MAX_STORAGE_BYTES", 0
)
SYNC_RATE_LIMIT_EVENTS = _get_nonnegative_int("SYNC_RATE_LIMIT_EVENTS", 120)
SYNC_RATE_LIMIT_WINDOW_SECONDS = _get_nonnegative_int(
    "SYNC_RATE_LIMIT_WINDOW_SECONDS", 60
)
SYNC_REDIS_PUBLISH_TIMEOUT_SECONDS = _get_nonnegative_int(
    "SYNC_REDIS_PUBLISH_TIMEOUT_SECONDS", 2
)

# The relay is a lossy synchronization buffer rather than permanent clipboard
# history.  Each non-zero limit is enforced independently and the oldest
# account events are removed until every enabled limit is satisfied.
SYNC_RETENTION_MAX_AGE_SECONDS = _get_nonnegative_int(
    "SYNC_RETENTION_MAX_AGE_SECONDS", 7 * 24 * 60 * 60
)
SYNC_RETENTION_MAX_EVENTS = _get_nonnegative_int("SYNC_RETENTION_MAX_EVENTS", 1000)
SYNC_RETENTION_MAX_STORAGE_BYTES = _get_nonnegative_int(
    "SYNC_RETENTION_MAX_STORAGE_BYTES", 128 * 1024 * 1024
)
SYNC_RETENTION_CLEANUP_INTERVAL_SECONDS = _get_nonnegative_int(
    "SYNC_RETENTION_CLEANUP_INTERVAL_SECONDS", 60 * 60
)


def validate_settings() -> None:
    if SYNC_ENABLED:
        positive_settings = {
            "SYNC_MAX_FRAME_BYTES": SYNC_MAX_FRAME_BYTES,
            "SYNC_MAX_EVENT_BYTES": SYNC_MAX_EVENT_BYTES,
            "SYNC_REPLAY_BATCH_SIZE": SYNC_REPLAY_BATCH_SIZE,
            "SYNC_MAX_QUEUE_BYTES": SYNC_MAX_QUEUE_BYTES,
            "SYNC_MAX_INVALID_MESSAGES": SYNC_MAX_INVALID_MESSAGES,
            "SYNC_HELLO_TIMEOUT_SECONDS": SYNC_HELLO_TIMEOUT_SECONDS,
            "SYNC_DATABASE_WORKERS": SYNC_DATABASE_WORKERS,
            "SYNC_REDIS_PUBLISH_TIMEOUT_SECONDS": SYNC_REDIS_PUBLISH_TIMEOUT_SECONDS,
            "SYNC_RETENTION_CLEANUP_INTERVAL_SECONDS": (
                SYNC_RETENTION_CLEANUP_INTERVAL_SECONDS
            ),
        }
        for name, value in positive_settings.items():
            if value < 1:
                raise RuntimeError(
                    f"{name} must be greater than zero when sync is enabled"
                )
        if SYNC_MAX_QUEUE_BYTES < SYNC_MAX_FRAME_BYTES:
            raise RuntimeError(
                "SYNC_MAX_QUEUE_BYTES must be at least SYNC_MAX_FRAME_BYTES"
            )
        encoded_event_bytes = 4 * ((SYNC_MAX_EVENT_BYTES + 2) // 3)
        if encoded_event_bytes + 1024 > SYNC_MAX_FRAME_BYTES:
            raise RuntimeError(
                "SYNC_MAX_FRAME_BYTES must accommodate the base64url event envelope"
            )
        if SYNC_RATE_LIMIT_EVENTS and SYNC_RATE_LIMIT_WINDOW_SECONDS < 1:
            raise RuntimeError(
                "SYNC_RATE_LIMIT_WINDOW_SECONDS must be positive when rate "
                "limiting is enabled"
            )


__all__ = [
    "DATABASE_URL",
    "REDIS_URL",
    "RUN_DATABASE_MIGRATIONS_ON_STARTUP",
    "SYNC_ACCOUNT_MAX_EVENTS",
    "SYNC_ACCOUNT_MAX_STORAGE_BYTES",
    "SYNC_DATABASE_WORKERS",
    "SYNC_ENABLED",
    "SYNC_HELLO_TIMEOUT_SECONDS",
    "SYNC_MAX_EVENT_BYTES",
    "SYNC_MAX_FRAME_BYTES",
    "SYNC_MAX_INVALID_MESSAGES",
    "SYNC_MAX_QUEUE_BYTES",
    "SYNC_RATE_LIMIT_EVENTS",
    "SYNC_RATE_LIMIT_WINDOW_SECONDS",
    "SYNC_REDIS_PUBLISH_TIMEOUT_SECONDS",
    "SYNC_REPLAY_BATCH_SIZE",
    "SYNC_RETENTION_CLEANUP_INTERVAL_SECONDS",
    "SYNC_RETENTION_MAX_AGE_SECONDS",
    "SYNC_RETENTION_MAX_EVENTS",
    "SYNC_RETENTION_MAX_STORAGE_BYTES",
    "validate_settings",
]
