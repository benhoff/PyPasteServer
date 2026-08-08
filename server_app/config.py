"""Application configuration settings.

The module intentionally keeps settings as simple constants so existing
deployments can continue configuring the application exclusively through
environment variables.  Sync limits are byte counts after UTF-8/base64
decoding unless their name explicitly contains ``FRAME``.
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


APP_ENV = os.getenv("APP_ENV", "development").strip().lower()
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./clipboard.db")
DEFAULT_JWT_SECRET = "supersecretkey"
JWT_SECRET = os.getenv("JWT_SECRET", DEFAULT_JWT_SECRET)
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379")

# Migration switches.  Query-string bearer tokens are off by default because
# URLs are routinely retained by access logs and reverse proxies.
SYNC_ENABLED = _get_bool("SYNC_ENABLED", True)
SYNC_ALLOW_QUERY_TOKEN = _get_bool("SYNC_ALLOW_QUERY_TOKEN", False)
SYNC_REQUIRE_TLS = _get_bool("SYNC_REQUIRE_TLS", False)
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

    if APP_ENV == "production":
        if JWT_SECRET == DEFAULT_JWT_SECRET or len(JWT_SECRET) < 32:
            raise RuntimeError(
                "production requires a non-default JWT_SECRET of at least 32 characters"
            )
        if SYNC_ENABLED and not SYNC_REQUIRE_TLS:
            raise RuntimeError("production sync requires SYNC_REQUIRE_TLS=true")


__all__ = [
    "APP_ENV",
    "DATABASE_URL",
    "DEFAULT_JWT_SECRET",
    "JWT_SECRET",
    "JWT_ALGORITHM",
    "REDIS_URL",
    "SYNC_ENABLED",
    "SYNC_ALLOW_QUERY_TOKEN",
    "SYNC_REQUIRE_TLS",
    "RUN_DATABASE_MIGRATIONS_ON_STARTUP",
    "SYNC_MAX_FRAME_BYTES",
    "SYNC_MAX_EVENT_BYTES",
    "SYNC_REPLAY_BATCH_SIZE",
    "SYNC_MAX_QUEUE_BYTES",
    "SYNC_MAX_INVALID_MESSAGES",
    "SYNC_HELLO_TIMEOUT_SECONDS",
    "SYNC_DATABASE_WORKERS",
    "SYNC_ACCOUNT_MAX_EVENTS",
    "SYNC_ACCOUNT_MAX_STORAGE_BYTES",
    "SYNC_RATE_LIMIT_EVENTS",
    "SYNC_RATE_LIMIT_WINDOW_SECONDS",
    "SYNC_REDIS_PUBLISH_TIMEOUT_SECONDS",
    "validate_settings",
]
