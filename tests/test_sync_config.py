from __future__ import annotations

import pytest

from server_app import config


def test_production_requires_nondefault_secret_and_tls(monkeypatch) -> None:
    monkeypatch.setattr(config, "APP_ENV", "production")
    monkeypatch.setattr(config, "JWT_SECRET", config.DEFAULT_JWT_SECRET)
    monkeypatch.setattr(config, "SYNC_ENABLED", True)
    monkeypatch.setattr(config, "SYNC_REQUIRE_TLS", False)
    with pytest.raises(RuntimeError, match="JWT_SECRET"):
        config.validate_settings()

    monkeypatch.setattr(config, "JWT_SECRET", "x" * 32)
    monkeypatch.setattr(config, "SYNC_ALLOW_LEGACY_BEARER", True)
    with pytest.raises(RuntimeError, match="TLS"):
        config.validate_settings()

    monkeypatch.setattr(config, "SYNC_ALLOW_LEGACY_BEARER", False)
    config.validate_settings()

    monkeypatch.setattr(config, "SYNC_REQUIRE_TLS", True)
    config.validate_settings()


def test_queue_must_hold_at_least_one_maximum_frame(monkeypatch) -> None:
    monkeypatch.setattr(config, "APP_ENV", "development")
    monkeypatch.setattr(config, "SYNC_ENABLED", True)
    monkeypatch.setattr(config, "SYNC_MAX_FRAME_BYTES", 1024)
    monkeypatch.setattr(config, "SYNC_MAX_QUEUE_BYTES", 1023)
    with pytest.raises(RuntimeError, match="QUEUE"):
        config.validate_settings()


def test_frame_must_accommodate_base64url_event(monkeypatch) -> None:
    monkeypatch.setattr(config, "APP_ENV", "development")
    monkeypatch.setattr(config, "SYNC_ENABLED", True)
    monkeypatch.setattr(config, "SYNC_MAX_FRAME_BYTES", 1024)
    monkeypatch.setattr(config, "SYNC_MAX_QUEUE_BYTES", 2048)
    monkeypatch.setattr(config, "SYNC_MAX_EVENT_BYTES", 1024)
    with pytest.raises(RuntimeError, match="base64url"):
        config.validate_settings()


def test_retention_cleanup_interval_must_be_positive(monkeypatch) -> None:
    monkeypatch.setattr(config, "APP_ENV", "development")
    monkeypatch.setattr(config, "SYNC_ENABLED", True)
    monkeypatch.setattr(config, "SYNC_RETENTION_CLEANUP_INTERVAL_SECONDS", 0)
    with pytest.raises(RuntimeError, match="RETENTION_CLEANUP"):
        config.validate_settings()
