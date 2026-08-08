"""Helpers for applying the application's versioned database migrations."""

from __future__ import annotations

import sys
from pathlib import Path

from alembic import command
from alembic.config import Config

from .db import engine


def _migration_root() -> Path:
    source_root = Path(__file__).resolve().parent.parent
    installed_root = Path(sys.prefix) / "share" / "pypasteserver"
    for root in (source_root, installed_root):
        if (root / "alembic.ini").is_file() and (root / "migrations").is_dir():
            return root
    raise RuntimeError("PyPasteServer migration resources are not installed")


def alembic_config() -> Config:
    root = _migration_root()
    config = Config(str(root / "alembic.ini"))
    config.set_main_option("script_location", str(root / "migrations"))
    return config


def run_migrations() -> None:
    """Upgrade the configured database to the latest committed revision."""

    config = alembic_config()
    with engine.begin() as connection:
        config.attributes["connection"] = connection
        command.upgrade(config, "head")


__all__ = ["alembic_config", "run_migrations"]
