"""Daemon package public API."""

from importlib import import_module, reload as _reload

# Modules whose configuration depends on environment variables (e.g. $HOME)
# are reloaded so tests that monkeypatch those vars observe the new values.
constants = _reload(import_module('.constants', __name__))
config = _reload(import_module('.config', __name__))

# Lazily import the remaining submodules.
clipboard_dev = import_module('.clipboard_dev', __name__)
crypto = import_module('.crypto', __name__)
klipper_bus = import_module('.klipper_bus', __name__)
sync_pipeline = import_module('.sync_pipeline', __name__)
util = import_module('.util', __name__)
ws_client = import_module('.ws_client', __name__)

# Reload the legacy monolithic daemon module and re-export its symbols for
# backwards compatibility with callers importing "daemon" directly.
_daemon_module = _reload(import_module('.daemon', __name__))
from .daemon import *  # noqa: F401,F403

__all__ = [
    "clipboard_dev",
    "config",
    "constants",
    "crypto",
    "klipper_bus",
    "sync_pipeline",
    "util",
    "ws_client",
]
