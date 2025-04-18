# tests/test_cli.py
import sys
import importlib
from pathlib import Path

import pytest

MODULE_NAME = "cli"  # adjust to your filename (minus .py)

def reload_module(monkeypatch):
    # Unload and re-import so module‑level load_config picks up our HOME
    if MODULE_NAME in sys.modules:
        del sys.modules[MODULE_NAME]
    return importlib.import_module(MODULE_NAME)

def test_load_config_without_create_no_exit(tmp_path, monkeypatch, capsys):
    # Point HOME at an empty temp dir so no config exists
    monkeypatch.setenv("HOME", str(tmp_path))

    app = reload_module(monkeypatch)
    cfg = app.load_config(create_if_missing=False)

    config_path = Path(tmp_path) / ".config" / "clipboard_app" / "config.ini"
    # 1) Should NOT exit
    # 2) Config file should still not exist
    assert not config_path.exists()

    # 3) Should print a warning to stderr about missing file + using default
    out, err = capsys.readouterr()
    expected = f"Configuration file not found at {config_path}. Using default configuration."
    assert expected in err

    # 4) Returned parser has no sections (defaults are applied later via fallback)
    assert cfg.sections() == []

def test_load_config_with_create(tmp_path, monkeypatch, capsys):
    # Point HOME at an empty temp dir
    monkeypatch.setenv("HOME", str(tmp_path))

    app = reload_module(monkeypatch)
    cfg = app.load_config(create_if_missing=True)

    config_path = Path(tmp_path) / ".config" / "clipboard_app" / "config.ini"
    # 1) Config file should now exist
    assert config_path.exists()

    out, err = capsys.readouterr()
    # 2) Should announce creation
    assert f"Configuration file not found at {config_path}. Creating default configuration." in out
    # 3) create_default_config() prints its own message
    assert f"Default configuration file created at {config_path}." in out

    # 4) And the ConfigParser should now have the default section/value
    assert cfg.has_section("Server")
    assert cfg.get("Server", "url") == "http://127.0.0.1:8001"

