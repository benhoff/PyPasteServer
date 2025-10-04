from __future__ import annotations

import importlib
import sys
import types
from pathlib import Path
from types import SimpleNamespace

import pytest


def reload_cli_modules(monkeypatch: pytest.MonkeyPatch, home_dir: Path):
    monkeypatch.setenv("HOME", str(home_dir))

    to_delete = [name for name in sys.modules if name == "cli" or name.startswith("cli.")]
    for name in to_delete:
        del sys.modules[name]

    class FakeMnemonic:
        def __init__(self, _language: str):
            self.language = _language

        def generate(self, *_, **__):  # pragma: no cover - simple stub
            return "stub mnemonic"

        def to_entropy(self, mnemonic: str):  # pragma: no cover - simple stub
            return mnemonic.encode()

        def to_mnemonic(self, entropy: bytes):  # pragma: no cover - simple stub
            return entropy.decode()

        def check(self, mnemonic: str) -> bool:  # pragma: no cover - simple stub
            return bool(mnemonic)

    mnemonic_stub = types.ModuleType("mnemonic")
    mnemonic_stub.Mnemonic = FakeMnemonic
    sys.modules["mnemonic"] = mnemonic_stub

    config = importlib.import_module("cli.config")
    commands = importlib.import_module("cli.commands")
    return config, commands


def test_load_config_without_create(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys):
    home_dir = tmp_path / "home_no_create"
    home_dir.mkdir()

    config_module, _ = reload_cli_modules(monkeypatch, home_dir)

    cfg = config_module.load_config(create_if_missing=False)

    config_path = home_dir / ".config" / "clipboard_app" / "config.ini"
    assert not config_path.exists()

    out, err = capsys.readouterr()
    expected = f"Configuration file not found at {config_path}. Using default configuration."
    assert expected in err
    assert out == ""
    assert cfg.sections() == []


def test_load_config_with_create(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys):
    home_dir = tmp_path / "home_create"
    home_dir.mkdir()

    config_module, _ = reload_cli_modules(monkeypatch, home_dir)

    cfg = config_module.load_config(create_if_missing=True)

    config_path = home_dir / ".config" / "clipboard_app" / "config.ini"
    assert config_path.exists()

    out, err = capsys.readouterr()
    assert err == ""
    assert f"Configuration file not found at {config_path}. Creating default configuration." in out
    assert f"Default configuration file created at {config_path}." in out
    assert cfg.has_section("Server")
    assert cfg.get("Server", "url") == "http://127.0.0.1:8001"


def test_register_command_creates_token_and_key(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys):
    home_dir = tmp_path / "home_register"
    home_dir.mkdir()

    config_module, commands = reload_cli_modules(monkeypatch, home_dir)

    server_url = "http://example.com"
    token_file = tmp_path / "token.json"
    key_file = tmp_path / "key"

    args = SimpleNamespace(server=server_url, token_file=token_file, key_file=key_file)

    user_payload = {"username": "alice", "email": "alice@example.com", "password": "secret"}
    captured = {}

    def fake_prompt():
        captured["prompt"] = True
        return user_payload

    def fake_register(server, data):
        captured["register"] = (server, data)
        return "abc123"

    def fake_generate(path):
        captured["mnemonic"] = path
        return "mnemonic"

    def fake_save_json(data, path):
        captured["save_json"] = (data, path)

    monkeypatch.setattr(commands, "prompt_user_details", fake_prompt)
    monkeypatch.setattr(commands, "register_user", fake_register)
    monkeypatch.setattr(commands, "generate_and_save_mnemonic", fake_generate)
    monkeypatch.setattr(commands, "save_json_data", fake_save_json)

    commands.register_command(args)

    config_path = config_module.DEFAULT_CONFIG_PATH
    assert config_path.exists()

    assert captured["prompt"] is True
    assert captured["register"] == (server_url, user_payload)
    assert captured["mnemonic"] == key_file
    assert captured["save_json"] == ({"access_token": "abc123"}, token_file)

    out, err = capsys.readouterr()
    assert "Registration successful." in out
    assert err == ""
