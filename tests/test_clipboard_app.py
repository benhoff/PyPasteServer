# tests/test_daemon.py
import os
import sys
import importlib
import errno
import pytest

MODULE_NAME = "daemon"

def reload_module(monkeypatch, *, fake_crypto=True, enc_key_path=None):
    """
    Reloads daemon.py, stubbing Crypto by default so we skip load_encryption_key.
    Pass enc_key_path to enable real-encryption branches and ensure the key-file
    lookup succeeds by pointing HOME at the temp root.
    """
    # 1) Unload if already imported
    if MODULE_NAME in sys.modules:
        del sys.modules[MODULE_NAME]

    # 2) Stub Crypto entirely if needed (disable encryption path)
    if fake_crypto:
        for mod in ("Crypto", "Crypto.Cipher", "Crypto.Random"):
            monkeypatch.setitem(sys.modules, mod, None)

    # 3) For real encryption tests, inject a minimal Crypto and point HOME correctly
    if enc_key_path:
        import types
        from Crypto.Cipher import ChaCha20_Poly1305
        from Crypto.Random import get_random_bytes

        fake_crypto_mod = types.ModuleType("Crypto")
        fake_crypto_mod.Cipher = types.ModuleType("Crypto.Cipher")
        fake_crypto_mod.Cipher.ChaCha20_Poly1305 = ChaCha20_Poly1305
        fake_crypto_mod.Random = types.ModuleType("Crypto.Random")
        fake_crypto_mod.Random.get_random_bytes = get_random_bytes

        monkeypatch.setitem(sys.modules, "Crypto", fake_crypto_mod)
        monkeypatch.setitem(sys.modules, "Crypto.Cipher", fake_crypto_mod.Cipher)
        monkeypatch.setitem(sys.modules, "Crypto.Random", fake_crypto_mod.Random)

        # Compute the temp HOME: key path is tmp/.config/clipboard_app/key
        # We need HOME=tmp (i.e. two levels up from key)
        temp_home = enc_key_path.parents[2]
        monkeypatch.setenv("HOME", str(temp_home))

    # 4) Finally import (or re-import) the module under test
    return importlib.import_module(MODULE_NAME)


def test_strip_http_prefix(monkeypatch):
    app = reload_module(monkeypatch)
    assert app.strip_http_prefix("https://foo.com") == "foo.com"
    assert app.strip_http_prefix("http://bar.org/path") == "bar.org/path"
    assert app.strip_http_prefix("example.net") == "example.net"


def test_load_config_override(tmp_path, monkeypatch):
    # Fake HOME so load_config looks in tmp_path/.config/clipboard_app
    monkeypatch.setenv("HOME", str(tmp_path))

    # Write an override config.ini
    cfg_dir = tmp_path / ".config" / "clipboard_app"
    cfg_dir.mkdir(parents=True, exist_ok=True)
    (cfg_dir / "config.ini").write_text(
        "[Server]\nurl = https://override.server.test\n"
    )

    app = reload_module(monkeypatch)
    cfg = app.load_config()
    assert cfg.get("Server", "url") == "https://override.server.test"


def test_read_all_success(monkeypatch):
    app = reload_module(monkeypatch)

    chunks = [b"hello ", b"world", b""]
    def fake_read(fd, size):
        return chunks.pop(0)

    monkeypatch.setattr(os, "read", fake_read)
    result = app.read_all(fd=0)
    assert result == "hello world"


def test_read_all_ewouldblock(monkeypatch):
    app = reload_module(monkeypatch)

    def raise_eagain(fd, size):
        raise OSError(errno.EAGAIN, "Resource temporarily unavailable")

    monkeypatch.setattr(os, "read", raise_eagain)

    calls = {"count": 0}
    def fake_timeout_add(delay, cb):
        calls["count"] += 1
        return 1

    monkeypatch.setattr(app.GLib, "timeout_add", fake_timeout_add)
    result = app.read_all(fd=0, retry_count=1)
    assert result == ""
    assert calls["count"] == 1

def test_setup_clipboard_device_handles_missing_device(monkeypatch, capsys):
    """
    If os.open('/dev/clipboard') raises ENOENT, setup_clipboard_device()
    should catch it, print an error, and NOT call sys.exit (so the app keeps running).
    """
    # Reload the module so we have a clean state
    app = reload_module(monkeypatch)

    # Stub os.open to simulate "No such file or directory"
    import errno
    def fake_open(path, flags):
        raise OSError(errno.ENOENT, f"No such file or directory: '{path}'")
    monkeypatch.setattr(app.os, "open", fake_open)

    # Replace sys.exit with a recorder so it doesn't actually exit
    exit_called = {"called": False}
    monkeypatch.setattr(app.sys, "exit", lambda code=1: exit_called.__setitem__("called", True))

    # Call the function under test
    app.setup_clipboard_device()

    # It should have printed the failure message...
    captured = capsys.readouterr()
    assert "Failed to open /dev/clipboard" in captured.err

    # ...but not actually called sys.exit
    assert exit_called["called"] is False


def test_load_token_success(tmp_path, monkeypatch):
    # Create token.json under tmp/.config/clipboard_app
    token_dir = tmp_path / ".config" / "clipboard_app"
    token_dir.mkdir(parents=True, exist_ok=True)
    (token_dir / "token.json").write_text('{"access_token":"XYZ"}')

    monkeypatch.setenv("HOME", str(tmp_path))
    app = reload_module(monkeypatch)
    assert app.load_token() == "XYZ"


def test_load_token_missing(monkeypatch):
    app = reload_module(monkeypatch)
    monkeypatch.setattr(app, "TOKEN_FILE", "/does/not/exist.json")
    with pytest.raises(SystemExit):
        app.load_token()


def test_encrypt_decrypt_roundtrip(tmp_path, monkeypatch):
    # Prepare a valid 32-byte key at tmp/.config/clipboard_app/key
    key_path = tmp_path / ".config" / "clipboard_app" / "key"
    key_path.parent.mkdir(parents=True, exist_ok=True)
    key_path.write_bytes(os.urandom(32))

    # Reload with real‑encryption enabled
    app = reload_module(monkeypatch, fake_crypto=False, enc_key_path=key_path)

    if not getattr(app, "ENCRYPTION_AVAILABLE", False):
        pytest.skip("Crypto library path not enabled")

    plaintext = "secret 😀"
    blob = app.encrypt_message(plaintext)
    decrypted = app.decrypt_message(blob["nonce"], blob["ciphertext"], blob["tag"])
    assert decrypted == plaintext

