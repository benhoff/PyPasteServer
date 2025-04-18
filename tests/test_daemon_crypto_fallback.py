# tests/test_daemon_crypto_fallback.py
import os
import sys
import importlib
import pytest

MODULE_NAME = "daemon"

def reload_module_with_crypto(monkeypatch):
    """
    Reloads daemon.py such that Crypto imports succeed,
    but the ENC_KEY_FILE lookup will fail (no key on disk).
    """
    # 1) Remove from sys.modules if already loaded
    if MODULE_NAME in sys.modules:
        del sys.modules[MODULE_NAME]

    # 2) Ensure Crypto is present so ENCRYPTION_AVAILABLE starts True
    #    We rely on the real pycryptodome being installed in your venv.
    #    If you need to stub it, you can monkeypatch sys.modules["Crypto"] accordingly.

    # 3) Point HOME at an empty temp dir so ~/.config/clipboard_app/key does NOT exist
    tmp = os.getenv("HOME")
    monkeypatch.setenv("HOME", "/nonexistent/home/for/crypto_test")

    # 4) Finally import
    return importlib.import_module(MODULE_NAME)

def test_missing_key_disables_encryption(monkeypatch):
    # Reload so it tries to load the key and (in the new code) catches the error
    app = reload_module_with_crypto(monkeypatch)

    # After import, ENCRYPTION_AVAILABLE should be False
    assert app.ENCRYPTION_AVAILABLE is False, "Should disable encryption when key file missing"

    # The dummy encrypt_message should just echo the plaintext under 'ciphertext'
    msg = "hello world"
    out = app.encrypt_message(msg)
    assert out["nonce"] == ""
    assert out["ciphertext"] == msg
    assert out["tag"] == ""

    # And decrypt_message should return exactly the ciphertext
    assert app.decrypt_message(out["nonce"], out["ciphertext"], out["tag"]) == msg

