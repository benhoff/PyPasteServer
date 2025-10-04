from __future__ import annotations
import base64
from typing import Dict, Optional

try:
    from Crypto.Cipher import ChaCha20_Poly1305
    from Crypto.Random import get_random_bytes
    CRYPTO_OK = True
except Exception:
    CRYPTO_OK = False

from .config import ENC_KEY_FILE, NONCE_SIZE

_key: Optional[bytes] = None


def _load_key() -> Optional[bytes]:
    global _key
    if _key is not None:
        return _key
    try:
        with open(ENC_KEY_FILE, 'rb') as f:
            k = f.read()
        if len(k) != 32:
            print(f"Invalid encryption key length in {ENC_KEY_FILE}. Expected 32 bytes.")
            return None
        _key = k
        return _key
    except FileNotFoundError:
        print(f"Encryption key file not found at {ENC_KEY_FILE}. Disabling WebSocket sync.")
        print("run python cli.py register, to create the default configuration file")
        return None
    except Exception as e:
        print(f"Error loading encryption key: {e}. Disabling WebSocket sync.")
        return None


def encryption_available() -> bool:
    return CRYPTO_OK and _load_key() is not None


def encrypt_message(message: str) -> Dict[str, str]:
    if not encryption_available():
        return {"nonce": "", "ciphertext": message, "tag": ""}
    nonce = get_random_bytes(NONCE_SIZE)
    cipher = ChaCha20_Poly1305.new(key=_load_key(), nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(message.encode())
    return {
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "tag": base64.b64encode(tag).decode(),
    }


def decrypt_message(nonce_b64: str, ciphertext_b64: str, tag_b64: str) -> str:
    if not encryption_available():
        return ciphertext_b64
    try:
        nonce = base64.b64decode(nonce_b64)
        ciphertext = base64.b64decode(ciphertext_b64)
        tag = base64.b64decode(tag_b64)
        cipher = ChaCha20_Poly1305.new(key=_load_key(), nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext.decode()
    except Exception as e:
        print(f"Decryption failed: {e}")
        return ""

