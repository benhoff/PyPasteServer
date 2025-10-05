import json
import threading
import time

try:
    import websocket  # websocket-client
    WS_OK = True
except Exception:
    WS_OK = False

from .config import TOKEN_FILE, SERVER_URL
from .crypto import encryption_available, encrypt_message, decrypt_message

class WSClient:
    def __init__(self, on_text):
        self.ws = None
        self.stop_event = threading.Event()
        self.on_text = on_text

    def _load_token(self) -> str:
        import json, sys
        try:
            with open(TOKEN_FILE, 'r') as f:
                data = json.load(f)
                return data['access_token']
        except Exception:
            print(f"Token file not found/invalid at {TOKEN_FILE}. Please register or login first.")
            sys.exit(1)

    def _on_open(self, ws):
        print("WebSocket connection established.")

    def _on_message(self, ws, message: str):
        try:
            data = json.loads(message)
        except Exception:
            print(f"Received invalid JSON message: {message}")
            return
        if data.get("type") in ("init", "update") and all(k in data for k in ("nonce", "ciphertext", "tag")):
            text = decrypt_message(data["nonce"], data["ciphertext"], data["tag"]) if encryption_available() else data.get("ciphertext", "")
            meta = data.get("meta") if isinstance(data.get("meta"), dict) else None
            if text:
                self.on_text(text, meta)

    def _on_error(self, ws, error):
        print(f"WebSocket error: {error}")

    def _on_close(self, ws, code, msg):
        print("WebSocket connection closed.")

    def start(self) -> bool:
        if not (WS_OK and encryption_available()):
            print("WebSocket client not started because encryption is unavailable or ws lib missing.")
            return False
        token = self._load_token()
        url = f"ws://{SERVER_URL}/ws?token={token}"
        self.ws = websocket.WebSocketApp(
            url,
            on_open=self._on_open,
            on_message=self._on_message,
            on_error=self._on_error,
            on_close=self._on_close,
        )
        thr = threading.Thread(target=self._run, daemon=True)
        thr.start()
        return True

    def _run(self):
        while not self.stop_event.is_set():
            try:
                self.ws.run_forever()
            except Exception as e:
                print(f"WebSocket connection error: {e}")
            if not self.stop_event.is_set():
                print("Attempting to reconnect WebSocket in 5 seconds...")
                time.sleep(5)

    def send_update(self, text: str, meta: dict | None = None):
        if not (self.ws and self.ws.sock and self.ws.sock.connected):
            return
        msg = encrypt_message(text) if encryption_available() else {"nonce": "", "ciphertext": text, "tag": ""}
        payload = {"type": "update", **msg}
        if meta:
            payload["meta"] = meta
        try:
            self.ws.send(json.dumps(payload))
        except Exception as e:
            print(f"Failed to send clipboard update: {e}")

    def stop(self):
        self.stop_event.set()
        if self.ws:
            self.ws.close()
