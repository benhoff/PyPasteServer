#!/usr/bin/env python3
import sys
import dbus
import dbus.mainloop.glib
import os
import fcntl
import signal
from gi.repository import GLib
import errno
import json
import threading
import time
import configparser
from pathlib import Path

# Attempt to import Crypto libraries
try:
    from Crypto.Cipher import ChaCha20_Poly1305
    from Crypto.Random import get_random_bytes
    import base64
    ENCRYPTION_AVAILABLE = True
except ImportError:
    print("Crypto library not found. WebSocket synchronization will be disabled. "
          "Install 'pycryptodome' to enable encryption and WebSocket features.", file=sys.stderr)
    ENCRYPTION_AVAILABLE = False

# Attempt to import websocket library if encryption is available
if ENCRYPTION_AVAILABLE:
    try:
        import websocket
    except ImportError:
        print("WebSocket library not found. WebSocket synchronization will be disabled. "
              "Install 'websocket-client' to enable WebSocket features.", file=sys.stderr)
        ENCRYPTION_AVAILABLE = False

# Define default configuration values
DEFAULT_CONFIG = {
    'Paths': {
        'token_file': '~/.config/clipboard_app/token.json',
        'enc_key_file': '~/.config/clipboard_app/key'
    },
    'Server': {
        'url': 'https://default.server.com'
    },
    'Encryption': {
        'nonce_size': '24'
    },
    'Retry': {
        'max_retries': '5'
    }
}

# Load Configuration
def load_config():
    """
    Loads the configuration from the config.ini file.
    If the configuration file is missing or invalid, defaults are used.
    
    Returns:
        configparser.ConfigParser: The loaded or default configuration.
    """
    config = configparser.ConfigParser()
    config.read_dict(DEFAULT_CONFIG)  # Load defaults first
    config_path = os.path.expanduser("~/.config/clipboard_app/config.ini")
    
    if os.path.exists(config_path):
        try:
            config.read(config_path)
            print(f"Configuration loaded from {config_path}.")
        except configparser.Error as e:
            print(f"Error parsing configuration file: {e}", file=sys.stderr)
            print("Using default configuration values.", file=sys.stderr)
    else:
        print(f"Configuration file not found at {config_path}. Using default configuration.", file=sys.stderr)
    
    return config

def strip_http_prefix(url):
    """
    Strips 'http://' or 'https://' from the beginning of the URL if present.

    Args:
        url (str): The original URL.

    Returns:
        str: The URL without the 'http://' or 'https://' prefix.
    """
    if url.startswith("http://"):
        return url[len("http://"):]
    elif url.startswith("https://"):
        return url[len("https://"):]
    return url

config = load_config()

# Extract configuration values with fallbacks
TOKEN_FILE = os.path.expanduser(config.get('Paths', 'token_file', fallback=DEFAULT_CONFIG['Paths']['token_file']))
ENC_KEY_FILE = os.path.expanduser(config.get('Paths', 'enc_key_file', fallback=DEFAULT_CONFIG['Paths']['enc_key_file']))
SERVER_URL = strip_http_prefix(config.get('Server', 'url', fallback=DEFAULT_CONFIG['Server']['url']))
NONCE_SIZE = config.getint('Encryption', 'nonce_size', fallback=int(DEFAULT_CONFIG['Encryption']['nonce_size']))
MAX_RETRIES = config.getint('Retry', 'max_retries', fallback=int(DEFAULT_CONFIG['Retry']['max_retries']))

# Optional: Logging setup based on config (if you decide to implement logging)
# import logging
# log_level = config.get('Logging', 'log_level', fallback='INFO').upper()
# logging.basicConfig(level=getattr(logging, log_level, logging.INFO))
# logger = logging.getLogger(__name__)

CLIPBOARD_HISTORY = None
klipper = None
clipboard_fd = None
ws = None
stop_event = threading.Event()

# Load Encryption Key if encryption is available
if ENCRYPTION_AVAILABLE:
    def load_encryption_key():
        """
        Attempts to load the encryption key from ENC_KEY_FILE.
        Returns the 32‐byte key on success, or None on any failure.
        """
        try:
            with open(ENC_KEY_FILE, 'rb') as f:
                key = f.read()
                if len(key) != 32:
                    print(f"Invalid encryption key length in {ENC_KEY_FILE}. Expected 32 bytes.", file=sys.stderr)
                    return None
                return key
        except FileNotFoundError:
            print(f"Encryption key file not found at {ENC_KEY_FILE}. Disabling WebSocket sync.", file=sys.stderr)
            print("run python cli.py register, to create the default configuration file")
            return None
        except Exception as e:
            print(f"Error loading encryption key: {e}. Disabling WebSocket sync.", file=sys.stderr)
            return None

    _key = load_encryption_key()
    if _key is None:
        # fallback: disable encryption & WebSocket features
        ENCRYPTION_AVAILABLE = False
    else:
        ENC_KEY = _key
        cipher = ChaCha20_Poly1305.new(key=ENC_KEY)

# Define encrypt/decrypt functions based on ENCRYPTION_AVAILABLE
if ENCRYPTION_AVAILABLE:
    def encrypt_message(message: str) -> dict:
        nonce = get_random_bytes(NONCE_SIZE)
        cipher = ChaCha20_Poly1305.new(key=ENC_KEY, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(message.encode())
        return {
            "nonce": base64.b64encode(nonce).decode(),
            "ciphertext": base64.b64encode(ciphertext).decode(),
            "tag": base64.b64encode(tag).decode()
        }

    def decrypt_message(nonce_b64: str, ciphertext_b64: str, tag_b64: str) -> str:
        try:
            nonce = base64.b64decode(nonce_b64)
            ciphertext = base64.b64decode(ciphertext_b64)
            tag = base64.b64decode(tag_b64)
            cipher = ChaCha20_Poly1305.new(key=ENC_KEY, nonce=nonce)
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)
            return plaintext.decode()
        except (ValueError, KeyError) as e:
            print(f"Decryption failed: {e}", file=sys.stderr)
            return ""
else:
    def encrypt_message(message: str) -> dict:
        return {
            "nonce": "",
            "ciphertext": message,
            "tag": ""
        }

    def decrypt_message(nonce_b64: str, ciphertext_b64: str, tag_b64: str) -> str:
        return ciphertext_b64

def read_all(fd, retry_count=MAX_RETRIES):
    """
    Attempts to read all available data from a non-blocking file descriptor.
    If EWOULDBLOCK is encountered, schedules a limited number of retries.

    Args:
        fd (int): The file descriptor to read from.
        retry_count (int): The number of remaining retry attempts.

    Returns:
        str: The decoded string data read from the file descriptor.
    """
    data = []
    try:
        while True:
            chunk = os.read(fd, 4096)
            if not chunk:
                # No more data available
                break
            data.append(chunk)
    except OSError as e:
        if e.errno in (errno.EAGAIN, errno.EWOULDBLOCK):
            if retry_count > 0:
                # Schedule a retry with decremented retry_count
                GLib.timeout_add(100, lambda: handle_retry_read(fd, retry_count - 1))
                print(f"EWOULDBLOCK encountered. Retrying in 100ms... ({MAX_RETRIES - retry_count + 1}/{MAX_RETRIES})")
            else:
                print(f"Maximum retry attempts ({MAX_RETRIES}) reached. Giving up on reading from fd {fd}.", file=sys.stderr)
            return ""  # Return empty string as no data was read this time
        else:
            # An unexpected error occurred
            raise

    # Decode and return the accumulated data
    return b''.join(data).decode('utf-8', errors='replace').strip()

def handle_retry_read(fd, retry_count):
    """
    Handles retrying the read operation after a short delay.

    Args:
        fd (int): The file descriptor to read from.
        retry_count (int): The number of remaining retry attempts.

    Returns:
        bool: False to ensure the timeout is not called again.
    """
    try:
        data = read_all(fd, retry_count)
        if data:
            process_read_data(data)
    except Exception as e:
        print(f"Error during retry read: {e}", file=sys.stderr)
    return False  # Ensure this timeout handler is only called once

def process_read_data(data):
    """
    Processes the data read from the clipboard device.

    Args:
        data (str): The clipboard data to process.
    """
    global CLIPBOARD_HISTORY
    if data and data != CLIPBOARD_HISTORY:
        print(f"Clipboard Updated (/dev/clipboard): {data}")
        CLIPBOARD_HISTORY = data
        if klipper:
            try:
                klipper.setClipboardContents(data)
            except dbus.DBusException as e:
                print(f"Error setting clipboard contents in Klipper: {e}", file=sys.stderr)
        # Send the updated clipboard content to the server if encryption and WebSocket are available
        if ENCRYPTION_AVAILABLE:
            send_clipboard_update(data)

def on_clipboard_history_updated():
    """
    Callback function triggered by Klipper's D-Bus signal when the clipboard history is updated.
    """
    global CLIPBOARD_HISTORY
    try:
        # Retrieve the latest clipboard data from Klipper
        clipboard_content = klipper.getClipboardContents()
        if clipboard_content == CLIPBOARD_HISTORY:
            return
        print(f"Clipboard Updated (D-Bus): {clipboard_content}")
        CLIPBOARD_HISTORY = clipboard_content
        klipper.setClipboardContents(clipboard_content)
        # Send the updated clipboard content to the server if encryption and WebSocket are available
        if ENCRYPTION_AVAILABLE:
            send_clipboard_update(clipboard_content)
    except dbus.DBusException as e:
        print(f"Error retrieving clipboard contents: {e}", file=sys.stderr)

def sigio_handler(signum, frame):
    global CLIPBOARD_HISTORY
    global klipper
    """Signal handler for SIGIO: triggered by asynchronous notifications from /dev/clipboard."""
    if clipboard_fd is not None:
        # Try reading from the device. This assumes the device 
        # provides some readable content upon update.
        try:
            os.lseek(clipboard_fd, 0, os.SEEK_SET)  # Reset to start if needed
            data = read_all(clipboard_fd)
            if data:
                print(f"Clipboard Updated (/dev/clipboard): {data}")
                if CLIPBOARD_HISTORY == data:
                    return
                print(f"Clipboard Updated (D-Bus): {data}")
                CLIPBOARD_HISTORY = data
                if klipper:
                    klipper.setClipboardContents(data)
                # Send the updated clipboard content to the server if encryption and WebSocket are available
                if ENCRYPTION_AVAILABLE:
                    send_clipboard_update(data)
        except OSError as e:
            print(f"Error reading /dev/clipboard: {e}", file=sys.stderr)

def on_clipboard_device_ready(source, condition):
    """
    Callback function triggered by GLib when /dev/clipboard is ready for reading.
    
    Args:
        source: The file descriptor.
        condition: The condition that triggered the callback (e.g., GLib.IO_IN).
    
    Returns:
        True to keep the callback active, False to remove it.
    """
    global CLIPBOARD_HISTORY
    if condition == GLib.IO_IN:
        try:
            # Read the new clipboard data from /dev/clipboard
            os.lseek(clipboard_fd, 0, os.SEEK_SET)  # Reset to start if needed
            data = read_all(clipboard_fd)
            if data and data != CLIPBOARD_HISTORY:
                print(f"Clipboard Updated (/dev/clipboard): {data}")
                CLIPBOARD_HISTORY = data
                # Update Klipper's clipboard contents via D-Bus
                klipper.setClipboardContents(data)
                # Send the updated clipboard content to the server if encryption and WebSocket are available
                if ENCRYPTION_AVAILABLE:
                    send_clipboard_update(data)
        except OSError as e:
            print(f"Error reading /dev/clipboard: {e}", file=sys.stderr)
        except dbus.DBusException as e:
            print(f"Error setting clipboard contents in Klipper: {e}", file=sys.stderr)
    return True  # Keep the callback active

def setup_clipboard_device():
    global clipboard_fd
    # Open the /dev/clipboard device
    try:
        clipboard_fd = os.open("/dev/clipboard", os.O_RDONLY | os.O_NONBLOCK)
    except OSError as e:
        print(f"Failed to open /dev/clipboard: {e}", file=sys.stderr)
        return False
        
    # Get current file flags
    flags = fcntl.fcntl(clipboard_fd, fcntl.F_GETFL)

    # Enable asynchronous I/O (FASYNC)
    fcntl.fcntl(clipboard_fd, fcntl.F_SETFL, flags | os.O_ASYNC)
        
    # Set the owner (process) to receive SIGIO signals
    fcntl.fcntl(clipboard_fd, fcntl.F_SETOWN, os.getpid())

    # Install signal handler for SIGIO
    signal.signal(signal.SIGIO, sigio_handler)
    return True

def load_token():
    """
    Loads the JWT access token from the token file.

    Returns:
        str: The access token.

    Exits:
        If the token file is missing or invalid.
    """
    try:
        with open(TOKEN_FILE, 'r') as f:
            data = json.load(f)
            return data["access_token"]
    except FileNotFoundError:
        print(f"Token file not found at {TOKEN_FILE}. Please register or login first.", file=sys.stderr)
        sys.exit(1)
    except KeyError:
        print(f"Access token not found in {TOKEN_FILE}. Please register or login first.", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError:
        print(f"Token file {TOKEN_FILE} is not valid JSON.", file=sys.stderr)
        sys.exit(1)

def send_clipboard_update(text):
    """
    Sends the encrypted clipboard update to the server via WebSocket.
    
    Args:
        text (str): The clipboard text to send.
    """
    global ws
    if ENCRYPTION_AVAILABLE and ws and ws.sock and ws.sock.connected:
        try:
            encrypted_message = encrypt_message(text)
            message = json.dumps({
                "type": "update",
                "nonce": encrypted_message["nonce"],
                "ciphertext": encrypted_message["ciphertext"],
                "tag": encrypted_message["tag"]
            })
            ws.send(message)
        except Exception as e:
            print(f"Failed to send clipboard update: {e}", file=sys.stderr)

def on_ws_open(ws):
    print("WebSocket connection established.")

def on_ws_message(ws, message):
    """
    Handles incoming messages from the server.
    
    Args:
        ws: The WebSocketApp instance.
        message (str): The received message.
    """
    global CLIPBOARD_HISTORY
    try:
        data = json.loads(message)
        if data.get("type") in ["init", "update"] and "nonce" in data and "ciphertext" in data and "tag" in data:
            decrypted_text = decrypt_message(data["nonce"], data["ciphertext"], data["tag"])
            if decrypted_text and decrypted_text != CLIPBOARD_HISTORY:
                print(f"Clipboard Updated (WebSocket): {decrypted_text}")
                CLIPBOARD_HISTORY = decrypted_text
                if klipper:
                    klipper.setClipboardContents(decrypted_text)
    except json.JSONDecodeError:
        print(f"Received invalid JSON message: {message}", file=sys.stderr)

def on_ws_error(ws, error):
    print(f"WebSocket error: {error}", file=sys.stderr)

def on_ws_close(ws, close_status_code, close_msg):
    print("WebSocket connection closed.")

def websocket_thread():
    """
    Thread function to handle WebSocket connection.
    """
    global ws
    access_token = load_token()
    ws_url = f"ws://{SERVER_URL}/ws?token={access_token}"

    ws = websocket.WebSocketApp(
        ws_url,
        on_open=on_ws_open,
        on_message=on_ws_message,
        on_error=on_ws_error,
        on_close=on_ws_close
    )

    while not stop_event.is_set():
        try:
            ws.run_forever()
        except Exception as e:
            print(f"WebSocket connection error: {e}", file=sys.stderr)
        # Wait before attempting to reconnect
        if not stop_event.is_set():
            print("Attempting to reconnect WebSocket in 5 seconds...")
            time.sleep(5)

def start_websocket():
    """
    Starts the WebSocket thread.
    """
    thread = threading.Thread(target=websocket_thread, daemon=True)
    thread.start()

def on_clipboard_history_updated_threaded():
    """
    Threaded callback for clipboard history updates.
    """
    on_clipboard_history_updated()

def start_websocket_client():
    """
    Initializes and starts the WebSocket client thread if encryption is available.
    """
    if ENCRYPTION_AVAILABLE:
        start_websocket()
    else:
        print("WebSocket client not started because encryption is unavailable.", file=sys.stderr)

def setup_websocket_callbacks():
    """
    Placeholder for any additional WebSocket setup if needed.
    """
    pass

def main():
    """
    Main function to set up D-Bus connections, signal receivers, WebSocket connection (if available), and the GLib main loop.
    """
    global klipper
    # Initialize the main D-Bus loop integration with GLib
    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
    loop = GLib.MainLoop()

    klipper_present = True
    try:
        # Connect to the session bus
        bus = dbus.SessionBus()
    except dbus.DBusException:
        klipper_present = False
        print("D-Bus interface not found. Clipboard synchronization via D-Bus is disabled.", file=sys.stderr)

    if klipper_present:
        # Attempt to get the Klipper D-Bus object
        try:
            klipper_proxy = bus.get_object("org.kde.klipper", "/klipper")
        except dbus.DBusException:
            klipper_present = False
       
        if klipper_present:
            # Get the Klipper interface
            klipper = dbus.Interface(klipper_proxy, dbus_interface="org.kde.klipper.klipper")
            
            # Connect to the clipboardHistoryUpdated signal from Klipper D-Bus
            bus.add_signal_receiver(
                handler_function=on_clipboard_history_updated_threaded,
                signal_name="clipboardHistoryUpdated",
                dbus_interface="org.kde.klipper.klipper",
                path="/klipper"
            )
        else:
            print("Klipper D-Bus interface not found. Clipboard synchronization via D-Bus is disabled.", file=sys.stderr)

    try:
    
        # Set up asynchronous monitoring of /dev/clipboard
        device_enabled = setup_clipboard_device()

        # Start WebSocket connection if encryption is available
        start_websocket_client()
        what_we = "Listening for clipboard changes "
        if klipper_present and not device_enabled:
            what_we += "(D-Bus)"
        elif device_enabled and not klipper_present:
            what_we += "(/dev/clipboard)"
        elif klipper_present and device_enabled:
            what_we += "(D-Bus and /dev/clipboard)"

        if ENCRYPTION_AVAILABLE:
            print("WebSocket synchronization is enabled.")
        else:
            print("WebSocket synchronization is disabled.")

        # TODO: I'm sure there are cases where encryption is available and we fail to setup websockets
        if not (klipper_present or device_enabled or ENCRYPTION_AVAILABLE):
            print(
                "All synchronization paths (D-Bus, /dev/clipboard, WebSocket) are disabled. Exiting.",
                file=sys.stderr
            )
            sys.exit(1)

        print(what_we)
        print("Press Ctrl+C to exit.")
        loop.run()
    except KeyboardInterrupt:
        print("\nExiting.")
        stop_event.set()
        if ws:
            ws.close()
        loop.quit()
    finally:
        # Clean up the file descriptor if it was opened
        if clipboard_fd is not None:
            os.close(clipboard_fd)

if __name__ == "__main__":
    main()

