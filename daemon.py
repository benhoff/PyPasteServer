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
import websocket
import time
from getpass import getpass
from Crypto.Cipher import ChaCha20_Poly1305
from Crypto.Random import get_random_bytes
import base64
import configparser
from pathlib import Path

# Load Configuration
def load_config():
    """
    Loads the configuration from the config.ini file.
    
    Returns:
        configparser.ConfigParser: The loaded configuration.
    
    Exits:
        If the configuration file is missing or invalid.
    """
    config = configparser.ConfigParser()
    config_path = os.path.expanduser("~/.config/clipboard_app/config.ini")
    
    if not os.path.exists(config_path):
        print(f"Configuration file not found at {config_path}.", file=sys.stderr)
        sys.exit(1)
    
    try:
        config.read(config_path)
        return config
    except configparser.Error as e:
        print(f"Error parsing configuration file: {e}", file=sys.stderr)
        sys.exit(1)


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

# Extract configuration values
TOKEN_FILE = os.path.expanduser(config.get('Paths', 'token_file'))
ENC_KEY_FILE = os.path.expanduser(config.get('Paths', 'enc_key_file'))
SERVER_URL = strip_http_prefix(config.get('Server', 'url'))
NONCE_SIZE = config.getint('Encryption', 'nonce_size')
MAX_RETRIES = config.getint('Retry', 'max_retries', fallback=5)

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

# Load Encryption Key
def load_encryption_key():
    """
    Loads the encryption key from the ENC_KEY_FILE.
    
    Returns:
        bytes: The 32-byte encryption key.
    
    Exits:
        If the key file is missing or invalid.
    """
    try:
        with open(ENC_KEY_FILE, 'rb') as f:
            key = f.read()
            if len(key) != 32:
                print(f"Invalid encryption key length in {ENC_KEY_FILE}. Expected 32 bytes.", file=sys.stderr)
                sys.exit(1)
            return key
    except FileNotFoundError:
        print(f"Encryption key file not found at {ENC_KEY_FILE}.", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error loading encryption key: {e}", file=sys.stderr)
        sys.exit(1)

ENC_KEY = load_encryption_key()
cipher = ChaCha20_Poly1305.new(key=ENC_KEY)

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
        # Send the updated clipboard content to the server
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
        # Send the updated clipboard content to the server
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
                # Send the updated clipboard content to the server
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
                # Send the updated clipboard content to the server
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
        sys.exit(1)
        
    # Get current file flags
    flags = fcntl.fcntl(clipboard_fd, fcntl.F_GETFL)

    # Enable asynchronous I/O (FASYNC)
    fcntl.fcntl(clipboard_fd, fcntl.F_SETFL, flags | os.O_ASYNC)
        
    # Set the owner (process) to receive SIGIO signals
    fcntl.fcntl(clipboard_fd, fcntl.F_SETOWN, os.getpid())

    # Install signal handler for SIGIO
    signal.signal(signal.SIGIO, sigio_handler)

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

def encrypt_message(message: str) -> dict:
    """
    Encrypts a plaintext message using ChaCha20-Poly1305.
    
    Args:
        message (str): The plaintext message to encrypt.
    
    Returns:
        dict: A dictionary containing Base64-encoded nonce and ciphertext.
    """
    nonce = get_random_bytes(NONCE_SIZE)  # Use nonce size from config
    cipher = ChaCha20_Poly1305.new(key=ENC_KEY, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(message.encode())
    return {
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "tag": base64.b64encode(tag).decode()
    }

def decrypt_message(nonce_b64: str, ciphertext_b64: str, tag_b64: str) -> str:
    """
    Decrypts a ciphertext message using ChaCha20-Poly1305.
    
    Args:
        nonce_b64 (str): Base64-encoded nonce.
        ciphertext_b64 (str): Base64-encoded ciphertext.
        tag_b64 (str): Base64-encoded authentication tag.
    
    Returns:
        str: The decrypted plaintext message.
    
    Raises:
        ValueError: If decryption fails.
    """
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

def send_clipboard_update(text):
    """
    Sends the encrypted clipboard update to the server via WebSocket.
    
    Args:
        text (str): The clipboard text to send.
    """
    global ws
    if ws and ws.sock and ws.sock.connected:
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
    Initializes and starts the WebSocket client thread.
    """
    start_websocket()

def setup_websocket_callbacks():
    """
    Placeholder for any additional WebSocket setup if needed.
    """
    pass

def main():
    """
    Main function to set up D-Bus connections, signal receivers, WebSocket connection, and the GLib main loop.
    """
    global klipper
    # Initialize the main D-Bus loop integration with GLib
    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
    loop = GLib.MainLoop()

    try:
        # Connect to the session bus
        bus = dbus.SessionBus()
        klipper_present = True

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
        
        # Set up asynchronous monitoring of /dev/clipboard
        setup_clipboard_device()

        # Start WebSocket connection
        start_websocket_client()

        print("Listening for clipboard changes (D-Bus and /dev/clipboard) and syncing via WebSocket.")
        print("Press Ctrl+C to exit.")
        loop.run()
    except dbus.DBusException as e:
        print(f"Failed to connect to Klipper D-Bus interface: {e}", file=sys.stderr)
        sys.exit(1)
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

