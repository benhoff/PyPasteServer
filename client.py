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

# Constants
TOKEN_FILE = os.path.expanduser("~/.clipboard_app/token.json")
SERVER_URL = "ws://127.0.0.1:8000/ws"  # Update with your server's WebSocket URL

CLIPBOARD_HISTORY = None
klipper = None
clipboard_fd = None
ws = None
stop_event = threading.Event()

def read_all(fd):
    """
    Reads all available data from a non-blocking file descriptor.

    Args:
        fd (int): The file descriptor to read from.

    Returns:
        str: The decoded string data read from the file descriptor.
    """
    data = []
    while True:
        try:
            chunk = os.read(fd, 4096)
            if not chunk:
                # No more data available
                break
            data.append(chunk)
        except OSError as e:
            if e.errno in (errno.EAGAIN, errno.EWOULDBLOCK):
                # No more data available for non-blocking read
                break
            else:
                # An unexpected error occurred
                raise
    return b''.join(data).decode('utf-8', errors='replace').strip()

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
            data = os.read(clipboard_fd, 4096).decode('utf-8', errors='replace').strip()
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

    Raises:
        FileNotFoundError: If the token file does not exist.
        KeyError: If the access token is not found in the file.
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
    Sends the clipboard update to the server via WebSocket.

    Args:
        text (str): The clipboard text to send.
    """
    global ws
    if ws and ws.connected:
        try:
            message = json.dumps({"text": text})
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
        if data.get("type") == "update" and "text" in data:
            new_text = data["text"]
            if new_text != CLIPBOARD_HISTORY:
                print(f"Clipboard Updated (WebSocket): {new_text}")
                CLIPBOARD_HISTORY = new_text
                if klipper:
                    klipper.setClipboardContents(new_text)
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
    ws_url = f"{SERVER_URL}?token={access_token}"

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

def on_clipboard_history_updated_threaded():
    """
    Threaded callback for clipboard history updates.
    """
    on_clipboard_history_updated()

def start_websocket():
    """
    Starts the WebSocket thread.
    """
    thread = threading.Thread(target=websocket_thread, daemon=True)
    thread.start()

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
        start_websocket()

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

