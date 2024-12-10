#!/usr/bin/env python3
import sys
import dbus
import dbus.mainloop.glib
import os
import fcntl
import signal
from gi.repository import GLib

CLIPBOARD_HISTORY = None
klipper = None
clipboard_fd = None

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
        # Add your custom logic here (e.g., processing, logging, etc.)
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
            data = os.read(clipboard_fd, 4096).decode('utf-8', errors='replace').strip()
            if data:
                print(f"Clipboard Updated (/dev/clipboard): {data}")
                if CLIPBOARD_HISTORY == data:
                    return
                print(f"Clipboard Updated (D-Bus): {data}")
                CLIPBOARD_HISTORY = data
                klipper.setClipboardContents(data)
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
        except OSError as e:
            print(f"Error reading /dev/clipboard: {e}", file=sys.stderr)
        except dbus.DBusException as e:
            print(f"Error setting clipboard contents in Klipper: {e}", file=sys.stderr)
    return True  # Keep the callback active

def setup_clipboard_device():
    global clipboard_fd
    # Open the /dev/clipboard device
    clipboard_fd = os.open("/dev/clipboard", os.O_RDONLY)
        
    # Get current file flags
    flags = fcntl.fcntl(clipboard_fd, fcntl.F_GETFL)

    # Enable asynchronous I/O (FASYNC)
    fcntl.fcntl(clipboard_fd, fcntl.F_SETFL, flags | os.O_ASYNC)
        
    # Set the owner (process) to receive SIGIO signals
    fcntl.fcntl(clipboard_fd, fcntl.F_SETOWN, os.getpid())

    # Install signal handler for SIGIO
    signal.signal(signal.SIGIO, sigio_handler)

def main():
    """
    Main function to set up D-Bus connections, signal receivers, and the GLib main loop.
    """
    global klipper
    # Initialize the main D-Bus loop integration with GLib
    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
    loop = GLib.MainLoop()

    try:
        # Connect to the session bus
        bus = dbus.SessionBus()

        # Attempt to get the Klipper D-Bus object
        try:
            klipper_proxy = bus.get_object("org.kde.klipper", "/klipper")
        except dbus.DBusException:
            print("Klipper not present. Exiting.")
            sys.exit(0)
        
        # Get the Klipper interface
        klipper = dbus.Interface(klipper_proxy, dbus_interface="org.kde.klipper.klipper")
        
        # Connect to the clipboardHistoryUpdated signal from Klipper D-Bus
        bus.add_signal_receiver(
            handler_function=on_clipboard_history_updated,
            signal_name="clipboardHistoryUpdated",
            dbus_interface="org.kde.klipper.klipper",
            path="/klipper"
        )
        
        # Set up asynchronous monitoring of /dev/clipboard
        setup_clipboard_device()

        print("Listening for clipboard changes (both D-Bus and /dev/clipboard). Press Ctrl+C to exit.")
        loop.run()
    except dbus.DBusException as e:
        print(f"Failed to connect to Klipper D-Bus interface: {e}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nExiting.")
        loop.quit()
    finally:
        # Clean up the file descriptor if it was opened
        if clipboard_fd is not None:
            os.close(clipboard_fd)

if __name__ == "__main__":
    main()

