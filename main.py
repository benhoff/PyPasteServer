#!/usr/bin/env python3
import sys
import dbus
import dbus.mainloop.glib
import fcntl
import os
import signal
from gi.repository import GLib

CLIPBOARD_HISTORY = None
klipper = None
clipboard_fd = None

def on_clipboard_history_updated():
    global CLIPBOARD_HISTORY
    try:
        # Retrieve the latest clipboard data from Klipper
        clipboard_content = klipper.getClipboardContents()
        if clipboard_content == CLIPBOARD_HISTORY:
            return
        print(f"Clipboard Updated (D-Bus): {clipboard_content}")
        CLIPBOARD_HISTORY = clipboard_content
    except dbus.DBusException as e:
        print(f"Error retrieving clipboard contents: {e}", file=sys.stderr)

def sigio_handler(signum, frame):
    """Signal handler for SIGIO: triggered by asynchronous notifications from /dev/clipboard."""
    if clipboard_fd is not None:
        # Try reading from the device. This assumes the device 
        # provides some readable content upon update.
        try:
            # Read the entire content - depending on the device, 
            # you might need to adjust how and what you read
            os.lseek(clipboard_fd, 0, os.SEEK_SET)  # Reset to start if needed
            data = os.read(clipboard_fd, 4096).decode('utf-8', errors='replace').strip()
            if data:
                print(f"Clipboard Updated (/dev/clipboard): {data}")
        except OSError as e:
            print(f"Error reading /dev/clipboard: {e}", file=sys.stderr)

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
    # Initialize the main D-Bus loop
    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
    loop = GLib.MainLoop()

    try:
        # Connect to the session bus
        bus = dbus.SessionBus()
        klipper_present = True 

        # Get the Klipper object
        try:
            klipper_proxy = bus.get_object("org.kde.klipper", "/klipper")
        except dbus.DBusException:
            klipper_present = False
       
        if klipper_present:
            global klipper
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

