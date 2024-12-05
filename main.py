#!/usr/bin/env python3
import sys
import dbus
import dbus.mainloop.glib
from gi.repository import GLib

CLIPBOARD_HISTORY = None

def on_clipboard_history_updated():
    global CLIPBOARD_HISTORY
    try:
        # Call the getClipboardContents method to retrieve the latest clipboard data
        clipboard_content = klipper.getClipboardContents()
        if clipboard_content == CLIPBOARD_HISTORY:
            return
        print(f"Clipboard Updated: {clipboard_content}")
        CLIPBOARD_HISTORY = clipboard_content
        # Add your custom logic here (e.g., processing, logging, etc.)
    except dbus.DBusException as e:
        print(f"Error retrieving clipboard contents: {e}", file=sys.stderr)

def main():
    # Initialize the main loop
    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
    loop = GLib.MainLoop()

    try:
        # Connect to the session bus
        bus = dbus.SessionBus()
        
        # Get the Klipper object
        klipper_proxy = bus.get_object("org.kde.klipper", "/klipper")
        
        # Get the Klipper interface
        global klipper
        klipper = dbus.Interface(klipper_proxy, dbus_interface="org.kde.klipper.klipper")
        
        # Connect to the clipboardHistoryUpdated signal
        bus.add_signal_receiver(
            handler_function=on_clipboard_history_updated,
            signal_name="clipboardHistoryUpdated",
            dbus_interface="org.kde.klipper.klipper",
            path="/klipper"  # **Use 'path' instead of 'object_path'**
        )
        
        print("Listening for clipboard changes. Press Ctrl+C to exit.")
        loop.run()
    except dbus.DBusException as e:
        print(f"Failed to connect to Klipper D-Bus interface: {e}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nExiting.")
        loop.quit()

if __name__ == "__main__":
    main()

