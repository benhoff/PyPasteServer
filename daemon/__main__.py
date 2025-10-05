import os
import sys
import dbus.mainloop.glib
from gi.repository import GLib
import time

from .sync_pipeline import SyncState
from .klipper_bus import KlipperBus
from .clipboard_dev import ClipboardDevice
from .ws_client import WSClient
from .crypto import encryption_available


def main():
    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
    loop = GLib.MainLoop()

    state = SyncState()

    def klipper_meta_stub() -> dict[str, int | str]:
        return {
            "ts_ns": time.time_ns(),
            "uid": os.getuid(),
            "comm": "klipper",
        }

    # callbacks
    def apply_to_system(text: str, meta: dict[str, int | str] | None):
        # pluggable sinks (klipper & websocket)
        if klipper.klipper:
            try:
                klipper.set(text)
            except Exception as e:
                print(f"Error setting clipboard via Klipper: {e}")
        if ws_enabled:
            ws.send_update(text, meta)

    def on_klipper_update():
        try:
            text = klipper.get()
            state.update_if_changed(text, klipper_meta_stub(), apply_to_system)
        except Exception as e:
            print(f"Error retrieving clipboard contents: {e}")

    def on_device_text(text: str, meta: dict[str, int | str] | None):
        state.update_if_changed(text, meta, apply_to_system)

    # start subsystems
    klipper = KlipperBus(on_update=on_klipper_update)
    klipper_ok = klipper.start()

    dev = ClipboardDevice(path="/dev/kclip", on_data=on_device_text)
    dev_ok = dev.start()

    ws = WSClient(on_text=lambda text, meta=None: state.update_if_changed(text, meta, apply_to_system))
    ws_enabled = ws.start()

    methods = {
        "D-Bus": klipper_ok,
        "/dev/kclip": dev_ok,
        "WebSocket": ws_enabled,
    }
    available = [k for k, ok in methods.items() if ok]
    if len(available) < 2:
        print(
            f"Error: Only {len(available)} synchronization method(s) available (" + ", ".join(available) + "); at least two required. Exiting.")
        sys.exit(1)

    print("Synchronization methods enabled: " + ", ".join(available))
    print("Press Ctrl+C to exit.")

    try:
        loop.run()
    except KeyboardInterrupt:
        print("\nExiting.")
    finally:
        ws.stop()
        dev.close()


if __name__ == "__main__":
    main()
