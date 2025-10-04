import dbus
import dbus.mainloop.glib
from gi.repository import GLib

class KlipperBus:
    def __init__(self, on_update):
        self.klipper = None
        self.on_update = on_update

    def start(self) -> bool:
        try:
            bus = dbus.SessionBus()
        except dbus.DBusException:
            print("D-Bus interface not found. Clipboard synchronization via D-Bus is disabled.")
            return False
        try:
            proxy = bus.get_object("org.kde.klipper", "/klipper")
            self.klipper = dbus.Interface(proxy, dbus_interface="org.kde.klipper.klipper")
            bus.add_signal_receiver(
                handler_function=lambda: self.on_update(),
                signal_name="clipboardHistoryUpdated",
                dbus_interface="org.kde.klipper.klipper",
                path="/klipper",
            )
            return True
        except dbus.DBusException:
            print("Klipper D-Bus interface not found. Clipboard synchronization via D-Bus is disabled.")
            return False

    def get(self) -> str:
        return self.klipper.getClipboardContents() if self.klipper else ""

    def set(self, s: str):
        if self.klipper:
            self.klipper.setClipboardContents(s)

