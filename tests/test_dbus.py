import pytest
import sys
from types import SimpleNamespace

# Import the user's script (assuming it's named daemon.py)
import daemon as app

#
# ─── Helpers for Main Tests ─────────────────────────────────────────────────────
#
class FakeLoop:
    def __init__(self, run_raises=None):
        self.run_raises = run_raises
        self.quit_called = False

    def run(self):
        if self.run_raises:
            raise self.run_raises

    def quit(self):
        self.quit_called = True


#
# ─── Test: D-Bus Unavailable ─────────────────────────────────────────────────────
#
def test_main_continues_when_dbus_unavailable(monkeypatch, capsys):
    """
    If dbus.SessionBus().get_object raises DBusException,
    main() should catch it, print a warning, and continue to run.
    """
    # Stub SessionBus to raise on get_object
    class FakeBus:
        def get_object(self, *args, **kwargs):
            raise app.dbus.DBusException("No D-Bus")

    monkeypatch.setattr(app.dbus, "SessionBus", lambda: FakeBus())

    # Stub GLib.MainLoop to exit immediately via KeyboardInterrupt
    fake_loop = FakeLoop(run_raises=KeyboardInterrupt)
    monkeypatch.setattr(app.GLib, "MainLoop", lambda: fake_loop)

    # Stub out device and websocket setup
    monkeypatch.setattr(app, "setup_clipboard_device", lambda: None)
    monkeypatch.setattr(app, "start_websocket_client", lambda: None)

    # Run main
    app.main()

    captured = capsys.readouterr()
    assert "Klipper D-Bus interface not found. Clipboard synchronization via D-Bus is disabled." in captured.err
    assert "Listening for clipboard changes" in captured.out
    assert fake_loop.quit_called


#
# ─── Test: D-Bus Available ────────────────────────────────────────────────────────
#
def test_main_registers_signal_receiver_when_dbus_available(monkeypatch, capsys):
    """
    If dbus.SessionBus().get_object succeeds, main() should call
    add_signal_receiver on the bus with the correct parameters.
    """
    recorded = {}

    # Stub SessionBus to return a bus with working get_object/add_signal_receiver
    class FakeBus:
        def get_object(self, service, path):
            return SimpleNamespace()  # dummy proxy

        def add_signal_receiver(self, handler_function, signal_name, dbus_interface, path):
            recorded['handler_function'] = handler_function
            recorded['signal_name'] = signal_name
            recorded['dbus_interface'] = dbus_interface
            recorded['path'] = path

    monkeypatch.setattr(app.dbus, "SessionBus", lambda: FakeBus())

    # Stub Interface to simply return a dummy klipper interface
    monkeypatch.setattr(app.dbus, "Interface", lambda proxy, dbus_interface: "klipper_iface")

    # Stub GLib.MainLoop to exit immediately via KeyboardInterrupt
    fake_loop = FakeLoop(run_raises=KeyboardInterrupt)
    monkeypatch.setattr(app.GLib, "MainLoop", lambda: fake_loop)

    # Stub out device and websocket setup
    monkeypatch.setattr(app, "setup_clipboard_device", lambda: None)
    monkeypatch.setattr(app, "start_websocket_client", lambda: None)

    # Run main
    app.main()

    # Verify the signal receiver was registered
    assert recorded.get('signal_name') == "clipboardHistoryUpdated"
    assert recorded.get('dbus_interface') == "org.kde.klipper.klipper"
    assert recorded.get('path') == "/klipper"

    captured = capsys.readouterr()
    assert "Listening for clipboard changes" in captured.out
    assert fake_loop.quit_called


#
# ─── Test: sys.exit Not Called on D-Bus Failure ─────────────────────────────────
#
def test_main_does_not_exit_on_dbus_unavailability(monkeypatch):
    """
    sys.exit should not be called when D-Bus is unavailable.
    """
    # Stub SessionBus to raise on get_object
    class FakeBus2:
        def get_object(self, *args, **kwargs):
            raise app.dbus.DBusException("fail")

    monkeypatch.setattr(app.dbus, "SessionBus", lambda: FakeBus2())

    # Stub GLib.MainLoop to exit immediately via KeyboardInterrupt
    fake_loop2 = FakeLoop(run_raises=KeyboardInterrupt)
    monkeypatch.setattr(app.GLib, "MainLoop", lambda: fake_loop2)

    # Stub side-effects
    monkeypatch.setattr(app, "setup_clipboard_device", lambda: None)
    monkeypatch.setattr(app, "start_websocket_client", lambda: None)

    # Monitor sys.exit
    exit_called = {'called': False}
    monkeypatch.setattr(sys, "exit", lambda code=0: exit_called.__setitem__('called', True))

    app.main()
    assert not exit_called['called']


