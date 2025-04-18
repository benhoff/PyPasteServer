# tests/test_dbus.py
import sys
import pytest
from types import SimpleNamespace

import daemon as app

class FakeLoop:
    def __init__(self, run_raises=None):
        self.run_raises = run_raises
        self.quit_called = False
    def run(self):
        if self.run_raises:
            raise self.run_raises
    def quit(self):
        self.quit_called = True

@pytest.fixture(autouse=True)
def stub_loop_and_ws(monkeypatch):
    monkeypatch.setattr(app.GLib, "MainLoop", lambda: FakeLoop(run_raises=KeyboardInterrupt))
    monkeypatch.setattr(app, "start_websocket_client", lambda: None)
    return None

def test_main_exits_if_two_methods_not_met(monkeypatch, capsys):
    # WS disabled
    monkeypatch.setattr(app, "ENCRYPTION_AVAILABLE", False)
    # DBus ok
    class FakeBus:
        def get_object(self, *a, **k): return SimpleNamespace()
        def add_signal_receiver(self, *a, **k): pass
    monkeypatch.setattr(app.dbus, "SessionBus", lambda *a, **k: FakeBus())
    monkeypatch.setattr(app.dbus, "Interface", lambda proxy, **kwargs: proxy)
    # Device disabled
    monkeypatch.setattr(app, "setup_clipboard_device", lambda: False)

    with pytest.raises(SystemExit) as exc:
        app.main()
    out, err = capsys.readouterr()
    # Only D-Bus is enabled here
    assert "Only 1 synchronization method(s) available (D-Bus);" in err
    assert exc.value.code == 1

def test_main_continues_when_two_methods_available(monkeypatch, capsys):
    # WS disabled
    monkeypatch.setattr(app, "ENCRYPTION_AVAILABLE", False)
    # DBus ok
    class FakeBus2:
        def get_object(self, *a, **k): return SimpleNamespace()
        def add_signal_receiver(self, *a, **k): pass
    monkeypatch.setattr(app.dbus, "SessionBus", lambda *a, **k: FakeBus2())
    monkeypatch.setattr(app.dbus, "Interface", lambda proxy, **kwargs: proxy)
    # Device enabled
    monkeypatch.setattr(app, "setup_clipboard_device", lambda: True)

    exit_called = {"called": False}
    monkeypatch.setattr(sys, "exit", lambda code=1: exit_called.__setitem__("called", True))

    app.main()
    out, err = capsys.readouterr()
    assert not exit_called["called"]
    assert "Synchronization methods enabled: D-Bus, /dev/clipboard" in out

def test_main_registers_signal_receiver_when_dbus_available(monkeypatch, capsys):
    recorder = {}
    class FakeBus3:
        def get_object(self, service, path):
            recorder["proxy"] = (service, path)
            return SimpleNamespace()
        def add_signal_receiver(self, handler_function, signal_name, dbus_interface, path):
            recorder.update(signal_name=signal_name, dbus_interface=dbus_interface, path=path)

    monkeypatch.setattr(app.dbus, "SessionBus", lambda *a, **k: FakeBus3())
    monkeypatch.setattr(app.dbus, "Interface", lambda proxy, **kwargs: proxy)
    monkeypatch.setattr(app, "setup_clipboard_device", lambda: True)
    monkeypatch.setattr(app, "ENCRYPTION_AVAILABLE", False)
    monkeypatch.setattr(sys, "exit", lambda code=1: None)

    app.main()

    assert recorder["signal_name"] == "clipboardHistoryUpdated"
    assert recorder["dbus_interface"] == "org.kde.klipper.klipper"
    assert recorder["path"] == "/klipper"
    out, err = capsys.readouterr()
    assert "Synchronization methods enabled" in out

