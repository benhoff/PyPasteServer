import os
import fcntl
import signal
from gi.repository import GLib
from .util import read_all

class ClipboardDevice:
    def __init__(self, path: str, on_data):
        self.path = path
        self.fd = None
        self.on_data = on_data

    def _sigio(self, signum, frame):
        if self.fd is None:
            return
        try:
            os.lseek(self.fd, 0, os.SEEK_SET)
            data = read_all(self.fd, on_retry=self._retry)
            if data:
                self.on_data(data)
        except OSError as e:
            print(f"Error reading {self.path}: {e}")

    def _retry(self, fd, retry_count):
        try:
            data = read_all(fd, retry_count, on_retry=self._retry)
            if data:
                self.on_data(data)
        except Exception as e:
            print(f"Error during retry read: {e}")
        return False

    def start(self) -> bool:
        try:
            self.fd = os.open(self.path, os.O_RDONLY | os.O_NONBLOCK)
        except OSError as e:
            print(f"Failed to open {self.path}: {e}")
            return False
        flags = fcntl.fcntl(self.fd, fcntl.F_GETFL)
        fcntl.fcntl(self.fd, fcntl.F_SETFL, flags | os.O_ASYNC)
        fcntl.fcntl(self.fd, fcntl.F_SETOWN, os.getpid())
        signal.signal(signal.SIGIO, self._sigio)
        # Also register GLib IO watch for readiness
        GLib.io_add_watch(self.fd, GLib.IO_IN, self._on_ready)
        return True

    def _on_ready(self, source, condition):
        if condition == GLib.IO_IN:
            try:
                os.lseek(self.fd, 0, os.SEEK_SET)
                data = read_all(self.fd, on_retry=self._retry)
                if data:
                    self.on_data(data)
            except OSError as e:
                print(f"Error reading {self.path}: {e}")
        return True

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None

