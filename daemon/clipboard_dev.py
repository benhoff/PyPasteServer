import errno
import fcntl
import os
import signal
from gi.repository import GLib

from .kclip import KCLIP_SLOT_DEFAULT, fetch_message, message_text


class ClipboardDevice:
    """Interface to the /dev/kclip device using the ioctl-based API."""

    def __init__(self, path: str, on_data, slot: int = KCLIP_SLOT_DEFAULT):
        self.path = path
        self.fd = None
        self.slot = slot
        self.on_data = on_data

    def _sigio(self, signum, frame):
        self._drain(nonblock=True)

    def _retry(self, fd, retry_count):  # kept for compatibility with util hooks
        try:
            message = fetch_message(fd, slot=self.slot, nonblock=True)
        except BlockingIOError:
            return False
        except OSError as e:
            print(f"Error fetching {self.path}: {e}")
            return False
        data = message_text(message)
        if data:
            self.on_data(data)
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
        GLib.io_add_watch(self.fd, GLib.IO_IN, self._on_ready)
        return True

    def _on_ready(self, source, condition):
        if condition == GLib.IO_IN:
            self._drain(nonblock=True)
        return True

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None

    def _drain(self, nonblock: bool):
        if self.fd is None:
            return

        while True:
            try:
                message = fetch_message(self.fd, slot=self.slot, nonblock=nonblock)
            except BlockingIOError:
                break
            except OSError as e:
                if e.errno in (errno.EAGAIN, errno.EWOULDBLOCK):
                    break
                print(f"Error fetching {self.path}: {e}")
                break

            data = message_text(message)
            if data:
                self.on_data(data)

            nonblock = True
