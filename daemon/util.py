import errno
from gi.repository import GLib

try:
    from .kclip import KCLIP_SLOT_DEFAULT, fetch_message, message_text
except ImportError:  # pragma: no cover - legacy direct invocation support
    from kclip import KCLIP_SLOT_DEFAULT, fetch_message, message_text

from .config import MAX_RETRIES


def read_all(fd: int, retry_count: int = MAX_RETRIES, on_retry=None) -> str:
    try:
        message = fetch_message(fd, slot=KCLIP_SLOT_DEFAULT, nonblock=True)
    except BlockingIOError:
        return ""
    except OSError as e:
        if e.errno in (errno.EAGAIN, errno.EWOULDBLOCK):
            if retry_count > 0 and on_retry is not None:
                GLib.timeout_add(100, lambda: on_retry(fd, retry_count - 1))
            return ""
        raise

    return message_text(message)
