import os
import errno
from gi.repository import GLib
from .config import MAX_RETRIES


def read_all(fd: int, retry_count: int = MAX_RETRIES, on_retry=None) -> str:
    data = []
    try:
        while True:
            chunk = os.read(fd, 4096)
            if not chunk:
                break
            data.append(chunk)
    except OSError as e:
        if e.errno in (errno.EAGAIN, errno.EWOULDBLOCK):
            if retry_count > 0 and on_retry is not None:
                GLib.timeout_add(100, lambda: on_retry(fd, retry_count - 1))
                print(f"EWOULDBLOCK encountered. Retrying in 100ms... ({MAX_RETRIES - retry_count + 1}/{MAX_RETRIES})")
            else:
                print(f"Maximum retry attempts ({MAX_RETRIES}) reached. Giving up on reading from fd {fd}.")
            return ""
        else:
            raise
    return b"".join(data).decode('utf-8', errors='replace').strip()

