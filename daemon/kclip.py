"""Helpers for interacting with the /dev/kclip misc device via ioctls.

This mirrors the UAPI defined in include/uapi/kclip_uapi.h from the kclip
kernel module. Only the pieces required by the daemon are implemented here.
"""

from __future__ import annotations

import ctypes
import errno
import os
from dataclasses import dataclass
from typing import Iterable, List

# ===== UAPI constants (mirroring include/uapi/kclip_uapi.h) =====
KCLIP_ABI_VERSION = 1
KCLIP_IOC_MAGIC = ord("U")
KCLIP_SLOT_DEFAULT = 0
KCLIP_MIME_MAX = 128
KCLIP_COMM_MAX = 16
KCLIP_PART_F_PRIMARY = 1 << 0
KCLIP_DEFAULT_MAX_PARTS = 16

# fetch flags
KCLIP_FETCH_F_NONBLOCK = 1 << 0
KCLIP_FETCH_F_PEEK = 1 << 1
KCLIP_FETCH_F_POP = 1 << 2
KCLIP_FETCH_F_GET_PART_FDS = 1 << 3


# ===== ioctl helper macros (adapted from linux/ioctl.h) =====
_IOC_NRBITS = 8
_IOC_TYPEBITS = 8
_IOC_SIZEBITS = 14
_IOC_DIRBITS = 2

_IOC_NRSHIFT = 0
_IOC_TYPESHIFT = _IOC_NRSHIFT + _IOC_NRBITS
_IOC_SIZESHIFT = _IOC_TYPESHIFT + _IOC_TYPEBITS
_IOC_DIRSHIFT = _IOC_SIZESHIFT + _IOC_SIZEBITS

_IOC_NONE = 0
_IOC_WRITE = 1
_IOC_READ = 2


def _IOC(direction: int, ioc_type: int, number: int, size: int) -> int:
    return (
        (direction << _IOC_DIRSHIFT)
        | (ioc_type << _IOC_TYPESHIFT)
        | (number << _IOC_NRSHIFT)
        | (size << _IOC_SIZESHIFT)
    )


def _IOWR(ioc_type: int, number: int, obj) -> int:
    size = ctypes.sizeof(obj)
    return _IOC(_IOC_READ | _IOC_WRITE, ioc_type, number, size)


def _IOW(ioc_type: int, number: int, obj) -> int:
    size = ctypes.sizeof(obj)
    return _IOC(_IOC_WRITE, ioc_type, number, size)


# ===== ctypes mirrors of the UAPI structs =====
class KclipMime(ctypes.Structure):
    _fields_ = [
        ("length", ctypes.c_uint16),
        ("_pad", ctypes.c_uint16),
        ("data", ctypes.c_char * KCLIP_MIME_MAX),
    ]


class KclipMeta(ctypes.Structure):
    _fields_ = [
        ("ts_ns", ctypes.c_uint64),
        ("uid", ctypes.c_uint32),
        ("pid", ctypes.c_uint32),
        ("comm", ctypes.c_char * KCLIP_COMM_MAX),
    ]


class KclipPart(ctypes.Structure):
    _fields_ = [
        ("mime", KclipMime),
        ("size", ctypes.c_uint64),
        ("flags", ctypes.c_uint64),
        ("memfd_fd", ctypes.c_int32),
        ("_pad", ctypes.c_uint32),
    ]


class KclipMsgFetch(ctypes.Structure):
    _fields_ = [
        ("abi_version", ctypes.c_uint16),
        ("struct_size", ctypes.c_uint16),
        ("slot", ctypes.c_uint32),
        ("flags", ctypes.c_uint32),
        ("out_seqno", ctypes.c_uint64),
        ("out_total_size", ctypes.c_uint64),
        ("out_parts_count", ctypes.c_uint32),
        ("_pad0", ctypes.c_uint32),
        ("out_meta", KclipMeta),
        ("out_parts_cap", ctypes.c_uint32),
        ("_pad1", ctypes.c_uint32),
        ("out_parts_ptr", ctypes.c_uint64),
    ]


KCLIP_IOC_MSG_FETCH = _IOWR(KCLIP_IOC_MAGIC, 0x02, KclipMsgFetch)


# libc.ioctl wrapper --------------------------------------------------------
libc = ctypes.CDLL(None, use_errno=True)
libc.ioctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_void_p]
libc.ioctl.restype = ctypes.c_int


@dataclass
class PartData:
    """Clipboard part returned by kclip."""

    mime: str
    size: int
    flags: int
    data: bytes


@dataclass
class Message:
    """Result of a MSG_FETCH call."""

    seqno: int
    total_size: int
    parts: List[PartData]
    meta: KclipMeta


def _decode_mime(mime: KclipMime) -> str:
    if mime.length == 0:
        return ""
    raw = bytes(mime.data[: mime.length])
    return raw.decode("utf-8", errors="ignore")


def _read_exact(fd: int, size: int) -> bytes:
    remaining = size
    chunks = []
    while remaining > 0:
        chunk = os.read(fd, remaining)
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def fetch_message(
    fd: int,
    *,
    slot: int = KCLIP_SLOT_DEFAULT,
    pop: bool = True,
    nonblock: bool = True,
    parts_cap: int = KCLIP_DEFAULT_MAX_PARTS,
) -> Message:
    """Retrieve one message from the queue for *slot* using MSG_FETCH.

    The message is popped from the queue by default and the contents of each
    part are read fully before returning. File descriptors installed by the
    kernel are always closed by this helper.
    """

    flags = KCLIP_FETCH_F_GET_PART_FDS
    if pop:
        flags |= KCLIP_FETCH_F_POP
    if nonblock:
        flags |= KCLIP_FETCH_F_NONBLOCK

    fetch = KclipMsgFetch()
    fetch.abi_version = KCLIP_ABI_VERSION
    fetch.struct_size = ctypes.sizeof(KclipMsgFetch)
    fetch.slot = slot
    fetch.flags = flags
    fetch.out_parts_cap = parts_cap

    part_array = (KclipPart * parts_cap)()
    fetch.out_parts_ptr = ctypes.addressof(part_array)

    # Issue ioctl
    if libc.ioctl(fd, KCLIP_IOC_MSG_FETCH, ctypes.byref(fetch)) != 0:
        err = ctypes.get_errno()
        if err in (errno.EAGAIN, errno.EWOULDBLOCK):
            raise BlockingIOError(err, os.strerror(err))
        raise OSError(err, os.strerror(err))

    count = fetch.out_parts_count
    parts: List[PartData] = []
    for idx in range(count):
        part = part_array[idx]
        data = b""
        if part.memfd_fd >= 0 and part.size > 0:
            try:
                os.lseek(part.memfd_fd, 0, os.SEEK_SET)
            except OSError:
                pass
            try:
                data = _read_exact(part.memfd_fd, int(part.size))
            finally:
                try:
                    os.close(part.memfd_fd)
                except OSError:
                    pass
        parts.append(
            PartData(
                mime=_decode_mime(part.mime),
                size=int(part.size),
                flags=int(part.flags),
                data=data,
            )
        )

    return Message(
        seqno=int(fetch.out_seqno),
        total_size=int(fetch.out_total_size),
        parts=parts,
        meta=fetch.out_meta,
    )


def message_text(message: Message) -> str:
    """Return the preferred textual representation of *message*."""

    if not message.parts:
        return ""

    def _pick(parts: Iterable[PartData]) -> PartData:
        for part in parts:
            if part.flags & KCLIP_PART_F_PRIMARY:
                return part
        return message.parts[0]

    part = _pick(message.parts)
    if not part.data:
        return ""
    return part.data.decode("utf-8", errors="replace")

