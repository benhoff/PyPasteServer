import os
import sys
from typing import TextIO

ANSI_CODES = {
    "reset": "\033[0m",
    "bold": "\033[1m",
    "cyan": "\033[36m",
    "green": "\033[32m",
    "yellow": "\033[33m",
    "red": "\033[31m",
}


def _supports_color(stream: TextIO) -> bool:
    if os.getenv("NO_COLOR") is not None:
        return False
    try:
        return stream.isatty()
    except Exception:
        return False


def color_text(text: str, color: str, *, stream: TextIO = sys.stdout) -> str:
    if not _supports_color(stream):
        return text

    prefix = ANSI_CODES.get(color)
    reset = ANSI_CODES.get("reset")
    if not prefix or not reset:
        return text

    return f"{prefix}{text}{reset}"


def style_text(text: str, *styles: str, stream: TextIO = sys.stdout) -> str:
    if not _supports_color(stream):
        return text

    codes = [ANSI_CODES.get(style) for style in styles if ANSI_CODES.get(style)]
    if not codes:
        return text

    reset = ANSI_CODES.get("reset", "")
    return f"{''.join(codes)}{text}{reset}"
