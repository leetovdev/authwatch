import os
import sys

_CODES = {
    "red": "31",
    "green": "32",
    "yellow": "33",
    "blue": "34",
    "cyan": "36",
    "gray": "90",
    "bold": "1",
}


def _supports_color() -> bool:
    if os.environ.get("NO_COLOR") or not sys.stdout.isatty():
        return False
    if os.name != "nt":
        return True
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-11)
        mode = ctypes.c_uint32()
        if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            return False
        return bool(kernel32.SetConsoleMode(handle, mode.value | 0x0004))
    except (AttributeError, OSError):
        return False


ENABLED = _supports_color()


def paint(text: str, *styles: str) -> str:
    if not ENABLED or not styles:
        return text
    return f"\033[{';'.join(_CODES[s] for s in styles)}m{text}\033[0m"
