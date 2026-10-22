"""UTF-8 output and VT colour processing for Windows consoles.

Windows Terminal/PowerShell default Python's stdio to the ANSI code page,
which can't encode warren's glyphs and banner, and a legacy conhost only
interprets ANSI colour escapes once VT processing is enabled. No-op elsewhere.
"""

from __future__ import annotations

import sys

_STD_OUTPUT_HANDLE = -11
_STD_ERROR_HANDLE = -12
_ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004


def _utf8_stdio() -> None:
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        encoding = (getattr(stream, "encoding", "") or "").lower().replace("-", "")
        if reconfigure is not None and encoding != "utf8":
            try:
                reconfigure(encoding="utf-8", errors="replace")
            except (OSError, ValueError):
                pass


def _enable_vt() -> None:
    import ctypes  # noqa: PLC0415
    from ctypes import wintypes  # noqa: PLC0415

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    for handle_id in (_STD_OUTPUT_HANDLE, _STD_ERROR_HANDLE):
        handle = kernel32.GetStdHandle(handle_id)
        mode = wintypes.DWORD()
        if handle and kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            kernel32.SetConsoleMode(handle, mode.value | _ENABLE_VIRTUAL_TERMINAL_PROCESSING)


def enable() -> None:
    if sys.platform != "win32":
        return
    _utf8_stdio()
    try:
        _enable_vt()
    except (OSError, AttributeError):
        pass
