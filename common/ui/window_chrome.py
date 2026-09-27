"""Shared Windows-native title-bar styling."""

from __future__ import annotations

import ctypes
import sys

from PySide6.QtWidgets import QWidget

from .theme import ThemeColors

_DWMWA_USE_IMMERSIVE_DARK_MODE = 20
_DWMWA_BORDER_COLOR = 34
_DWMWA_CAPTION_COLOR = 35
_DWMWA_TEXT_COLOR = 36


def apply_native_title_bar(window: QWidget, colors: ThemeColors) -> bool:
    """Apply theme colors to a Windows title bar while retaining native controls."""
    if sys.platform != "win32":
        return False

    try:
        dwmapi = ctypes.WinDLL("dwmapi")
        hwnd = ctypes.c_void_p(int(window.winId()))
    except (AttributeError, OSError):
        return False

    def set_attribute(attribute: int, value: int) -> bool:
        color = ctypes.c_uint(value)
        result = dwmapi.DwmSetWindowAttribute(
            hwnd,
            attribute,
            ctypes.byref(color),
            ctypes.sizeof(color),
        )
        return result == 0

    is_dark = _relative_luminance(colors.window_background) < 0.5
    dark_mode = ctypes.c_int(int(is_dark))
    try:
        dwmapi.DwmSetWindowAttribute(
            hwnd,
            _DWMWA_USE_IMMERSIVE_DARK_MODE,
            ctypes.byref(dark_mode),
            ctypes.sizeof(dark_mode),
        )
        results = (
            set_attribute(_DWMWA_CAPTION_COLOR, _colorref(colors.window_background)),
            set_attribute(_DWMWA_TEXT_COLOR, _colorref(colors.text)),
            set_attribute(_DWMWA_BORDER_COLOR, _colorref(colors.panel_border)),
        )
    except (OSError, ctypes.ArgumentError):
        return False
    return all(results)


def _colorref(color: str) -> int:
    """Convert a ``#RRGGBB`` color to a Windows COLORREF value."""
    red = int(color[1:3], 16)
    green = int(color[3:5], 16)
    blue = int(color[5:7], 16)
    return red | (green << 8) | (blue << 16)


def _relative_luminance(color: str) -> float:
    red = int(color[1:3], 16)
    green = int(color[3:5], 16)
    blue = int(color[5:7], 16)
    return (0.2126 * red + 0.7152 * green + 0.0722 * blue) / 255
