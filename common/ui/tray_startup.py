"""Shared system-tray startup behavior for desktop applications."""

from __future__ import annotations


def should_show_window_on_start(
    *,
    start_minimized_to_tray: bool,
    system_tray_available: bool,
) -> bool:
    """Show unless the user explicitly requested a hidden tray startup."""
    return not start_minimized_to_tray or not system_tray_available
