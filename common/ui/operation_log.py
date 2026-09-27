"""Shared geometry helpers for operation logs."""

from __future__ import annotations

from math import ceil

from PySide6.QtWidgets import QPlainTextEdit

OPERATION_LOG_VISIBLE_LINES = 15


def fix_operation_log_height(
    editor: QPlainTextEdit,
    visible_lines: int = OPERATION_LOG_VISIBLE_LINES,
) -> int:
    """Fix an operation log to an exact number of full text lines."""
    if visible_lines < 1:
        raise ValueError("visible_lines must be positive")
    editor.ensurePolished()
    document_margins = ceil(editor.document().documentMargin() * 2)
    viewport_height = editor.fontMetrics().lineSpacing() * visible_lines + document_margins
    total_height = viewport_height + editor.frameWidth() * 2
    editor.setFixedHeight(total_height)
    return total_height
