"""Shared compact icon-action button behavior."""

from __future__ import annotations

from PySide6.QtCore import QSize, Qt
from PySide6.QtGui import QKeyEvent
from PySide6.QtWidgets import QToolButton, QWidget


class IconActionButton(QToolButton):
    """Theme-styled action button activated by Space, Enter, or Return."""

    def __init__(
        self,
        accessible_name: str,
        *,
        size: int = 32,
        icon_size: int = 18,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.setObjectName("iconAction")
        self.setToolTip(accessible_name)
        self.setAccessibleName(accessible_name)
        self.setFixedSize(size, size)
        self.setIconSize(QSize(icon_size, icon_size))

    def keyPressEvent(self, event: QKeyEvent) -> None:
        if event.key() in (Qt.Key.Key_Enter, Qt.Key.Key_Return):
            self.click()
            event.accept()
            return
        super().keyPressEvent(event)
