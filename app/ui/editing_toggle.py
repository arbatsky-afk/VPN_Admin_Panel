"""Theme-aware Editing toggle used by the Admin Panel shell."""

from __future__ import annotations

from PySide6.QtCore import QEvent, QRectF, QSize, Qt
from PySide6.QtGui import QColor, QEnterEvent, QPainter, QPaintEvent, QPen
from PySide6.QtWidgets import QAbstractButton, QWidget

from common.ui.theme import ThemeColors


class EditingToggle(QAbstractButton):
    """Compact binary control whose off state represents Read only."""

    _WIDTH = 104
    _HEIGHT = 21
    _TRACK_WIDTH = 30
    _TRACK_HEIGHT = 14
    _KNOB_SIZE = 8

    def __init__(self, colors: ThemeColors, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._colors = colors
        self.setObjectName("editingToggle")
        self.setText("Edit mode")
        self.setCheckable(True)
        self.setFixedSize(self._WIDTH, self._HEIGHT)
        self.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setToolTip("Editing automatically returns to Read only after 10 minutes")
        self.setAccessibleName("Edit mode")
        self.setAccessibleDescription("Off is Read only; on enables Editing for 10 minutes")

    def sizeHint(self) -> QSize:
        return QSize(self._WIDTH, self._HEIGHT)

    def set_theme_colors(self, colors: ThemeColors) -> None:
        """Apply a new theme without changing the checked state."""
        self._colors = colors
        self.update()

    def enterEvent(self, event: QEnterEvent) -> None:
        self.update()
        super().enterEvent(event)

    def leaveEvent(self, event: QEvent) -> None:
        self.update()
        super().leaveEvent(event)

    def paintEvent(self, _event: QPaintEvent) -> None:
        colors = self._colors
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        enabled = self.isEnabled()
        checked = self.isChecked()
        hovered = self.underMouse()
        pressed = self.isDown()

        text_color = QColor(colors.text if enabled else colors.muted_text)
        painter.setPen(text_color)
        text_width = self.width() - self._TRACK_WIDTH - 8
        painter.drawText(
            0,
            0,
            text_width,
            self.height(),
            Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter,
            self.text(),
        )

        track_left = self.width() - self._TRACK_WIDTH - 1
        track_top = (self.height() - self._TRACK_HEIGHT) / 2
        track = QRectF(
            track_left,
            track_top,
            self._TRACK_WIDTH,
            self._TRACK_HEIGHT,
        )

        if not enabled:
            track_color = QColor(colors.control_background)
            border_color = QColor(colors.control_border)
            knob_color = QColor(colors.muted_text)
        elif checked:
            track_color = QColor(colors.blue_hover if hovered or pressed else colors.blue)
            border_color = track_color
            knob_color = QColor(colors.control_background)
        else:
            track_color = QColor(
                colors.blue_dark_hover if hovered or pressed else colors.control_background
            )
            border_color = QColor(colors.blue if hovered else colors.control_border)
            knob_color = QColor(colors.muted_text)

        painter.setPen(QPen(border_color, 1))
        painter.setBrush(track_color)
        painter.drawRoundedRect(track, self._TRACK_HEIGHT / 2, self._TRACK_HEIGHT / 2)

        knob_margin = (self._TRACK_HEIGHT - self._KNOB_SIZE) / 2
        knob_left = (
            track.right() - knob_margin - self._KNOB_SIZE
            if checked
            else track.left() + knob_margin
        )
        knob = QRectF(
            knob_left,
            track.top() + knob_margin,
            self._KNOB_SIZE,
            self._KNOB_SIZE,
        )
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(knob_color)
        painter.drawEllipse(knob)

        if self.hasFocus():
            focus_pen = QPen(QColor(colors.blue_hover), 1, Qt.PenStyle.DotLine)
            painter.setPen(focus_pen)
            painter.setBrush(Qt.BrushStyle.NoBrush)
            focus_rect = QRectF(self.rect()).adjusted(0.5, 0.5, -0.5, -0.5)
            painter.drawRoundedRect(focus_rect, 4, 4)
