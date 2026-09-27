"""Shared theme-aware checkbox controls."""

from __future__ import annotations

from PySide6.QtCore import QPointF, Qt
from PySide6.QtGui import QColor, QPainter, QPaintEvent, QPen
from PySide6.QtWidgets import QCheckBox, QStyle, QStyleOptionButton, QWidget

from .theme import ThemeColors


def _contrasting_check_color(background: str) -> QColor:
    color = QColor(background)
    brightness = (color.red() * 299 + color.green() * 587 + color.blue() * 114) / 1000
    return QColor("#07111E" if brightness >= 150 else "#FFFFFF")


class GreenCheckBox(QCheckBox):
    """Checkbox whose selected state uses the theme success color."""

    INDICATOR_SIZE = 14

    def __init__(
        self,
        text: str,
        colors: ThemeColors,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(text, parent)
        self._colors = colors
        self.setObjectName("greenCheckBox")
        self.setAccessibleName(text)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setMinimumHeight(self.INDICATOR_SIZE + 2)
        self.setStyleSheet(self._build_stylesheet(colors))

    def paintEvent(self, event: QPaintEvent) -> None:
        super().paintEvent(event)
        if not self.isChecked():
            return

        option = QStyleOptionButton()
        self.initStyleOption(option)
        indicator = self.style().subElementRect(
            QStyle.SubElement.SE_CheckBoxIndicator,
            option,
            self,
        )
        background = self._colors.success if self.isEnabled() else self._colors.control_border
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        pen = QPen(_contrasting_check_color(background), 2.2)
        pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        pen.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
        painter.setPen(pen)
        painter.drawLine(
            QPointF(indicator.left() + 3.0, indicator.center().y()),
            QPointF(indicator.left() + 6.5, indicator.bottom() - 3.0),
        )
        painter.drawLine(
            QPointF(indicator.left() + 6.5, indicator.bottom() - 3.0),
            QPointF(indicator.right() - 2.5, indicator.top() + 3.0),
        )

    @classmethod
    def _build_stylesheet(cls, colors: ThemeColors) -> str:
        return f"""
            QCheckBox#greenCheckBox {{
                spacing: 6px; font-size: 13px;
            }}
            QCheckBox#greenCheckBox::indicator {{
                width: {cls.INDICATOR_SIZE}px; height: {cls.INDICATOR_SIZE}px;
                border: 1px solid {colors.muted_text}; border-radius: 4px;
                background: {colors.control_background};
            }}
            QCheckBox#greenCheckBox::indicator:hover {{
                border-color: {colors.blue}; background: {colors.blue_dark_hover};
            }}
            QCheckBox#greenCheckBox:focus::indicator {{
                border-color: {colors.blue_hover};
            }}
            QCheckBox#greenCheckBox::indicator:checked {{
                border-color: {colors.success}; background: {colors.success};
            }}
            QCheckBox#greenCheckBox::indicator:disabled {{
                border-color: {colors.control_border};
                background: {colors.control_background};
            }}
            QCheckBox#greenCheckBox::indicator:checked:disabled {{
                border-color: {colors.control_border};
                background: {colors.control_border};
            }}
        """
