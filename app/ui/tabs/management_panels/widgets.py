"""Small stateless presentation helpers shared by Management panels."""

from PySide6.QtCore import Qt
from PySide6.QtGui import QPainter, QPalette, QPen
from PySide6.QtWidgets import (
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QSizePolicy,
    QWidget,
)

CONNECTION_FIELD_WIDTH = 182
_CONNECTION_FIELD_VERTICAL_SPACING = 6


class _ConnectionActionConnector(QWidget):
    """Draw a small tree connector from two editable fields to one action."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setFixedWidth(28)

    def paintEvent(self, event) -> None:
        painter = QPainter(self)
        pen = QPen(self.palette().color(QPalette.ColorRole.Mid))
        pen.setWidth(1)
        painter.setPen(pen)
        top = (self.height() - _CONNECTION_FIELD_VERTICAL_SPACING) // 4
        bottom = self.height() - top
        branch = self.width() // 2
        middle = (top + bottom) // 2
        painter.drawLine(0, top, branch, top)
        painter.drawLine(0, bottom, branch, bottom)
        painter.drawLine(branch, top, branch, bottom)
        painter.drawLine(branch, middle, self.width(), middle)


def status_value(label: str) -> tuple[str, QLabel]:
    value = QLabel("Loading…")
    value.setObjectName("managementDockerValue")
    return label, value


def set_status_value(value: QLabel, text: str, *, state: str = "") -> None:
    value.setProperty("state", state)
    value.setText(text)
    style = value.style()
    style.unpolish(value)
    style.polish(value)
    value.update()


def service_value_state(state: str) -> str:
    if state == "active":
        return "good"
    if state in {"inactive", "failed"}:
        return "bad"
    return ""


def startup_value_state(state: str) -> str:
    if state == "enabled":
        return "good"
    if state in {"disabled", "masked"}:
        return "bad"
    return ""


def status_row(
    value: tuple[str, QLabel],
    buttons: tuple[QWidget, ...] = (),
    *,
    label_width: int = 104,
) -> QWidget:
    container = QWidget()
    # Keep one pixel around the 28px action buttons at scaled display factors.
    container.setFixedHeight(30)
    row = QHBoxLayout(container)
    row.setContentsMargins(0, 0, 0, 0)
    row.setSpacing(8)
    label = QLabel(value[0])
    label.setObjectName("managementDockerLabel")
    label.setFixedWidth(label_width)
    row.addWidget(label)
    row.addWidget(value[1])
    for button in buttons:
        row.addWidget(button)
    row.addStretch()
    return container


def connection_settings_rows(
    port_input: QLineEdit,
    sni_input: QLineEdit,
    action: QPushButton,
) -> QWidget:
    container = QWidget()
    grid = QGridLayout(container)
    grid.setContentsMargins(0, 0, 0, 0)
    grid.setHorizontalSpacing(8)
    grid.setVerticalSpacing(_CONNECTION_FIELD_VERTICAL_SPACING)
    for row, (label_text, input_widget) in enumerate((("Port", port_input), ("SNI", sni_input))):
        label = QLabel(label_text)
        label.setObjectName("managementDockerLabel")
        label.setFixedWidth(104)
        grid.addWidget(label, row, 0)
        grid.addWidget(input_widget, row, 1)
    connector = _ConnectionActionConnector()
    action.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)
    grid.addWidget(connector, 0, 2, 2, 1)
    grid.addWidget(action, 0, 3, 2, 1, Qt.AlignmentFlag.AlignVCenter)
    grid.setColumnStretch(4, 1)
    return container


def single_connection_setting_row(
    label_text: str,
    input_widget: QLineEdit,
    action: QPushButton,
) -> QWidget:
    container = QWidget()
    row = QHBoxLayout(container)
    row.setContentsMargins(0, 0, 0, 0)
    row.setSpacing(8)
    label = QLabel(label_text)
    label.setObjectName("managementDockerLabel")
    label.setFixedWidth(104)
    row.addWidget(label)
    row.addWidget(input_widget)
    action.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)
    row.addWidget(action)
    row.addStretch()
    return container
