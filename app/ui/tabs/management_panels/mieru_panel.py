"""Mieru-specific Management presentation panel."""

from PySide6.QtCore import QSize, Signal
from PySide6.QtWidgets import QLineEdit, QPushButton, QToolButton, QVBoxLayout, QWidget

from app.services.management import MieruManagementStatus
from app.ui.tabs.management_panels.widgets import (
    CONNECTION_FIELD_WIDTH,
    service_value_state,
    set_status_value,
    single_connection_setting_row,
    startup_value_state,
    status_row,
    status_value,
)
from common.ui.icon_assets import action_icon


class MieruPanel(QWidget):
    """Present Mieru state and its editable public listener port."""

    action_requested = Signal(str)
    port_update_requested = Signal(str)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.status: MieruManagementStatus | None = None
        self.controls_enabled = True
        self.editing_enabled = True
        self._icon_colors = ("#8f9bad", "#22c55e", "#ef4444")

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 28, 0, 0)
        layout.setSpacing(2)
        self.service_value = status_value("Service")
        self.startup_value = status_value("Start at boot")
        self.runtime_value = status_value("Proxy runtime")
        self.transport_value = status_value("Transport")
        self.port_input = QLineEdit()
        self.port_input.setPlaceholderText("TCP/UDP port")
        self.port_input.setFixedWidth(CONNECTION_FIELD_WIDTH)
        self.port_apply_button = QPushButton("Apply")
        self.port_apply_button.setObjectName("operationAction")
        self.port_apply_button.clicked.connect(
            lambda: self.port_update_requested.emit(self.port_input.text())
        )
        self.port_input.textChanged.connect(self._update_controls)
        self.mtu_value = status_value("MTU")
        self.users_value = status_value("Users")
        for value in (self.service_value[1], self.startup_value[1]):
            value.setFixedWidth(98)
        self.buttons = {
            action: QToolButton() for action in ("start", "stop", "restart", "enable", "disable")
        }
        tooltips = {
            "start": "Start Mieru",
            "stop": "Stop Mieru",
            "restart": "Restart Mieru",
            "enable": "Enable Mieru at boot",
            "disable": "Disable Mieru at boot",
        }
        for action, button in self.buttons.items():
            button.setToolTip(tooltips[action])
            button.setObjectName("managementDockerIconAction")
            button.setIconSize(QSize(16, 16))
            button.clicked.connect(
                lambda _checked=False, requested_action=action: self.action_requested.emit(
                    requested_action
                )
            )
        layout.addWidget(
            status_row(
                self.service_value,
                tuple(self.buttons[action] for action in ("start", "stop", "restart")),
            )
        )
        layout.addWidget(
            status_row(
                self.startup_value,
                tuple(self.buttons[action] for action in ("enable", "disable")),
            )
        )
        for value in (self.runtime_value, self.transport_value):
            layout.addWidget(status_row(value))
        layout.addWidget(
            single_connection_setting_row("Port", self.port_input, self.port_apply_button)
        )
        for value in (self.mtu_value, self.users_value):
            layout.addWidget(status_row(value))
        layout.addStretch()
        self.render()

    def set_status(self, status: MieruManagementStatus) -> None:
        self.status = status
        self.render()

    def clear_status(self) -> None:
        self.status = None
        self.render()

    def set_controls_enabled(self, enabled: bool) -> None:
        self.controls_enabled = enabled
        self._update_controls()

    def set_editing_enabled(self, enabled: bool) -> None:
        self.editing_enabled = enabled
        self._update_controls()

    def set_action_colors(self, normal: str, success: str, error: str) -> None:
        self._icon_colors = (normal, success, error)
        self._update_controls()

    def render(self) -> None:
        status = self.status
        values = (
            self.service_value,
            self.startup_value,
            self.runtime_value,
            self.transport_value,
            self.mtu_value,
            self.users_value,
        )
        if status is None:
            for _label, value in values:
                set_status_value(value, "Loading…")
            self.port_input.clear()
            self._update_controls()
            return
        set_status_value(
            self.service_value[1],
            f"● {status.service.service_state.capitalize()}",
            state=service_value_state(status.service.service_state),
        )
        set_status_value(
            self.startup_value[1],
            f"● {status.service.startup_state.capitalize()}",
            state=startup_value_state(status.service.startup_state),
        )
        runtime_state = (
            "good"
            if status.runtime_state == "RUNNING"
            else "bad"
            if status.runtime_state == "IDLE"
            else ""
        )
        set_status_value(self.runtime_value[1], status.runtime_state, state=runtime_state)
        set_status_value(self.transport_value[1], status.transport)
        self.port_input.setText(str(status.port))
        set_status_value(self.mtu_value[1], str(status.mtu))
        set_status_value(self.users_value[1], str(status.user_count))
        self._update_controls()

    def _update_controls(self) -> None:
        status = self.status
        enabled = self.controls_enabled and status is not None
        service_state = status.service.service_state if status is not None else "unknown"
        startup_state = status.service.startup_state if status is not None else "unknown"
        self.buttons["start"].setEnabled(enabled and service_state in {"inactive", "failed"})
        self.buttons["stop"].setEnabled(enabled and service_state == "active")
        self.buttons["restart"].setEnabled(enabled and service_state == "active")
        self.buttons["enable"].setEnabled(enabled and startup_state == "disabled")
        self.buttons["disable"].setEnabled(enabled and startup_state == "enabled")
        normal, _success, _error = self._icon_colors
        self.buttons["start"].setIcon(action_icon("play", normal))
        self.buttons["stop"].setIcon(action_icon("square", normal))
        self.buttons["restart"].setIcon(action_icon("repeat-2", normal))
        self.buttons["enable"].setIcon(action_icon("play", normal))
        self.buttons["disable"].setIcon(action_icon("square", normal))
        fields_available = self.controls_enabled and status is not None
        self.port_input.setEnabled(fields_available)
        self.port_input.setReadOnly(not self.editing_enabled)
        changed = status is not None and self.port_input.text() != str(status.port)
        self.port_apply_button.setEnabled(fields_available and self.editing_enabled and changed)
