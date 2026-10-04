"""Nginx-specific Management presentation panel."""

from PySide6.QtCore import QSize, Signal
from PySide6.QtWidgets import QToolButton, QVBoxLayout, QWidget

from app.services.management import NginxManagementStatus
from app.ui.tabs.management_panels.widgets import (
    service_value_state,
    set_status_value,
    startup_value_state,
    status_row,
    status_value,
)
from common.ui.icon_assets import action_icon


class NginxPanel(QWidget):
    """Present read-only Nginx service and listener health state."""

    action_requested = Signal(str)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("managementNginxPanel")
        self.status: NginxManagementStatus | None = None
        self.controls_enabled = True
        self._icon_colors = ("#8f9bad", "#22c55e", "#ef4444")

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 28, 0, 0)
        layout.setSpacing(2)
        self.values = {
            "service": status_value("Service"),
            "startup": status_value("Start at boot"),
            "http": status_value("HTTP"),
            "https": status_value("HTTPS"),
        }
        for key in ("service", "startup"):
            self.values[key][1].setFixedWidth(98)
        self.buttons = {
            action: QToolButton() for action in ("start", "stop", "restart", "enable", "disable")
        }
        tooltips = {
            "start": "Start Nginx",
            "stop": "Stop Nginx",
            "restart": "Restart Nginx",
            "enable": "Enable Nginx at boot",
            "disable": "Disable Nginx at boot",
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
                self.values["service"],
                tuple(self.buttons[action] for action in ("start", "stop", "restart")),
                label_width=118,
            )
        )
        layout.addWidget(
            status_row(
                self.values["startup"],
                tuple(self.buttons[action] for action in ("enable", "disable")),
                label_width=118,
            )
        )
        for key in ("http", "https"):
            layout.addWidget(status_row(self.values[key], label_width=118))
        layout.addStretch()
        self.render()

    def set_status(self, status: NginxManagementStatus) -> None:
        self.status = status
        self.render()

    def clear_status(self) -> None:
        self.status = None
        self.render()

    def set_controls_enabled(self, enabled: bool) -> None:
        self.controls_enabled = enabled
        self._update_buttons()

    def set_action_colors(self, normal: str, success: str, error: str) -> None:
        self._icon_colors = (normal, success, error)
        self._update_buttons()

    def render(self) -> None:
        status = self.status
        if status is None:
            for _label, value in self.values.values():
                set_status_value(value, "Loading…")
            self._update_buttons()
            return
        set_status_value(
            self.values["service"][1],
            f"● {status.service.service_state.capitalize()}",
            state=service_value_state(status.service.service_state),
        )
        set_status_value(
            self.values["startup"][1],
            f"● {status.service.startup_state.capitalize()}",
            state=startup_value_state(status.service.startup_state),
        )
        set_status_value(
            self.values["http"][1],
            f"{status.http_port} · {'Healthy' if status.http_healthy else 'Unhealthy'}",
            state="good" if status.http_healthy else "bad",
        )
        set_status_value(
            self.values["https"][1],
            f"{status.https_port} · {'Healthy' if status.https_healthy else 'Unhealthy'}",
            state="good" if status.https_healthy else "bad",
        )
        self._update_buttons()

    def _update_buttons(self) -> None:
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
