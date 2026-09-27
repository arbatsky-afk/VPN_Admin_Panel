"""Netdata-specific Management presentation panel."""

from PySide6.QtCore import QSize, Signal
from PySide6.QtWidgets import (
    QApplication,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

from app.services.management import NetdataAccessDetails, NetdataManagementStatus
from app.ui.tabs.management_panels.widgets import (
    service_value_state,
    set_status_value,
    startup_value_state,
    status_row,
    status_value,
)
from common.ui.icon_assets import action_icon


class NetdataPanel(QWidget):
    """Present Netdata health, access URL, copy intent, and service intents."""

    action_requested = Signal(str)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("managementNetdataPanel")
        self.status: NetdataManagementStatus | None = None
        self.access: NetdataAccessDetails | None = None
        self.controls_enabled = True
        self._icon_colors = ("#8f9bad", "#22c55e", "#ef4444")

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 28, 0, 0)
        layout.setSpacing(2)
        self.values = {
            "service": status_value("Service"),
            "startup": status_value("Start at boot"),
            "cloud": status_value("Netdata Cloud"),
            "protection": status_value("Access"),
        }
        self.access_inputs = {"url": QLineEdit()}
        for key, input_widget in self.access_inputs.items():
            input_widget.setObjectName(f"managementNetdata{key.capitalize()}Field")
            input_widget.setReadOnly(True)
            input_widget.setMinimumWidth(280)
        self.copy_buttons = {key: QToolButton() for key in self.access_inputs}
        for key, button in self.copy_buttons.items():
            display_name = "URL"
            button.setObjectName("managementDockerIconAction")
            button.setIconSize(QSize(16, 16))
            button.setToolTip(f"Copy Netdata {display_name}")
            button.setAccessibleName(f"Copy Netdata {display_name}")
            button.clicked.connect(
                lambda _checked=False, field=key: self._copy_access_field(field)
            )
        for key in ("service", "startup"):
            self.values[key][1].setFixedWidth(98)
        self.buttons = {
            action: QToolButton() for action in ("start", "stop", "restart", "enable", "disable")
        }
        tooltips = {
            "start": "Start Netdata",
            "stop": "Stop Netdata",
            "restart": "Restart Netdata",
            "enable": "Enable Netdata at boot",
            "disable": "Disable Netdata at boot",
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
        layout.addWidget(status_row(self.values["cloud"], label_width=118))
        layout.addWidget(status_row(self.values["protection"], label_width=118))
        layout.addWidget(self._access_row("URL", "url"))
        layout.addStretch()
        self.render()
        self.set_access(None)

    def set_status(self, status: NetdataManagementStatus) -> None:
        self.status = status
        self.render()

    def clear_status(self) -> None:
        self.status = None
        self.render()

    def set_access(self, access: NetdataAccessDetails | None) -> None:
        self.access = access
        values = {"url": access.url if access is not None else ""}
        for key, value in values.items():
            self.access_inputs[key].setText(value)
            self.copy_buttons[key].setEnabled(bool(value))

    def set_controls_enabled(self, enabled: bool) -> None:
        self.controls_enabled = enabled
        self._update_buttons()

    def set_action_colors(self, normal: str, success: str, error: str) -> None:
        self._icon_colors = (normal, success, error)
        self._update_buttons()
        for button in self.copy_buttons.values():
            button.setIcon(action_icon("copy", normal))

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
            self.values["cloud"][1],
            "● Online" if status.cloud_online else "● Offline",
            state="good" if status.cloud_online else "bad",
        )
        set_status_value(
            self.values["protection"][1],
            "● Cloud SSO" if status.proxy_bearer_protected else "● Unprotected",
            state="good" if status.proxy_bearer_protected else "bad",
        )
        self._update_buttons()

    def _access_row(self, label_text: str, field: str) -> QWidget:
        container = QWidget()
        container.setFixedHeight(30)
        row = QHBoxLayout(container)
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(8)
        label = QLabel(label_text)
        label.setObjectName("managementDockerLabel")
        label.setFixedWidth(118)
        row.addWidget(label)
        row.addWidget(self.access_inputs[field], 1)
        row.addWidget(self.copy_buttons[field])
        return container

    def _copy_access_field(self, field: str) -> None:
        input_widget = self.access_inputs.get(field)
        if input_widget is not None and input_widget.text():
            QApplication.clipboard().setText(input_widget.text())

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
