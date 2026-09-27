"""Docker-specific Management presentation panel."""

from PySide6.QtCore import QSize, Signal
from PySide6.QtWidgets import QToolButton, QVBoxLayout, QWidget

from app.services.management import DockerManagementStatus
from app.ui.tabs.management_panels.widgets import (
    service_value_state,
    set_status_value,
    startup_value_state,
    status_row,
    status_value,
)
from common.ui.icon_assets import action_icon


class DockerPanel(QWidget):
    """Present Docker and detected AmneziaWG state and action intents."""

    action_requested = Signal(str)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("managementDockerPanel")
        self.status: DockerManagementStatus | None = None
        self.controls_enabled = True
        self._icon_colors = ("#8f9bad", "#22c55e", "#ef4444")

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 28, 0, 0)
        layout.setSpacing(2)
        self.service_value = status_value("Service")
        self.startup_value = status_value("Start at boot")
        self.amnezia_value = status_value("AmneziaWG")
        self.amnezia_port_value = status_value("UDP port")
        for value in (self.service_value[1], self.startup_value[1]):
            value.setFixedWidth(98)
        self.buttons = {
            action: QToolButton() for action in ("start", "stop", "restart", "enable", "disable")
        }
        self.buttons["start"].setToolTip("Start Docker")
        self.buttons["stop"].setToolTip("Stop Docker")
        self.buttons["restart"].setToolTip("Restart Docker")
        self.buttons["enable"].setToolTip("Enable Docker at boot")
        self.buttons["disable"].setToolTip("Disable Docker at boot")
        for action, button in self.buttons.items():
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
                self.startup_value, tuple(self.buttons[action] for action in ("enable", "disable"))
            )
        )
        layout.addWidget(status_row(self.amnezia_value))
        layout.addWidget(status_row(self.amnezia_port_value))
        layout.addStretch()
        self.render()

    def set_status(self, status: DockerManagementStatus) -> None:
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
            for _label, value in (
                self.service_value,
                self.startup_value,
                self.amnezia_value,
                self.amnezia_port_value,
            ):
                set_status_value(value, "Loading…")
            self._update_buttons()
            return
        set_status_value(
            self.service_value[1],
            f"● {status.service_state.capitalize()}",
            state=service_value_state(status.service_state),
        )
        set_status_value(
            self.startup_value[1],
            f"● {status.startup_state.capitalize()}",
            state=startup_value_state(status.startup_state),
        )
        if status.amnezia_state == "detected":
            if status.amnezia_container_state == "running":
                set_status_value(self.amnezia_value[1], "● Running", state="good")
            else:
                set_status_value(
                    self.amnezia_value[1],
                    f"Detected · {status.amnezia_container_state or 'unknown'}",
                )
            set_status_value(self.amnezia_port_value[1], self._port_summary(status))
        elif status.amnezia_state == "not_detected":
            set_status_value(self.amnezia_value[1], "Not detected")
            set_status_value(self.amnezia_port_value[1], "—")
        else:
            set_status_value(self.amnezia_value[1], "Unknown (Docker unavailable)")
            set_status_value(self.amnezia_port_value[1], "—")
        self._update_buttons()

    @staticmethod
    def _port_summary(status: DockerManagementStatus) -> str:
        if not status.amnezia_udp_ports:
            return "No published UDP port"
        ports = sorted({port.port for port in status.amnezia_udp_ports})
        port_text = ", ".join(str(port) for port in ports) + "/udp"
        hosts = {port.host_address for port in status.amnezia_udp_ports}
        families: list[str] = []
        if any("." in host for host in hosts):
            families.append("IPv4")
        if any(":" in host for host in hosts):
            families.append("IPv6")
        return f"{port_text} · {' + '.join(families)}" if families else port_text

    def _update_buttons(self) -> None:
        status = self.status
        enabled = self.controls_enabled and status is not None
        service_state = status.service_state if status is not None else "unknown"
        startup_state = status.startup_state if status is not None else "unknown"
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
