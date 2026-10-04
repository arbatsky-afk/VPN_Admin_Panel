"""Base + Security-specific Management presentation panel."""

from PySide6.QtCore import QSize, Qt, Signal
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

from app.services.management import (
    BaseSecurityManagementStatus,
    ServiceManagementStatus,
)
from app.ui.tabs.management_panels.widgets import (
    service_value_state,
    set_status_value,
    startup_value_state,
    status_row,
    status_value,
)
from common.ui.icon_assets import action_icon


class BaseSecurityPanel(QWidget):
    """Present nftables, Fail2Ban, and allowed inbound ports."""

    action_requested = Signal(str, str)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("managementBaseSecurityPanel")
        self.status: BaseSecurityManagementStatus | None = None
        self.controls_enabled = True
        self._icon_colors = ("#8f9bad", "#22c55e", "#ef4444")

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 28, 0, 0)
        layout.setSpacing(2)
        self.values = {
            "nftables": (status_value("nftables"), status_value("Start at boot")),
            "fail2ban": (status_value("Fail2Ban"), status_value("Start at boot")),
        }
        for service_values in self.values.values():
            for _label, value in service_values:
                value.setFixedWidth(98)
        self.buttons = {
            (service, action): QToolButton()
            for service in ("nftables", "fail2ban")
            for action in ("start", "stop", "restart", "enable", "disable")
        }
        action_labels = {
            "start": "Start",
            "stop": "Stop",
            "restart": "Restart",
            "enable": "Enable at boot",
            "disable": "Disable at boot",
        }
        for (service, action), button in self.buttons.items():
            service_label = "nftables" if service == "nftables" else "Fail2Ban"
            button.setToolTip(f"{action_labels[action]} {service_label}")
            button.setObjectName("managementDockerIconAction")
            button.setIconSize(QSize(16, 16))
            button.clicked.connect(
                lambda _checked=False, requested_service=service, requested_action=action: (
                    self.action_requested.emit(
                        requested_service,
                        requested_action,
                    )
                )
            )
        layout.addWidget(self._service_row("fail2ban", 0, ("start", "stop", "restart")))
        layout.addWidget(self._service_row("fail2ban", 1, ("enable", "disable")))
        layout.addSpacing(2)
        self.divider = QFrame()
        self.divider.setObjectName("managementBaseSecurityDivider")
        self.divider.setFrameShape(QFrame.Shape.HLine)
        self.divider.setFixedHeight(1)
        layout.addWidget(self.divider)
        layout.addSpacing(2)
        layout.addWidget(self._service_row("nftables", 0, ("start", "stop", "restart")))
        layout.addWidget(self._service_row("nftables", 1, ("enable", "disable")))
        self.ports_value = status_value("Allowed ports")
        self.ports_value[1].setWordWrap(True)
        layout.addWidget(self._ports_row())
        layout.addStretch()
        self.render()

    def set_status(self, status: BaseSecurityManagementStatus) -> None:
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
            for service_values in self.values.values():
                set_status_value(service_values[0][1], "Loading…")
                set_status_value(service_values[1][1], "Loading…")
            set_status_value(self.ports_value[1], "Loading…")
            self._update_buttons()
            return
        self._set_service_values("nftables", status.nftables)
        self._set_service_values("fail2ban", status.fail2ban)
        set_status_value(self.ports_value[1], self._allowed_ports_summary(status))
        self._update_buttons()

    def _set_service_values(self, service: str, status: ServiceManagementStatus) -> None:
        service_value, startup_value = self.values[service]
        set_status_value(
            service_value[1],
            f"● {status.service_state.capitalize()}",
            state=service_value_state(status.service_state),
        )
        set_status_value(
            startup_value[1],
            f"● {status.startup_state.capitalize()}",
            state=startup_value_state(status.startup_state),
        )

    def _service_row(self, service: str, value_index: int, actions: tuple[str, ...]) -> QWidget:
        return status_row(
            self.values[service][value_index],
            tuple(self.buttons[(service, action)] for action in actions),
        )

    def _ports_row(self) -> QWidget:
        container = QWidget()
        row = QHBoxLayout(container)
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(8)
        label = QLabel(self.ports_value[0])
        label.setObjectName("managementDockerLabel")
        label.setFixedWidth(104)
        row.addWidget(label, 0, Qt.AlignmentFlag.AlignTop)
        row.addWidget(self.ports_value[1], 1, Qt.AlignmentFlag.AlignTop)
        return container

    @staticmethod
    def _allowed_ports_summary(status: BaseSecurityManagementStatus) -> str:
        if not status.allowed_ports:
            return "No active inbound ports found"
        return "\n".join(
            f"{port.protocol.upper()} {port.port}" + (f" · {port.owner}" if port.owner else "")
            for port in status.allowed_ports
        )

    def _update_buttons(self) -> None:
        status = self.status
        normal, _success, _error = self._icon_colors
        service_statuses = (
            ("nftables", status.nftables if status is not None else None),
            ("fail2ban", status.fail2ban if status is not None else None),
        )
        for service, service_status in service_statuses:
            enabled = self.controls_enabled and service_status is not None
            service_state = (
                service_status.service_state if service_status is not None else "unknown"
            )
            startup_state = (
                service_status.startup_state if service_status is not None else "unknown"
            )
            self.buttons[(service, "start")].setEnabled(
                enabled and service_state in {"inactive", "failed"}
            )
            self.buttons[(service, "stop")].setEnabled(enabled and service_state == "active")
            self.buttons[(service, "restart")].setEnabled(enabled and service_state == "active")
            self.buttons[(service, "enable")].setEnabled(enabled and startup_state == "disabled")
            self.buttons[(service, "disable")].setEnabled(enabled and startup_state == "enabled")
            self.buttons[(service, "start")].setIcon(action_icon("play", normal))
            self.buttons[(service, "stop")].setIcon(action_icon("square", normal))
            self.buttons[(service, "restart")].setIcon(action_icon("repeat-2", normal))
            self.buttons[(service, "enable")].setIcon(action_icon("play", normal))
            self.buttons[(service, "disable")].setIcon(action_icon("square", normal))
