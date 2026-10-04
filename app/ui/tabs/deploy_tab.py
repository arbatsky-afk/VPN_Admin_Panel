"""Deploy tab controls with no server-operation logic."""

from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import QHBoxLayout, QLabel, QPushButton, QVBoxLayout, QWidget


class DeployTab(QWidget):
    """Display Deploy actions and report the user's requested action."""

    ssh_fix_requested = Signal()
    base_security_requested = Signal()
    xray_requested = Signal()
    hysteria2_requested = Signal()
    mieru_requested = Signal()
    docker_requested = Signal()
    amnezia_information_requested = Signal()
    nginx_requested = Signal()
    netdata_requested = Signal()

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("actionTabPage")
        self._operation_controls_enabled = True
        self._editing_enabled = True

        tab_layout = QVBoxLayout(self)
        tab_layout.setContentsMargins(12, 12, 12, 12)
        tab_layout.setSpacing(12)

        deploy_group = QWidget()
        deploy_layout = QVBoxLayout(deploy_group)
        deploy_layout.setContentsMargins(0, 0, 0, 0)
        deploy_layout.setSpacing(3)

        recovery_hint = QLabel("Use SSH Fix only when key-based SSH access is unavailable.")
        recovery_hint.setObjectName("deployHint")
        self.ssh_fix_button = QPushButton("SSH Fix")
        self.ssh_fix_button.setObjectName("deployAction")
        self.ssh_fix_button.clicked.connect(self.ssh_fix_requested)

        foundation_hint = QLabel("Install Base + Security before any component.")
        foundation_hint.setObjectName("deployHint")
        self.base_security_button = QPushButton("Base + Security")
        self.base_security_button.setObjectName("deployAction")
        self.base_security_button.clicked.connect(self.base_security_requested)

        components_hint = QLabel(
            "Choose any combination; install in any order after Base + Security."
        )
        components_hint.setObjectName("deployHint")
        component_arrows_layout = QHBoxLayout()
        component_arrows_layout.setSpacing(8)
        for _ in range(5):
            component_arrows_layout.addWidget(self._flow_arrow(), 1)

        components_layout = QHBoxLayout()
        components_layout.setSpacing(8)
        self.components_layout = components_layout
        self.xray_button = self._component_button("Xray", self.xray_requested)
        self.hysteria2_button = self._component_button("Hysteria2", self.hysteria2_requested)
        self.mieru_button = self._component_button("Mieru", self.mieru_requested)
        self.docker_button = self._component_button("Docker", self.docker_requested)
        self.amnezia_button = self._component_button("Amnezia", self.amnezia_information_requested)
        self.nginx_button = self._component_button("Nginx", self.nginx_requested)
        self.netdata_button = self._component_button("Netdata", self.netdata_requested)
        for button in (
            self.xray_button,
            self.hysteria2_button,
            self.mieru_button,
        ):
            components_layout.addWidget(button, 1, Qt.AlignmentFlag.AlignTop)
        docker_amnezia_stack = QWidget()
        self.docker_amnezia_layout = QVBoxLayout(docker_amnezia_stack)
        self.docker_amnezia_layout.setContentsMargins(0, 0, 0, 0)
        self.docker_amnezia_layout.setSpacing(3)
        self.docker_amnezia_layout.addWidget(self.docker_button)
        self.docker_amnezia_information_arrow = self._flow_arrow()
        self.docker_amnezia_layout.addWidget(self.docker_amnezia_information_arrow)
        self.docker_amnezia_layout.addWidget(self.amnezia_button)
        components_layout.addWidget(docker_amnezia_stack, 1, Qt.AlignmentFlag.AlignTop)
        nginx_netdata_stack = QWidget()
        self.nginx_netdata_layout = QVBoxLayout(nginx_netdata_stack)
        self.nginx_netdata_layout.setContentsMargins(0, 0, 0, 0)
        self.nginx_netdata_layout.setSpacing(3)
        self.nginx_netdata_layout.addWidget(self.nginx_button)
        self.nginx_netdata_dependency_arrow = self._flow_arrow()
        self.nginx_netdata_layout.addWidget(self.nginx_netdata_dependency_arrow)
        self.nginx_netdata_layout.addWidget(self.netdata_button)
        components_layout.addWidget(nginx_netdata_stack, 1)

        deploy_layout.addWidget(recovery_hint)
        deploy_layout.addWidget(self.ssh_fix_button)
        deploy_layout.addWidget(self._flow_arrow())
        deploy_layout.addWidget(foundation_hint)
        deploy_layout.addWidget(self.base_security_button)
        deploy_layout.addLayout(component_arrows_layout)
        deploy_layout.addWidget(components_hint)
        deploy_layout.addLayout(components_layout)
        tab_layout.addWidget(deploy_group)
        tab_layout.addStretch()

        self._operation_buttons = (
            self.ssh_fix_button,
            self.base_security_button,
            self.xray_button,
            self.hysteria2_button,
            self.mieru_button,
            self.docker_button,
            self.nginx_button,
            self.netdata_button,
        )

    @staticmethod
    def _flow_arrow() -> QLabel:
        arrow = QLabel("↓")
        arrow.setObjectName("deployFlowArrow")
        arrow.setAlignment(Qt.AlignmentFlag.AlignHCenter)
        arrow.setFixedHeight(18)
        return arrow

    @staticmethod
    def _component_button(label: str, signal: Signal) -> QPushButton:
        button = QPushButton(label)
        button.setObjectName("deployAction")
        button.clicked.connect(signal)
        return button

    def set_operation_controls_enabled(self, enabled: bool) -> None:
        """Enable or disable every action controlled by the global operation gate."""
        self._operation_controls_enabled = enabled
        self._update_operation_buttons()

    def set_editing_enabled(self, enabled: bool) -> None:
        self._editing_enabled = enabled
        self._update_operation_buttons()

    def _update_operation_buttons(self) -> None:
        enabled = self._operation_controls_enabled and self._editing_enabled
        for button in self._operation_buttons:
            button.setEnabled(enabled)
