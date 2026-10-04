"""Management tab presentation and fixed Component action controls."""

from __future__ import annotations

from typing import Literal

from PySide6.QtCore import QSize, Qt, Signal
from PySide6.QtWidgets import (
    QAbstractItemView,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QPlainTextEdit,
    QSizePolicy,
    QStackedLayout,
    QTableWidget,
    QTableWidgetItem,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

from app.services.inventory import (
    ComponentInventory,
    InventorySnapshot,
    ManagementParameter,
)
from app.services.management import (
    BaseSecurityManagementStatus,
    DockerManagementStatus,
    Hysteria2ManagementStatus,
    MieruManagementStatus,
    NetdataAccessDetails,
    NetdataManagementStatus,
    NginxManagementStatus,
    XrayManagementStatus,
)
from app.ui.tabs.management_panels import (
    BaseSecurityPanel,
    DockerPanel,
    Hysteria2Panel,
    MieruPanel,
    NetdataPanel,
    NginxPanel,
    XrayPanel,
)
from common.ui.icon_assets import action_icon

ManagementViewState = Literal["idle", "loading", "ready", "error"]


class ManagementTab(QWidget):
    """Render Management-capable Components from an already collected snapshot."""

    docker_inspection_requested = Signal()
    docker_action_requested = Signal(str)
    base_security_inspection_requested = Signal()
    base_security_action_requested = Signal(str, str)
    xray_inspection_requested = Signal()
    xray_action_requested = Signal(str)
    xray_connection_update_requested = Signal(str, str)
    hysteria2_inspection_requested = Signal()
    hysteria2_action_requested = Signal(str)
    hysteria2_connection_update_requested = Signal(str, str)
    mieru_inspection_requested = Signal()
    mieru_action_requested = Signal(str)
    mieru_port_update_requested = Signal(str)
    nginx_inspection_requested = Signal()
    nginx_action_requested = Signal(str)
    netdata_inspection_requested = Signal()
    netdata_action_requested = Signal(str)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("actionTabPage")
        self._components: dict[str, ComponentInventory] = {}
        self._editing_enabled = True
        self._docker_icon_colors = ("#8f9bad", "#22c55e", "#ef4444")
        self._selection_to_restore: str | None = None
        self._docker_status_to_restore = False
        self._base_security_status_to_restore = False
        self._xray_status_to_restore = False
        self._hysteria2_status_to_restore = False
        self._mieru_status_to_restore = False
        self._nginx_status_to_restore = False
        self._netdata_status_to_restore = False
        self._refreshing_component_id: str | None = None

        self.status_label = QLabel()
        self.status_label.setObjectName("managementStatus")
        self.status_label.setWordWrap(True)
        self.status_label.setSizePolicy(
            QSizePolicy.Policy.Ignored,
            QSizePolicy.Policy.Preferred,
        )
        self.refresh_selected_button = QToolButton()
        self.refresh_selected_button.setObjectName("managementDockerIconAction")
        self.refresh_selected_button.setIconSize(QSize(16, 16))
        self.refresh_selected_button.setToolTip("Refresh selected component")
        self.refresh_selected_button.clicked.connect(self._refresh_selected_component)
        self.refresh_selected_button.setVisible(False)
        self.refresh_selected_label = QLabel()
        self.refresh_selected_label.setObjectName("managementStatus")
        self.refresh_selected_label.setVisible(False)

        self.table = QTableWidget(0, 2)
        self.table.setObjectName("managementTable")
        self.table.setHorizontalHeaderLabels(("Component", "Software"))
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        self.table.setFrameShape(QFrame.Shape.NoFrame)
        table_header = self.table.horizontalHeader()
        table_header.setFixedHeight(28)
        table_header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        table_header.setSectionResizeMode(1, QHeaderView.ResizeMode.Fixed)
        table_header.resizeSection(1, 88)
        self.table.verticalHeader().setDefaultSectionSize(28)
        table_height = table_header.height() + 7 * self.table.verticalHeader().defaultSectionSize()
        self.table.setFixedHeight(table_height)
        self.table.setFixedWidth(250)
        self.table.verticalHeader().setVisible(False)
        self.table.itemSelectionChanged.connect(self._show_selected_component)

        details_group = QWidget()
        details_layout = QVBoxLayout(details_group)
        details_layout.setContentsMargins(0, 0, 0, 0)
        details_layout.setSpacing(6)
        self.details_pages = QWidget()
        self.details_stack = QStackedLayout(self.details_pages)
        self.details_stack.setContentsMargins(0, 0, 0, 0)
        details_layout.addWidget(self.details_pages)
        self.details_text = QPlainTextEdit()
        self.details_text.setObjectName("managementDetailsText")
        self.details_text.setReadOnly(True)
        self.details_text.setLineWrapMode(QPlainTextEdit.LineWrapMode.WidgetWidth)
        self.details_text.setMinimumHeight(150)
        self.details_stack.addWidget(self.details_text)

        self.docker_panel = DockerPanel()
        self.docker_panel.action_requested.connect(self.docker_action_requested.emit)
        self.docker_service_value = self.docker_panel.service_value
        self.docker_startup_value = self.docker_panel.startup_value
        self.amnezia_value = self.docker_panel.amnezia_value
        self.amnezia_port_value = self.docker_panel.amnezia_port_value
        self.docker_buttons = self.docker_panel.buttons
        self.details_stack.addWidget(self.docker_panel)

        self.base_security_panel = BaseSecurityPanel()
        self.base_security_panel.action_requested.connect(self.base_security_action_requested.emit)
        self.base_security_values = self.base_security_panel.values
        self.base_security_buttons = self.base_security_panel.buttons
        self.base_security_divider = self.base_security_panel.divider
        self.base_security_ports_value = self.base_security_panel.ports_value
        self.details_stack.addWidget(self.base_security_panel)

        self.xray_panel = XrayPanel()
        self.xray_panel.action_requested.connect(self.xray_action_requested.emit)
        self.xray_panel.connection_update_requested.connect(
            self.xray_connection_update_requested.emit
        )
        self.xray_service_value = self.xray_panel.service_value
        self.xray_startup_value = self.xray_panel.startup_value
        self.xray_protocol_value = self.xray_panel.protocol_value
        self.xray_port_input = self.xray_panel.port_input
        self.xray_sni_input = self.xray_panel.sni_input
        self.xray_apply_button = self.xray_panel.apply_button
        self.xray_buttons = self.xray_panel.buttons
        self.details_stack.addWidget(self.xray_panel)

        self.hysteria2_panel = Hysteria2Panel()
        self.hysteria2_panel.action_requested.connect(self.hysteria2_action_requested.emit)
        self.hysteria2_panel.connection_update_requested.connect(
            self.hysteria2_connection_update_requested.emit
        )
        self.hysteria2_service_value = self.hysteria2_panel.service_value
        self.hysteria2_startup_value = self.hysteria2_panel.startup_value
        self.hysteria2_protocol_value = self.hysteria2_panel.protocol_value
        self.hysteria2_port_input = self.hysteria2_panel.port_input
        self.hysteria2_sni_input = self.hysteria2_panel.sni_input
        self.hysteria2_apply_button = self.hysteria2_panel.apply_button
        self.hysteria2_buttons = self.hysteria2_panel.buttons
        self.details_stack.addWidget(self.hysteria2_panel)

        self.mieru_panel = MieruPanel()
        self.mieru_panel.action_requested.connect(self.mieru_action_requested.emit)
        self.mieru_panel.port_update_requested.connect(self.mieru_port_update_requested.emit)
        self.mieru_service_value = self.mieru_panel.service_value
        self.mieru_startup_value = self.mieru_panel.startup_value
        self.mieru_runtime_value = self.mieru_panel.runtime_value
        self.mieru_transport_value = self.mieru_panel.transport_value
        self.mieru_port_input = self.mieru_panel.port_input
        self.mieru_port_apply_button = self.mieru_panel.port_apply_button
        self.mieru_mtu_value = self.mieru_panel.mtu_value
        self.mieru_users_value = self.mieru_panel.users_value
        self.mieru_buttons = self.mieru_panel.buttons
        self.details_stack.addWidget(self.mieru_panel)

        self.nginx_panel = NginxPanel()
        self.nginx_panel.action_requested.connect(self.nginx_action_requested.emit)
        self.nginx_values = self.nginx_panel.values
        self.nginx_buttons = self.nginx_panel.buttons
        self.details_stack.addWidget(self.nginx_panel)

        self.netdata_panel = NetdataPanel()
        self.netdata_panel.action_requested.connect(self.netdata_action_requested.emit)
        self.netdata_values = self.netdata_panel.values
        self.netdata_access_inputs = self.netdata_panel.access_inputs
        self.netdata_copy_buttons = self.netdata_panel.copy_buttons
        self.netdata_buttons = self.netdata_panel.buttons
        self.details_stack.addWidget(self.netdata_panel)
        details_layout.addStretch(1)
        details_layout.addWidget(self.status_label, 0, Qt.AlignmentFlag.AlignCenter)
        details_layout.addStretch(1)
        refresh_layout = QHBoxLayout()
        refresh_layout.setContentsMargins(0, 0, 0, 0)
        refresh_layout.addStretch()
        refresh_layout.addWidget(self.refresh_selected_label)
        refresh_layout.addWidget(self.refresh_selected_button)
        details_layout.addLayout(refresh_layout)

        tab_layout = QVBoxLayout(self)
        tab_layout.setContentsMargins(12, 12, 12, 12)
        tab_layout.setSpacing(8)
        content_layout = QHBoxLayout()
        content_layout.setSpacing(20)
        content_layout.addWidget(
            self.table, 0, Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignTop
        )
        content_layout.addWidget(details_group, 1)
        tab_layout.addLayout(content_layout, 1)

    def display_snapshot(
        self,
        snapshot: InventorySnapshot,
        *,
        netdata_access: NetdataAccessDetails | None = None,
    ) -> None:
        """Show the Management-capable Components in an Inventory snapshot."""
        self.netdata_panel.set_access(netdata_access)
        previously_selected = self._selection_to_restore or self.selected_component_id()
        self._selection_to_restore = None
        managed_components = tuple(
            component
            for component in snapshot.components
            if component.declaration is not None and component.declaration.management_handler
        )
        self._components = {component.component_id: component for component in managed_components}
        preserve_docker_status = self._docker_status_to_restore and "docker" in self._components
        self._docker_status_to_restore = False
        if not preserve_docker_status:
            self.docker_panel.clear_status()
        preserve_base_security_status = (
            self._base_security_status_to_restore and "base-security" in self._components
        )
        self._base_security_status_to_restore = False
        if not preserve_base_security_status:
            self.base_security_panel.clear_status()
        preserve_xray_status = self._xray_status_to_restore and "xray" in self._components
        self._xray_status_to_restore = False
        if not preserve_xray_status:
            self.xray_panel.clear_status()
        preserve_hysteria2_status = (
            self._hysteria2_status_to_restore and "hysteria2" in self._components
        )
        self._hysteria2_status_to_restore = False
        if not preserve_hysteria2_status:
            self.hysteria2_panel.clear_status()
        preserve_mieru_status = self._mieru_status_to_restore and "mieru" in self._components
        self._mieru_status_to_restore = False
        if not preserve_mieru_status:
            self.mieru_panel.clear_status()
        preserve_nginx_status = self._nginx_status_to_restore and "nginx" in self._components
        self._nginx_status_to_restore = False
        if not preserve_nginx_status:
            self.nginx_panel.clear_status()
        preserve_netdata_status = self._netdata_status_to_restore and "netdata" in self._components
        self._netdata_status_to_restore = False
        if not preserve_netdata_status:
            self.netdata_panel.clear_status()
        self.table.setRowCount(0)
        for component in managed_components:
            row = self.table.rowCount()
            self.table.insertRow(row)
            declaration = component.declaration
            if declaration is None:
                continue
            component_item = QTableWidgetItem(declaration.display_name)
            component_item.setData(Qt.ItemDataRole.UserRole, component.component_id)
            self.table.setItem(row, 0, component_item)
            self.table.setItem(row, 1, QTableWidgetItem(component.software_version or "n/a"))
        if managed_components:
            self._set_status("ready", f"Loaded {len(managed_components)} managed components.")
            selected_row = next(
                (
                    row
                    for row in range(self.table.rowCount())
                    if self.table.item(row, 0).data(Qt.ItemDataRole.UserRole)
                    == previously_selected
                ),
                0,
            )
            self.table.selectRow(selected_row)
        else:
            self._set_status("ready", "No installed components declare Management capabilities.")

    def clear(
        self,
        message: str,
        *,
        state: ManagementViewState = "idle",
        preserve_selection: bool = False,
        preserve_docker_status: bool = False,
        preserve_base_security_status: bool = False,
        preserve_xray_status: bool = False,
        preserve_hysteria2_status: bool = False,
        preserve_mieru_status: bool = False,
        preserve_nginx_status: bool = False,
        preserve_netdata_status: bool = False,
    ) -> None:
        """Remove stale rows and show the requested loading or error state."""
        self._refreshing_component_id = None
        self.netdata_panel.set_access(None)
        self.refresh_selected_label.clear()
        self.refresh_selected_label.setVisible(False)
        self._selection_to_restore = self.selected_component_id() if preserve_selection else None
        self._docker_status_to_restore = (
            preserve_docker_status and self.docker_panel.status is not None
        )
        self._base_security_status_to_restore = (
            preserve_base_security_status and self.base_security_panel.status is not None
        )
        self._xray_status_to_restore = preserve_xray_status and self.xray_panel.status is not None
        self._hysteria2_status_to_restore = (
            preserve_hysteria2_status and self.hysteria2_panel.status is not None
        )
        self._mieru_status_to_restore = (
            preserve_mieru_status and self.mieru_panel.status is not None
        )
        self._nginx_status_to_restore = (
            preserve_nginx_status and self.nginx_panel.status is not None
        )
        self._netdata_status_to_restore = (
            preserve_netdata_status and self.netdata_panel.status is not None
        )
        self.table.clearSelection()
        self.table.setRowCount(0)
        self._components = {}
        if not self._docker_status_to_restore:
            self.docker_panel.clear_status()
        if not self._base_security_status_to_restore:
            self.base_security_panel.clear_status()
        if not self._xray_status_to_restore:
            self.xray_panel.clear_status()
        if not self._hysteria2_status_to_restore:
            self.hysteria2_panel.clear_status()
        if not self._mieru_status_to_restore:
            self.mieru_panel.clear_status()
        if not self._nginx_status_to_restore:
            self.nginx_panel.clear_status()
        if not self._netdata_status_to_restore:
            self.netdata_panel.clear_status()
        self._show_selected_component()
        self._set_status(state, message)

    def set_docker_status(self, status: DockerManagementStatus) -> None:
        """Display fresh Docker and AmneziaWG state for the selected server."""
        self.docker_panel.set_status(status)
        self.finish_selected_component_refresh("docker")
        self._update_selected_refresh_button()

    def set_docker_controls_enabled(self, enabled: bool) -> None:
        self.docker_panel.set_controls_enabled(enabled)
        self._update_selected_refresh_button()

    def set_base_security_status(self, status: BaseSecurityManagementStatus) -> None:
        """Display fresh nftables and Fail2Ban state for the selected server."""
        self.base_security_panel.set_status(status)
        self.finish_selected_component_refresh("base-security")
        self._update_selected_refresh_button()

    def set_base_security_controls_enabled(self, enabled: bool) -> None:
        self.base_security_panel.set_controls_enabled(enabled)
        self._update_selected_refresh_button()

    def set_xray_status(self, status: XrayManagementStatus) -> None:
        """Display fresh non-secret Xray connection details for the selected server."""
        self.xray_panel.set_status(status)
        self.finish_selected_component_refresh("xray")
        self._update_selected_refresh_button()

    def set_xray_controls_enabled(self, enabled: bool) -> None:
        self.xray_panel.set_controls_enabled(enabled)
        self._update_selected_refresh_button()

    def set_hysteria2_status(self, status: Hysteria2ManagementStatus) -> None:
        self.hysteria2_panel.set_status(status)
        self.finish_selected_component_refresh("hysteria2")
        self._update_selected_refresh_button()

    def set_hysteria2_controls_enabled(self, enabled: bool) -> None:
        self.hysteria2_panel.set_controls_enabled(enabled)
        self._update_selected_refresh_button()

    def set_mieru_status(self, status: MieruManagementStatus) -> None:
        """Display fresh non-secret Mieru service and public profile details."""
        self.mieru_panel.set_status(status)
        self.finish_selected_component_refresh("mieru")
        self._update_selected_refresh_button()

    def set_mieru_controls_enabled(self, enabled: bool) -> None:
        self.mieru_panel.set_controls_enabled(enabled)
        self._update_selected_refresh_button()

    def set_nginx_status(self, status: NginxManagementStatus) -> None:
        self.nginx_panel.set_status(status)
        self.finish_selected_component_refresh("nginx")
        self._update_selected_refresh_button()

    def set_nginx_controls_enabled(self, enabled: bool) -> None:
        self.nginx_panel.set_controls_enabled(enabled)
        self._update_selected_refresh_button()

    def set_netdata_status(self, status: NetdataManagementStatus) -> None:
        self.netdata_panel.set_status(status)
        self.finish_selected_component_refresh("netdata")
        self._update_selected_refresh_button()

    def set_netdata_controls_enabled(self, enabled: bool) -> None:
        self.netdata_panel.set_controls_enabled(enabled)
        self._update_selected_refresh_button()

    def set_editing_enabled(self, enabled: bool) -> None:
        self._editing_enabled = enabled
        self.xray_panel.set_editing_enabled(enabled)
        self.hysteria2_panel.set_editing_enabled(enabled)
        self.mieru_panel.set_editing_enabled(enabled)

    @property
    def editing_enabled(self) -> bool:
        return self._editing_enabled

    def set_docker_action_colors(self, normal: str, success: str, error: str) -> None:
        """Apply the current theme to compact Docker action controls."""
        self._docker_icon_colors = (normal, success, error)
        self.docker_panel.set_action_colors(normal, success, error)
        self.base_security_panel.set_action_colors(normal, success, error)
        self.xray_panel.set_action_colors(normal, success, error)
        self.hysteria2_panel.set_action_colors(normal, success, error)
        self.mieru_panel.set_action_colors(normal, success, error)
        self.nginx_panel.set_action_colors(normal, success, error)
        self.netdata_panel.set_action_colors(normal, success, error)
        self._update_selected_refresh_button()

    def selected_component_id(self) -> str | None:
        """Return the current navigation selection without exposing table details."""
        return self._selected_component_id()

    def docker_needs_inspection(self) -> bool:
        """Return whether the selected Docker view has no fresh detail status."""
        return self._selected_component_id() == "docker" and self.docker_panel.status is None

    def base_security_needs_inspection(self) -> bool:
        """Return whether the selected Base + Security view has no fresh detail status."""
        return (
            self._selected_component_id() == "base-security"
            and self.base_security_panel.status is None
        )

    def xray_needs_inspection(self) -> bool:
        """Return whether the selected Xray view has no fresh detail status."""
        return self._selected_component_id() == "xray" and self.xray_panel.status is None

    def hysteria2_needs_inspection(self) -> bool:
        return self._selected_component_id() == "hysteria2" and self.hysteria2_panel.status is None

    def mieru_needs_inspection(self) -> bool:
        return self._selected_component_id() == "mieru" and self.mieru_panel.status is None

    def nginx_needs_inspection(self) -> bool:
        return self._selected_component_id() == "nginx" and self.nginx_panel.status is None

    def netdata_needs_inspection(self) -> bool:
        return self._selected_component_id() == "netdata" and self.netdata_panel.status is None

    def _show_selected_component(self) -> None:
        component_id = self._selected_component_id()
        self._update_selected_refresh_button()
        if component_id is None:
            self.details_text.clear()
            self._show_details_page(self.details_text)
            return
        component = self._components.get(component_id)
        if component is None or component.declaration is None:
            self.details_text.clear()
            self._show_details_page(self.details_text)
            return
        if component_id == "docker":
            self.details_text.clear()
            self._show_details_page(self.docker_panel)
            self.docker_panel.render()
            if self.docker_needs_inspection():
                self.docker_inspection_requested.emit()
            return
        if component_id == "base-security":
            self.details_text.clear()
            self._show_details_page(self.base_security_panel)
            self.base_security_panel.render()
            if self.base_security_needs_inspection():
                self.base_security_inspection_requested.emit()
            return
        if component_id == "xray":
            self.details_text.clear()
            self._show_details_page(self.xray_panel)
            self.xray_panel.render()
            if self.xray_needs_inspection():
                self.xray_inspection_requested.emit()
            return
        if component_id == "hysteria2":
            self.details_text.clear()
            self._show_details_page(self.hysteria2_panel)
            self.hysteria2_panel.render()
            if self.hysteria2_needs_inspection():
                self.hysteria2_inspection_requested.emit()
            return
        if component_id == "mieru":
            self.details_text.clear()
            self._show_details_page(self.mieru_panel)
            self.mieru_panel.render()
            if self.mieru_needs_inspection():
                self.mieru_inspection_requested.emit()
            return
        if component_id == "nginx":
            self.details_text.clear()
            self._show_details_page(self.nginx_panel)
            self.nginx_panel.render()
            if self.nginx_needs_inspection():
                self.nginx_inspection_requested.emit()
            return
        if component_id == "netdata":
            self.details_text.clear()
            self._show_details_page(self.netdata_panel)
            self.netdata_panel.render()
            if self.netdata_needs_inspection():
                self.netdata_inspection_requested.emit()
            return
        self._show_details_page(self.details_text)
        declaration = component.declaration
        systemd_lines = [
            f"• {check.target}: {check.detail}"
            for check in component.checks
            if check.category == "systemd"
        ] or ["• No systemd units declared."]
        parameter_lines = [
            self._parameter_line(parameter) for parameter in declaration.management_parameters
        ] or ["• No Management parameters declared."]
        action_lines = [f"• {action}" for action in declaration.management_actions] or [
            "• No actions declared."
        ]
        self.details_text.setPlainText(
            "Systemd\n"
            + "\n".join(systemd_lines)
            + "\n\nParameters\n"
            + "\n".join(parameter_lines)
            + "\n\nAllowed actions\n"
            + "\n".join(action_lines)
        )

    def _show_details_page(self, page: QWidget) -> None:
        """Show one details page while retaining the largest page's geometry."""
        self.details_stack.setCurrentWidget(page)

    def _selected_component_id(self) -> str | None:
        selected_rows = self.table.selectionModel().selectedRows()
        if not selected_rows:
            return None
        component_item = self.table.item(selected_rows[0].row(), 0)
        component_id = component_item.data(Qt.ItemDataRole.UserRole) if component_item else None
        return component_id if isinstance(component_id, str) else None

    def _refresh_selected_component(self) -> None:
        component_id = self._selected_component_id()
        component_name = {
            "docker": "Docker",
            "base-security": "Base + Security",
            "xray": "Xray",
            "hysteria2": "Hysteria2",
            "mieru": "Mieru",
            "nginx": "Nginx",
            "netdata": "Netdata",
        }.get(component_id)
        if component_name is None:
            return
        self._refreshing_component_id = component_id
        self.refresh_selected_label.setText(f"Refreshing {component_name}\N{HORIZONTAL ELLIPSIS}")
        self.refresh_selected_label.setVisible(True)
        if component_id == "docker":
            self.docker_inspection_requested.emit()
        elif component_id == "base-security":
            self.base_security_inspection_requested.emit()
        elif component_id == "xray":
            self.xray_inspection_requested.emit()
        elif component_id == "hysteria2":
            self.hysteria2_inspection_requested.emit()
        elif component_id == "mieru":
            self.mieru_inspection_requested.emit()
        elif component_id == "nginx":
            self.nginx_inspection_requested.emit()
        elif component_id == "netdata":
            self.netdata_inspection_requested.emit()

    def finish_selected_component_refresh(self, component_id: str) -> None:
        if self._refreshing_component_id != component_id:
            return
        self._refreshing_component_id = None
        self.refresh_selected_label.clear()
        self.refresh_selected_label.setVisible(False)

    def _update_selected_refresh_button(self) -> None:
        component_id = self._selected_component_id()
        if component_id == "docker":
            status = self.docker_panel.status
            controls_enabled = self.docker_panel.controls_enabled
            name = "Docker"
        elif component_id == "base-security":
            status = self.base_security_panel.status
            controls_enabled = self.base_security_panel.controls_enabled
            name = "Base + Security"
        elif component_id == "xray":
            status = self.xray_panel.status
            controls_enabled = self.xray_panel.controls_enabled
            name = "Xray"
        elif component_id == "hysteria2":
            status = self.hysteria2_panel.status
            controls_enabled = self.hysteria2_panel.controls_enabled
            name = "Hysteria2"
        elif component_id == "mieru":
            status = self.mieru_panel.status
            controls_enabled = self.mieru_panel.controls_enabled
            name = "Mieru"
        elif component_id == "nginx":
            status = self.nginx_panel.status
            controls_enabled = self.nginx_panel.controls_enabled
            name = "Nginx"
        elif component_id == "netdata":
            status = self.netdata_panel.status
            controls_enabled = self.netdata_panel.controls_enabled
            name = "Netdata"
        else:
            self.refresh_selected_button.setVisible(False)
            return
        self.refresh_selected_button.setVisible(True)
        normal, _success, _error = self._docker_icon_colors
        self.refresh_selected_button.setIcon(action_icon("refresh-cw", normal))
        self.refresh_selected_button.setToolTip(f"Refresh {name}")
        self.refresh_selected_button.setEnabled(status is not None and controls_enabled)

    @staticmethod
    def _parameter_line(parameter: ManagementParameter) -> str:
        details = [parameter.parameter_type]
        if parameter.minimum is not None or parameter.maximum is not None:
            minimum = str(parameter.minimum) if parameter.minimum is not None else "—"
            maximum = str(parameter.maximum) if parameter.maximum is not None else "—"
            details.append(f"range {minimum}–{maximum}")
        if parameter.value_format:
            details.append(parameter.value_format)
        details.append("modifiable" if parameter.modifiable else "read-only")
        return f"• {parameter.label}: {'; '.join(details)}"

    def _set_status(self, state: ManagementViewState, message: str) -> None:
        visible = state in {"loading", "error"}
        self.status_label.setProperty("state", state)
        self.status_label.setText(
            "Loading…" if state == "loading" else (message if visible else "")
        )
        self.status_label.setVisible(visible)
        style = self.status_label.style()
        style.unpolish(self.status_label)
        style.polish(self.status_label)
        self.status_label.update()
