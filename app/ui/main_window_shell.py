"""Shared visual shell of the main application window."""

from __future__ import annotations

from collections.abc import Sequence

from PySide6.QtCore import Qt, QTimer, Signal
from PySide6.QtGui import QAction
from PySide6.QtWidgets import (
    QComboBox,
    QFrame,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMenu,
    QPlainTextEdit,
    QSizePolicy,
    QStackedWidget,
    QTabWidget,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

from common.ui.icon_assets import action_icon
from common.ui.icon_button import IconActionButton
from common.ui.operation_log import fix_operation_log_height
from common.ui.theme import available_themes, get_theme, is_light_theme

from .editing_toggle import EditingToggle
from .tabs.backup_restore_tab import BackupRestoreTab
from .tabs.deploy_tab import DeployTab
from .tabs.management_tab import ManagementTab
from .tabs.subscriptions_tab import SubscriptionsTab
from .tabs.users_tab import UsersTab

EDITING_AUTO_LOCK_INTERVAL_MS = 10 * 60 * 1000


class MainWindowShell(QWidget):
    """Build common controls and expose only user-interface intentions."""

    theme_requested = Signal(str)
    recent_server_selected = Signal(int)
    server_ip_edited = Signal(str)
    server_ip_submitted = Signal()
    server_ip_editing_finished = Signal()
    server_alias_editing_finished = Signal()
    check_ssh_requested = Signal()
    settings_requested = Signal()
    remove_recent_server_requested = Signal()
    server_reboot_requested = Signal()
    action_tab_changed = Signal(int)
    copy_log_requested = Signal()
    clear_log_requested = Signal()

    def __init__(
        self,
        recent_servers: Sequence[dict[str, str]],
        theme_key: str,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._recent_servers = list(recent_servers)
        self._server_controls_enabled = True
        self._editing_enabled = False
        self._editing_timeout = QTimer(self)
        self._editing_timeout.setObjectName("editingAutoLockTimer")
        self._editing_timeout.setSingleShot(True)
        self._editing_timeout.setTimerType(Qt.TimerType.PreciseTimer)
        self._editing_timeout.setInterval(EDITING_AUTO_LOCK_INTERVAL_MS)
        self._editing_timeout.timeout.connect(self._expire_editing)
        self._build_layout(theme_key)

    def _build_layout(self, theme_key: str) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 8, 24, 24)
        layout.setSpacing(16)

        self._build_theme_menu(theme_key)
        self.edit_mode_button = EditingToggle(get_theme(theme_key).colors)
        self.edit_mode_button.toggled.connect(self.set_editing_enabled)
        server_section = self._build_server_section()
        self.set_global_action_icons(get_theme(theme_key).colors.muted_text)
        layout.addWidget(server_section)
        layout.addWidget(self._build_tabs_area(), 1)
        layout.addWidget(self._build_log_area())
        self.set_editing_enabled(False)

    @property
    def editing_enabled(self) -> bool:
        return self._editing_enabled

    def _build_theme_menu(self, theme_key: str) -> None:
        self.theme_button = QToolButton()
        self.theme_button.setObjectName("themeButton")
        self.theme_button.setToolTip("Choose theme")
        self.theme_button.setPopupMode(QToolButton.ToolButtonPopupMode.InstantPopup)
        theme_menu = QMenu(self.theme_button)
        self.theme_actions: dict[str, QAction] = {}
        has_dark_theme = False
        light_separator_added = False
        for theme in available_themes():
            if is_light_theme(theme.key) and has_dark_theme and not light_separator_added:
                theme_menu.addSeparator()
                light_separator_added = True
            action = theme_menu.addAction(theme.display_name)
            action.setCheckable(True)
            action.setChecked(theme.key == theme_key)
            action.triggered.connect(
                lambda _checked=False, key=theme.key: self.theme_requested.emit(key)
            )
            self.theme_actions[theme.key] = action
            has_dark_theme = has_dark_theme or not is_light_theme(theme.key)
        self.theme_button.setMenu(theme_menu)

    def _build_server_section(self) -> QWidget:
        connection_group = QGroupBox()
        connection_group.setObjectName("serverGroup")
        connection_layout = QGridLayout(connection_group)
        connection_layout.setHorizontalSpacing(12)
        connection_layout.setVerticalSpacing(8)
        connection_layout.setColumnMinimumWidth(3, 8)

        self.server_alias_input = QLineEdit()
        last_server_alias = self._recent_servers[0]["alias"] if self._recent_servers else ""
        self.server_alias_input.setText(last_server_alias)
        self.server_alias_input.setPlaceholderText("For example, primary server")
        self.server_alias_input.setClearButtonEnabled(True)
        self.server_alias_input.setFixedWidth(170)
        self.server_alias_input.editingFinished.connect(self.server_alias_editing_finished)
        self.server_alias_label = QLabel("Comment / alias")
        connection_layout.addWidget(self.server_alias_input, 1, 1)

        self.remove_recent_server_button = QToolButton()
        self.remove_recent_server_button.setObjectName("iconAction")
        self.remove_recent_server_button.setToolTip("Remove selected server from Recent")
        self.remove_recent_server_button.setAccessibleName("Remove selected server from Recent")
        self.remove_recent_server_button.setFixedSize(28, 28)
        self.remove_recent_server_button.clicked.connect(self.remove_recent_server_requested)
        connection_layout.addWidget(
            self.remove_recent_server_button,
            1,
            2,
            Qt.AlignmentFlag.AlignVCenter,
        )

        self.server_ip_input = QComboBox()
        self.server_ip_input.setEditable(True)
        self.server_ip_input.setInsertPolicy(QComboBox.InsertPolicy.NoInsert)
        self.server_ip_input.setMaxVisibleItems(10)
        last_server_ip = self._recent_servers[0]["ip"] if self._recent_servers else ""
        self._fill_recent_servers(last_server_ip)
        ip_editor = self.server_ip_input.lineEdit()
        ip_editor.setPlaceholderText("IPv4 address, for example 203.0.113.10")
        self.server_ip_input.setFixedWidth(210)
        self.server_ip_input.activated.connect(self.recent_server_selected)
        ip_editor.textEdited.connect(self.server_ip_edited)
        ip_editor.returnPressed.connect(self.server_ip_submitted)
        ip_editor.editingFinished.connect(self.server_ip_editing_finished)
        self.server_ip_input.currentTextChanged.connect(self._update_remove_recent_server_button)
        self.server_ip_label = QLabel("Server IP")
        connection_layout.addWidget(self.server_ip_label, 0, 0)
        connection_layout.addWidget(self.server_ip_input, 1, 0)

        self.settings_button = IconActionButton("Settings", size=28)
        self.settings_button.setObjectName("headerIconAction")
        self.settings_button.clicked.connect(self.settings_requested)

        self.ssh_button = IconActionButton("Check SSH", size=28)
        self.ssh_button.setObjectName("headerIconAction")
        self.ssh_button.clicked.connect(self.check_ssh_requested)

        self.server_reboot_button = IconActionButton(
            "Reboot selected server",
            size=28,
        )
        self.server_reboot_button.setObjectName("headerIconAction")
        self.server_reboot_button.clicked.connect(self.server_reboot_requested)

        self.settings_label = QLabel("Settings")
        self.ssh_label = QLabel("Check SSH")
        self.server_reboot_label = QLabel("Reboot")
        for label in (self.settings_label, self.ssh_label, self.server_reboot_label):
            label.setAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)

        server_actions = QWidget()
        server_actions.setObjectName("serverActions")
        server_actions_layout = QHBoxLayout(server_actions)
        server_actions_layout.setContentsMargins(0, 0, 0, 0)
        server_actions_layout.setSpacing(4)
        server_actions_layout.addWidget(self.settings_button)
        server_actions_layout.addWidget(self.settings_label)
        server_actions_layout.addSpacing(24)
        server_actions_layout.addWidget(self.ssh_button)
        server_actions_layout.addWidget(self.ssh_label)
        server_actions_layout.addSpacing(24)
        server_actions_layout.addWidget(self.server_reboot_button)
        server_actions_layout.addWidget(self.server_reboot_label)
        connection_layout.addWidget(
            server_actions,
            1,
            4,
            1,
            2,
            Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter,
        )

        connection_layout.addWidget(
            self.server_alias_label,
            0,
            1,
            Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter,
        )
        connection_layout.setColumnStretch(1, 1)

        self.section_divider = QFrame()
        self.section_divider.setObjectName("sectionDivider")
        self.section_divider.setFrameShape(QFrame.Shape.NoFrame)
        server_section = QWidget()
        server_section_layout = QVBoxLayout(server_section)
        server_section_layout.setContentsMargins(0, 0, 0, 0)
        server_section_layout.setSpacing(0)
        server_section_layout.addWidget(connection_group)
        server_section_layout.addWidget(self.section_divider)
        return server_section

    def _build_tabs_area(self) -> QWidget:
        self.action_tabs = QTabWidget()
        self.action_tabs.setObjectName("actionTabs")
        self.deploy_tab = DeployTab()
        self.users_tab = UsersTab()
        self.management_tab = ManagementTab()
        self.subscriptions_tab = SubscriptionsTab()
        self.backup_tab = BackupRestoreTab()
        self.action_tabs.addTab(self.deploy_tab, "Deploy")
        self.management_tab_index = self.action_tabs.addTab(self.management_tab, "Manage")
        self.users_tab_index = self.action_tabs.addTab(self.users_tab, "Users")
        self.subscriptions_tab_index = self.action_tabs.addTab(
            self.subscriptions_tab, "Subscriptions"
        )
        self.backup_tab_index = self.action_tabs.addTab(self.backup_tab, "Backup && Restore")
        self.action_tabs.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        self.action_tabs.currentChanged.connect(self.action_tab_changed)
        tabs_corner = QWidget(self.action_tabs)
        tabs_corner_layout = QHBoxLayout(tabs_corner)
        tabs_corner_layout.setContentsMargins(0, 0, 14, 7)
        tabs_corner_layout.setSpacing(0)
        tabs_corner_layout.addWidget(self.edit_mode_button)
        self.action_tabs.setCornerWidget(tabs_corner, Qt.Corner.TopRightCorner)

        tabs_area = QWidget()
        tabs_area_layout = QVBoxLayout(tabs_area)
        tabs_area_layout.setContentsMargins(0, 0, 0, 16)
        tabs_area_layout.addWidget(self.action_tabs)
        return tabs_area

    def _build_log_area(self) -> QStackedWidget:
        log_group = QGroupBox()
        log_group.setObjectName("operationLogGroup")
        log_layout = QHBoxLayout(log_group)
        log_layout.setSpacing(10)
        log_actions = QVBoxLayout()
        log_actions.setSpacing(8)
        log_actions.addWidget(self.theme_button)
        log_actions.addStretch()

        self.copy_log_button = QToolButton()
        self.copy_log_button.setObjectName("iconAction")
        self.copy_log_button.setToolTip("Copy log")
        self.copy_log_button.setFixedSize(32, 32)
        self.copy_log_button.clicked.connect(self.copy_log_requested)
        log_actions.addWidget(self.copy_log_button)
        self.clear_log_button = QToolButton()
        self.clear_log_button.setObjectName("iconAction")
        self.clear_log_button.setToolTip("Clear log")
        self.clear_log_button.setFixedSize(32, 32)
        self.clear_log_button.clicked.connect(self.clear_log_requested)
        log_actions.addWidget(self.clear_log_button)

        self.log = QPlainTextEdit()
        self.log.setReadOnly(True)
        self.log.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        self.log.setObjectName("operationLog")
        fix_operation_log_height(self.log)
        log_layout.addWidget(self.log, 1)
        log_layout.addLayout(log_actions)

        self.content_stack = QStackedWidget()
        self.content_stack.addWidget(log_group)
        return self.content_stack

    def refresh_operation_log_height(self) -> None:
        """Recalculate the fixed 15-line height after a theme change."""
        fix_operation_log_height(self.log)

    @staticmethod
    def recent_server_label(server: dict[str, str]) -> str:
        alias = server["alias"]
        return f"{server['ip']} — {alias}" if alias else server["ip"]

    def _fill_recent_servers(self, current_ip: str) -> None:
        self.server_ip_input.clear()
        for server in self._recent_servers:
            self.server_ip_input.addItem(self.recent_server_label(server), server["ip"])
        self.server_ip_input.setEditText(current_ip)

    def update_recent_servers(
        self, recent_servers: Sequence[dict[str, str]], current_ip: str
    ) -> None:
        self._recent_servers = list(recent_servers)
        self.server_ip_input.blockSignals(True)
        self._fill_recent_servers(current_ip)
        self.server_ip_input.blockSignals(False)
        self._update_remove_recent_server_button()

    def set_theme_selection(self, theme_key: str) -> None:
        for key, action in self.theme_actions.items():
            action.setChecked(key == theme_key)

    def set_global_action_icons(self, color: str) -> None:
        """Apply the active theme color to global compact actions."""
        self.settings_button.setIcon(action_icon("settings", color))
        self.ssh_button.setIcon(action_icon("square-terminal", color))
        self.server_reboot_button.setIcon(action_icon("refresh-cw", color))

    def set_server_controls_enabled(self, enabled: bool) -> None:
        self._server_controls_enabled = enabled
        self._update_server_controls()

    def set_editing_enabled(self, enabled: bool) -> None:
        self._editing_enabled = enabled
        if enabled:
            self._editing_timeout.start()
        else:
            self._editing_timeout.stop()
        self.edit_mode_button.blockSignals(True)
        self.edit_mode_button.setChecked(enabled)
        self.edit_mode_button.blockSignals(False)
        self._update_server_controls()
        self.deploy_tab.set_editing_enabled(enabled)
        self.users_tab.set_editing_enabled(enabled)
        self.subscriptions_tab.set_editing_enabled(enabled)
        self.management_tab.set_editing_enabled(enabled)
        self.backup_tab.set_editing_enabled(enabled)

    def _expire_editing(self) -> None:
        self.set_editing_enabled(False)

    def _update_server_controls(self) -> None:
        self.server_alias_input.setEnabled(self._server_controls_enabled)
        self.server_ip_input.setEnabled(self._server_controls_enabled)
        self.settings_button.setEnabled(True)
        self.ssh_button.setEnabled(self._server_controls_enabled)
        self._update_remove_recent_server_button()
        self.server_reboot_button.setEnabled(
            self._server_controls_enabled and self._editing_enabled
        )

    def _update_remove_recent_server_button(self) -> None:
        current_ip = self.server_ip_input.currentText().strip()
        is_recent = any(server["ip"] == current_ip for server in self._recent_servers)
        self.remove_recent_server_button.setEnabled(self._server_controls_enabled and is_recent)
