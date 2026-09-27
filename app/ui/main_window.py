"""PySide6 desktop shell for the existing VPN automation services."""

from __future__ import annotations

from html import escape
from pathlib import Path
from typing import Literal

from PySide6.QtCore import QSize, Qt
from PySide6.QtGui import QAction, QCloseEvent
from PySide6.QtWidgets import (
    QApplication,
    QDialog,
    QLabel,
    QMainWindow,
    QMenu,
    QStatusBar,
    QStyle,
    QSystemTrayIcon,
)

from app.services.backup import LocalBackupArchive
from app.services.inventory import ComponentInventory, InventorySnapshot
from app.services.management import load_netdata_access_details
from app.services.modular_deployment import NginxTlsSettings
from app.services.settings_manager import SettingsManager
from app.services.ssh import validate_server_ip
from app.services.ssh_settings import SshSettingsError
from common.ui.icon_assets import action_icon, recolor_icon_hue
from common.ui.theme import DEFAULT_THEME_KEY, build_stylesheet, get_theme
from common.ui.window_chrome import apply_native_title_bar

from .alert_confirmation_dialog import (
    AlertConfirmationDialog,
    NginxTlsDialog,
    ThemedTextInputDialog,
    ThemedWarningDialog,
)
from .application_shutdown_coordinator import (
    ApplicationShutdownBlocked,
    ApplicationShutdownBlocker,
    ApplicationShutdownCoordinator,
)
from .backup_restore_operation_controller import BackupRestoreOperationController
from .backup_runner import BackupRunner
from .deploy_server_operation_controller import DeployServerOperationController
from .inventory_runner import InventoryPurpose, InventoryRequestContext, InventoryRunner
from .main_window_shell import MainWindowShell
from .management_operation_controller import ManagementOperationController
from .management_runner import ManagementRunner
from .operation_gate import OperationGate
from .operational_telegram_controller import OperationalTelegramController
from .operational_telegram_transport import OperationalTelegramStatus
from .process_runner import PowerShellRunner
from .restore_preflight_runner import RestorePreflightRunner
from .restore_runner import RestoreRunner
from .settings_dialog import SettingsDialog
from .subscriptions_operation_controller import SubscriptionsOperationController
from .subscriptions_runner import SubscriptionsRunner
from .tabs.management_tab import ManagementViewState
from .users_operation_controller import UsersOperationController
from .users_operation_runner import UsersOperationRunner

OperationOutcome = Literal["success", "warning", "error"]
PANEL_ICON_COLOR = "#F97316"


class MainWindow(QMainWindow):
    """Application shell and coordinator for the existing automation services."""

    def __init__(self, settings: SettingsManager | None = None) -> None:
        super().__init__()
        self.operation_gate = OperationGate()
        self.settings = settings if settings is not None else SettingsManager()
        self.recent_servers = self.settings.recent_servers()
        saved_theme_key = self.settings.get("ui.theme", DEFAULT_THEME_KEY)
        self.theme_key = saved_theme_key if isinstance(saved_theme_key, str) else DEFAULT_THEME_KEY
        self.theme_key = get_theme(self.theme_key).key
        self.runner = PowerShellRunner(self)
        self.users_runner = UsersOperationRunner(Path(__file__).resolve().parents[2], self)
        self.subscriptions_runner = SubscriptionsRunner(Path(__file__).resolve().parents[2], self)
        self.inventory_runner = InventoryRunner(Path(__file__).resolve().parents[2], self)
        self.inventory_runner.completed.connect(self._inventory_completed)
        self.inventory_runner.failed.connect(self._inventory_failed)
        self.management_runner = ManagementRunner(Path(__file__).resolve().parents[2], self)
        self.telegram_inventory_runner = InventoryRunner(Path(__file__).resolve().parents[2], self)
        self.telegram_management_runner = ManagementRunner(
            Path(__file__).resolve().parents[2], self
        )
        self.backup_runner = BackupRunner(Path(__file__).resolve().parents[2], self)
        self.restore_preflight_runner = RestorePreflightRunner(self)
        self.restore_runner = RestoreRunner(Path(__file__).resolve().parents[2], self)
        self.inventory_context: InventoryRequestContext | None = None
        self.setWindowTitle("VPN Admin Panel")
        self.resize(900, self.height())
        self.setObjectName("mainWindow")
        self._allow_close = False
        self.tray_icon: QSystemTrayIcon | None = None
        self._initialize_status_bar()
        self._initialize_shell()
        self._initialize_tray()
        self._restore_window_position()
        self._report_settings_persistence_state()

    def closeEvent(self, event: QCloseEvent) -> None:
        if not self._allow_close and self.tray_icon is not None:
            self.hide()
            event.ignore()
            return
        shutdown_outcome = self.shutdown_coordinator.shutdown()
        if isinstance(shutdown_outcome, ApplicationShutdownBlocked):
            messages = {
                ApplicationShutdownBlocker.DEPLOY_OPERATION_ACTIVE: (
                    "A PowerShell operation is still running. Wait for Check SSH or Deploy "
                    "to finish; for SSH Fix, close its console and wait for the automatic "
                    "Check SSH before closing the panel."
                ),
                ApplicationShutdownBlocker.TELEGRAM_STOP_FAILED: (
                    "Не удалось безопасно остановить Telegram transport. Выход отменён."
                ),
                ApplicationShutdownBlocker.SUBSCRIPTIONS_SHUTDOWN_FAILED: (
                    "Could not safely stop subscription publication. Window closing was cancelled."
                ),
                ApplicationShutdownBlocker.USERS_CANCEL_FAILED: (
                    "Could not safely stop the current Users operation. "
                    "Window closing was cancelled."
                ),
                ApplicationShutdownBlocker.DIRECT_RUNNER_TIMEOUT: (
                    "Не удалось безопасно остановить фоновую SSH-операцию. Закрытие окна отменено."
                ),
                ApplicationShutdownBlocker.BACKUP_RESTORE_SHUTDOWN_FAILED: (
                    "Could not safely stop Backup or Restore. Window closing was cancelled."
                ),
            }
            self._write_operation_result(
                messages[shutdown_outcome.blocker],
                "error",
            )
            if shutdown_outcome.blocker is not ApplicationShutdownBlocker.DEPLOY_OPERATION_ACTIVE:
                self._allow_close = False
            event.ignore()
            return
        self._save_window_position()
        if self.tray_icon is not None:
            self.tray_icon.hide()
        super().closeEvent(event)
        QApplication.quit()

    def _initialize_status_bar(self) -> None:
        status_bar = QStatusBar(self)
        status_bar.setObjectName("globalStatusBar")
        status_bar.setSizeGripEnabled(False)
        self.telegram_status_label = QLabel("Telegram: Disabled", status_bar)
        self.telegram_status_label.setObjectName("telegramStatus")
        self.telegram_status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        status_bar.addWidget(self.telegram_status_label, 1)
        self.setStatusBar(status_bar)

    def _initialize_shell(self) -> None:
        self.shell = MainWindowShell(self.recent_servers, self.theme_key)
        self.setCentralWidget(self.shell)
        self._current_action_tab_index = self.shell.action_tabs.currentIndex()
        self.users_controller = UsersOperationController(
            Path(__file__).resolve().parents[2],
            self.users_runner,
            self.shell.users_tab,
            current_server_ip=self._server_ip,
            users_is_visible=lambda: (
                self.shell.action_tabs.currentIndex() == self.shell.users_tab_index
            ),
            operation_is_busy=lambda: self.operation_gate.busy,
            request_inventory=self._refresh_users_inventory,
            write_log=self._write_log,
            write_result=self._write_operation_result,
            hide_content=lambda: self.shell.content_stack.setCurrentIndex(0),
        )
        self.subscriptions_controller = SubscriptionsOperationController(
            Path(__file__).resolve().parents[2],
            self.operation_gate,
            self.subscriptions_runner,
            self.shell.subscriptions_tab,
            current_server_ip=self._server_ip,
            current_server_text=lambda: self.shell.server_ip_input.currentText(),
            editing_enabled=lambda: self.shell.editing_enabled,
            cancel_users=self.users_controller.cancel,
            resume_users=self.users_controller.resume_if_visible,
            set_operation_controls_enabled=self._set_operation_controls_enabled,
            write_log=self._write_log,
            write_result=self._write_operation_result,
            confirm=lambda *args, **kwargs: self._confirm(*args, **kwargs),
            copy_url=lambda url: QApplication.clipboard().setText(url),
            subscriptions_is_visible=lambda: (
                self.shell.action_tabs.currentIndex() == self.shell.subscriptions_tab_index
            ),
            request_inventory=self._refresh_subscriptions_inventory,
        )
        self.management_controller = ManagementOperationController(
            self.operation_gate,
            self.management_runner,
            self.shell.management_tab,
            cancel_users=self.users_controller.cancel,
            current_server_ip=self._server_ip,
            set_operation_controls_enabled=self._set_operation_controls_enabled,
            write_log=self._write_log,
            write_result=self._write_operation_result,
            resume_users=self.users_controller.resume_if_visible,
            refresh_snapshot=self._refresh_management_snapshot,
            request_reconciliation_inventory=self._request_archive_inventory,
            editing_enabled=lambda: self.shell.management_tab.editing_enabled,
            confirm=lambda *args, **kwargs: self._confirm(*args, **kwargs),
            management_is_visible=lambda: (
                self.shell.action_tabs.currentIndex() == self.shell.management_tab_index
            ),
        )
        self.deploy_server_controller = DeployServerOperationController(
            self.operation_gate,
            self.runner,
            self.management_runner,
            current_server_ip=self._server_ip,
            current_server_alias=lambda: self.shell.server_alias_input.text(),
            cancel_users=self.users_controller.cancel,
            resume_users=self.users_controller.resume_if_visible,
            set_operation_controls_enabled=self._set_operation_controls_enabled,
            write_log=self._write_log,
            write_result=self._write_operation_result,
            confirm=lambda *args, **kwargs: self._confirm(*args, **kwargs),
            request_nginx_tls=self._request_nginx_tls,
            request_inventory=self._request_archive_inventory,
        )
        self.backup_restore_controller = BackupRestoreOperationController(
            Path(__file__).resolve().parents[2],
            self.operation_gate,
            self.backup_runner,
            self.restore_preflight_runner,
            self.restore_runner,
            self.shell.backup_tab,
            current_server_ip=self._server_ip,
            recent_servers=lambda: self.recent_servers,
            cancel_users=self.users_controller.cancel,
            resume_users=self.users_controller.resume_if_visible,
            set_operation_controls_enabled=self._set_operation_controls_enabled,
            write_log=self._write_log,
            write_result=self._write_operation_result,
            write_inventory_component=self._write_inventory_component,
            confirm=lambda *args, **kwargs: self._confirm(*args, **kwargs),
            request_inventory=self._request_archive_inventory,
            consume_inventory=self._consume_inventory_context,
        )
        self.telegram_controller = OperationalTelegramController(
            Path(__file__).resolve().parents[2],
            self.settings,
            self.operation_gate,
            self.telegram_inventory_runner,
            self.telegram_management_runner,
            recent_servers=lambda: self.settings.recent_servers(),
            cancel_users=self.users_controller.cancel,
            write_result=self._write_operation_result,
            set_status=self._set_telegram_status,
            parent=self,
        )
        self.shutdown_coordinator = ApplicationShutdownCoordinator(
            deploy_controller=self.deploy_server_controller,
            telegram_controller=self.telegram_controller,
            subscriptions_controller=self.subscriptions_controller,
            users_controller=self.users_controller,
            inventory_runner=self.inventory_runner,
            management_runner=self.management_runner,
            telegram_inventory_runner=self.telegram_inventory_runner,
            telegram_management_runner=self.telegram_management_runner,
            backup_restore_controller=self.backup_restore_controller,
        )
        self.telegram_controller.management_status_confirmed.connect(
            self.management_controller.apply_external_status
        )
        self.shell.theme_requested.connect(self._change_theme)
        self.shell.recent_server_selected.connect(self._select_recent_server)
        self.shell.server_ip_edited.connect(self._server_ip_edited)
        self.shell.server_ip_submitted.connect(self._server_ip_submitted)
        self.shell.server_ip_editing_finished.connect(self._server_ip_editing_finished)
        self.shell.server_alias_editing_finished.connect(self._server_alias_editing_finished)
        self.shell.check_ssh_requested.connect(self.deploy_server_controller.check_ssh)
        self.shell.settings_requested.connect(self._configure_settings)
        self.shell.remove_recent_server_requested.connect(self._request_remove_recent_server)
        self.shell.server_reboot_requested.connect(self.deploy_server_controller.reboot_server)
        self.shell.action_tab_changed.connect(self._change_action_tab)
        self.shell.copy_log_requested.connect(self._copy_log)
        self.shell.clear_log_requested.connect(self._clear_log)
        self.shell.deploy_tab.ssh_fix_requested.connect(self.deploy_server_controller.ssh_fix)
        self.shell.deploy_tab.base_security_requested.connect(
            self.deploy_server_controller.deploy_base_security
        )
        self.shell.deploy_tab.xray_requested.connect(self.deploy_server_controller.deploy_xray)
        self.shell.deploy_tab.hysteria2_requested.connect(
            self.deploy_server_controller.deploy_hysteria2
        )
        self.shell.deploy_tab.mieru_requested.connect(self.deploy_server_controller.deploy_mieru)
        self.shell.deploy_tab.docker_requested.connect(self.deploy_server_controller.deploy_docker)
        self.shell.deploy_tab.amnezia_information_requested.connect(self._show_amnezia_information)
        self.shell.deploy_tab.nginx_requested.connect(self.deploy_server_controller.deploy_nginx)
        self.shell.deploy_tab.netdata_requested.connect(
            self.deploy_server_controller.deploy_netdata
        )
        self.shell.backup_tab.backup_requested.connect(
            self.backup_restore_controller.create_local_backup
        )
        self.shell.backup_tab.refresh_requested.connect(
            self.backup_restore_controller.refresh_archive_list
        )
        self.shell.backup_tab.restore_requested.connect(
            self.backup_restore_controller.restore_selected_backup
        )
        self.shell.backup_tab.delete_requested.connect(self._delete_backup_requested)
        self.shell.users_tab.add_requested.connect(self._add_user_requested)
        self.shell.users_tab.add_protocols_requested.connect(self._add_protocols_requested)
        self.shell.users_tab.save_links_requested.connect(self._save_user_links_requested)
        self.shell.users_tab.delete_requested.connect(self._delete_user_requested)
        self.shell.subscriptions_tab.make_requested.connect(
            self.subscriptions_controller.make_subscription
        )
        self.shell.subscriptions_tab.copy_requested.connect(
            self.subscriptions_controller.copy_current_url
        )
        self.shell.subscriptions_tab.server_subscription_selected.connect(
            self.subscriptions_controller.server_subscription_selected
        )
        self.shell.subscriptions_tab.refresh_server_requested.connect(
            self.subscriptions_controller.refresh_server
        )
        self.shell.subscriptions_tab.delete_orphan_requested.connect(
            self.subscriptions_controller.delete_orphan
        )
        self.shell.subscriptions_tab.delete_active_requested.connect(
            self.subscriptions_controller.delete_active
        )
        self.shell.management_tab.docker_inspection_requested.connect(
            self.management_controller.inspect_docker
        )
        self.shell.management_tab.docker_action_requested.connect(
            self.management_controller.docker_action_requested
        )
        self.shell.management_tab.base_security_inspection_requested.connect(
            self.management_controller.inspect_base_security
        )
        self.shell.management_tab.base_security_action_requested.connect(
            self.management_controller.base_security_action_requested
        )
        self.shell.management_tab.xray_inspection_requested.connect(
            self.management_controller.inspect_xray
        )
        self.shell.management_tab.xray_action_requested.connect(
            self.management_controller.xray_action_requested
        )
        self.shell.management_tab.xray_connection_update_requested.connect(
            self.management_controller.xray_connection_update_requested
        )
        self.shell.management_tab.hysteria2_inspection_requested.connect(
            self.management_controller.inspect_hysteria2
        )
        self.shell.management_tab.hysteria2_action_requested.connect(
            self.management_controller.hysteria2_action_requested
        )
        self.shell.management_tab.hysteria2_connection_update_requested.connect(
            self.management_controller.hysteria2_connection_update_requested
        )
        self.shell.management_tab.mieru_inspection_requested.connect(
            self.management_controller.inspect_mieru
        )
        self.shell.management_tab.mieru_action_requested.connect(
            self.management_controller.mieru_action_requested
        )
        self.shell.management_tab.mieru_port_update_requested.connect(
            self.management_controller.mieru_port_update_requested
        )
        self.shell.management_tab.nginx_inspection_requested.connect(
            self.management_controller.inspect_nginx
        )
        self.shell.management_tab.nginx_action_requested.connect(
            self.management_controller.nginx_action_requested
        )
        self.shell.management_tab.netdata_inspection_requested.connect(
            self.management_controller.inspect_netdata
        )
        self.shell.management_tab.netdata_action_requested.connect(
            self.management_controller.netdata_action_requested
        )
        self._clear_management_data("Open Management to load the selected server.")
        self._apply_style()
        self.shell.action_tabs.setCurrentWidget(self.shell.deploy_tab)
        self._write_log("Panel is ready.")
        self.telegram_controller.start()

    def _initialize_tray(self) -> None:
        if not QSystemTrayIcon.isSystemTrayAvailable():
            return
        icon = self.windowIcon()
        if icon.isNull():
            icon = self.style().standardIcon(QStyle.StandardPixmap.SP_ComputerIcon)
        icon = recolor_icon_hue(icon, PANEL_ICON_COLOR)
        self.setWindowIcon(icon)
        tray = QSystemTrayIcon(icon, self)
        tray.setToolTip("VPN Admin")
        menu = QMenu(self)
        open_action = QAction("Open Admin Panel", menu)
        open_action.triggered.connect(self._restore_from_tray)
        exit_action = QAction("Exit", menu)
        exit_action.triggered.connect(self._exit_application)
        menu.addAction(open_action)
        menu.addSeparator()
        menu.addAction(exit_action)
        tray.setContextMenu(menu)
        tray.activated.connect(self._tray_activated)
        tray.show()
        self.tray_icon = tray

    def _tray_activated(self, reason: QSystemTrayIcon.ActivationReason) -> None:
        if reason == QSystemTrayIcon.ActivationReason.DoubleClick:
            self._restore_from_tray()

    def _restore_from_tray(self) -> None:
        self.showNormal()
        self.raise_()
        self.activateWindow()

    def _exit_application(self) -> None:
        self._allow_close = True
        if not self.close():
            self._allow_close = False

    def _configure_settings(self) -> None:
        try:
            dialog = SettingsDialog(
                self.telegram_controller,
                self.settings,
                get_theme(self.theme_key).colors,
                parent=self,
            )
        except SshSettingsError as error:
            ThemedWarningDialog(
                self,
                "Settings",
                str(error),
                get_theme(self.theme_key).colors,
            ).exec()
            return
        if dialog.exec() == QDialog.DialogCode.Accepted:
            self._write_operation_result("Settings saved.", "success")

    def _report_settings_persistence_state(self) -> None:
        if self.settings.recovery_notice is not None:
            self._write_operation_result(self.settings.recovery_notice, "warning")
        if self.settings.persistence_available:
            return
        reason = self.settings.persistence_error or "The settings file could not be loaded safely."
        self._write_operation_result(
            f"{reason} It was left unchanged. Settings changes cannot be saved until "
            "the file is fixed or restored and Admin Panel is restarted.",
            "error",
        )

    def _request_remove_recent_server(self) -> None:
        if self.operation_gate.busy:
            ThemedWarningDialog(
                self,
                "Admin Panel is busy",
                "Wait for the current server operation to finish before removing a Recent server.",
                get_theme(self.theme_key).colors,
            ).exec()
            return
        server_ip, error = validate_server_ip(self.shell.server_ip_input.currentText())
        if error is not None or not any(
            server["ip"] == server_ip for server in self.recent_servers
        ):
            ThemedWarningDialog(
                self,
                "Recent server was not removed",
                "The selected server is no longer removable.",
                get_theme(self.theme_key).colors,
            ).exec()
            return
        if not self._confirm(
            "Remove Recent server",
            "Remove this IPv4 only from the local Recent list? The physical server, SSH settings, "
            "Backup archives, Subscriptions, and generated connections will not be deleted.",
            "Remove",
            highlight_text=f"Server: {server_ip}",
        ):
            return
        if not self._remove_recent_server(server_ip):
            ThemedWarningDialog(
                self,
                "Recent server was not removed",
                "The selected server is no longer removable.",
                get_theme(self.theme_key).colors,
            ).exec()

    def _remove_recent_server(self, server_ip: str) -> bool:
        if self.operation_gate.busy:
            return False
        current_ip, current_error = validate_server_ip(self.shell.server_ip_input.currentText())
        removing_current = current_error is None and current_ip == server_ip
        if removing_current and not self.users_controller.cancel(
            "Select a server to load Users data."
        ):
            return False
        try:
            removed = self.settings.remove_recent_server(server_ip)
        except (OSError, TypeError, ValueError):
            return False
        if not removed:
            return False

        if removing_current:
            self.shell.server_ip_input.setEditText("")
            self.shell.server_alias_input.clear()
            self.shell.subscriptions_tab.clear_name()
            self.subscriptions_controller.pair_changed()
            self.subscriptions_controller.server_ip_edited()
            self._clear_management_data("Select a server to load Management data.")
            current_for_combo = ""
        else:
            current_for_combo = self.shell.server_ip_input.currentText().strip()
        self._refresh_recent_servers(current_for_combo)
        self.telegram_controller.recent_servers_changed()
        self.backup_restore_controller.refresh_archive_list()
        self._write_operation_result(
            f"Removed {server_ip} from Recent. No server or related local data was deleted.",
            "success",
        )
        return True

    def _show_amnezia_information(self) -> None:
        ThemedWarningDialog(
            self,
            "Amnezia",
            "Amnezia should be installed by the Amnezia application.",
            get_theme(self.theme_key).colors,
        ).exec()

    def _request_nginx_tls(
        self,
        initial_settings: NginxTlsSettings | None,
    ) -> NginxTlsSettings | None:
        dialog = NginxTlsDialog(
            self,
            get_theme(self.theme_key).colors,
            initial_settings=initial_settings,
        )
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return None
        return dialog.settings()

    def _set_telegram_status(self, status: OperationalTelegramStatus) -> None:
        colors = get_theme(self.theme_key).colors
        text, color = {
            OperationalTelegramStatus.DISABLED: ("Disabled", colors.muted_text),
            OperationalTelegramStatus.STARTING: ("Starting", colors.amber),
            OperationalTelegramStatus.PAIRING_REQUIRED: (
                "Pairing required",
                colors.amber,
            ),
            OperationalTelegramStatus.ONLINE: ("● Online", colors.success),
            OperationalTelegramStatus.OFFLINE_RECONNECTING: (
                "● Offline / reconnecting",
                colors.error,
            ),
        }[status]
        self.telegram_status_label.setText(f"Telegram: {text}")
        self.telegram_status_label.setToolTip(f"Telegram: {text}")
        self.telegram_status_label.setStyleSheet(
            f"QLabel#telegramStatus {{ color: {color}; }}" if color else ""
        )

    def _apply_style(self) -> None:
        colors = get_theme(self.theme_key).colors
        self.setStyleSheet(build_stylesheet(colors))
        self.shell.refresh_operation_log_height()
        self.shell.theme_button.setIcon(action_icon("palette", colors.muted_text))
        self.shell.theme_button.setIconSize(QSize(18, 18))
        self.shell.edit_mode_button.set_theme_colors(colors)
        self.shell.set_global_action_icons(colors.muted_text)
        self.shell.backup_tab.set_refresh_icon(colors.muted_text)
        self.shell.backup_tab.set_action_icons(colors.muted_text, colors.amber)
        self.shell.backup_tab.set_delete_icon(colors.error)
        self.shell.users_tab.set_action_icons(colors.muted_text)
        self.shell.users_tab.set_delete_icon(colors.error)
        self.shell.subscriptions_tab.set_copy_icon(colors.muted_text)
        self.shell.subscriptions_tab.set_refresh_icon(colors.muted_text)
        self.shell.subscriptions_tab.set_publish_icon(colors.muted_text)
        self.shell.subscriptions_tab.set_server_action_icons(
            colors.amber,
            colors.error,
        )
        self.shell.subscriptions_tab.set_checkbox_color(colors.success)
        self.shell.management_tab.set_docker_action_colors(
            colors.muted_text, colors.success, colors.error
        )
        for button, icon_name in (
            (self.shell.remove_recent_server_button, "trash-2"),
            (self.shell.server_reboot_button, "refresh-cw"),
            (self.shell.copy_log_button, "copy"),
            (self.shell.clear_log_button, "trash-2"),
        ):
            button.setIcon(action_icon(icon_name, colors.muted_text))
            button.setIconSize(QSize(18, 18))
        apply_native_title_bar(self, colors)
        if hasattr(self, "telegram_controller"):
            status = (
                self.telegram_controller.manager.status
                if self.telegram_controller.manager is not None
                else OperationalTelegramStatus.DISABLED
            )
            self._set_telegram_status(status)

    def _change_theme(self, theme_key: str) -> None:
        if not isinstance(theme_key, str):
            return
        selected_theme_key = get_theme(theme_key).key
        self.shell.set_theme_selection(selected_theme_key)
        if selected_theme_key == self.theme_key:
            return
        self.theme_key = selected_theme_key
        self._apply_style()
        if not self.settings.persistence_available:
            self._write_operation_result(
                "Theme changed for this session only because settings persistence is unavailable.",
                "warning",
            )
            return
        self.settings.set("ui.theme", self.theme_key)
        self.settings.save()

    def _restore_window_position(self) -> None:
        position = self.settings.get("main_window.position")
        if isinstance(position, dict):
            x = position.get("x")
            y = position.get("y")
            if (
                isinstance(x, int)
                and not isinstance(x, bool)
                and isinstance(y, int)
                and not isinstance(y, bool)
            ):
                self.move(x, y)

        size = self.settings.get("main_window.size")
        if isinstance(size, dict):
            width = size.get("width")
            height = size.get("height")
            if (
                isinstance(width, int)
                and not isinstance(width, bool)
                and width > 0
                and isinstance(height, int)
                and not isinstance(height, bool)
                and height > 0
            ):
                self.resize(width, height)

    def _save_window_position(self) -> bool:
        if not self.settings.persistence_available:
            return False
        position = self.pos()
        self.settings.set("main_window.position", {"x": position.x(), "y": position.y()})
        size = self.size()
        self.settings.set("main_window.size", {"width": size.width(), "height": size.height()})
        try:
            self.settings.save()
        except OSError as error:
            self._write_operation_result(f"Could not save the window position: {error}", "warning")
            return False
        return True

    # Server selection and settings

    def _server_ip(self) -> str | None:
        server_ip, error = validate_server_ip(self.shell.server_ip_input.currentText())
        if error:
            ThemedWarningDialog(
                self, "Invalid address", error, get_theme(self.theme_key).colors
            ).exec()
            self.shell.server_ip_input.setFocus()
            return None
        self.shell.server_ip_input.setEditText(server_ip)
        server_alias = self.shell.server_alias_input.text().strip()
        self.shell.server_alias_input.setText(server_alias)
        if self.settings.persistence_available:
            try:
                self.settings.remember_server(server_alias, server_ip)
            except OSError as save_error:
                self._write_operation_result(
                    f"Could not save the server in Recent: {save_error}", "warning"
                )
            else:
                self._refresh_recent_servers(server_ip)
        return server_ip

    def _server_alias_editing_finished(self) -> None:
        server_ip, error = validate_server_ip(self.shell.server_ip_input.currentText())
        if error is not None:
            return
        server_alias = self.shell.server_alias_input.text().strip()
        self.shell.server_alias_input.setText(server_alias)
        if not self.settings.persistence_available:
            return
        try:
            updated = self.settings.update_recent_server_alias(server_alias, server_ip)
        except (OSError, TypeError, ValueError):
            self._write_operation_result("Could not save the server alias.", "error")
            return
        if updated:
            self._refresh_recent_servers(server_ip)

    def _select_recent_server(self, index: int) -> None:
        if index < 0 or index >= len(self.recent_servers):
            return
        server = self.recent_servers[index]
        self.shell.server_alias_input.setText(server["alias"])
        self.shell.server_ip_input.setEditText(server["ip"])
        self.subscriptions_controller.pair_changed()
        if self.shell.action_tabs.currentIndex() == self.shell.users_tab_index:
            self.users_controller.switch_server(server["ip"])
        elif self.shell.action_tabs.currentIndex() == self.shell.management_tab_index:
            self._refresh_management_snapshot()
        elif self.shell.action_tabs.currentIndex() == self.shell.subscriptions_tab_index:
            self.subscriptions_controller.server_changed()

    def _server_ip_edited(self, _text: str) -> None:
        self.shell.server_alias_input.clear()
        self.subscriptions_controller.pair_changed()
        if self.shell.action_tabs.currentIndex() == self.shell.users_tab_index:
            self.users_controller.server_ip_edited()
        elif self.shell.action_tabs.currentIndex() == self.shell.management_tab_index:
            self._clear_management_data(
                "Server address changed. Press Enter or leave the field to refresh."
            )
        elif self.shell.action_tabs.currentIndex() == self.shell.subscriptions_tab_index:
            self.subscriptions_controller.server_ip_edited()

    def _server_ip_submitted(self) -> None:
        if self.shell.action_tabs.currentIndex() == self.shell.users_tab_index:
            self.users_controller.connect_selected_server()
            return
        if self.shell.action_tabs.currentIndex() == self.shell.management_tab_index:
            self._refresh_management_snapshot()
            return
        if self.shell.action_tabs.currentIndex() == self.shell.subscriptions_tab_index:
            if self._server_ip() is not None:
                self.subscriptions_controller.server_changed()
            return
        self.check_ssh()

    def _server_ip_editing_finished(self) -> None:
        if self.operation_gate.busy:
            return
        if self.shell.action_tabs.currentIndex() == self.shell.users_tab_index:
            self.users_controller.server_ip_editing_finished(
                self.shell.server_ip_input.currentText()
            )
            return
        if self.shell.action_tabs.currentIndex() not in {
            self.shell.management_tab_index,
            self.shell.subscriptions_tab_index,
        }:
            return
        # Opening the editable combobox popup also finishes the line editor.
        # Its activated signal applies the selected server immediately afterwards,
        # so refreshing here would start Inventory for the previous address.
        if self.shell.server_ip_input.view().isVisible():
            return
        _server_ip, error = validate_server_ip(self.shell.server_ip_input.currentText())
        if error:
            if self.shell.action_tabs.currentIndex() == self.shell.subscriptions_tab_index:
                self.shell.subscriptions_tab.clear_server_subscriptions()
                self.shell.subscriptions_tab.set_server_status(
                    "error", f"Invalid server address: {error}"
                )
            else:
                self._clear_management_data(f"Invalid server address: {error}", state="error")
            return
        if self.shell.action_tabs.currentIndex() == self.shell.subscriptions_tab_index:
            self.subscriptions_controller.server_changed()
        else:
            self._refresh_management_snapshot()

    def _refresh_recent_servers(self, current_ip: str) -> None:
        self.recent_servers = self.settings.recent_servers()
        self.shell.update_recent_servers(self.recent_servers, current_ip)

    # Shared operation log

    def _write_log(
        self, message: str, *, reveal_log: bool = True, color: str | None = None
    ) -> None:
        if reveal_log:
            self.shell.content_stack.setCurrentIndex(0)
        if color is None:
            self.shell.log.appendPlainText(message)
            return
        self.shell.log.appendHtml(
            f'<span style="color: {escape(color)};">{escape(message)}</span>'
        )

    def _write_operation_result(self, message: str, outcome: OperationOutcome) -> None:
        colors = get_theme(self.theme_key).colors
        color = {
            "success": colors.success,
            "warning": colors.amber,
            "error": colors.error,
        }[outcome]
        self._write_log(message, color=color)

    def _clear_log(self) -> None:
        self.shell.log.clear()

    def _copy_log(self) -> None:
        QApplication.clipboard().setText(self.shell.log.toPlainText())

    def _add_user_requested(self) -> None:
        dialog = ThemedTextInputDialog(
            self, "Add user", "User name:", "Add user", get_theme(self.theme_key).colors
        )
        if dialog.exec() == QDialog.DialogCode.Accepted and dialog.text().strip():
            name = dialog.text()
            self.users_controller.run_action("create", name.strip())

    def _save_user_links_requested(self) -> None:
        user_name = self.users_controller.selected_user()
        if user_name is None:
            ThemedWarningDialog(
                self,
                "No user selected",
                "Select a user before saving configurations.",
                get_theme(self.theme_key).colors,
            ).exec()
            return
        self.users_controller.run_action("get", user_name)

    def _add_protocols_requested(self) -> None:
        user_name = self.users_controller.selected_user()
        if user_name is not None:
            self.users_controller.run_action("extend", user_name)

    def _delete_user_requested(self, user_name: str) -> None:
        if self._confirm(
            "Delete user",
            f"Delete user {user_name} from {self.users_controller.view_ip}? "
            "All Xray, Hysteria2, and Mieru access for this user will be revoked.",
            "Delete user",
        ):
            self.users_controller.run_action("delete", user_name)

    def _delete_backup_requested(self, archive: LocalBackupArchive) -> None:
        if self._confirm(
            "Delete Backup archive",
            "Delete this local Backup archive? This action cannot be undone.",
            "Delete",
            highlight_text=f"Archive: {archive.path.name}",
        ):
            self.backup_restore_controller.delete_selected_backup(archive)

    # Inventory, Management, Backup and Restore orchestration

    def _request_archive_inventory(
        self,
        request: InventoryRequestContext,
    ) -> bool:
        self.inventory_context = request
        if self.inventory_runner.start_collection(request):
            return True
        self.inventory_context = None
        return False

    def _consume_inventory_context(self) -> None:
        self.inventory_context = None

    def _start_inventory_collection(
        self,
        requester: str,
        *,
        purpose: InventoryPurpose,
    ) -> None:
        if self.operation_gate.busy:
            return
        server_ip = self._server_ip()
        if server_ip is None or self.operation_gate.busy:
            return
        users_cancelled = self.users_controller.cancel(
            "Checking Users authorization…" if purpose == "users" else "Users data is not loaded.",
            state="loading" if purpose == "users" else "idle",
        )
        if not users_cancelled:
            self._write_operation_result("Could not close the current Users operation.", "error")
            return
        operation = self.operation_gate.begin(
            f"Inventory ({requester})",
            scope="inventory",
            server_ip=server_ip,
        )
        if operation is None:
            if purpose == "users":
                self.users_controller.inventory_failed("Another server operation is running.")
            self.users_controller.resume_if_visible()
            return
        request = InventoryRequestContext(
            operation.token,
            purpose,
            requester,
            server_ip,
        )
        self.inventory_context = request
        self._set_operation_controls_enabled(False)
        self._write_log(f"=== {self.operation_gate.title}: {server_ip} ===")
        if not self.inventory_runner.start_collection(request):
            self._inventory_failed(request, "Inventory collection is already running.")

    def _inventory_completed(self, request: object, snapshot: object) -> None:
        context = self._matching_inventory_context(request)
        if context is None:
            return
        if not isinstance(snapshot, InventorySnapshot):
            self._inventory_failed(context, "Inventory runner returned an invalid snapshot.")
            return
        if snapshot.server_ip != context.server_ip:
            self._inventory_failed(
                context,
                "Inventory runner returned a snapshot for a different server.",
            )
            return
        if snapshot.profile != context.inventory_profile:
            self._inventory_failed(
                context,
                "Inventory runner returned a snapshot with a different profile.",
            )
            return
        if context.purpose == "nginx_deploy":
            self.inventory_context = None
            nginx = snapshot.component("nginx")
            nginx_state = "not installed" if nginx is None else nginx.status
            self._write_log(f"Nginx Inventory: {nginx_state}.")
            self.deploy_server_controller.inventory_completed(context, snapshot)
            return
        if context.purpose in {"management", "management_reconciliation"}:
            netdata_access = (
                load_netdata_access_details(
                    Path(__file__).resolve().parents[2], snapshot.server_ip
                )
                if snapshot.component("netdata") is not None
                else None
            )
            self.shell.management_tab.display_snapshot(snapshot, netdata_access=netdata_access)
        elif context.purpose in {
            "backup",
            "restore_compatibility",
            "restore_verification",
        }:
            self.backup_restore_controller.inventory_completed(
                context,
                snapshot,
            )
            return
        self._write_log(
            f"Inventory requested by {context.requester}; server: {context.server_ip}."
        )
        if not snapshot.components:
            self._write_log("No installed components are registered.")
        for component in snapshot.components:
            self._write_inventory_component(component)
        if context.purpose == "management_reconciliation":
            self.inventory_context = None
            self.management_controller.reconciliation_inventory_completed(context)
            return
        if context.purpose == "subscriptions":
            self.inventory_context = None
            self.subscriptions_controller.inventory_completed(snapshot)
            return
        outcome: OperationOutcome = (
            "success"
            if snapshot.profile != "full"
            or all(component.status == "active" for component in snapshot.components)
            else "warning"
        )
        self._finish_inventory_operation(outcome, resume_users=context.purpose != "users")
        if context.purpose == "users":
            self.users_controller.inventory_completed(snapshot)
            return
        if context.purpose == "management":
            if self.shell.management_tab.docker_needs_inspection():
                self.management_controller.inspect_docker()
            elif self.shell.management_tab.base_security_needs_inspection():
                self.management_controller.inspect_base_security()
            elif self.shell.management_tab.xray_needs_inspection():
                self.management_controller.inspect_xray()
            elif self.shell.management_tab.hysteria2_needs_inspection():
                self.management_controller.inspect_hysteria2()
            elif self.shell.management_tab.mieru_needs_inspection():
                self.management_controller.inspect_mieru()
            elif self.shell.management_tab.nginx_needs_inspection():
                self.management_controller.inspect_nginx()
            elif self.shell.management_tab.netdata_needs_inspection():
                self.management_controller.inspect_netdata()

    def _write_inventory_component(self, component: ComponentInventory) -> None:
        name = (
            component.declaration.display_name if component.declaration else component.component_id
        )
        self._write_log(f"[{component.status}] {name} ({component.component_id})")
        for check in component.checks:
            marker = "OK" if check.passed else "ERROR"
            self._write_log(f"  {marker} {check.category}: {check.target} — {check.detail}")

    def _inventory_failed(self, request: object, message: str) -> None:
        context = self._matching_inventory_context(request)
        if context is None:
            return
        if context.purpose == "management_reconciliation":
            self.inventory_context = None
            self.management_controller.reconciliation_failed(context, message)
            return
        if context.purpose == "management":
            self._clear_management_data(message, state="error")
        elif context.purpose == "users":
            self.users_controller.inventory_failed(message)
        elif context.purpose == "subscriptions":
            self.inventory_context = None
            self.subscriptions_controller.inventory_failed(message)
            return
        elif context.purpose == "nginx_deploy":
            self.inventory_context = None
            self.deploy_server_controller.inventory_failed(context, message)
            return
        else:
            self.backup_restore_controller.inventory_failed(
                context,
                message,
            )
            return
        self._write_operation_result(message, "error")
        self._finish_inventory_operation("error", resume_users=context.purpose != "users")

    def _matching_inventory_context(
        self,
        request: object,
    ) -> InventoryRequestContext | None:
        if not isinstance(request, InventoryRequestContext):
            return None
        context = self.inventory_context
        if context != request:
            return None
        operation = self.operation_gate.current
        if operation is None or operation.token != request.operation_token:
            return None
        if operation.scope != "inventory" or operation.server_ip != request.server_ip:
            return None
        return context

    def _finish_inventory_operation(
        self,
        outcome: OperationOutcome,
        *,
        resume_users: bool = True,
    ) -> None:
        outcome_text = {
            "success": "successful",
            "warning": "completed with warnings",
            "error": "failed",
        }[outcome]
        self._write_operation_result(
            f"=== {self.operation_gate.title}: {outcome_text} ===",
            outcome,
        )
        context = self.operation_gate.current
        if context is not None:
            self.operation_gate.finish(context)
        self.inventory_context = None
        self._set_operation_controls_enabled(True)
        if resume_users:
            self.users_controller.resume_if_visible()

    def _set_operation_controls_enabled(self, enabled: bool) -> None:
        self.shell.set_server_controls_enabled(enabled)
        self.shell.deploy_tab.set_operation_controls_enabled(enabled)
        self.shell.backup_tab.set_operation_controls_enabled(enabled)
        self.shell.users_tab.set_operation_controls_enabled(enabled)
        self.shell.management_tab.set_docker_controls_enabled(enabled)
        self.shell.management_tab.set_base_security_controls_enabled(enabled)
        self.shell.management_tab.set_xray_controls_enabled(enabled)
        self.shell.management_tab.set_hysteria2_controls_enabled(enabled)
        self.shell.management_tab.set_mieru_controls_enabled(enabled)
        self.shell.management_tab.set_nginx_controls_enabled(enabled)
        self.shell.management_tab.set_netdata_controls_enabled(enabled)
        self.shell.subscriptions_tab.set_operation_controls_enabled(enabled)

    # Tab activation and one-shot Users operations

    def _change_action_tab(self, index: int) -> None:
        previous_index = self._current_action_tab_index
        self._current_action_tab_index = index
        if (
            previous_index == self.shell.subscriptions_tab_index
            and index != self.shell.subscriptions_tab_index
        ):
            self.shell.subscriptions_tab.clear_name()
            self.subscriptions_controller.hide()
        if index == self.shell.users_tab_index:
            self.users_controller.show()
        elif index == self.shell.management_tab_index:
            self._show_management()
        elif index == self.shell.subscriptions_tab_index:
            self.subscriptions_controller.show()
            if self.users_controller.has_session:
                self.users_controller.hide()
        elif index == self.shell.backup_tab_index:
            self.backup_restore_controller.refresh_archive_list()
            if self.users_controller.has_session:
                self.users_controller.hide()
        elif self.users_controller.has_session:
            self.users_controller.hide()

    def _refresh_users_inventory(self) -> None:
        self._start_inventory_collection("Users", purpose="users")

    def _refresh_subscriptions_inventory(self) -> None:
        self._start_inventory_collection("Subscriptions", purpose="subscriptions")

    def _show_management(self) -> None:
        if self.operation_gate.busy:
            return
        self._refresh_management_snapshot()

    def _refresh_management_snapshot(
        self,
        *,
        preserve_selection: bool = False,
        preserve_docker_status: bool = False,
        preserve_base_security_status: bool = False,
        preserve_xray_status: bool = False,
        preserve_hysteria2_status: bool = False,
        preserve_mieru_status: bool = False,
        preserve_nginx_status: bool = False,
        preserve_netdata_status: bool = False,
    ) -> None:
        if self.operation_gate.busy:
            return
        _server_ip, error = validate_server_ip(self.shell.server_ip_input.currentText())
        if error:
            self._clear_management_data(f"Invalid server address: {error}", state="error")
            return
        self.shell.management_tab.clear(
            "Loading Management snapshot…",
            state="loading",
            preserve_selection=preserve_selection,
            preserve_docker_status=preserve_docker_status,
            preserve_base_security_status=preserve_base_security_status,
            preserve_xray_status=preserve_xray_status,
            preserve_hysteria2_status=preserve_hysteria2_status,
            preserve_mieru_status=preserve_mieru_status,
            preserve_nginx_status=preserve_nginx_status,
            preserve_netdata_status=preserve_netdata_status,
        )
        self._start_inventory_collection("Management", purpose="management")

    def _clear_management_data(self, message: str, *, state: ManagementViewState = "idle") -> None:
        self.shell.management_tab.clear(message, state=state)

    def _confirm(
        self, title: str, text: str, action_label: str, *, highlight_text: str | None = None
    ) -> bool:
        dialog = AlertConfirmationDialog(
            self,
            title,
            text,
            action_label,
            get_theme(self.theme_key).colors,
            highlight_text=highlight_text,
        )
        return dialog.exec() == QDialog.DialogCode.Accepted
