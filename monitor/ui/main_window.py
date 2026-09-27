from __future__ import annotations

import time
from datetime import datetime, timezone
from ipaddress import IPv4Address
from pathlib import Path

from PySide6.QtCore import QMimeData, QObject, QPointF, QSize, Qt, QThread, QTimer, Signal
from PySide6.QtGui import (
    QAction,
    QCloseEvent,
    QColor,
    QDragEnterEvent,
    QDragMoveEvent,
    QDropEvent,
    QPainter,
    QPaintEvent,
    QPen,
)
from PySide6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QCheckBox,
    QFileDialog,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QMainWindow,
    QMenu,
    QMessageBox,
    QPlainTextEdit,
    QSizePolicy,
    QStatusBar,
    QStyle,
    QStyleOptionButton,
    QSystemTrayIcon,
    QTableWidget,
    QTableWidgetItem,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

from common.ui.icon_assets import action_icon
from common.ui.icon_button import IconActionButton
from common.ui.operation_log import fix_operation_log_height
from common.ui.theme import available_themes, build_stylesheet, get_theme, is_light_theme
from common.ui.window_chrome import apply_native_title_bar
from monitor.coordinator import MonitorCoordinator
from monitor.domain import ConnectionSnapshot, ConnectionStatus
from monitor.importer import ImportFileError, connection_user_name
from monitor.information import OperationLogInformationOutput
from monitor.settings import MonitorSettings
from monitor.telegram import TelegramStatus
from monitor.ui.settings_dialog import SettingsDialog


class MonitorBridge(QObject):
    snapshot_received = Signal(object)
    cycle_changed = Signal(bool, object)
    telegram_status_changed = Signal(object)


class _ShutdownThread(QThread):
    completed = Signal(bool)

    def __init__(self, coordinator: MonitorCoordinator) -> None:
        super().__init__()
        self._coordinator = coordinator

    def run(self) -> None:
        self.completed.emit(self._coordinator.stop())


class _SettingsThread(QThread):
    completed = Signal(bool, str)

    def __init__(self, coordinator: MonitorCoordinator, settings: MonitorSettings) -> None:
        super().__init__()
        self._coordinator = coordinator
        self._settings = settings

    def run(self) -> None:
        try:
            self._coordinator.save_settings(self._settings)
        except (OSError, RuntimeError, ValueError) as error:
            self.completed.emit(False, str(error))
            return
        self.completed.emit(True, "")


STATUS_TEXT = {
    ConnectionStatus.UNKNOWN: "UNKNOWN",
    ConnectionStatus.CHECKING: "Checking",
    ConnectionStatus.RETRYING: "Retrying",
    ConnectionStatus.OK: "OK",
    ConnectionStatus.OK_NO_IP: "Works, IP unavailable",
    ConnectionStatus.FAIL: "FAIL",
    ConnectionStatus.DISABLED: "Disabled",
}

MONITOR_ROW_ACTION_COLUMN_WIDTH = 56


def _contrasting_check_color(background: str) -> QColor:
    color = QColor(background)
    brightness = (color.red() * 299 + color.green() * 587 + color.blue() * 114) / 1000
    return QColor("#07111E" if brightness >= 150 else "#FFFFFF")


class _MonitorEnabledCheckBox(QCheckBox):
    def __init__(self, checked_background: str) -> None:
        super().__init__()
        self.setObjectName("monitorEnabledCheck")
        self.setAccessibleName("Enabled")
        self._check_color = _contrasting_check_color(checked_background)

    def set_checked_background(self, checked_background: str) -> None:
        self._check_color = _contrasting_check_color(checked_background)
        self.update()

    def paintEvent(self, event: QPaintEvent) -> None:
        super().paintEvent(event)
        check_state = self.checkState()
        if check_state == Qt.CheckState.Unchecked:
            return
        option = QStyleOptionButton()
        self.initStyleOption(option)
        indicator = self.style().subElementRect(
            QStyle.SubElement.SE_CheckBoxIndicator,
            option,
            self,
        )
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        pen = QPen(self._check_color, 2.2)
        pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        pen.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
        painter.setPen(pen)
        if check_state == Qt.CheckState.PartiallyChecked:
            painter.drawLine(
                QPointF(indicator.left() + 3.0, indicator.center().y()),
                QPointF(indicator.right() - 3.0, indicator.center().y()),
            )
            return
        painter.drawLine(
            QPointF(indicator.left() + 3.0, indicator.center().y()),
            QPointF(indicator.left() + 6.5, indicator.bottom() - 3.0),
        )
        painter.drawLine(
            QPointF(indicator.left() + 6.5, indicator.bottom() - 3.0),
            QPointF(indicator.right() - 2.5, indicator.top() + 3.0),
        )


class _MonitorMasterCheckBox(_MonitorEnabledCheckBox):
    def __init__(self, checked_background: str) -> None:
        super().__init__(checked_background)
        self.setAccessibleName("Enable or disable all connections")
        self.setTristate(True)

    def nextCheckState(self) -> None:
        next_state = (
            Qt.CheckState.Unchecked
            if self.checkState() == Qt.CheckState.Checked
            else Qt.CheckState.Checked
        )
        self.setCheckState(next_state)


class _MonitorConnectionsTable(QTableWidget):
    file_dropped = Signal(str)

    def __init__(self, rows: int, columns: int) -> None:
        super().__init__(rows, columns)
        self.setAcceptDrops(True)
        self.setDragDropMode(QAbstractItemView.DragDropMode.DropOnly)

    @staticmethod
    def _single_local_file(mime_data: QMimeData) -> Path | None:
        if not mime_data.hasUrls():
            return None
        urls = mime_data.urls()
        if len(urls) != 1 or not urls[0].isLocalFile():
            return None
        path = Path(urls[0].toLocalFile())
        return path if path.is_file() else None

    def dragEnterEvent(self, event: QDragEnterEvent) -> None:
        if self._single_local_file(event.mimeData()) is None:
            event.ignore()
            return
        event.acceptProposedAction()

    def dragMoveEvent(self, event: QDragMoveEvent) -> None:
        if self._single_local_file(event.mimeData()) is None:
            event.ignore()
            return
        event.acceptProposedAction()

    def dropEvent(self, event: QDropEvent) -> None:
        path = self._single_local_file(event.mimeData())
        if path is None:
            event.ignore()
            return
        event.acceptProposedAction()
        self.file_dropped.emit(str(path))


class MonitorWindow(QMainWindow):
    def __init__(self, coordinator: MonitorCoordinator, bridge: MonitorBridge) -> None:
        super().__init__()
        self.coordinator = coordinator
        self.bridge = bridge
        self._allow_close = False
        self._updating_table = False
        self._shutdown_thread: _ShutdownThread | None = None
        self._settings_thread: _SettingsThread | None = None
        self._exit_after_settings = False
        self._rows: dict[str, int] = {}
        self._delete_action_buttons: list[QToolButton] = []
        self._next_check_deadline: float | None = None
        self._log_clear_marker: dict[str, object] | None = None
        self.theme_key = get_theme(coordinator.settings.theme_key).key
        self.theme_actions: dict[str, QAction] = {}
        self.setWindowTitle("Monitoring")
        self.resize(920, 560)
        self._build_ui()
        self._apply_theme()
        self._restore_window_geometry()
        self._build_tray()
        bridge.snapshot_received.connect(self._apply_snapshot)
        bridge.cycle_changed.connect(self._apply_cycle)
        bridge.telegram_status_changed.connect(self._apply_telegram_status)
        self._reload_table()
        self._reload_log()
        self._apply_telegram_status(coordinator.telegram.status)

    def _build_ui(self) -> None:
        central = QWidget()
        central.setObjectName("monitorCentral")
        root = QVBoxLayout(central)
        root.setContentsMargins(24, 20, 24, 24)
        root.setSpacing(16)

        self.status_panel = QWidget()
        status_row = QHBoxLayout(self.status_panel)
        status_row.setContentsMargins(0, 0, 0, 0)
        status_row.setSpacing(0)
        self.telegram_status = QLabel("Telegram: Starting")
        self.telegram_status.setObjectName("monitorTelegramStatus")
        self.telegram_status.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.next_check = QLabel("Next check: —")
        self.next_check.setObjectName("monitorNextCheckStatus")
        self.next_check.setAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        self.next_check.setSizePolicy(
            QSizePolicy.Policy.Preferred,
            QSizePolicy.Policy.Preferred,
        )
        self.check_now_button = IconActionButton("Check now")
        self.check_now_button.setEnabled(False)
        self.check_now_button.clicked.connect(self._check_now)
        self.settings_button = IconActionButton("Settings")
        self.settings_button.clicked.connect(self._settings)
        self.settings_label = QLabel("Settings")
        self.settings_label.setAlignment(
            Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter
        )
        settings_action = QWidget()
        settings_action_layout = QHBoxLayout(settings_action)
        settings_action_layout.setContentsMargins(0, 0, 0, 0)
        settings_action_layout.setSpacing(4)
        settings_action_layout.addWidget(self.settings_label)
        settings_action_layout.addWidget(self.settings_button)
        self._build_theme_menu()
        status_row.addWidget(self.next_check)
        status_row.addSpacing(4)
        status_row.addWidget(self.check_now_button)
        status_row.addStretch(1)
        status_row.addSpacing(32)
        status_row.addWidget(settings_action)
        root.addWidget(self.status_panel)

        content = QHBoxLayout()
        content.setSpacing(10)
        self.table = _MonitorConnectionsTable(0, 9)
        self.table.file_dropped.connect(self._import_file)
        self.table.setHorizontalHeaderLabels(
            [
                "",
                "Server IP",
                "Name",
                "Protocol",
                "Last check",
                "IPv4",
                "Ping",
                "Status",
                "",
            ]
        )
        center = Qt.AlignmentFlag.AlignCenter
        left = Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter
        right = Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter
        for column, alignment in enumerate(
            (center, left, right, left, center, left, center, center, center)
        ):
            self.table.horizontalHeaderItem(column).setTextAlignment(alignment)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.verticalHeader().setVisible(False)
        self.table.verticalHeader().setDefaultSectionSize(32)
        header = self.table.horizontalHeader()
        header.setMinimumHeight(32)
        for column, width in {
            0: 60,
            1: 108,
            3: 74,
            4: 84,
            5: 80,
            6: 54,
            7: 134,
        }.items():
            header.setSectionResizeMode(column, QHeaderView.Interactive)
            header.resizeSection(column, width)
        header.setSectionResizeMode(2, QHeaderView.Stretch)
        header.setSectionResizeMode(8, QHeaderView.Fixed)
        header.resizeSection(8, MONITOR_ROW_ACTION_COLUMN_WIDTH)
        self.master_enabled_header = QWidget(header.viewport())
        self.master_enabled_header.setObjectName("monitorMasterEnabledHeader")
        master_enabled_layout = QHBoxLayout(self.master_enabled_header)
        master_enabled_layout.setContentsMargins(0, 0, 0, 0)
        master_enabled_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.master_enabled_checkbox = _MonitorMasterCheckBox(
            get_theme(self.theme_key).colors.success
        )
        self.master_enabled_checkbox.clicked.connect(self._master_enabled_changed)
        master_enabled_layout.addWidget(self.master_enabled_checkbox)
        content.addWidget(self.table, 1)

        actions = QVBoxLayout()
        actions.setContentsMargins(0, 0, 0, 0)
        actions.setSpacing(0)
        self.action_header = QWidget()
        actions.addWidget(self.action_header)

        self.add_button = IconActionButton("Add")
        self.add_button.clicked.connect(self._add)
        actions.addWidget(self.add_button)
        actions.addStretch()
        content.addLayout(actions)
        root.addLayout(content, 1)
        header.geometriesChanged.connect(self._sync_action_header_height)
        header.geometriesChanged.connect(self._sync_master_enabled_header)
        header.sectionResized.connect(
            lambda _section, _old_size, _new_size: self._sync_master_enabled_header()
        )
        QTimer.singleShot(0, self._sync_action_header_height)
        QTimer.singleShot(0, self._sync_master_enabled_header)

        self.copy_log_button = QToolButton()
        self.copy_log_button.setObjectName("iconAction")
        self.copy_log_button.setToolTip("Copy log")
        self.copy_log_button.setFixedSize(32, 32)
        self.copy_log_button.clicked.connect(self._copy_log)
        self.clear_log_button = QToolButton()
        self.clear_log_button.setObjectName("iconAction")
        self.clear_log_button.setToolTip("Clear log")
        self.clear_log_button.setFixedSize(32, 32)
        self.clear_log_button.clicked.connect(self._clear_log)
        log_group = QGroupBox()
        log_group.setObjectName("operationLogGroup")
        log_layout = QHBoxLayout(log_group)
        log_layout.setContentsMargins(0, 0, 0, 0)
        log_layout.setSpacing(8)
        log_actions = QVBoxLayout()
        log_actions.setSpacing(8)
        log_actions.addWidget(self.theme_button)
        log_actions.addStretch()
        log_actions.addWidget(self.copy_log_button)
        log_actions.addWidget(self.clear_log_button)
        self.log = QPlainTextEdit()
        self.log.setObjectName("operationLog")
        self.log.setReadOnly(True)
        self.log.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        fix_operation_log_height(self.log)
        log_layout.addWidget(self.log, 1)
        log_layout.addLayout(log_actions)
        self.log_group = log_group
        root.addWidget(self.log_group)
        self.setCentralWidget(central)

        status_bar = QStatusBar(self)
        status_bar.setObjectName("globalStatusBar")
        status_bar.setSizeGripEnabled(False)
        status_bar.addWidget(self.telegram_status, 1)
        self.setStatusBar(status_bar)

        self.countdown_timer = QTimer(self)
        self.countdown_timer.setInterval(250)
        self.countdown_timer.timeout.connect(self._update_countdown)
        self.countdown_timer.start()

    def _sync_action_header_height(self) -> None:
        viewport = self.table.viewport()
        first_row_top = viewport.mapTo(self.table, viewport.rect().topLeft()).y()
        if first_row_top > 0 and self.action_header.height() != first_row_top:
            self.action_header.setFixedHeight(first_row_top)

    def _sync_master_enabled_header(self) -> None:
        header = self.table.horizontalHeader()
        self.master_enabled_header.setGeometry(
            header.sectionViewportPosition(0),
            0,
            header.sectionSize(0),
            header.viewport().height(),
        )
        self.master_enabled_header.raise_()

    def _build_theme_menu(self) -> None:
        self.theme_button = QToolButton()
        self.theme_button.setObjectName("themeButton")
        self.theme_button.setToolTip("Choose Monitor theme")
        self.theme_button.setFixedSize(32, 32)
        self.theme_button.setPopupMode(QToolButton.ToolButtonPopupMode.InstantPopup)
        menu = QMenu(self.theme_button)
        has_dark_theme = False
        light_separator_added = False
        for theme in available_themes():
            if is_light_theme(theme.key) and has_dark_theme and not light_separator_added:
                menu.addSeparator()
                light_separator_added = True
            action = menu.addAction(theme.display_name)
            action.setCheckable(True)
            action.setChecked(theme.key == self.theme_key)
            action.triggered.connect(lambda _checked=False, key=theme.key: self._change_theme(key))
            self.theme_actions[theme.key] = action
            has_dark_theme = has_dark_theme or not is_light_theme(theme.key)
        self.theme_button.setMenu(menu)

    def _apply_theme(self) -> None:
        colors = get_theme(self.theme_key).colors
        self.setStyleSheet(build_stylesheet(colors))
        fix_operation_log_height(self.log)
        self.master_enabled_checkbox.set_checked_background(colors.success)
        self.theme_button.setIcon(action_icon("palette", colors.muted_text))
        self.theme_button.setIconSize(QSize(18, 18))
        for button, icon_name in (
            (self.check_now_button, "refresh-cw"),
            (self.add_button, "plus"),
            (self.settings_button, "settings"),
            (self.copy_log_button, "copy"),
            (self.clear_log_button, "trash-2"),
        ):
            button.setIcon(action_icon(icon_name, colors.muted_text))
            button.setIconSize(QSize(18, 18))
        apply_native_title_bar(self, colors)
        if hasattr(self, "table"):
            self._reload_table()

    def _restore_window_geometry(self) -> None:
        settings = self.coordinator.settings
        self.resize(settings.window_width, settings.window_height)
        if settings.window_x is not None and settings.window_y is not None:
            self.move(settings.window_x, settings.window_y)

    def _save_window_geometry(self) -> None:
        position = self.pos()
        size = self.size()
        try:
            self.coordinator.save_window_geometry(
                position.x(),
                position.y(),
                size.width(),
                size.height(),
            )
        except (OSError, ValueError) as error:
            self.coordinator.operation_log.write(
                "window_geometry_save_error", error_type=type(error).__name__
            )

    def _change_theme(self, theme_key: str) -> None:
        if theme_key not in self.theme_actions or theme_key == self.theme_key:
            return
        try:
            settings = self.coordinator.save_theme_key(theme_key)
        except (OSError, ValueError) as error:
            self.theme_actions[self.theme_key].setChecked(True)
            QMessageBox.critical(self, "Monitor theme", str(error))
            return
        self.theme_key = settings.theme_key
        for key, action in self.theme_actions.items():
            action.setChecked(key == self.theme_key)
        self._apply_theme()

    def _build_tray(self) -> None:
        self.tray = QSystemTrayIcon(self)
        icon = self.windowIcon()
        if icon.isNull():
            icon = self.style().standardIcon(QStyle.StandardPixmap.SP_ComputerIcon)
        self.tray.setIcon(icon)
        self.tray.setToolTip("VPN Monitor")
        menu = QMenu(self)
        open_action = menu.addAction("Open Monitoring")
        exit_action = menu.addAction("Exit")
        open_action.triggered.connect(self._show_from_tray)
        exit_action.triggered.connect(self._exit)
        self.tray.setContextMenu(menu)
        self.tray.activated.connect(
            lambda reason: (
                self._show_from_tray()
                if reason == QSystemTrayIcon.ActivationReason.DoubleClick
                else None
            )
        )
        if QSystemTrayIcon.isSystemTrayAvailable():
            self.tray.show()

    def _reload_table(self) -> None:
        snapshots = sorted(
            self.coordinator.snapshots(),
            key=lambda snapshot: IPv4Address(snapshot.connection.expected_ipv4),
        )
        colors = get_theme(self.theme_key).colors
        self._updating_table = True
        try:
            self._clear_delete_actions()
            self.table.setRowCount(len(snapshots))
            self._rows.clear()
            for row, snapshot in enumerate(snapshots):
                self._rows[snapshot.connection.connection_id] = row
                enabled_item = QTableWidgetItem()
                enabled_item.setData(Qt.ItemDataRole.UserRole, snapshot.connection.connection_id)
                enabled_item.setFlags(Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable)
                enabled_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
                self.table.setItem(row, 0, enabled_item)
                enabled_checkbox = _MonitorEnabledCheckBox(colors.success)
                enabled_checkbox.setChecked(snapshot.connection.enabled)
                enabled_checkbox.toggled.connect(
                    lambda checked, connection_id=snapshot.connection.connection_id: (
                        self._enabled_changed(connection_id, checked)
                    )
                )
                enabled_cell = QWidget()
                enabled_layout = QHBoxLayout(enabled_cell)
                enabled_layout.setContentsMargins(0, 0, 0, 0)
                enabled_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
                enabled_layout.addWidget(enabled_checkbox)
                self.table.setCellWidget(row, 0, enabled_cell)
                for column, value in (
                    (1, snapshot.connection.expected_ipv4),
                    (3, snapshot.connection.protocol),
                ):
                    item = QTableWidgetItem(value)
                    item.setTextAlignment(
                        Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter
                    )
                    self.table.setItem(row, column, item)
                name_item = QTableWidgetItem(connection_user_name(snapshot.connection))
                name_item.setTextAlignment(
                    Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter
                )
                self.table.setItem(row, 2, name_item)
                self._render_snapshot(row, snapshot)
                self._set_delete_action(row, snapshot.connection.connection_id)
        finally:
            self._updating_table = False
        self._sync_master_enabled_state(snapshots)

    def _apply_snapshot(self, snapshot: ConnectionSnapshot) -> None:
        row = self._rows.get(snapshot.connection.connection_id)
        if row is None:
            self._reload_table()
            return
        self._render_snapshot(row, snapshot)

    def _render_snapshot(self, row: int, snapshot: ConnectionSnapshot) -> None:
        status = QTableWidgetItem(STATUS_TEXT[snapshot.status])
        status.setForeground(self._status_color(snapshot.status))
        status.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
        self.table.setItem(row, 7, status)
        checked = snapshot.checked_at or "—"
        if snapshot.checked_at:
            try:
                checked = (
                    datetime.fromisoformat(snapshot.checked_at).astimezone().strftime("%H:%M:%S")
                )
            except ValueError:
                pass
        checked_item = QTableWidgetItem(checked)
        checked_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
        self.table.setItem(row, 4, checked_item)
        ping = ""
        ipv4 = ""
        if snapshot.result:
            if snapshot.result.latency_ms is not None:
                ping = str(snapshot.result.latency_ms)
            if snapshot.result.observed_ipv4:
                ipv4 = (
                    "matched"
                    if snapshot.result.observed_ipv4 == snapshot.connection.expected_ipv4
                    else "not matched"
                )
        ipv4_item = QTableWidgetItem(ipv4)
        ipv4_item.setTextAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        self.table.setItem(row, 5, ipv4_item)
        ping_item = QTableWidgetItem(ping)
        ping_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
        self.table.setItem(row, 6, ping_item)

    def _set_delete_action(self, row: int, connection_id: str) -> None:
        action_cell = QWidget()
        action_layout = QHBoxLayout(action_cell)
        action_layout.setContentsMargins(4, 2, 4, 2)
        action_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        delete_button = QToolButton(action_cell)
        delete_button.setObjectName("monitorRowAction")
        delete_button.setToolTip("Delete connection")
        delete_button.setAccessibleName("Delete connection")
        delete_button.setFixedSize(28, 28)
        delete_button.setIconSize(QSize(16, 16))
        delete_button.setIcon(action_icon("trash-2", get_theme(self.theme_key).colors.error))
        delete_button.clicked.connect(
            lambda _checked=False, current=connection_id: self._delete_connection(current)
        )
        action_layout.addWidget(delete_button)
        self._delete_action_buttons.append(delete_button)
        self.table.setCellWidget(row, 8, action_cell)

    def _clear_delete_actions(self) -> None:
        for button in self._delete_action_buttons:
            button.clicked.disconnect()
        self._delete_action_buttons.clear()

    def _status_color(self, status: ConnectionStatus) -> QColor:
        colors = get_theme(self.theme_key).colors
        color = {
            ConnectionStatus.OK: colors.success,
            ConnectionStatus.OK_NO_IP: colors.amber,
            ConnectionStatus.FAIL: colors.error,
            ConnectionStatus.RETRYING: colors.amber,
            ConnectionStatus.CHECKING: colors.blue,
        }.get(status, colors.muted_text)
        return QColor(color)

    def _apply_cycle(self, running: bool, next_check: object) -> None:
        self._next_check_deadline = None
        if self.coordinator.settings_recovery_error is not None:
            self.next_check.setText("Monitoring stopped / stopping: restart required")
            self.check_now_button.setEnabled(False)
            return
        if running and isinstance(next_check, str):
            try:
                scheduled = datetime.fromisoformat(next_check)
                if scheduled.tzinfo is None:
                    scheduled = scheduled.replace(tzinfo=timezone.utc)
                delay = max(0.0, (scheduled - datetime.now(timezone.utc)).total_seconds())
            except ValueError:
                delay = float(self.coordinator.settings.check_interval_seconds)
            self._next_check_deadline = time.monotonic() + delay
            self.check_now_button.setEnabled(True)
            self._update_countdown()
        elif running:
            self.next_check.setText("Next check: checking…")
            self.check_now_button.setEnabled(False)
        else:
            self.next_check.setText("Next check: —")
            self.check_now_button.setEnabled(False)
        self._reload_log()

    def _apply_telegram_status(self, status: TelegramStatus) -> None:
        text = {
            TelegramStatus.STARTING: "Telegram: Starting",
            TelegramStatus.ONLINE: "Telegram: ● Online",
            TelegramStatus.OFFLINE_RECONNECTING: "Telegram: ● Offline / reconnecting",
        }[status]
        self.telegram_status.setText(text)
        self.telegram_status.setProperty("state", status.value)
        self.telegram_status.style().unpolish(self.telegram_status)
        self.telegram_status.style().polish(self.telegram_status)
        self._reload_log()

    def _update_countdown(self) -> None:
        if self._next_check_deadline is None:
            return
        remaining = max(0, int(self._next_check_deadline - time.monotonic() + 0.999))
        minutes, seconds = divmod(remaining, 60)
        self.next_check.setText(f"Next check: {minutes:02d}:{seconds:02d}")
        if remaining == 0:
            self.check_now_button.setEnabled(False)

    def _check_now(self) -> None:
        if not self.coordinator.check_now():
            return
        self._next_check_deadline = None
        self.next_check.setText("Next check: checking…")
        self.check_now_button.setEnabled(False)

    def _enabled_changed(self, connection_id: str, enabled: bool) -> None:
        if self._updating_table:
            return
        try:
            self.coordinator.set_enabled(connection_id, enabled)
        except (OSError, RuntimeError, ValueError) as error:
            QMessageBox.critical(self, "Monitor", str(error))
            self._reload_table()
            return
        self._sync_master_enabled_state(self.coordinator.snapshots())

    def _sync_master_enabled_state(
        self,
        snapshots: tuple[ConnectionSnapshot, ...] | list[ConnectionSnapshot],
    ) -> None:
        checkbox = self.master_enabled_checkbox
        checkbox.blockSignals(True)
        checkbox.setEnabled(bool(snapshots))
        enabled_count = sum(snapshot.connection.enabled for snapshot in snapshots)
        if not snapshots or enabled_count == 0:
            state = Qt.CheckState.Unchecked
        elif enabled_count == len(snapshots):
            state = Qt.CheckState.Checked
        else:
            state = Qt.CheckState.PartiallyChecked
        checkbox.setCheckState(state)
        checkbox.blockSignals(False)

    def _master_enabled_changed(self, enabled: bool) -> None:
        if self._updating_table:
            return
        try:
            for snapshot in self.coordinator.snapshots():
                if snapshot.connection.enabled != enabled:
                    self.coordinator.set_enabled(
                        snapshot.connection.connection_id,
                        enabled,
                    )
        except (OSError, RuntimeError, ValueError) as error:
            QMessageBox.critical(self, "Monitor", str(error))
        self._reload_table()

    def _add(self) -> None:
        filename, _selected_filter = QFileDialog.getOpenFileName(
            self,
            "Import VPN connections",
            "",
            "Connection files (*.txt *.yaml *.yml);;All files (*)",
        )
        if not filename:
            return
        self._import_file(filename)

    def _import_file(self, filename: str) -> None:
        try:
            summary = self.coordinator.import_file(Path(filename))
        except (OSError, ImportFileError) as error:
            QMessageBox.critical(self, "Import failed", str(error))
            return
        self._reload_table()
        QMessageBox.information(
            self,
            "Import complete",
            f"Imported: {summary.imported}\nDuplicates: {summary.duplicate}\n"
            f"Invalid: {summary.invalid}\nUnsupported: {summary.unsupported}",
        )

    def _delete_connection(self, connection_id: str) -> None:
        answer = QMessageBox.question(
            self,
            "Delete connection",
            "Delete this connection? This action cannot be undone.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        self.coordinator.delete(connection_id)
        self._reload_table()

    def _settings(self) -> None:
        if self._settings_thread is not None and self._settings_thread.isRunning():
            return
        dialog = SettingsDialog(
            self.coordinator.settings,
            get_theme(self.theme_key).colors,
            self,
        )
        if dialog.exec() != dialog.DialogCode.Accepted:
            return
        self.setEnabled(False)
        worker = _SettingsThread(self.coordinator, dialog.settings)
        self._settings_thread = worker
        worker.completed.connect(self._settings_completed)
        worker.start()

    def _settings_completed(self, saved: bool, message: str) -> None:
        self.setEnabled(True)
        if not saved:
            if self.coordinator.settings_recovery_error is not None:
                self._apply_cycle(False, None)
            QMessageBox.critical(self, "Settings", message)
        else:
            self.theme_key = get_theme(self.coordinator.settings.theme_key).key
            for key, action in self.theme_actions.items():
                action.setChecked(key == self.theme_key)
            self._apply_theme()
            self._reload_table()
            self._reload_log()
        if self._exit_after_settings:
            self._exit_after_settings = False
            self._exit()

    def _copy_log(self) -> None:
        QApplication.clipboard().setText(self.log.toPlainText())

    def _clear_log(self) -> None:
        records = self.coordinator.operation_log.read_recent(200)
        self._log_clear_marker = dict(records[-1]) if records else None
        self.log.clear()

    def _reload_log(self) -> None:
        records = self.coordinator.operation_log.read_recent(200)
        if self._log_clear_marker is not None:
            marker_index = next(
                (
                    index
                    for index in range(len(records) - 1, -1, -1)
                    if records[index] == self._log_clear_marker
                ),
                None,
            )
            if marker_index is not None:
                records = records[marker_index + 1 :]
        lines = [self._format_log_record(record) for record in records]
        self.log.setPlainText("\n".join(lines))
        scrollbar = self.log.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())

    @staticmethod
    def _format_log_record(record: dict[str, object]) -> str:
        header = f"{record.get('timestamp', '')}  {record.get('event', '')}"
        if record.get("event") == OperationLogInformationOutput.EVENT:
            message = record.get("message")
            if isinstance(message, str):
                return f"{header}\n{message}"
        fields = " ".join(
            f"{key}={value}" for key, value in record.items() if key not in {"timestamp", "event"}
        )
        return f"{header}  {fields}"

    def _show_from_tray(self) -> None:
        self.showNormal()
        self.raise_()
        self.activateWindow()

    def _exit(self) -> None:
        if self._settings_thread is not None and self._settings_thread.isRunning():
            self._exit_after_settings = True
            return
        if self._shutdown_thread is not None and self._shutdown_thread.isRunning():
            return
        self.setEnabled(False)
        worker = _ShutdownThread(self.coordinator)
        self._shutdown_thread = worker
        worker.completed.connect(self._shutdown_completed)
        worker.start()

    def _shutdown_completed(self, stopped: bool) -> None:
        if not stopped:
            self.setEnabled(True)
            QMessageBox.critical(self, "Monitor", "Current Mihomo check did not stop in time.")
            return
        self._save_window_geometry()
        self._allow_close = True
        self.tray.hide()
        QApplication.instance().quit()

    def closeEvent(self, event: QCloseEvent) -> None:
        if self._allow_close:
            event.accept()
            return
        if self._settings_thread is None or not self._settings_thread.isRunning():
            self._save_window_geometry()
        event.ignore()
        self.hide()
