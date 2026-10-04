"""Backup and Restore tab presentation."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path

from PySide6.QtCore import QSize, Qt, Signal
from PySide6.QtWidgets import (
    QAbstractItemView,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QMenu,
    QTableWidget,
    QTableWidgetItem,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

from app.services.backup import LocalBackupArchive
from common.ui.icon_assets import action_icon
from common.ui.icon_button import IconActionButton

BACKUP_ROW_ACTION_COLUMN_WIDTH = 56


class _ArchiveHeader(QHeaderView):
    """Keep archive filtering inside the Server IP table header."""

    filter_changed = Signal(str)
    _FILTER_SECTION = 1

    def __init__(
        self,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(Qt.Orientation.Horizontal, parent)
        self._selected_source_ip = ""
        self._options: tuple[tuple[str, str], ...] = ()
        self.filter_button = QToolButton(self.viewport())
        self.filter_button.setObjectName("headerFilterButton")
        self.filter_button.setText("▾")
        self.filter_button.setToolTip("Filter Server IP: All IP addresses")
        self.filter_button.setAutoRaise(True)
        self.filter_button.setPopupMode(QToolButton.ToolButtonPopupMode.InstantPopup)
        self.filter_menu = QMenu(self.filter_button)
        self.filter_button.setMenu(self.filter_menu)
        self.sectionResized.connect(lambda *_args: self._position_header_controls())
        self.sectionMoved.connect(lambda *_args: self._position_header_controls())
        self.geometriesChanged.connect(self._position_header_controls)
        self._rebuild_menu()

    @property
    def selected_source_ip(self) -> str:
        return self._selected_source_ip

    def set_options(
        self,
        options: tuple[tuple[str, str], ...],
        selected_source_ip: str,
    ) -> None:
        self._options = options
        available = {server_ip for server_ip, _label in options}
        self._selected_source_ip = selected_source_ip if selected_source_ip in available else ""
        self._rebuild_menu()

    def _select(self, server_ip: str) -> None:
        if server_ip == self._selected_source_ip:
            return
        self._selected_source_ip = server_ip
        self._rebuild_menu()
        self.filter_changed.emit(server_ip)

    def _rebuild_menu(self) -> None:
        self.filter_menu.clear()
        for server_ip, label in (("", "All IP addresses"), *self._options):
            action = self.filter_menu.addAction(label)
            action.setData(server_ip)
            action.setCheckable(True)
            action.setChecked(server_ip == self._selected_source_ip)
            action.triggered.connect(lambda _checked=False, value=server_ip: self._select(value))
        selected_label = next(
            (label for server_ip, label in self._options if server_ip == self._selected_source_ip),
            "All IP addresses",
        )
        self.filter_button.setToolTip(f"Filter Server IP: {selected_label}")

    def _position_header_controls(self) -> None:
        if self.count() <= self._FILTER_SECTION:
            self.filter_button.hide()
            return
        button_size = 24
        section_right = self.sectionViewportPosition(self._FILTER_SECTION) + self.sectionSize(
            self._FILTER_SECTION
        )
        self.filter_button.setGeometry(
            section_right - button_size - 2,
            max(0, (self.height() - button_size) // 2),
            button_size,
            button_size,
        )
        self.filter_button.show()

    def resizeEvent(self, event) -> None:
        super().resizeEvent(event)
        self._position_header_controls()


class BackupRestoreTab(QWidget):
    """Display local archives and emit the user's requested backup action."""

    backup_requested = Signal()
    refresh_requested = Signal()
    restore_requested = Signal(object)
    delete_requested = Signal(object)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("actionTabPage")
        self._archives: tuple[LocalBackupArchive, ...] = ()
        self._server_aliases: dict[str, str] = {}
        self._operation_controls_enabled = True
        self._editing_enabled = True
        self._delete_buttons: list[QToolButton] = []
        self._delete_icon_color = "#000000"
        self._backup_icon_color = "#000000"
        self._restore_icon_color = "#000000"

        tab_layout = QVBoxLayout(self)
        tab_layout.setContentsMargins(12, 12, 12, 12)
        tab_layout.setSpacing(8)

        content_spacing = 16
        self.backup_button = IconActionButton("Create backup")
        self.backup_button.clicked.connect(self.backup_requested)
        self.restore_button = IconActionButton("Restore selected backup")
        self.restore_button.clicked.connect(self._request_restore)
        self.set_action_icons(
            self._backup_icon_color,
            self._restore_icon_color,
        )

        self.refresh_button = QToolButton()
        self.refresh_button.setObjectName("iconAction")
        self.refresh_button.setToolTip("Refresh archives")
        self.refresh_button.setFixedSize(32, 32)
        self.refresh_button.clicked.connect(self.refresh_requested)

        self.status_label = QLabel()
        self.status_label.setObjectName("managementStatus")
        self.status_label.setVisible(False)
        self.table = QTableWidget(0, 5)
        self.table.setObjectName("backupTable")
        self.source_ip_header = _ArchiveHeader(self.table)
        self.source_ip_header.setObjectName("backupTableHeader")
        self.table.setHorizontalHeader(self.source_ip_header)
        self.table.setHorizontalHeaderLabels(
            ["Created", "Server IP", "Comment / alias", "Size", "Actions"]
        )
        self.table.verticalHeader().setVisible(False)
        self.table.horizontalHeader().setFixedHeight(40)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setColumnWidth(0, 180)
        self.table.setColumnWidth(1, 140)
        self.table.setColumnWidth(2, 180)
        self.source_ip_header.setSectionResizeMode(0, QHeaderView.ResizeMode.Fixed)
        self.source_ip_header.setSectionResizeMode(1, QHeaderView.ResizeMode.Fixed)
        self.source_ip_header.setSectionResizeMode(2, QHeaderView.ResizeMode.Fixed)
        self.source_ip_header.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self.source_ip_header.setSectionResizeMode(4, QHeaderView.ResizeMode.Fixed)
        self.table.setColumnWidth(4, BACKUP_ROW_ACTION_COLUMN_WIDTH)
        self.table.itemSelectionChanged.connect(self._update_action_buttons)
        self.source_ip_header.filter_changed.connect(self._apply_filter)

        content_layout = QHBoxLayout()
        content_layout.setSpacing(content_spacing)
        content_layout.addWidget(self.table, 1)
        actions_layout = QVBoxLayout()
        actions_layout.setContentsMargins(0, 0, 0, 0)
        actions_layout.setSpacing(0)
        actions_layout.addSpacing(4)
        actions_layout.addWidget(self.refresh_button)
        actions_layout.addSpacing(4)
        actions_layout.addWidget(self.backup_button)
        actions_layout.addSpacing(8)
        actions_layout.addWidget(self.restore_button)
        actions_layout.addStretch()
        content_layout.addLayout(actions_layout)
        tab_layout.addWidget(self.status_label)
        tab_layout.addLayout(content_layout, 1)
        self._update_action_buttons()

    def set_archives(
        self,
        archives: tuple[LocalBackupArchive, ...],
        server_aliases: Mapping[str, str] | None = None,
    ) -> None:
        """Replace the displayed archive list while retaining the current IP filter."""
        self._archives = archives
        self._server_aliases = {
            server_ip: alias.strip()
            for server_ip, alias in (server_aliases or {}).items()
            if alias.strip()
        }
        previous_filter = self.source_ip_header.selected_source_ip
        available_ips = sorted(
            {archive.source_server_ip for archive in self._archives},
            key=lambda server_ip: tuple(int(octet) for octet in server_ip.split(".")),
        )
        filter_options: list[tuple[str, str]] = []
        for server_ip in available_ips:
            alias = self._server_aliases.get(server_ip, "")
            label = f"{server_ip} — {alias}" if alias else server_ip
            filter_options.append((server_ip, label))
        self.source_ip_header.set_options(tuple(filter_options), previous_filter)
        self._apply_filter()

    def show_list_error(self, message: str) -> None:
        """Clear stale data when the local archive service cannot provide a list."""
        self._archives = ()
        self.source_ip_header.set_options((), "")
        self._clear_archive_rows()
        self.status_label.setText(message)
        self.status_label.setVisible(True)
        self._update_action_buttons()

    def selected_archive(self) -> LocalBackupArchive | None:
        """Return the currently selected archive, if it is part of the active list."""
        selected_rows = self.table.selectionModel().selectedRows()
        if not selected_rows:
            return None
        item = self.table.item(selected_rows[0].row(), 0)
        archive_path = Path(str(item.data(Qt.ItemDataRole.UserRole))) if item is not None else None
        if archive_path is None:
            return None
        return next((archive for archive in self._archives if archive.path == archive_path), None)

    def set_operation_controls_enabled(self, enabled: bool) -> None:
        """Apply the global operation gate without enabling selection-only actions."""
        self._operation_controls_enabled = enabled
        self.backup_button.setEnabled(enabled)
        self.refresh_button.setEnabled(enabled)
        self.source_ip_header.filter_button.setEnabled(enabled)
        self.table.setEnabled(enabled)
        self._update_action_buttons()

    def set_editing_enabled(self, enabled: bool) -> None:
        self._editing_enabled = enabled
        self.backup_button.setEnabled(self._operation_controls_enabled)
        self._update_action_buttons()

    def set_refresh_icon(self, color: str) -> None:
        """Apply the active theme colour to the local Refresh control."""
        self.refresh_button.setIcon(action_icon("refresh-cw", color))

    def set_action_icons(self, backup_color: str, restore_color: str) -> None:
        """Apply active theme colours to Backup and Restore actions."""
        self._backup_icon_color = backup_color
        self._restore_icon_color = restore_color
        self.backup_button.setIcon(action_icon("archive", backup_color))
        self.restore_button.setIcon(action_icon("archive-restore", restore_color))

    def set_delete_icon(self, color: str) -> None:
        """Apply the active theme colour to current and future row actions."""
        self._delete_icon_color = color
        for button in self._delete_buttons:
            button.setIcon(action_icon("trash-2", color))

    def _apply_filter(self, _server_ip: str | None = None) -> None:
        selected_server_ip = self.source_ip_header.selected_source_ip
        archives = tuple(
            archive
            for archive in self._archives
            if not selected_server_ip or archive.source_server_ip == selected_server_ip
        )
        self._clear_archive_rows()
        self.table.setRowCount(len(archives))
        for row, archive in enumerate(archives):
            created_item = QTableWidgetItem(archive.created_at.strftime("%Y-%m-%d %H:%M:%S"))
            created_item.setData(Qt.ItemDataRole.UserRole, str(archive.path))
            self.table.setItem(row, 0, created_item)
            self.table.setItem(row, 1, QTableWidgetItem(archive.source_server_ip))
            self.table.setItem(
                row,
                2,
                QTableWidgetItem(self._server_aliases.get(archive.source_server_ip, "")),
            )
            self.table.setItem(
                row, 3, QTableWidgetItem(self._format_archive_size(archive.size_bytes))
            )
            action_cell = QWidget()
            action_layout = QHBoxLayout(action_cell)
            action_layout.setContentsMargins(4, 2, 4, 2)
            action_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
            delete_button = QToolButton(action_cell)
            delete_button.setObjectName("backupRowAction")
            delete_button.setToolTip("Delete Backup archive")
            delete_button.setAccessibleName("Delete Backup archive")
            delete_button.setFixedSize(28, 28)
            delete_button.setIconSize(QSize(16, 16))
            delete_button.setIcon(action_icon("trash-2", self._delete_icon_color))
            delete_button.clicked.connect(
                lambda _checked=False, current=archive: self.delete_requested.emit(current)
            )
            action_layout.addWidget(delete_button)
            self._delete_buttons.append(delete_button)
            self.table.setCellWidget(row, 4, action_cell)
        if not self._archives:
            self.status_label.setText("No local Backup archives found.")
            self.status_label.setVisible(True)
        elif not archives:
            self.status_label.setText("No Backup archives match the selected IP address.")
            self.status_label.setVisible(True)
        else:
            self.status_label.clear()
            self.status_label.setVisible(False)
        self._update_action_buttons()

    def _clear_archive_rows(self) -> None:
        for button in self._delete_buttons:
            button.clicked.disconnect()
        self.table.setRowCount(0)
        self._delete_buttons.clear()

    def _request_restore(self) -> None:
        archive = self.selected_archive()
        if archive is not None:
            self.restore_requested.emit(archive)

    def _update_action_buttons(self) -> None:
        restore_enabled = (
            self._operation_controls_enabled
            and self._editing_enabled
            and self.selected_archive() is not None
        )
        self.restore_button.setEnabled(restore_enabled)
        delete_enabled = self._operation_controls_enabled and self._editing_enabled
        for button in self._delete_buttons:
            button.setEnabled(delete_enabled)

    @staticmethod
    def _format_archive_size(size_bytes: int) -> str:
        if size_bytes < 1024:
            return f"{size_bytes} B"
        if size_bytes < 1024 * 1024:
            return f"{size_bytes / 1024:.1f} KiB"
        return f"{size_bytes / (1024 * 1024):.1f} MiB"
