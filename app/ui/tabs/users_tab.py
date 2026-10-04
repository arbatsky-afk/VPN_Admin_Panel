"""Users tab presentation without SSH-session lifecycle logic."""

from __future__ import annotations

from PySide6.QtCore import QEvent, QSize, Qt, Signal
from PySide6.QtWidgets import (
    QAbstractItemView,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QTableWidget,
    QTableWidgetItem,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

from common.ui.icon_assets import action_icon
from common.ui.icon_button import IconActionButton

USERS_ROW_ACTION_COLUMN_WIDTH = 56


class UsersTab(QWidget):
    """Display Users data and report the user's requested action."""

    add_requested = Signal()
    add_protocols_requested = Signal()
    save_links_requested = Signal()
    delete_requested = Signal(str)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("actionTabPage")
        self._controls_enabled = False
        self._operation_controls_enabled = True
        self._editing_enabled = True
        self._available_create_protocols: frozenset[str] = frozenset()
        self._delete_buttons: list[QToolButton] = []
        self._delete_icon_color = "#000000"
        self._action_icon_color = "#000000"
        self.status_label = QLabel()
        self.status_label.setObjectName("usersStatus")
        self.status_label.setWordWrap(True)
        self.table = QTableWidget(0, 3)
        self.table.setObjectName("usersTable")
        self.table.horizontalHeader().setObjectName("usersTableHeader")
        self.table.setHorizontalHeaderLabels(("Name", "Protocols", "Actions"))
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        self.table.setMinimumHeight(208)
        self.table.verticalHeader().setVisible(False)
        self.table.horizontalHeader().setFixedHeight(40)
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Fixed)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Fixed)
        self.table.setColumnWidth(0, 150)
        self.table.setColumnWidth(2, USERS_ROW_ACTION_COLUMN_WIDTH)
        self.status_label.setParent(self.table.viewport())
        self.status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.status_label.setGeometry(self.table.viewport().rect())
        self.table.viewport().installEventFilter(self)
        self.add_button = IconActionButton("Add user")
        self.add_button.clicked.connect(self.add_requested)
        self.add_protocols_button = IconActionButton("Add protocols")
        self.add_protocols_button.clicked.connect(self.add_protocols_requested)
        self.save_links_button = IconActionButton("Save user links")
        self.save_links_button.clicked.connect(self.save_links_requested)
        self.table.itemSelectionChanged.connect(self._update_controls)
        self.set_action_icons(self._action_icon_color)
        tab_layout = QVBoxLayout(self)
        tab_layout.setContentsMargins(12, 12, 12, 12)
        tab_layout.setSpacing(8)
        content_layout = QHBoxLayout()
        content_layout.setContentsMargins(0, 0, 0, 0)
        content_layout.setSpacing(16)
        content_layout.addWidget(self.table, 1)
        actions_layout = QVBoxLayout()
        actions_layout.setContentsMargins(0, 0, 0, 0)
        actions_layout.setSpacing(8)
        actions_layout.addSpacing(self.table.horizontalHeader().height())
        actions_layout.addWidget(self.add_button)
        actions_layout.addWidget(self.add_protocols_button)
        actions_layout.addWidget(self.save_links_button)
        actions_layout.addStretch()
        content_layout.addLayout(actions_layout)
        tab_layout.addLayout(content_layout, 1)
        self.set_controls_enabled(False)

    def set_users(self, users: list[dict[str, object]]) -> None:
        """Render validated Users helper records."""
        self._clear_rows()
        for user in users:
            row = self.table.rowCount()
            self.table.insertRow(row)
            user_name = str(user["name"])
            protocols = " + ".join(
                name
                for name, enabled in (
                    ("Xray", user["xray"]),
                    ("Hysteria", user["hysteria"]),
                    ("Mieru", user["mieru"]),
                )
                if enabled
            )
            name_item = QTableWidgetItem(user_name)
            name_item.setData(
                Qt.ItemDataRole.UserRole,
                tuple(
                    protocol
                    for protocol, enabled in (
                        ("xray", user["xray"]),
                        ("hysteria2", user["hysteria"]),
                        ("mieru", user["mieru"]),
                    )
                    if enabled
                ),
            )
            self.table.setItem(row, 0, name_item)
            self.table.setItem(row, 1, QTableWidgetItem(f"● {protocols}"))
            action_cell = QWidget()
            action_layout = QHBoxLayout(action_cell)
            action_layout.setContentsMargins(4, 2, 4, 2)
            action_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
            delete_button = QToolButton(action_cell)
            delete_button.setObjectName("usersRowAction")
            delete_button.setToolTip("Delete user")
            delete_button.setAccessibleName("Delete user")
            delete_button.setFixedSize(28, 28)
            delete_button.setIconSize(QSize(16, 16))
            delete_button.setIcon(action_icon("trash-2", self._delete_icon_color))
            delete_button.clicked.connect(
                lambda _checked=False, name=user_name: self.delete_requested.emit(name)
            )
            action_layout.addWidget(delete_button)
            self._delete_buttons.append(delete_button)
            self.table.setCellWidget(row, 2, action_cell)
        self._update_controls()

    def clear(self) -> None:
        """Immediately remove stale rows and block all actions."""
        self.table.clearSelection()
        self._clear_rows()
        self.set_controls_enabled(False)

    def _clear_rows(self) -> None:
        for button in self._delete_buttons:
            button.clicked.disconnect()
        self.table.setRowCount(0)
        self._delete_buttons.clear()

    def set_controls_enabled(self, enabled: bool) -> None:
        self._controls_enabled = enabled
        self._update_controls()

    def set_editing_enabled(self, enabled: bool) -> None:
        self._editing_enabled = enabled
        self._update_controls()

    def set_operation_controls_enabled(self, enabled: bool) -> None:
        self._operation_controls_enabled = enabled
        self._update_controls()

    def set_available_create_protocols(self, protocols: tuple[str, ...]) -> None:
        self._available_create_protocols = frozenset(protocols)
        self._update_controls()

    def set_delete_icon(self, color: str) -> None:
        """Apply the active theme colour to current and future row actions."""
        self._delete_icon_color = color
        for button in self._delete_buttons:
            button.setIcon(action_icon("trash-2", color))

    def set_action_icons(self, color: str) -> None:
        """Apply the active theme colour to the Users actions."""
        self._action_icon_color = color
        self.add_button.setIcon(action_icon("user-plus", color))
        self.add_protocols_button.setIcon(action_icon("network", color))
        self.save_links_button.setIcon(action_icon("save", color))

    def _update_controls(self) -> None:
        self.table.setEnabled(self._controls_enabled)
        actions_enabled = self._controls_enabled and self._operation_controls_enabled
        mutations_enabled = actions_enabled and self._editing_enabled
        self.add_button.setEnabled(mutations_enabled)
        selected_protocols = self.selected_protocols()
        self.add_protocols_button.setEnabled(
            mutations_enabled
            and selected_protocols is not None
            and bool(self._available_create_protocols - selected_protocols)
        )
        self.save_links_button.setEnabled(actions_enabled)
        for button in self._delete_buttons:
            button.setEnabled(mutations_enabled)

    def set_status(self, state: str, message: str) -> None:
        visible = state in {"connecting", "loading", "error"} or message.startswith(
            "Server address changed."
        )
        self.status_label.setProperty("state", state)
        self.status_label.setText(
            "Loading…" if state in {"connecting", "loading"} else (message if visible else "")
        )
        self.status_label.setVisible(visible)
        style = self.status_label.style()
        style.unpolish(self.status_label)
        style.polish(self.status_label)
        self.status_label.update()

    def eventFilter(self, watched, event) -> bool:
        if watched is self.table.viewport() and event.type() == QEvent.Type.Resize:
            self.status_label.setGeometry(self.table.viewport().rect())
        return super().eventFilter(watched, event)

    def selected_user(self) -> str | None:
        selected_rows = self.table.selectionModel().selectedRows()
        if not selected_rows:
            return None
        item = self.table.item(selected_rows[0].row(), 0)
        return item.text() if item else None

    def selected_protocols(self) -> frozenset[str] | None:
        selected_rows = self.table.selectionModel().selectedRows()
        if not selected_rows:
            return None
        item = self.table.item(selected_rows[0].row(), 0)
        protocols = item.data(Qt.ItemDataRole.UserRole) if item else None
        return frozenset(protocols) if isinstance(protocols, tuple) else None

    def focus_table(self) -> None:
        self.table.setFocus()
