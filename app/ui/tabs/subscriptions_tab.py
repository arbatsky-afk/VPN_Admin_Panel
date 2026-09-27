"""Subscriptions tab presentation without publication lifecycle logic."""

from __future__ import annotations

from PySide6.QtCore import QPointF, QSignalBlocker, QSize, Qt, Signal
from PySide6.QtGui import QColor, QPainter, QPaintEvent, QPen
from PySide6.QtWidgets import (
    QAbstractItemView,
    QCheckBox,
    QComboBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QSizePolicy,
    QStyle,
    QStyleOptionButton,
    QTableWidget,
    QTableWidgetItem,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

from app.services.subscriptions import (
    SubscriptionReconciliation,
    SubscriptionReconciliationItem,
)
from common.ui.icon_assets import action_icon
from common.ui.icon_button import IconActionButton

_TABLE_ROW_HEIGHT = 30
_SERVER_STATUS_ROW_HEIGHT = 20


def _contrasting_check_color(background: str) -> QColor:
    color = QColor(background)
    brightness = (color.red() * 299 + color.green() * 587 + color.blue() * 114) / 1000
    return QColor("#07111E" if brightness >= 150 else "#FFFFFF")


class _SubscriptionSourceCheckBox(QCheckBox):
    """Compact, high-contrast checkbox matching the Monitor table."""

    def __init__(self, checked_background: str, accessible_name: str) -> None:
        super().__init__()
        self.setObjectName("monitorEnabledCheck")
        self.setAccessibleName(accessible_name)
        self.set_checked_background(checked_background)

    def set_checked_background(self, background: str) -> None:
        self._check_color = _contrasting_check_color(background)
        self.update()

    def paintEvent(self, event: QPaintEvent) -> None:
        super().paintEvent(event)
        state = self.checkState()
        if state == Qt.CheckState.Unchecked:
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
        if state == Qt.CheckState.PartiallyChecked:
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


class _MasterSubscriptionCheckBox(_SubscriptionSourceCheckBox):
    def nextCheckState(self) -> None:
        target = (
            Qt.CheckState.Unchecked
            if self.checkState() == Qt.CheckState.Checked
            else Qt.CheckState.Checked
        )
        self.setCheckState(target)


class _SingleLineStatusLabel(QLabel):
    def minimumSizeHint(self) -> QSize:
        hint = super().minimumSizeHint()
        return QSize(0, hint.height())


class _SubscriptionSourcesHeader(QHeaderView):
    toggle_all_requested = Signal(bool)

    def __init__(self, checked_background: str, parent: QWidget) -> None:
        super().__init__(Qt.Orientation.Horizontal, parent)
        self.master_checkbox = _MasterSubscriptionCheckBox(
            checked_background,
            "Select all connection files",
        )
        self.master_checkbox.setParent(self.viewport())
        self.master_checkbox.setTristate(True)
        self.master_checkbox.stateChanged.connect(self._master_state_changed)
        self.sectionResized.connect(lambda *_: self._position_master_checkbox())
        self.geometriesChanged.connect(self._position_master_checkbox)

    def set_master_state(self, state: Qt.CheckState) -> None:
        blocker = QSignalBlocker(self.master_checkbox)
        self.master_checkbox.setCheckState(state)
        del blocker

    def set_checked_background(self, background: str) -> None:
        self.master_checkbox.set_checked_background(background)

    def resizeEvent(self, event) -> None:
        super().resizeEvent(event)
        self._position_master_checkbox()

    def _position_master_checkbox(self) -> None:
        size = self.master_checkbox.sizeHint()
        section_x = self.sectionViewportPosition(0)
        section_width = self.sectionSize(0)
        self.master_checkbox.setGeometry(
            section_x + max(0, (section_width - size.width()) // 2),
            max(0, (self.viewport().height() - size.height()) // 2),
            size.width(),
            size.height(),
        )
        self.master_checkbox.raise_()

    def _master_state_changed(self, state: int) -> None:
        check_state = Qt.CheckState(state)
        if check_state != Qt.CheckState.PartiallyChecked:
            self.toggle_all_requested.emit(check_state == Qt.CheckState.Checked)


class SubscriptionsTab(QWidget):
    """Select generated sources and display only the confirmed bearer URL."""

    make_requested = Signal()
    copy_requested = Signal()
    name_changed = Signal(str)
    refresh_server_requested = Signal()
    server_subscription_selected = Signal(object)
    delete_orphan_requested = Signal(object)
    delete_active_requested = Signal(object)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("actionTabPage")
        self._operation_controls_enabled = True
        self._editing_enabled = False
        self._files_by_name: dict[str, tuple[str, ...]] = {}
        self._updating_sources = False
        self._updating_server_selection = False
        self._checked_background = "#78DF69"
        self._server_view: SubscriptionReconciliation | None = None
        self._server_items: tuple[SubscriptionReconciliationItem, ...] = ()
        self._server_ready = False
        self._server_action_buttons: list[QToolButton] = []
        self._publish_icon_color = "#000000"
        self._server_action_icon_colors = {
            "Delete orphan": "#F0B43B",
            "Delete active": "#FF8798",
        }

        self.server_status = _SingleLineStatusLabel(
            "Open Subscriptions to inspect the selected server."
        )
        self.server_status.setObjectName("subscriptionServerStatus")
        self.server_status.setWordWrap(False)
        self.server_status.setAlignment(
            Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter
        )

        server_status_row = QWidget()
        server_status_row.setObjectName("subscriptionServerStatusRow")
        server_status_row.setFixedHeight(_SERVER_STATUS_ROW_HEIGHT)
        server_status_layout = QHBoxLayout(server_status_row)
        server_status_layout.setContentsMargins(0, 0, 0, 0)
        server_status_layout.setSpacing(5)
        server_status_layout.addStretch(1)
        server_status_layout.addWidget(self.server_status)

        self.refresh_server_button = QToolButton()
        self.refresh_server_button.setObjectName("iconAction")
        self.refresh_server_button.setToolTip("Refresh published subscriptions")
        self.refresh_server_button.setAccessibleName("Refresh published subscriptions")
        self.refresh_server_button.setFixedSize(32, 32)
        self.refresh_server_button.setIconSize(QSize(18, 18))
        self.refresh_server_button.clicked.connect(self.refresh_server_requested)

        self.server_table = QTableWidget(0, 3)
        self.server_table.setObjectName("publishedSubscriptions")
        self.server_table.setHorizontalHeaderLabels(("Name", "Status", "Actions"))
        self.server_table.horizontalHeaderItem(0).setTextAlignment(
            Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter
        )
        server_vertical_header = self.server_table.verticalHeader()
        server_vertical_header.setVisible(False)
        server_vertical_header.setSectionResizeMode(QHeaderView.ResizeMode.Fixed)
        server_vertical_header.setDefaultSectionSize(_TABLE_ROW_HEIGHT)
        self.server_table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.server_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.server_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.server_table.setAlternatingRowColors(True)
        self.server_table.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.server_table.setMinimumHeight(72)
        self.server_table.horizontalHeader().setSectionResizeMode(
            0, QHeaderView.ResizeMode.Stretch
        )
        self.server_table.horizontalHeader().setSectionResizeMode(
            1, QHeaderView.ResizeMode.ResizeToContents
        )
        self.server_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Fixed)
        self.server_table.setColumnWidth(2, 72)
        self.server_table.itemSelectionChanged.connect(self._server_selection_changed)

        server_header = QWidget()
        server_header.setObjectName("publishedSubscriptionsHeader")
        server_header.setFixedHeight(38)
        server_header_layout = QHBoxLayout(server_header)
        server_header_layout.setContentsMargins(0, 0, 0, 0)
        server_header_layout.setSpacing(8)
        server_header_layout.addStretch(1)
        self.server_title = QLabel("Published")
        self.server_title.setObjectName("publishedSubscriptionsTitle")
        self.server_title.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        server_header_layout.addWidget(self.server_title)
        server_header_layout.addWidget(self.refresh_server_button)

        server_row = QWidget()
        server_row.setObjectName("publishedSubscriptionsRow")
        server_row_layout = QVBoxLayout(server_row)
        server_row_layout.setContentsMargins(0, 0, 0, 0)
        server_row_layout.setSpacing(8)
        server_row_layout.addWidget(server_header)
        server_row_layout.addWidget(self.server_table, 1)

        self.name_input = QComboBox()
        self.name_input.setObjectName("subscriptionName")
        self.name_input.setPlaceholderText("Select a name")
        self.name_input.setSizeAdjustPolicy(
            QComboBox.SizeAdjustPolicy.AdjustToMinimumContentsLengthWithIcon
        )
        self.name_input.setMinimumContentsLength(4)
        self.name_input.setFixedWidth(210)
        self.name_input.currentTextChanged.connect(self._name_selected)

        self.make_button = IconActionButton("Publish selected")
        self.make_button.setIcon(action_icon("upload", self._publish_icon_color))
        self.make_button.clicked.connect(self.make_requested)

        self.sources_table = QTableWidget(0, 2)
        self.sources_table.setObjectName("subscriptionSources")
        self._sources_header = _SubscriptionSourcesHeader(
            self._checked_background,
            self.sources_table,
        )
        self._sources_header.setObjectName("subscriptionSourcesHeader")
        self.sources_table.setHorizontalHeader(self._sources_header)
        self.sources_table.setHorizontalHeaderLabels(("", "Connection file"))
        sources_vertical_header = self.sources_table.verticalHeader()
        sources_vertical_header.setVisible(False)
        sources_vertical_header.setSectionResizeMode(QHeaderView.ResizeMode.Fixed)
        sources_vertical_header.setDefaultSectionSize(_TABLE_ROW_HEIGHT)
        self.sources_table.setSelectionMode(QAbstractItemView.SelectionMode.NoSelection)
        self.sources_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.sources_table.setAlternatingRowColors(True)
        self.sources_table.setMinimumHeight(72)
        self.sources_table.setSizePolicy(
            QSizePolicy.Policy.Expanding,
            QSizePolicy.Policy.Expanding,
        )
        header = self._sources_header
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Fixed)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.sources_table.setColumnWidth(0, 38)
        header.toggle_all_requested.connect(self._set_all_sources_checked)

        self.url_input = QLineEdit()
        self.url_input.setObjectName("subscriptionUrl")
        self.url_input.setReadOnly(True)
        self.url_input.setPlaceholderText("A confirmed subscription URL will appear here")

        self.copy_button = QToolButton()
        self.copy_button.setObjectName("iconAction")
        self.copy_button.setToolTip("Copy subscription URL")
        self.copy_button.setAccessibleName("Copy subscription URL")
        self.copy_button.setFixedSize(32, 32)
        self.copy_button.setIconSize(QSize(18, 18))
        self.copy_button.clicked.connect(self.copy_requested)

        url_row = QWidget()
        url_layout = QHBoxLayout(url_row)
        url_layout.setContentsMargins(0, 0, 0, 0)
        url_layout.setSpacing(10)
        url_layout.addWidget(self.url_input, 1)
        url_layout.addWidget(self.copy_button)

        publication_header = QWidget()
        publication_header.setObjectName("subscriptionPublicationHeader")
        publication_header.setFixedHeight(38)
        publication_header_layout = QHBoxLayout(publication_header)
        publication_header_layout.setContentsMargins(0, 0, 0, 0)
        publication_header_layout.setSpacing(8)
        name_label = QLabel("Name")
        name_label.setObjectName("subscriptionNameLabel")
        publication_header_layout.addWidget(name_label)
        publication_header_layout.addWidget(self.name_input)
        publication_header_layout.addWidget(self.make_button)
        publication_header_layout.addStretch(1)

        publication_row = QWidget()
        publication_row.setObjectName("subscriptionPublicationRow")
        publication_row_layout = QVBoxLayout(publication_row)
        publication_row_layout.setContentsMargins(0, 0, 0, 0)
        publication_row_layout.setSpacing(8)
        publication_row_layout.addWidget(publication_header)
        publication_row_layout.addWidget(self.sources_table, 1)

        url_section = QWidget()
        url_section.setObjectName("subscriptionUrlSection")
        url_section.setFixedHeight(34)
        url_section_layout = QHBoxLayout(url_section)
        url_section_layout.setContentsMargins(0, 0, 0, 0)
        url_section_layout.setSpacing(14)
        url_label = QLabel("Subscription URL")
        url_label.setObjectName("subscriptionUrlLabel")
        url_section_layout.addWidget(url_label)
        url_section_layout.addWidget(url_row, 1)

        publication_column = QWidget()
        publication_column.setObjectName("subscriptionPublicationColumn")
        publication_column_layout = QVBoxLayout(publication_column)
        publication_column_layout.setContentsMargins(0, 0, 0, 0)
        publication_column_layout.setSpacing(4)
        self.publication_header_spacer = QWidget()
        self.publication_header_spacer.setObjectName("subscriptionPublicationHeaderSpacer")
        self.publication_header_spacer.setFixedHeight(_SERVER_STATUS_ROW_HEIGHT)
        publication_column_layout.addWidget(self.publication_header_spacer)
        publication_column_layout.addWidget(publication_row, 1)

        server_column = QWidget()
        server_column.setObjectName("publishedSubscriptionsColumn")
        server_column_layout = QVBoxLayout(server_column)
        server_column_layout.setContentsMargins(0, 0, 0, 0)
        server_column_layout.setSpacing(4)
        server_column_layout.addWidget(server_status_row)
        server_column_layout.addWidget(server_row, 1)

        workspace = QWidget()
        workspace.setObjectName("subscriptionsWorkspace")
        workspace_layout = QHBoxLayout(workspace)
        workspace_layout.setContentsMargins(0, 0, 0, 0)
        workspace_layout.setSpacing(10)
        workspace_layout.addWidget(publication_column, 1)
        workspace_layout.addWidget(server_column, 1)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 18, 12, 12)
        layout.setSpacing(12)
        layout.addWidget(workspace, 1)
        layout.addWidget(url_section)
        self._update_controls()

    @property
    def name(self) -> str:
        return self.name_input.currentText().strip()

    @property
    def selected_source_filenames(self) -> tuple[str, ...]:
        selected: list[str] = []
        for row in range(self.sources_table.rowCount()):
            checkbox = self._source_checkbox(row)
            filename = self.sources_table.item(row, 1)
            if checkbox is not None and filename is not None and checkbox.isChecked():
                selected.append(filename.text())
        return tuple(selected)

    @property
    def url(self) -> str:
        return self.url_input.text()

    def set_operation_controls_enabled(self, enabled: bool) -> None:
        self._operation_controls_enabled = enabled
        self._update_controls()

    def set_editing_enabled(self, enabled: bool) -> None:
        self._editing_enabled = enabled
        self._update_controls()

    def set_url(self, url: str) -> None:
        self.url_input.setText(url)
        self.url_input.setCursorPosition(0)
        self.copy_button.setEnabled(bool(url))

    def clear_url(self) -> None:
        self.set_url("")

    def set_server_status(self, state: str, message: str) -> None:
        self.server_status.setProperty("state", state)
        self.server_status.setText(message)
        self.server_status.setToolTip(message)
        self._server_ready = state == "ready"
        self.server_status.style().unpolish(self.server_status)
        self.server_status.style().polish(self.server_status)
        self._update_controls()

    def set_server_ip(self, server_ip: str) -> None:
        server_ip = server_ip.strip()
        self.server_title.setText(f"Published on {server_ip}" if server_ip else "Published")

    def set_server_subscriptions(self, view: SubscriptionReconciliation) -> None:
        self._server_view = view
        self._server_items = view.items
        self._server_action_buttons.clear()
        self.server_table.setRowCount(0)
        labels = {
            "active": "Active",
            "missing": "Missing",
            "orphan": "Orphan",
            "active_orphan": "Active + orphan",
            "missing_orphan": "Missing + orphan",
            "deleting": "Deleting",
            "republish_required": "Republish required",
        }
        for item in view.items:
            row = self.server_table.rowCount()
            self.server_table.insertRow(row)
            name_item = QTableWidgetItem(item.name)
            status_item = QTableWidgetItem(labels[item.status])
            name_item.setFlags(Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable)
            status_item.setFlags(Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable)
            self.server_table.setItem(row, 0, name_item)
            self.server_table.setItem(row, 1, status_item)
            self._set_server_actions(row, item)
        self._update_controls()

    def clear_server_subscriptions(self) -> None:
        self._server_view = None
        self._server_items = ()
        self._server_ready = False
        self._server_action_buttons.clear()
        self.server_table.setRowCount(0)
        self._update_controls()

    def set_copy_icon(self, color: str) -> None:
        self.copy_button.setIcon(action_icon("copy", color))

    def set_refresh_icon(self, color: str) -> None:
        self.refresh_server_button.setIcon(action_icon("refresh-cw", color))

    def set_publish_icon(self, color: str) -> None:
        self._publish_icon_color = color
        self.make_button.setIcon(action_icon("upload", color))

    def set_server_action_icons(self, orphan_color: str, active_color: str) -> None:
        self._server_action_icon_colors = {
            "Delete orphan": orphan_color,
            "Delete active": active_color,
        }
        for button in self._server_action_buttons:
            self._set_server_action_icon(button)

    def set_checkbox_color(self, color: str) -> None:
        self._checked_background = color
        self._sources_header.set_checked_background(color)
        for row in range(self.sources_table.rowCount()):
            checkbox = self._source_checkbox(row)
            if checkbox is not None:
                checkbox.set_checked_background(color)

    def set_source_catalog(self, files_by_name: dict[str, tuple[str, ...]]) -> None:
        previous_name = self.name
        self._files_by_name = {
            name: tuple(filenames)
            for name, filenames in files_by_name.items()
            if name and filenames
        }
        blocker = QSignalBlocker(self.name_input)
        self.name_input.clear()
        self.name_input.addItems(tuple(self._files_by_name))
        if previous_name in self._files_by_name:
            self.name_input.setCurrentText(previous_name)
        else:
            self.name_input.setCurrentIndex(-1)
        del blocker
        self._populate_sources()
        self._update_controls()

    def select_server_subscription(
        self,
        preferred_name: str | None = None,
    ) -> SubscriptionReconciliationItem | None:
        if not self._server_items:
            return None
        row = 0
        if preferred_name:
            row = next(
                (
                    index
                    for index, item in enumerate(self._server_items)
                    if item.name == preferred_name
                ),
                0,
            )
        self._updating_server_selection = True
        try:
            self.server_table.setCurrentCell(row, 0)
            self.server_table.selectRow(row)
        finally:
            self._updating_server_selection = False
        return self._server_items[row]

    def _server_selection_changed(self) -> None:
        if self._updating_server_selection:
            return
        row = self.server_table.currentRow()
        if 0 <= row < len(self._server_items):
            self.server_subscription_selected.emit(self._server_items[row])

    def clear_source_catalog(self) -> None:
        self.set_source_catalog({})

    def clear_name(self) -> None:
        self.name_input.setCurrentIndex(-1)
        self.clear_url()

    def _name_selected(self, text: str) -> None:
        self._populate_sources()
        self.name_changed.emit(text)
        self._update_controls()

    def _populate_sources(self) -> None:
        self._updating_sources = True
        try:
            self.sources_table.setRowCount(0)
            for filename in self._files_by_name.get(self.name, ()):
                row = self.sources_table.rowCount()
                self.sources_table.insertRow(row)
                checkbox_item = QTableWidgetItem()
                checkbox_item.setFlags(Qt.ItemFlag.ItemIsEnabled)
                checkbox = _SubscriptionSourceCheckBox(
                    self._checked_background,
                    f"Select {filename}",
                )
                checkbox.setChecked(True)
                checkbox.toggled.connect(self._source_checkbox_toggled)
                checkbox_cell = QWidget()
                checkbox_layout = QHBoxLayout(checkbox_cell)
                checkbox_layout.setContentsMargins(0, 0, 0, 0)
                checkbox_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
                checkbox_layout.addWidget(checkbox)
                filename_item = QTableWidgetItem(filename)
                filename_item.setFlags(Qt.ItemFlag.ItemIsEnabled)
                self.sources_table.setItem(row, 0, checkbox_item)
                self.sources_table.setCellWidget(row, 0, checkbox_cell)
                self.sources_table.setItem(row, 1, filename_item)
        finally:
            self._updating_sources = False
        self._update_master_check_state()

    def _set_all_sources_checked(self, checked: bool) -> None:
        if not self.sources_table.isEnabled():
            return
        self._updating_sources = True
        try:
            for row in range(self.sources_table.rowCount()):
                checkbox = self._source_checkbox(row)
                if checkbox is not None:
                    checkbox.setChecked(checked)
        finally:
            self._updating_sources = False
        self._update_master_check_state()
        self._update_controls()

    def _source_checkbox_toggled(self) -> None:
        if self._updating_sources:
            return
        self._update_master_check_state()
        self._update_controls()

    def _source_checkbox(self, row: int) -> _SubscriptionSourceCheckBox | None:
        cell = self.sources_table.cellWidget(row, 0)
        return cell.findChild(_SubscriptionSourceCheckBox) if cell is not None else None

    def _update_master_check_state(self) -> None:
        states = [
            checkbox.checkState()
            for row in range(self.sources_table.rowCount())
            if (checkbox := self._source_checkbox(row)) is not None
        ]
        if states and all(state == Qt.CheckState.Checked for state in states):
            state = Qt.CheckState.Checked
        elif any(state == Qt.CheckState.Checked for state in states):
            state = Qt.CheckState.PartiallyChecked
        else:
            state = Qt.CheckState.Unchecked
        self._sources_header.set_master_state(state)

    def _update_controls(self) -> None:
        self.name_input.setEnabled(self._operation_controls_enabled and bool(self._files_by_name))
        self.sources_table.setEnabled(self._operation_controls_enabled and bool(self.name))
        self._sources_header.master_checkbox.setEnabled(
            self.sources_table.isEnabled() and self.sources_table.rowCount() > 0
        )
        self.make_button.setEnabled(
            self._operation_controls_enabled
            and self._editing_enabled
            and bool(self.name)
            and bool(self.selected_source_filenames)
        )
        self.copy_button.setEnabled(bool(self.url))
        self.refresh_server_button.setEnabled(self._operation_controls_enabled)
        destructive_enabled = (
            self._operation_controls_enabled and self._editing_enabled and self._server_ready
        )
        for button in self._server_action_buttons:
            button.setEnabled(destructive_enabled)

    def _set_server_actions(
        self,
        row: int,
        item: SubscriptionReconciliationItem,
    ) -> None:
        actions = []
        if item.orphan_artifacts:
            actions.append(("Delete orphan", self.delete_orphan_requested))
        if item.registry_state is not None and item.status in {
            "active",
            "active_orphan",
            "deleting",
            "republish_required",
        }:
            actions.append(("Delete active", self.delete_active_requested))
        if not actions:
            return

        action_cell = QWidget()
        action_cell.setObjectName("publishedSubscriptionActionCell")
        action_layout = QHBoxLayout(action_cell)
        action_layout.setContentsMargins(4, 2, 4, 2)
        action_layout.setSpacing(4)
        action_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        for action_name, signal in actions:
            button = QToolButton(action_cell)
            button.setObjectName("subscriptionRowAction")
            button.setProperty("subscriptionAction", action_name)
            button.setToolTip(action_name)
            button.setAccessibleName(action_name)
            button.setFixedSize(28, 28)
            button.setIconSize(QSize(16, 16))
            self._set_server_action_icon(button)
            button.clicked.connect(
                lambda _checked=False, current=item, requested=signal: requested.emit(current)
            )
            action_layout.addWidget(button)
            self._server_action_buttons.append(button)
        self.server_table.setCellWidget(row, 2, action_cell)

    def _set_server_action_icon(self, button: QToolButton) -> None:
        action_name = button.property("subscriptionAction")
        icon_name = "unlink" if action_name == "Delete orphan" else "trash-2"
        button.setIcon(action_icon(icon_name, self._server_action_icon_colors[action_name]))
