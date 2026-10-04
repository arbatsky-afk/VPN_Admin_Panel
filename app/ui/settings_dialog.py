"""Unified Admin Panel settings dialog."""

from __future__ import annotations

from copy import deepcopy
from pathlib import Path

from PySide6.QtCore import QPointF, Qt
from PySide6.QtGui import QColor, QPainter, QPaintEvent, QPen, QShowEvent
from PySide6.QtWidgets import (
    QAbstractItemView,
    QButtonGroup,
    QDialog,
    QFileDialog,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QPushButton,
    QRadioButton,
    QSpinBox,
    QStyle,
    QStyleOptionButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from app.services.operational_telegram_settings import (
    MAX_AUDIT_LOG_RETENTION_DAYS,
    MIN_AUDIT_LOG_RETENTION_DAYS,
    OperationalTelegramSettings,
    OperationalTelegramSettingsError,
)
from app.services.settings_manager import NetdataCloudSettingsError, SettingsManager
from app.services.ssh_settings import (
    SshKeyRecord,
    SshSettingsError,
    editable_ssh_settings,
    save_ssh_settings,
)
from common.ui.checkbox import GreenCheckBox
from common.ui.theme import ThemeColors
from common.ui.window_chrome import apply_native_title_bar

from .alert_confirmation_dialog import ThemedWarningDialog
from .operational_telegram_controller import OperationalTelegramController


def _contrasting_check_color(background: str) -> QColor:
    color = QColor(background)
    brightness = (color.red() * 299 + color.green() * 587 + color.blue() * 114) / 1000
    return QColor("#07111E" if brightness >= 150 else "#FFFFFF")


class _PrimaryKeyRadioButton(QRadioButton):
    """Exclusive Primary selector drawn like the Monitor enabled checkbox."""

    def __init__(self, checked_background: str) -> None:
        super().__init__()
        self.setObjectName("primaryKeyRadio")
        self.setAccessibleName("Primary SSH key")
        self._check_color = _contrasting_check_color(checked_background)

    def paintEvent(self, event: QPaintEvent) -> None:
        super().paintEvent(event)
        if not self.isChecked():
            return
        option = QStyleOptionButton()
        self.initStyleOption(option)
        indicator = self.style().subElementRect(
            QStyle.SubElement.SE_RadioButtonIndicator,
            option,
            self,
        )
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        pen = QPen(self._check_color, 2.2)
        pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        pen.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
        painter.setPen(pen)
        painter.drawLine(
            QPointF(indicator.left() + 3.0, indicator.center().y()),
            QPointF(indicator.left() + 6.5, indicator.bottom() - 3.0),
        )
        painter.drawLine(
            QPointF(indicator.left() + 6.5, indicator.bottom() - 3.0),
            QPointF(indicator.right() - 2.5, indicator.top() + 3.0),
        )


class SettingsDialog(QDialog):
    """Edit SSH and operational Telegram settings through one entry point."""

    def __init__(
        self,
        controller: OperationalTelegramController,
        settings_manager: SettingsManager,
        colors: ThemeColors,
        *,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.controller = controller
        self.settings_manager = settings_manager
        self._colors = colors
        self.current_telegram = controller.settings
        self._detected_user_id = self.current_telegram.authorized_user_id
        ssh_port, key_records = editable_ssh_settings(settings_manager)

        claim_token, claim_rooms, netdata_settings_error = (
            settings_manager.editable_netdata_cloud_settings()
        )

        self.setObjectName("panelSettingsDialog")
        self.setWindowTitle("Settings")
        self.setModal(True)
        self.setWindowModality(Qt.WindowModality.WindowModal)
        self.setFixedSize(540, 700)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 12, 14, 12)
        layout.setSpacing(7)

        self.persistence_warning_label = QLabel()
        self.persistence_warning_label.setObjectName("settingsPersistenceWarning")
        self.persistence_warning_label.setWordWrap(True)
        if not settings_manager.persistence_available:
            reason = (
                settings_manager.persistence_error
                or "The settings file could not be loaded safely."
            )
            self.persistence_warning_label.setText(
                f"{reason} The file is protected from changes in this session. "
                "Fix or restore it, then restart Admin Panel."
            )
            layout.addWidget(self.persistence_warning_label)

        startup_layout = QHBoxLayout()
        startup_layout.setSpacing(4)
        self.start_minimized_checkbox = GreenCheckBox(
            "Start minimized to tray. Applies on next launch",
            colors,
        )
        self.start_minimized_checkbox.setChecked(settings_manager.start_minimized_to_tray())
        startup_layout.addWidget(self.start_minimized_checkbox)
        startup_layout.addStretch()
        layout.addLayout(startup_layout)

        self.ssh_group = QGroupBox("SSH keys")
        ssh_layout = QVBoxLayout(self.ssh_group)
        ssh_layout.setSpacing(5)
        ssh_form = QFormLayout()
        ssh_form.setHorizontalSpacing(10)
        ssh_form.setVerticalSpacing(4)
        self.ssh_port_input = QSpinBox()
        self.ssh_port_input.setObjectName("settingsSshPort")
        self.ssh_port_input.setRange(1, 65535)
        self.ssh_port_input.setValue(ssh_port)
        self.ssh_port_input.setFixedWidth(82)
        ssh_form.addRow("SSH port", self.ssh_port_input)
        ssh_layout.addLayout(ssh_form)

        self.table = QTableWidget(0, 4)
        self.table.setObjectName("settingsSshKeysTable")
        self.table.setHorizontalHeaderLabels(("Primary", "Name", "Private key", "Status"))
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(
            QAbstractItemView.EditTrigger.DoubleClicked
            | QAbstractItemView.EditTrigger.EditKeyPressed
        )
        self.table.verticalHeader().setVisible(False)
        self.table.verticalHeader().setDefaultSectionSize(27)
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        ssh_layout.addWidget(self.table)

        key_actions = QHBoxLayout()
        self.add_button = QPushButton("Add key")
        self.add_button.clicked.connect(self._add_key)
        key_actions.addWidget(self.add_button)
        self.remove_button = QPushButton("Remove")
        self.remove_button.clicked.connect(self._remove_selected_key)
        key_actions.addWidget(self.remove_button)
        key_actions.addStretch()
        ssh_layout.addLayout(key_actions)
        layout.addWidget(self.ssh_group)

        self.telegram_group = QGroupBox("Telegram Bot")
        telegram_layout = QVBoxLayout(self.telegram_group)
        telegram_layout.setSpacing(5)
        telegram_form = QFormLayout()
        telegram_form.setHorizontalSpacing(10)
        telegram_form.setVerticalSpacing(4)
        self.token_input = QLineEdit(self.current_telegram.bot_token)
        self.token_input.setPlaceholderText("Leave empty to disable Telegram")
        telegram_form.addRow("Bot token", self.token_input)
        self.chat_id_input = QLineEdit(
            "" if self.current_telegram.chat_id is None else str(self.current_telegram.chat_id)
        )
        self.chat_id_input.setFixedWidth(170)
        self.chat_id_input.setPlaceholderText("Numeric Telegram chat ID")
        telegram_form.addRow("Chat ID", self.chat_id_input)

        identity = QWidget(self)
        identity_layout = QHBoxLayout(identity)
        identity_layout.setContentsMargins(0, 0, 0, 0)
        self.user_id_input = QLineEdit()
        self.user_id_input.setFixedWidth(170)
        self.user_id_input.setReadOnly(True)
        self._show_user_id(self._detected_user_id)
        self.detect_button = QPushButton("Detect User ID")
        self.detect_button.clicked.connect(self._detect_user)
        identity_layout.addWidget(self.user_id_input, 1)
        identity_layout.addWidget(self.detect_button)
        telegram_form.addRow("Authorized User ID", identity)

        self.retention_input = QSpinBox()
        self.retention_input.setRange(MIN_AUDIT_LOG_RETENTION_DAYS, MAX_AUDIT_LOG_RETENTION_DAYS)
        self.retention_input.setValue(self.current_telegram.audit_log_retention_days)
        telegram_form.addRow("Audit log retention (days)", self.retention_input)
        telegram_layout.addLayout(telegram_form)

        self.info_label = QLabel()
        self.info_label.setObjectName("settingsHint")
        self.info_label.setWordWrap(True)
        if controller.settings_error:
            self.info_label.setText(
                "The saved Telegram section is invalid and the bot is disabled: "
                f"{controller.settings_error}"
            )
        telegram_layout.addWidget(self.info_label)
        layout.addWidget(self.telegram_group)

        self.netdata_group = QGroupBox("Netdata")
        netdata_layout = QVBoxLayout(self.netdata_group)
        netdata_layout.setSpacing(5)
        netdata_form = QFormLayout()
        netdata_form.setHorizontalSpacing(10)
        netdata_form.setVerticalSpacing(4)
        self.claim_token_input = QLineEdit(claim_token)
        self.claim_token_input.setPlaceholderText("Required for Netdata Deploy")
        netdata_form.addRow("Claim token", self.claim_token_input)
        self.claim_rooms_input = QLineEdit(claim_rooms)
        self.claim_rooms_input.setPlaceholderText("Comma-separated Room IDs (optional)")
        netdata_form.addRow("Claim rooms", self.claim_rooms_input)
        netdata_layout.addLayout(netdata_form)
        self.netdata_info_label = QLabel()
        self.netdata_info_label.setObjectName("settingsHint")
        self.netdata_info_label.setWordWrap(True)
        self.netdata_info_label.setText(
            netdata_settings_error
            or "Claim token is required only for Netdata Deploy; Claim rooms is optional."
        )
        netdata_layout.addWidget(self.netdata_info_label)
        layout.addWidget(self.netdata_group)

        buttons = QHBoxLayout()
        buttons.setSpacing(6)
        buttons.addStretch()
        cancel_button = QPushButton("Cancel")
        cancel_button.clicked.connect(self.reject)
        buttons.addWidget(cancel_button)
        self.save_button = QPushButton("Save")
        self.save_button.setObjectName("settingsSave")
        self.save_button.clicked.connect(self._save)
        buttons.addWidget(self.save_button)
        layout.addLayout(buttons)

        self._primary_buttons = QButtonGroup(self)
        self._primary_buttons.setExclusive(True)
        for record in key_records:
            self._append_key(record)
        if self.table.rowCount():
            self.table.selectRow(0)
        self.table.itemSelectionChanged.connect(self._update_remove_button)
        self._update_remove_button()
        self.detect_button.setEnabled(
            self.current_telegram.configured and self.current_telegram.authorized_user_id is None
        )
        if not settings_manager.persistence_available:
            self.start_minimized_checkbox.setEnabled(False)
            self.ssh_group.setEnabled(False)
            self.telegram_group.setEnabled(False)
            self.netdata_group.setEnabled(False)
            self.save_button.setEnabled(False)
        self.controller.authorized_user_detected.connect(self._identified)
        self.setStyleSheet(self._build_stylesheet(colors))
        key_table_height = (
            self.table.horizontalHeader().sizeHint().height()
            + self.table.verticalHeader().defaultSectionSize() * 4
            + self.table.frameWidth() * 2
        )
        self.table.setFixedHeight(key_table_height)

    def showEvent(self, event: QShowEvent) -> None:
        super().showEvent(event)
        apply_native_title_bar(self, self._colors)

    def _append_key(self, record: SshKeyRecord) -> None:
        row = self.table.rowCount()
        self.table.insertRow(row)
        primary = _PrimaryKeyRadioButton(self._colors.success)
        primary.setChecked(record.is_primary)
        self._primary_buttons.addButton(primary)
        cell = QWidget()
        cell_layout = QHBoxLayout(cell)
        cell_layout.setContentsMargins(0, 0, 0, 0)
        cell_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        cell_layout.addWidget(primary)
        self.table.setCellWidget(row, 0, cell)
        self.table.setItem(row, 1, QTableWidgetItem(record.name))
        path_item = QTableWidgetItem(str(record.private_key_path))
        path_item.setFlags(Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable)
        path_item.setToolTip(str(record.private_key_path))
        self.table.setItem(row, 2, path_item)
        public_path = Path(f"{record.private_key_path}.pub")
        status = QTableWidgetItem("Ready" if public_path.is_file() else "Missing .pub")
        status.setForeground(
            QColor(self._colors.success if public_path.is_file() else self._colors.error)
        )
        status.setFlags(Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable)
        self.table.setItem(row, 3, status)

    def _add_key(self) -> None:
        ssh_directory = Path.home() / ".ssh"
        initial = str(ssh_directory) if ssh_directory.is_dir() else ""
        selected, _ = QFileDialog.getOpenFileName(
            self, "Select private SSH key", initial, "All files (*)"
        )
        if not selected:
            return
        path = Path(selected)
        if any(path == record.private_key_path for record in self._records()):
            self._warning("Duplicate SSH key", "This private key is already in the list.")
            return
        self._append_key(SshKeyRecord(path.stem or path.name, path, self.table.rowCount() == 0))
        self.table.selectRow(self.table.rowCount() - 1)
        self._update_remove_button()

    def _remove_selected_key(self) -> None:
        row = self.table.currentRow()
        if row < 0:
            return
        primary = self._primary_button_for_row(row)
        was_primary = primary.isChecked()
        self._primary_buttons.removeButton(primary)
        self.table.removeRow(row)
        if was_primary and self.table.rowCount():
            self._primary_button_for_row(0).setChecked(True)
        self._update_remove_button()

    def _records(self) -> tuple[SshKeyRecord, ...]:
        return tuple(
            SshKeyRecord(
                self.table.item(row, 1).text(),
                Path(self.table.item(row, 2).text()),
                self._primary_button_for_row(row).isChecked(),
            )
            for row in range(self.table.rowCount())
        )

    def _primary_button_for_row(self, row: int) -> QRadioButton:
        cell = self.table.cellWidget(row, 0)
        primary = cell.findChild(QRadioButton) if cell is not None else None
        if primary is None:
            raise RuntimeError("SSH key table row has no primary-key control.")
        return primary

    def _detect_user(self) -> None:
        accepted, command = self.controller.begin_identification()
        self.info_label.setText(
            f"Send this command in the configured Telegram chat within 5 minutes:\n{command}"
            if accepted
            else command
        )

    def _identified(self, user_id: int) -> None:
        self._detected_user_id = user_id
        self._show_user_id(user_id)
        self.info_label.setText("User detected. Click Save to store the authorization.")

    def _show_user_id(self, user_id: int | None) -> None:
        self.user_id_input.setText("Not detected" if user_id is None else str(user_id))

    def _save(self) -> None:
        if not self.settings_manager.persistence_available:
            return
        records = self._records()
        missing_public = [
            r.name for r in records if not Path(f"{r.private_key_path}.pub").is_file()
        ]
        if missing_public:
            self._warning(
                "Public key required",
                "SSH Fix needs a matching .pub file for: " + ", ".join(missing_public) + ".",
            )
            return
        token = self.token_input.text().strip()
        raw_chat_id = self.chat_id_input.text().strip()
        try:
            chat_id = int(raw_chat_id) if raw_chat_id else None
        except ValueError:
            self.info_label.setText("Chat ID must be a non-zero integer.")
            return
        detected = self._detected_user_id
        if token != self.current_telegram.bot_token or chat_id != self.current_telegram.chat_id:
            detected = None
        if not token and chat_id is None:
            detected = None
        try:
            telegram = OperationalTelegramSettings.validated(
                token, chat_id, detected, self.retention_input.value()
            )
        except OperationalTelegramSettingsError as error:
            self.info_label.setText(str(error))
            return

        try:
            claim_token, claim_rooms = self.settings_manager.validate_netdata_cloud_settings(
                self.claim_token_input.text(),
                self.claim_rooms_input.text(),
            )
        except NetdataCloudSettingsError as error:
            self.netdata_info_label.setText(str(error))
            return

        previous_ssh = deepcopy(self.settings_manager.get("ssh"))
        had_ssh = self.settings_manager.get("ssh") is not None
        previous_netdata = deepcopy(self.settings_manager.get("netdata_cloud"))
        had_netdata = self.settings_manager.get("netdata_cloud") is not None
        previous_start_minimized = deepcopy(
            self.settings_manager.get("ui.start_minimized_to_tray")
        )
        had_start_minimized = self.settings_manager.get("ui.start_minimized_to_tray") is not None
        try:
            save_ssh_settings(
                self.settings_manager,
                records,
                self.ssh_port_input.value(),
                save=False,
            )
            self.settings_manager.set_netdata_cloud_settings(
                claim_token,
                claim_rooms,
                save=False,
            )
            self.settings_manager.set(
                "ui.start_minimized_to_tray",
                self.start_minimized_checkbox.isChecked(),
            )
        except SshSettingsError as error:
            self._warning("SSH settings were not saved", str(error))
            return
        accepted, message = self.controller.apply_settings(telegram)
        if not accepted:
            if had_ssh:
                self.settings_manager.set("ssh", previous_ssh)
            else:
                self.settings_manager.unset("ssh")
            if had_netdata:
                self.settings_manager.set("netdata_cloud", previous_netdata)
            else:
                self.settings_manager.unset("netdata_cloud")
            if had_start_minimized:
                self.settings_manager.set("ui.start_minimized_to_tray", previous_start_minimized)
            else:
                self.settings_manager.unset("ui.start_minimized_to_tray")
            self.info_label.setText(message)
            return
        self.accept()

    def _update_remove_button(self) -> None:
        self.remove_button.setEnabled(self.table.currentRow() >= 0)

    def _warning(self, title: str, text: str) -> None:
        ThemedWarningDialog(self, title, text, self._colors).exec()

    def done(self, result: int) -> None:
        try:
            self.controller.authorized_user_detected.disconnect(self._identified)
        except RuntimeError:
            pass
        super().done(result)

    @staticmethod
    def _build_stylesheet(colors: ThemeColors) -> str:
        return f"""
            QDialog#panelSettingsDialog {{
                background: {colors.panel_background}; color: {colors.text}; font-size: 12px;
            }}
            QDialog#panelSettingsDialog QWidget {{
                font-size: 12px;
            }}
            QDialog#panelSettingsDialog QGroupBox {{
                border: 1px solid {colors.panel_border}; border-radius: 6px;
                margin-top: 8px; padding: 12px 10px 8px;
                font-size: 14px; font-weight: 600;
            }}
            QDialog#panelSettingsDialog QGroupBox::title {{
                subcontrol-origin: margin; left: 10px; padding: 0 4px;
            }}
            QDialog#panelSettingsDialog QLineEdit,
            QDialog#panelSettingsDialog QComboBox,
            QDialog#panelSettingsDialog QSpinBox {{
                min-height: 25px; padding-left: 8px;
            }}
            QDialog#panelSettingsDialog QSpinBox#settingsSshPort {{
                padding: 1px 19px 1px 6px;
            }}
            QDialog#panelSettingsDialog QSpinBox::up-button,
            QDialog#panelSettingsDialog QSpinBox::down-button {{
                width: 22px; height: 13px;
            }}
            QDialog#panelSettingsDialog QSpinBox#settingsSshPort::up-button,
            QDialog#panelSettingsDialog QSpinBox#settingsSshPort::down-button {{
                width: 18px;
            }}
            QDialog#panelSettingsDialog QPushButton {{
                min-height: 26px; padding: 1px 10px; font-size: 12px;
            }}
            QDialog#panelSettingsDialog QLabel#settingsSectionLabel {{
                color: {colors.muted_text}; font-size: 11px; font-weight: 600;
            }}
            QDialog#panelSettingsDialog QLabel#settingsHint {{
                color: {colors.muted_text}; font-size: 11px;
            }}
            QTableWidget#settingsSshKeysTable {{
                background: {colors.control_background}; border: 1px solid {colors.control_border};
                border-radius: 7px; gridline-color: {colors.panel_border}; color: {colors.text};
            }}
            QTableWidget#settingsSshKeysTable::item:selected {{ background: {colors.blue_dark_hover}; }}
            QHeaderView::section {{
                background: {colors.panel_background}; border: 0;
                border-bottom: 1px solid {colors.panel_border}; color: {colors.muted_text};
                padding: 4px; font-size: 11px; font-weight: 600;
            }}
            QRadioButton#primaryKeyRadio {{ spacing: 0; }}
            QRadioButton#primaryKeyRadio::indicator {{
                width: 14px; height: 14px; border: 1px solid {colors.muted_text};
                border-radius: 4px; background: {colors.control_background};
            }}
            QRadioButton#primaryKeyRadio::indicator:hover {{
                border-color: {colors.blue}; background: {colors.blue_dark_hover};
            }}
            QRadioButton#primaryKeyRadio::indicator:checked {{
                border-color: {colors.success}; background: {colors.success};
            }}
            QPushButton#settingsSave {{
                background: {colors.blue}; border: 1px solid {colors.blue_hover}; color: white;
            }}
            QPushButton#settingsSave:hover {{ background: {colors.blue_hover}; }}
            QLabel#settingsPersistenceWarning {{
                background: {colors.warning_background}; border: 1px solid {colors.deploy_border};
                border-radius: 5px; color: {colors.text}; padding: 7px 9px;
            }}
        """  # noqa: E501 -- embedded Qt stylesheet
