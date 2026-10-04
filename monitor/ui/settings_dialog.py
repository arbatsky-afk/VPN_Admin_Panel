from __future__ import annotations

from dataclasses import replace

from PySide6.QtGui import QShowEvent
from PySide6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QHBoxLayout,
    QLineEdit,
    QMessageBox,
    QSpinBox,
    QVBoxLayout,
)

from common.ui.checkbox import GreenCheckBox
from common.ui.theme import ThemeColors
from common.ui.window_chrome import apply_native_title_bar
from monitor.settings import MonitorSettings, SettingsError


class SettingsDialog(QDialog):
    def __init__(
        self,
        settings: MonitorSettings,
        colors: ThemeColors,
        parent=None,  # type: ignore[no-untyped-def]
    ) -> None:
        super().__init__(parent)
        self.setObjectName("monitorSettingsDialog")
        self.setWindowTitle("Monitor settings")
        self.setFixedSize(510, 520)
        self._settings = settings
        self._colors = colors
        self._numbers: dict[str, QSpinBox] = {}
        self._urls: dict[str, QLineEdit] = {}

        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 12, 14, 12)
        layout.setSpacing(7)

        startup_layout = QHBoxLayout()
        startup_layout.setSpacing(4)
        self.start_minimized_checkbox = GreenCheckBox(
            "Start minimized to tray. Applies on next launch",
            colors,
        )
        self.start_minimized_checkbox.setChecked(settings.start_minimized_to_tray)
        startup_layout.addWidget(self.start_minimized_checkbox)
        startup_layout.addStretch()
        layout.addLayout(startup_layout)

        form = QFormLayout()
        form.setHorizontalSpacing(10)
        form.setVerticalSpacing(4)
        bot_token = settings.bot_token if isinstance(settings.bot_token, str) else ""
        chat_id = (
            settings.chat_id
            if isinstance(settings.chat_id, int) and not isinstance(settings.chat_id, bool)
            else None
        )
        self.bot_token_field = QLineEdit(bot_token)
        self.bot_token_field.setPlaceholderText("Leave empty to disable Telegram")
        self.chat_id_field = QLineEdit("" if chat_id is None else str(chat_id))
        self.chat_id_field.setFixedWidth(170)
        self.chat_id_field.setPlaceholderText("Numeric Telegram chat ID")
        form.addRow("Bot token", self.bot_token_field)
        form.addRow("Chat ID", self.chat_id_field)
        ranges = {
            "check_interval_seconds": (10, 86400, "Check interval (seconds)"),
            "parallel_checks": (1, 8, "Parallel checks"),
            "retry_delay_seconds": (1, 3600, "Retry delay (seconds)"),
            "max_attempts": (1, 5, "Maximum attempts"),
            "mihomo_start_timeout_seconds": (1, 120, "Mihomo start timeout"),
            "probe_timeout_seconds": (1, 300, "Probe timeout"),
            "mihomo_stop_grace_seconds": (1, 60, "Mihomo stop grace"),
            "operation_log_retention_days": (1, 365, "Operation log retention (days)"),
            "event_log_retention_days": (1, 3650, "Event retention (days)"),
            "max_redirects": (0, 10, "Maximum redirects"),
        }
        for name, (minimum, maximum, label) in ranges.items():
            field = QSpinBox()
            field.setProperty("compactNumber", True)
            field.setRange(minimum, maximum)
            field.setValue(getattr(settings, name))
            field.setFixedWidth(82)
            self._numbers[name] = field
            form.addRow(label, field)
        for name, label in (
            ("primary_ip_url", "Primary IPv4 endpoint"),
            ("secondary_ip_url", "Secondary IPv4 endpoint"),
            ("connectivity_check_url", "Connectivity endpoint"),
        ):
            field = QLineEdit(getattr(settings, name))
            self._urls[name] = field
            form.addRow(label, field)
        buttons = QDialogButtonBox(QDialogButtonBox.Save | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self._accept)
        buttons.rejected.connect(self.reject)
        layout.addLayout(form)
        layout.addWidget(buttons)
        self.setStyleSheet(self._build_stylesheet(colors))

    def showEvent(self, event: QShowEvent) -> None:
        super().showEvent(event)
        apply_native_title_bar(self, self._colors)

    @property
    def settings(self) -> MonitorSettings:
        return self._settings

    @staticmethod
    def _build_stylesheet(colors: ThemeColors) -> str:
        return f"""
            QDialog#monitorSettingsDialog {{
                background: {colors.panel_background}; color: {colors.text}; font-size: 12px;
            }}
            QDialog#monitorSettingsDialog QWidget {{
                font-size: 12px;
            }}
            QDialog#monitorSettingsDialog QLineEdit,
            QDialog#monitorSettingsDialog QComboBox,
            QDialog#monitorSettingsDialog QSpinBox {{
                min-height: 25px; padding-left: 8px;
            }}
            QDialog#monitorSettingsDialog QSpinBox::up-button,
            QDialog#monitorSettingsDialog QSpinBox::down-button {{
                width: 22px; height: 13px;
            }}
            QDialog#monitorSettingsDialog QSpinBox[compactNumber="true"] {{
                padding: 1px 19px 1px 6px;
            }}
            QDialog#monitorSettingsDialog QSpinBox[compactNumber="true"]::up-button,
            QDialog#monitorSettingsDialog QSpinBox[compactNumber="true"]::down-button {{
                width: 18px;
            }}
            QDialog#monitorSettingsDialog QPushButton {{
                min-height: 26px; padding: 1px 10px; font-size: 12px;
            }}
        """

    def _accept(self) -> None:
        values = {name: field.value() for name, field in self._numbers.items()}
        values.update({name: field.text().strip() for name, field in self._urls.items()})
        bot_token = self.bot_token_field.text().strip()
        chat_id_text = self.chat_id_field.text().strip()
        chat_id: int | None = None
        if chat_id_text:
            try:
                chat_id = int(chat_id_text)
            except ValueError:
                QMessageBox.warning(self, "Invalid settings", "Chat ID must be an integer.")
                return
            if chat_id == 0:
                QMessageBox.warning(self, "Invalid settings", "Chat ID must not be zero.")
                return
        if bool(bot_token) != (chat_id is not None):
            QMessageBox.warning(
                self,
                "Invalid settings",
                "Bot token and Chat ID must both be filled or both be empty.",
            )
            return
        values.update(bot_token=bot_token, chat_id=chat_id)
        values["start_minimized_to_tray"] = self.start_minimized_checkbox.isChecked()
        try:
            self._settings = replace(self._settings, **values).validate()
        except SettingsError as error:
            QMessageBox.warning(self, "Invalid settings", str(error))
            return
        self.accept()
