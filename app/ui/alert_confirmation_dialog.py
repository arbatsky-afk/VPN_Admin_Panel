"""Theme-aware confirmation dialog for infrastructure-changing actions."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QShowEvent
from PySide6.QtWidgets import (
    QComboBox,
    QDialog,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from app.services.modular_deployment import NginxTlsSettings, validate_nginx_tls_settings
from common.ui.theme import ThemeColors
from common.ui.window_chrome import apply_native_title_bar


class AlertConfirmationDialog(QDialog):
    """A modal confirmation dialog styled as a high-attention application alert."""

    def __init__(
        self,
        parent: QWidget,
        title: str,
        text: str,
        action_label: str,
        colors: ThemeColors,
        *,
        highlight_text: str | None = None,
    ) -> None:
        super().__init__(parent)
        self._colors = colors
        self.setWindowTitle(title)
        self.setModal(True)
        self.setWindowModality(Qt.WindowModality.WindowModal)
        self.setFixedWidth(520)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 22, 24, 20)
        layout.setSpacing(14)

        title_label = QLabel(title)
        title_label.setObjectName("alertTitle")
        layout.addWidget(title_label)

        message_label = QLabel(text)
        message_label.setObjectName("alertMessage")
        message_label.setWordWrap(True)
        layout.addWidget(message_label)

        if highlight_text:
            highlight_label = QLabel(highlight_text)
            highlight_label.setObjectName("alertHighlight")
            highlight_label.setWordWrap(True)
            layout.addWidget(highlight_label)

        buttons_layout = QHBoxLayout()
        buttons_layout.addStretch()
        cancel_button = QPushButton("Cancel")
        cancel_button.setObjectName("alertCancel")
        cancel_button.clicked.connect(self.reject)
        buttons_layout.addWidget(cancel_button)

        confirm_button = QPushButton(action_label)
        confirm_button.setObjectName("alertConfirm")
        confirm_button.clicked.connect(self.accept)
        buttons_layout.addWidget(confirm_button)
        layout.addLayout(buttons_layout)

        self.setStyleSheet(self._build_stylesheet(colors))
        self.adjustSize()
        self.setFixedSize(self.size())

    def showEvent(self, event: QShowEvent) -> None:
        super().showEvent(event)
        apply_native_title_bar(self, self._colors)

    @staticmethod
    def _build_stylesheet(colors: ThemeColors) -> str:
        return f"""
            QDialog {{
                background: {colors.deploy_background}; color: {colors.text};
                border: 1px solid {colors.deploy_border};
            }}
            QLabel#alertTitle {{ color: {colors.amber}; font-size: 20px; font-weight: 700; }}
            QLabel#alertMessage {{ color: {colors.text}; font-size: 14px; line-height: 1.35; }}
            QLabel#alertHighlight {{
                background: {colors.control_background}; border: 1px solid {colors.amber};
                border-radius: 7px; color: {colors.amber_hover}; font-size: 19px;
                font-weight: 700; padding: 10px 12px;
            }}
            QPushButton {{
                border-radius: 7px; min-height: 32px; padding: 2px 14px; font-weight: 600;
            }}
            QPushButton#alertCancel {{
                background: {colors.control_background}; border: 1px solid {colors.control_border}; color: {colors.text};
            }}
            QPushButton#alertCancel:hover {{ background: {colors.blue_dark}; border-color: {colors.panel_border}; }}
            QPushButton#alertConfirm {{
                background: {colors.amber}; border: 1px solid {colors.amber_hover}; color: {colors.control_background};
            }}
            QPushButton#alertConfirm:hover {{ background: {colors.amber_hover}; }}
        """  # noqa: E501 -- embedded Qt stylesheet


class ThemedTextInputDialog(QDialog):
    """A theme-aware text input dialog for normal application operations."""

    def __init__(
        self, parent: QWidget, title: str, label: str, action_label: str, colors: ThemeColors
    ) -> None:
        super().__init__(parent)
        self._colors = colors
        self.setWindowTitle(title)
        self.setModal(True)
        self.setWindowModality(Qt.WindowModality.WindowModal)
        self.setFixedWidth(420)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 22, 24, 20)
        layout.setSpacing(14)

        title_label = QLabel(title)
        title_label.setObjectName("textInputTitle")
        layout.addWidget(title_label)

        input_label = QLabel(label)
        input_label.setObjectName("textInputLabel")
        layout.addWidget(input_label)

        self.text_input = QLineEdit()
        self.text_input.setObjectName("textInputField")
        layout.addWidget(self.text_input)

        buttons_layout = QHBoxLayout()
        buttons_layout.addStretch()
        cancel_button = QPushButton("Cancel")
        cancel_button.setObjectName("textInputCancel")
        cancel_button.clicked.connect(self.reject)
        buttons_layout.addWidget(cancel_button)

        confirm_button = QPushButton(action_label)
        confirm_button.setObjectName("textInputConfirm")
        confirm_button.clicked.connect(self.accept)
        buttons_layout.addWidget(confirm_button)
        layout.addLayout(buttons_layout)

        self.text_input.returnPressed.connect(self.accept)
        self.setStyleSheet(self._build_stylesheet(colors))
        self.adjustSize()
        self.setFixedSize(self.size())

    def text(self) -> str:
        return self.text_input.text()

    def showEvent(self, event: QShowEvent) -> None:
        super().showEvent(event)
        apply_native_title_bar(self, self._colors)
        self.text_input.setFocus()

    @staticmethod
    def _build_stylesheet(colors: ThemeColors) -> str:
        return f"""
            QDialog {{
                background: {colors.panel_background}; color: {colors.text};
                border: 1px solid {colors.panel_border};
            }}
            QLabel#textInputTitle {{ color: {colors.blue}; font-size: 20px; font-weight: 700; }}
            QLabel#textInputLabel {{ color: {colors.text}; font-size: 14px; }}
            QLineEdit#textInputField {{
                background: {colors.control_background}; border: 1px solid {colors.control_border};
                border-radius: 8px; min-height: 34px; padding: 1px 10px; color: {colors.text};
                font-size: 16px;
            }}
            QLineEdit#textInputField:focus {{ border: 2px solid {colors.blue}; }}
            QPushButton {{ border-radius: 7px; min-height: 32px; padding: 2px 14px; font-weight: 600; }}
            QPushButton#textInputCancel {{
                background: {colors.control_background}; border: 1px solid {colors.control_border}; color: {colors.text};
            }}
            QPushButton#textInputCancel:hover {{ background: {colors.blue_dark}; border-color: {colors.panel_border}; }}
            QPushButton#textInputConfirm {{
                background: {colors.blue}; border: 1px solid {colors.blue_hover}; color: white;
            }}
            QPushButton#textInputConfirm:hover {{ background: {colors.blue_hover}; }}
        """  # noqa: E501 -- embedded Qt stylesheet


class NginxTlsDialog(QDialog):
    """Select the desired managed TLS state for Nginx Deploy."""

    def __init__(
        self,
        parent: QWidget,
        colors: ThemeColors,
        *,
        initial_settings: NginxTlsSettings | None = None,
    ) -> None:
        super().__init__(parent)
        self._colors = colors
        self._settings: NginxTlsSettings | None = None
        self.setObjectName("nginxTlsDialog")
        self.setWindowTitle("Nginx TLS")
        self.setModal(True)
        self.setWindowModality(Qt.WindowModality.WindowModal)
        self.setFixedWidth(470)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 22, 24, 20)
        layout.setSpacing(14)
        title = QLabel("Nginx TLS state")
        title.setObjectName("nginxTlsTitle")
        layout.addWidget(title)
        message = QLabel(
            "Choose the final managed TLS state. The current server state is selected "
            "automatically when Nginx is already installed."
        )
        message.setObjectName("nginxTlsMessage")
        message.setWordWrap(True)
        layout.addWidget(message)

        form = QFormLayout()
        self.mode_input = QComboBox()
        self.mode_input.setObjectName("nginxTlsMode")
        self.mode_input.addItem("Self-signed", "self_signed")
        self.mode_input.addItem("Let's Encrypt", "letsencrypt")
        self.mode_input.currentIndexChanged.connect(self._mode_changed)
        form.addRow("TLS mode", self.mode_input)
        self.domain_input = QLineEdit()
        self.domain_input.setObjectName("nginxTlsDomain")
        self.domain_input.setPlaceholderText("vpn.example.com")
        form.addRow("Domain", self.domain_input)
        layout.addLayout(form)

        self.error_label = QLabel()
        self.error_label.setObjectName("nginxTlsError")
        self.error_label.setWordWrap(True)
        layout.addWidget(self.error_label)

        buttons = QHBoxLayout()
        buttons.addStretch()
        cancel = QPushButton("Cancel")
        cancel.clicked.connect(self.reject)
        buttons.addWidget(cancel)
        deploy = QPushButton("Continue")
        deploy.setObjectName("nginxTlsContinue")
        deploy.clicked.connect(self._accept_selection)
        buttons.addWidget(deploy)
        layout.addLayout(buttons)
        if initial_settings is not None:
            mode_index = self.mode_input.findData(initial_settings.mode)
            if mode_index >= 0:
                self.mode_input.setCurrentIndex(mode_index)
            if initial_settings.mode == "letsencrypt":
                self.domain_input.setText(initial_settings.domain)
        self._mode_changed()
        self.setStyleSheet(self._build_stylesheet(colors))
        self.adjustSize()
        self.setFixedSize(self.size())

    def settings(self) -> NginxTlsSettings | None:
        return self._settings

    def _mode_changed(self) -> None:
        letsencrypt = self.mode_input.currentData() == "letsencrypt"
        self.domain_input.setEnabled(letsencrypt)
        if not letsencrypt:
            self.domain_input.clear()
            self.error_label.clear()

    def _accept_selection(self) -> None:
        try:
            self._settings = validate_nginx_tls_settings(
                self.mode_input.currentData(),
                self.domain_input.text(),
            )
        except ValueError as error:
            self.error_label.setText(str(error))
            return
        self.accept()

    def showEvent(self, event: QShowEvent) -> None:
        super().showEvent(event)
        apply_native_title_bar(self, self._colors)

    @staticmethod
    def _build_stylesheet(colors: ThemeColors) -> str:
        return f"""
            QDialog#nginxTlsDialog {{
                background: {colors.panel_background}; color: {colors.text};
                border: 1px solid {colors.panel_border};
            }}
            QLabel#nginxTlsTitle {{ color: {colors.blue}; font-size: 20px; font-weight: 700; }}
            QLabel#nginxTlsMessage {{ color: {colors.text}; font-size: 13px; }}
            QLabel#nginxTlsError {{ color: {colors.error}; font-size: 12px; }}
            QLineEdit, QComboBox {{
                background: {colors.control_background}; border: 1px solid {colors.control_border};
                border-radius: 7px; min-height: 30px; padding: 1px 8px; color: {colors.text};
            }}
            QPushButton {{ border-radius: 7px; min-height: 32px; padding: 2px 14px; }}
            QPushButton#nginxTlsContinue {{
                background: {colors.blue}; border: 1px solid {colors.blue_hover}; color: white;
            }}
        """


class ThemedWarningDialog(QDialog):
    """A modal application-styled warning dialog with a single acknowledgement action."""

    def __init__(self, parent: QWidget, title: str, text: str, colors: ThemeColors) -> None:
        super().__init__(parent)
        self._colors = colors
        self.setWindowTitle(title)
        self.setModal(True)
        self.setWindowModality(Qt.WindowModality.WindowModal)
        self.setFixedWidth(460)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 22, 24, 20)
        layout.setSpacing(14)

        title_label = QLabel(title)
        title_label.setObjectName("warningTitle")
        layout.addWidget(title_label)

        message_label = QLabel(text)
        message_label.setObjectName("warningMessage")
        message_label.setWordWrap(True)
        layout.addWidget(message_label)

        buttons_layout = QHBoxLayout()
        buttons_layout.addStretch()
        ok_button = QPushButton("OK")
        ok_button.setObjectName("warningOk")
        ok_button.clicked.connect(self.accept)
        buttons_layout.addWidget(ok_button)
        layout.addLayout(buttons_layout)

        self.setStyleSheet(self._build_stylesheet(colors))
        self.adjustSize()
        self.setFixedSize(self.size())

    def showEvent(self, event: QShowEvent) -> None:
        super().showEvent(event)
        apply_native_title_bar(self, self._colors)

    @staticmethod
    def _build_stylesheet(colors: ThemeColors) -> str:
        return f"""
            QDialog {{
                background: {colors.warning_background}; color: {colors.text};
                border: 1px solid {colors.deploy_border};
            }}
            QLabel#warningTitle {{ color: {colors.amber}; font-size: 20px; font-weight: 700; }}
            QLabel#warningMessage {{ color: {colors.text}; font-size: 14px; line-height: 1.35; }}
            QPushButton#warningOk {{
                background: {colors.blue}; border: 1px solid {colors.blue_hover}; border-radius: 7px;
                min-height: 32px; padding: 2px 18px; color: white; font-weight: 600;
            }}
            QPushButton#warningOk:hover {{ background: {colors.blue_hover}; }}
        """  # noqa: E501 -- embedded Qt stylesheet
