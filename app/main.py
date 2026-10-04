"""Application entry point."""

from __future__ import annotations

import sys

from PySide6.QtCore import QDir, QLockFile, QStandardPaths
from PySide6.QtWidgets import QApplication, QMessageBox

from common.ui.tray_startup import should_show_window_on_start

from .services.settings_manager import SettingsManager
from .ui.main_window import MainWindow


def run() -> None:
    application = QApplication(sys.argv)
    application.setQuitOnLastWindowClosed(False)
    application.setApplicationName("VPN Admin Panel")
    data_directory = QStandardPaths.writableLocation(
        QStandardPaths.StandardLocation.AppLocalDataLocation
    )
    QDir().mkpath(data_directory)
    instance_lock = QLockFile(QDir(data_directory).filePath("vpn-admin-panel.lock"))
    if not instance_lock.tryLock(0):
        QMessageBox.warning(None, "VPN Admin Panel", "VPN Admin Panel is already running.")
        return

    try:
        settings = SettingsManager()
        settings.ensure_netdata_cloud_defaults()
        window = MainWindow(settings=settings)
        if should_show_window_on_start(
            start_minimized_to_tray=window.settings.start_minimized_to_tray(),
            system_tray_available=window.tray_icon is not None,
        ):
            window.show()
        sys.exit(application.exec())
    finally:
        instance_lock.unlock()
