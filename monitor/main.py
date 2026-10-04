from __future__ import annotations

import sys
from pathlib import Path

from PySide6.QtCore import QDir, QLockFile, QStandardPaths
from PySide6.QtGui import QIcon
from PySide6.QtWidgets import QApplication, QMessageBox, QStyle, QSystemTrayIcon

from common.ui.tray_startup import should_show_window_on_start
from monitor.coordinator import MonitorCoordinator
from monitor.settings import MonitorPaths
from monitor.ui.main_window import MonitorBridge, MonitorWindow

MONITOR_ICON_PATH = Path(__file__).resolve().parents[1] / "assets" / "icons" / "vpn-monitor.ico"


def configure_application_icon(application: QApplication) -> QIcon:
    icon = QIcon(str(MONITOR_ICON_PATH))
    if icon.isNull():
        icon = application.style().standardIcon(QStyle.StandardPixmap.SP_ComputerIcon)
    application.setWindowIcon(icon)
    return icon


def main() -> int:
    app = QApplication(sys.argv)
    app.setApplicationName("VPN Admin Panel Monitor")
    app.setQuitOnLastWindowClosed(False)
    configure_application_icon(app)
    data_directory = QStandardPaths.writableLocation(
        QStandardPaths.StandardLocation.AppLocalDataLocation
    )
    QDir().mkpath(data_directory)
    instance_lock = QLockFile(QDir(data_directory).filePath("vpn-admin-panel-monitor.lock"))
    if not instance_lock.tryLock(0):
        QMessageBox.warning(None, "Monitoring", "Monitor is already running.")
        return 1
    try:
        paths = MonitorPaths.default()
        bridge = MonitorBridge()
        coordinator = MonitorCoordinator(
            paths,
            on_snapshot=bridge.snapshot_received.emit,
            on_cycle=bridge.cycle_changed.emit,
            on_telegram_status=bridge.telegram_status_changed.emit,
        )
        window = MonitorWindow(coordinator, bridge)
        app.aboutToQuit.connect(coordinator.stop)
        if should_show_window_on_start(
            start_minimized_to_tray=coordinator.settings.start_minimized_to_tray,
            system_tray_available=QSystemTrayIcon.isSystemTrayAvailable(),
        ):
            window.show()
        coordinator.start()
        return app.exec()
    except Exception as error:  # noqa: BLE001 - top-level GUI failure boundary
        QMessageBox.critical(None, "Monitoring", str(error))
        return 2
    finally:
        instance_lock.unlock()


if __name__ == "__main__":
    raise SystemExit(main())
