"""Generate Windows shortcut icons matching the Panel and Monitor tray icons."""

from __future__ import annotations

import struct
import sys
from pathlib import Path

from PySide6.QtCore import QBuffer, QByteArray, QIODevice, QSize
from PySide6.QtGui import QIcon
from PySide6.QtWidgets import QApplication, QStyle

PROJECT_DIRECTORY = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_DIRECTORY))

from common.ui.icon_assets import recolor_icon_hue  # noqa: E402

ICON_DIRECTORY = PROJECT_DIRECTORY / "assets" / "icons"
ICON_SIZES = (16, 20, 24, 32, 40, 48, 64, 128, 256)
PANEL_ICON_COLOR = "#F97316"
FUTURE_ICON_COLOR = "#22C55E"


def _png_bytes(icon: QIcon, edge: int) -> bytes:
    pixmap = icon.pixmap(QSize(edge, edge))
    if pixmap.isNull():
        raise RuntimeError(f"Could not render the {edge}x{edge} icon.")
    data = QByteArray()
    buffer = QBuffer(data)
    if not buffer.open(QIODevice.OpenModeFlag.WriteOnly) or not pixmap.save(buffer, "PNG"):
        raise RuntimeError(f"Could not encode the {edge}x{edge} icon.")
    buffer.close()
    return bytes(data)


def _write_ico(path: Path, icon: QIcon) -> None:
    images = tuple((edge, _png_bytes(icon, edge)) for edge in ICON_SIZES)
    offset = 6 + 16 * len(images)
    entries = bytearray()
    payload = bytearray()
    for edge, image in images:
        dimension = 0 if edge == 256 else edge
        entries.extend(
            struct.pack(
                "<BBBBHHII",
                dimension,
                dimension,
                0,
                0,
                1,
                32,
                len(image),
                offset,
            )
        )
        payload.extend(image)
        offset += len(image)
    path.write_bytes(struct.pack("<HHH", 0, 1, len(images)) + entries + payload)


def main() -> int:
    application = QApplication.instance() or QApplication([])
    monitor_icon = application.style().standardIcon(QStyle.StandardPixmap.SP_ComputerIcon)
    if monitor_icon.isNull():
        raise RuntimeError("Could not load the system computer icon.")
    panel_icon = recolor_icon_hue(monitor_icon, PANEL_ICON_COLOR)
    future_icon = recolor_icon_hue(monitor_icon, FUTURE_ICON_COLOR)
    ICON_DIRECTORY.mkdir(parents=True, exist_ok=True)
    _write_ico(ICON_DIRECTORY / "vpn-monitor.ico", monitor_icon)
    _write_ico(ICON_DIRECTORY / "vpn-admin.ico", panel_icon)
    _write_ico(ICON_DIRECTORY / "vpn-green.ico", future_icon)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
