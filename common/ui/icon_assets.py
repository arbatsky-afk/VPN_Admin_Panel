"""Theme-aware rendering for shared local SVG action icons."""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import QByteArray, QSize, Qt
from PySide6.QtGui import QColor, QIcon, QImage, QPainter, QPixmap
from PySide6.QtSvg import QSvgRenderer

_ICONS_DIRECTORY = Path(__file__).with_name("assets") / "icons"
_ICON_SIZE = QSize(18, 18)
_APPLICATION_ICON_SIZES = (16, 20, 24, 32, 40, 48, 64, 128, 256)


def action_icon(name: str, color: str) -> QIcon:
    """Render a bundled monochrome SVG using the active theme color."""
    svg = (_ICONS_DIRECTORY / f"{name}.svg").read_text(encoding="utf-8")
    renderer = QSvgRenderer(QByteArray(svg.replace("currentColor", color).encode("utf-8")))
    pixmap = QPixmap(_ICON_SIZE)
    pixmap.fill(Qt.GlobalColor.transparent)
    painter = QPainter(pixmap)
    renderer.render(painter)
    painter.end()
    return QIcon(pixmap)


def recolor_icon_hue(icon: QIcon, color: str) -> QIcon:
    """Change saturated pixels to one hue while preserving shape and shading."""
    if icon.isNull():
        return QIcon()
    target = QColor(color)
    if not target.isValid():
        raise ValueError("Invalid icon color.")
    target_hue, target_saturation, _lightness, _alpha = target.getHsl()
    result = QIcon()
    for edge in _APPLICATION_ICON_SIZES:
        source = icon.pixmap(QSize(edge, edge))
        image = source.toImage().convertToFormat(QImage.Format.Format_ARGB32)
        for y in range(image.height()):
            for x in range(image.width()):
                pixel = image.pixelColor(x, y)
                _hue, saturation, lightness, alpha = pixel.getHsl()
                if alpha == 0 or saturation < 24:
                    continue
                image.setPixelColor(
                    x,
                    y,
                    QColor.fromHsl(
                        target_hue,
                        max(saturation, target_saturation),
                        lightness,
                        alpha,
                    ),
                )
        result.addPixmap(QPixmap.fromImage(image))
    return result
