"""Concrete presentation panels used by the Management tab facade."""

from app.ui.tabs.management_panels.base_security_panel import BaseSecurityPanel
from app.ui.tabs.management_panels.docker_panel import DockerPanel
from app.ui.tabs.management_panels.hysteria2_panel import Hysteria2Panel
from app.ui.tabs.management_panels.mieru_panel import MieruPanel
from app.ui.tabs.management_panels.netdata_panel import NetdataPanel
from app.ui.tabs.management_panels.nginx_panel import NginxPanel
from app.ui.tabs.management_panels.xray_panel import XrayPanel

__all__ = [
    "BaseSecurityPanel",
    "DockerPanel",
    "Hysteria2Panel",
    "MieruPanel",
    "NetdataPanel",
    "NginxPanel",
    "XrayPanel",
]
