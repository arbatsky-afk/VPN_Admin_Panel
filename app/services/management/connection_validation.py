"""Validation of editable public connection parameters."""

from __future__ import annotations

import ipaddress
import re

from .errors import ManagementError

_HOSTNAME = re.compile(
    r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)"
    r"(?:\.(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?))*$"
)


def validate_connection_settings(
    component: str,
    transport: str,
    port: object,
    sni: object,
) -> tuple[int, str]:
    """Validate shared editable Xray and Hysteria2 connection settings."""
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise ManagementError(f"The {component} {transport} port is outside the valid range.")
    if not isinstance(sni, str) or "." not in sni or not _HOSTNAME.fullmatch(sni):
        raise ManagementError(f"The {component} SNI must be a fully qualified hostname.")
    try:
        ipaddress.ip_address(sni)
    except ValueError:
        return port, sni
    raise ManagementError(f"The {component} SNI must be a fully qualified hostname.")


def validate_mieru_port(port: object) -> int:
    """Validate the only editable Mieru connection parameter."""
    if type(port) is not int or not 1025 <= port <= 65535:
        raise ManagementError("The Mieru port must be an integer between 1025 and 65535.")
    return port
