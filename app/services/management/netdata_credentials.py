"""Local read-only Netdata access details."""

from pathlib import Path

from ..ssh import validate_server_ip
from .contracts import NetdataAccessDetails
from .errors import ManagementError


def load_netdata_access_details(project_directory: Path, server_ip: str) -> NetdataAccessDetails:
    """Build one server's fixed HTTPS Netdata dashboard URL."""
    del project_directory
    normalized_ip, validation_error = validate_server_ip(server_ip)
    if validation_error or normalized_ip != server_ip:
        raise ManagementError(validation_error or "The Netdata server IP must be normalized.")
    return NetdataAccessDetails(f"https://{normalized_ip}/netdata/")
