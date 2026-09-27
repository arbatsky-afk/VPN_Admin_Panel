"""Fixed delayed server reboot operation."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from ..ssh import validate_server_ip
from ..ssh_settings import SshConnectionSettings, SshSettingsError, primary_ssh_connection
from ..ssh_transport import (
    SshCancelledError,
    SshCommand,
    SshLaunchError,
    SshTimeoutError,
    SshTimeoutProfile,
    run_buffered_ssh,
)
from .errors import ManagementError, ManagementIndeterminateError, ManagementLaunchError


class SshServerRebootTransport:
    """Schedule a server reboot only after SSH has acknowledged the fixed request."""

    _REMOTE_COMMAND = (
        "systemd-run --quiet --unit=vpn-admin-panel-reboot --on-active=2s /bin/systemctl reboot"
    )

    def __init__(
        self,
        server_ip: str,
        private_key: Path,
        ssh_port: int = 22,
        timeout_seconds: int = 20,
        cancelled: Callable[[], bool] | None = None,
    ) -> None:
        server_ip, validation_error = validate_server_ip(server_ip)
        if validation_error:
            raise ManagementError(validation_error)
        if not private_key.is_file():
            raise ManagementError("The configured SSH private key could not be found.")
        if not 1 <= ssh_port <= 65535:
            raise ManagementError("The SSH port is outside the valid range.")
        self.server_ip = server_ip
        self.private_key = private_key
        self.ssh_port = ssh_port
        self.timeout_seconds = timeout_seconds
        self.cancelled = cancelled

    def execute(self) -> None:
        try:
            result = run_buffered_ssh(
                SshCommand(
                    self.server_ip,
                    SshConnectionSettings(self.private_key, self.ssh_port),
                    (self._REMOTE_COMMAND,),
                    SshTimeoutProfile(
                        connect_timeout_seconds=self.timeout_seconds,
                        total_timeout_seconds=self.timeout_seconds + 10,
                    ),
                ),
                cancelled=self.cancelled,
            )
        except SshLaunchError as error:
            raise ManagementLaunchError(
                "SSH server reboot request could not be launched."
            ) from error
        except (SshCancelledError, SshTimeoutError) as error:
            raise ManagementIndeterminateError(
                "timeout", "Server reboot request timed out; scheduling is unknown."
            ) from error
        if result.returncode != 0:
            raise ManagementIndeterminateError(
                "connection_lost",
                "Server reboot scheduling was not acknowledged.",
            )


def schedule_server_reboot(
    project_directory: Path, server_ip: str, *, cancelled: Callable[[], bool] | None = None
) -> None:
    """Acknowledge a delayed systemd reboot before the SSH connection closes."""
    try:
        connection = primary_ssh_connection(project_directory)
    except SshSettingsError as error:
        raise ManagementError(f"Could not read local SSH configuration: {error}") from error
    SshServerRebootTransport(
        server_ip, connection.private_key_path, connection.port, cancelled=cancelled
    ).execute()
