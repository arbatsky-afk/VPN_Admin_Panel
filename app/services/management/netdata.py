"""Fixed Netdata inspection and service actions."""

from __future__ import annotations

import base64
import json
import shlex
from collections.abc import Callable
from pathlib import Path

from .._remote_source import load_remote_source
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
from .contracts import (
    NETDATA_ACTIONS,
    NetdataAction,
    NetdataManagementStatus,
    ServiceManagementStatus,
)
from .errors import (
    ManagementError,
    ManagementIndeterminateError,
    ManagementLaunchError,
    _raise_remote_response_error,
    _response_failure_reason,
)

_SERVICE_STATES = frozenset(
    {"active", "inactive", "failed", "activating", "deactivating", "unknown"}
)
_STARTUP_STATES = frozenset({"enabled", "disabled", "static", "indirect", "masked", "unknown"})


def _remote_action_set(actions: frozenset[str]) -> str:
    return "{" + ", ".join(repr(action) for action in sorted(actions)) + "}"


REMOTE_NETDATA_MANAGEMENT_SCRIPT = load_remote_source(
    "manage_netdata.py",
    source_kind="Management",
    exception_type=ManagementError,
).replace("__MANAGEMENT_ACTIONS__", _remote_action_set(NETDATA_ACTIONS))


class SshNetdataManagementTransport:
    """Run one fixed Netdata operation and return its narrow typed status."""

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

    def execute(self, action: NetdataAction) -> NetdataManagementStatus:
        if action not in NETDATA_ACTIONS:
            raise ManagementError("Unsupported Netdata action.")
        encoded_script = base64.b64encode(REMOTE_NETDATA_MANAGEMENT_SCRIPT.encode("utf-8")).decode(
            "ascii"
        )
        python_command = (
            "import base64;exec(compile(base64.b64decode("
            + repr(encoded_script)
            + "), '<management>', 'exec'))"
        )
        remote_command = f"python3 -c {shlex.quote(python_command)} {action}"
        try:
            result = run_buffered_ssh(
                SshCommand(
                    self.server_ip,
                    SshConnectionSettings(self.private_key, self.ssh_port),
                    (remote_command,),
                    SshTimeoutProfile.short_operation(self.timeout_seconds),
                ),
                cancelled=self.cancelled,
            )
        except SshLaunchError as error:
            raise ManagementLaunchError("SSH Netdata operation could not be launched.") from error
        except (SshCancelledError, SshTimeoutError) as error:
            raise ManagementIndeterminateError(
                "timeout", "Netdata operation timed out; the server state is unknown."
            ) from error
        try:
            response = json.loads(result.stdout)
        except json.JSONDecodeError as error:
            if result.returncode != 0:
                raise ManagementIndeterminateError(
                    _response_failure_reason(result),
                    f"Netdata {action} returned no authoritative result.",
                ) from error
            raise ManagementIndeterminateError(
                "invalid_response", "The remote Netdata response is invalid."
            ) from error
        if not isinstance(response, dict):
            raise ManagementIndeterminateError(
                "invalid_response", "The remote Netdata response must be an object."
            )
        remote_error = response.get("error")
        if isinstance(remote_error, str) and remote_error:
            _raise_remote_response_error(result, action, remote_error)
        if result.returncode != 0:
            raise ManagementIndeterminateError(
                _response_failure_reason(result),
                f"Netdata {action} returned no authoritative result.",
            )
        try:
            return self._parse_status(response)
        except ManagementError as error:
            raise ManagementIndeterminateError("invalid_response", str(error)) from error

    @staticmethod
    def _parse_status(response: dict[str, object]) -> NetdataManagementStatus:
        expected_keys = {
            "service",
            "listen_port",
            "bind_mode",
            "dashboard_healthy",
            "cloud_online",
            "proxy_bearer_protected",
        }
        if set(response) != expected_keys:
            raise ManagementError("The remote Netdata response has unexpected fields.")
        service = response["service"]
        if not isinstance(service, dict) or set(service) != {"service_state", "startup_state"}:
            raise ManagementError("The remote Netdata response has invalid service status.")
        service_state = service.get("service_state")
        startup_state = service.get("startup_state")
        if not isinstance(service_state, str) or service_state not in _SERVICE_STATES:
            raise ManagementError("The remote Netdata response has an invalid service state.")
        if not isinstance(startup_state, str) or startup_state not in _STARTUP_STATES:
            raise ManagementError("The remote Netdata response has an invalid startup state.")
        if response["listen_port"] != 19999 or isinstance(response["listen_port"], bool):
            raise ManagementError("The remote Netdata response has an invalid listen port.")
        if response["bind_mode"] != "localhost":
            raise ManagementError("The remote Netdata response has an invalid bind mode.")
        if not all(
            isinstance(response[key], bool)
            for key in ("dashboard_healthy", "cloud_online", "proxy_bearer_protected")
        ):
            raise ManagementError("The remote Netdata response has invalid dashboard health.")
        return NetdataManagementStatus(
            ServiceManagementStatus(service_state, startup_state),
            19999,
            "localhost",
            response["dashboard_healthy"],
            response["cloud_online"],
            response["proxy_bearer_protected"],
        )


def manage_netdata(
    project_directory: Path,
    server_ip: str,
    action: NetdataAction,
    *,
    cancelled: Callable[[], bool] | None = None,
) -> NetdataManagementStatus:
    """Execute one whitelisted Netdata service action through a fresh SSH call."""
    try:
        connection = primary_ssh_connection(project_directory)
    except SshSettingsError as error:
        raise ManagementError(f"Could not read local SSH configuration: {error}") from error
    return SshNetdataManagementTransport(
        server_ip,
        connection.private_key_path,
        connection.port,
        cancelled=cancelled,
    ).execute(action)
