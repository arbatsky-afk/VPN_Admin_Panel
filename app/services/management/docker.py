"""Fixed Docker inspection and service actions."""

from __future__ import annotations

import base64
import json
import re
import shlex
from collections.abc import Callable
from pathlib import Path

from .._remote_source import load_remote_source
from ..ssh import validate_server_ip
from ..ssh_settings import SshConnectionSettings, SshSettingsError, primary_ssh_connection
from ..ssh_transport import (
    SshCancelledError,
    SshCommand,
    SshCompletedProcess,
    SshLaunchError,
    SshTimeoutError,
    SshTimeoutProfile,
    run_buffered_ssh,
)
from .contracts import DOCKER_ACTIONS, DockerAction, DockerManagementStatus, PublishedUdpPort
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
_AMNEZIA_STATES = frozenset({"detected", "not_detected", "unknown"})
_CONTAINER_STATE = re.compile(r"^[a-z][a-z-]{0,31}$")


def _remote_action_set(actions: frozenset[str]) -> str:
    return "{" + ", ".join(repr(action) for action in sorted(actions)) + "}"


REMOTE_DOCKER_MANAGEMENT_SCRIPT = load_remote_source(
    "manage_docker.py",
    source_kind="Management",
    exception_type=ManagementError,
).replace("__MANAGEMENT_ACTIONS__", _remote_action_set(DOCKER_ACTIONS))


class SshDockerManagementTransport:
    """Run one fixed Docker operation and return its narrow JSON result."""

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

    def execute(self, action: DockerAction) -> DockerManagementStatus:
        if action not in DOCKER_ACTIONS:
            raise ManagementError("Unsupported Docker action.")
        encoded_script = base64.b64encode(REMOTE_DOCKER_MANAGEMENT_SCRIPT.encode("utf-8")).decode(
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
            raise ManagementLaunchError("SSH Docker operation could not be launched.") from error
        except (SshCancelledError, SshTimeoutError) as error:
            raise ManagementIndeterminateError(
                "timeout", "Docker operation timed out; the server state is unknown."
            ) from error
        response = self._response(result, action)
        try:
            return self._parse_status(response)
        except ManagementError as error:
            raise ManagementIndeterminateError("invalid_response", str(error)) from error

    def _response(self, result: SshCompletedProcess, action: DockerAction) -> dict[str, object]:
        try:
            response = json.loads(result.stdout)
        except json.JSONDecodeError as error:
            raise ManagementIndeterminateError(
                _response_failure_reason(result), "The remote Docker response is invalid."
            ) from error
        if not isinstance(response, dict):
            raise ManagementIndeterminateError(
                "invalid_response", "The remote Docker response must be an object."
            )
        error = response.get("error")
        if isinstance(error, str) and error:
            _raise_remote_response_error(result, action, error)
        if result.returncode != 0:
            raise ManagementIndeterminateError(
                _response_failure_reason(result),
                f"Docker {action} returned no authoritative result.",
            )
        return response

    @staticmethod
    def _parse_status(response: dict[str, object]) -> DockerManagementStatus:
        service_state = response.get("service_state")
        startup_state = response.get("startup_state")
        amnezia = response.get("amnezia")
        if not isinstance(service_state, str) or service_state not in _SERVICE_STATES:
            raise ManagementError("The remote Docker response has an invalid service state.")
        if not isinstance(startup_state, str) or startup_state not in _STARTUP_STATES:
            raise ManagementError("The remote Docker response has an invalid startup state.")
        if not isinstance(amnezia, dict):
            raise ManagementError("The remote Docker response has no Amnezia status.")
        amnezia_state = amnezia.get("state")
        container_state = amnezia.get("container_state")
        ports = amnezia.get("udp_ports")
        if not isinstance(amnezia_state, str) or amnezia_state not in _AMNEZIA_STATES:
            raise ManagementError("The remote Docker response has an invalid Amnezia state.")
        if container_state is not None and (
            not isinstance(container_state, str) or not _CONTAINER_STATE.fullmatch(container_state)
        ):
            raise ManagementError(
                "The remote Docker response has an invalid Amnezia container state."
            )
        if not isinstance(ports, list):
            raise ManagementError("The remote Docker response has invalid Amnezia ports.")
        parsed_ports: list[PublishedUdpPort] = []
        for port in ports:
            if not isinstance(port, dict):
                raise ManagementError("The remote Docker response has invalid Amnezia ports.")
            host_address = port.get("host_address")
            host_port = port.get("port")
            if (
                not isinstance(host_address, str)
                or not host_address
                or isinstance(host_port, bool)
                or not isinstance(host_port, int)
                or not 1 <= host_port <= 65535
            ):
                raise ManagementError("The remote Docker response has invalid Amnezia ports.")
            parsed_ports.append(PublishedUdpPort(host_address, host_port))
        return DockerManagementStatus(
            service_state,
            startup_state,
            amnezia_state,
            container_state,
            tuple(sorted(set(parsed_ports), key=lambda item: (item.port, item.host_address))),
        )


def manage_docker(
    project_directory: Path,
    server_ip: str,
    action: DockerAction,
    *,
    cancelled: Callable[[], bool] | None = None,
) -> DockerManagementStatus:
    """Execute one whitelisted Docker service action through a fresh SSH call."""
    try:
        connection = primary_ssh_connection(project_directory)
    except SshSettingsError as error:
        raise ManagementError(f"Could not read local SSH configuration: {error}") from error
    return SshDockerManagementTransport(
        server_ip, connection.private_key_path, connection.port, cancelled=cancelled
    ).execute(action)
