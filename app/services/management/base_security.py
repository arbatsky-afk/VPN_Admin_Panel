"""Fixed Base and Security inspection and service actions."""

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
    SshCompletedProcess,
    SshLaunchError,
    SshTimeoutError,
    SshTimeoutProfile,
    run_buffered_ssh,
)
from .contracts import (
    BASE_SECURITY_ACTIONS,
    BASE_SECURITY_SERVICES,
    AllowedInboundPort,
    BaseSecurityAction,
    BaseSecurityManagementStatus,
    BaseSecurityService,
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
_PORT_PROTOCOLS = frozenset({"tcp", "udp"})


def _remote_action_set(actions: frozenset[str]) -> str:
    return "{" + ", ".join(repr(action) for action in sorted(actions)) + "}"


REMOTE_BASE_SECURITY_MANAGEMENT_SCRIPT = load_remote_source(
    "manage_base_security.py",
    source_kind="Management",
    exception_type=ManagementError,
).replace("__MANAGEMENT_ACTIONS__", _remote_action_set(BASE_SECURITY_ACTIONS))


class SshBaseSecurityManagementTransport:
    """Run one fixed Base + Security operation and return its narrow JSON result."""

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

    def execute(
        self, service: BaseSecurityService, action: BaseSecurityAction
    ) -> BaseSecurityManagementStatus:
        if service not in BASE_SECURITY_SERVICES or action not in BASE_SECURITY_ACTIONS:
            raise ManagementError("Unsupported Base + Security action.")
        encoded_script = base64.b64encode(
            REMOTE_BASE_SECURITY_MANAGEMENT_SCRIPT.encode("utf-8")
        ).decode("ascii")
        python_command = (
            "import base64;exec(compile(base64.b64decode("
            + repr(encoded_script)
            + "), '<management>', 'exec'))"
        )
        remote_command = f"python3 -c {shlex.quote(python_command)} {action} {service}"
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
            raise ManagementLaunchError(
                "SSH Base + Security operation could not be launched."
            ) from error
        except (SshCancelledError, SshTimeoutError) as error:
            raise ManagementIndeterminateError(
                "timeout", "Base + Security operation timed out; the server state is unknown."
            ) from error
        response = self._response(result, action)
        try:
            return self._parse_status(response)
        except ManagementError as error:
            raise ManagementIndeterminateError("invalid_response", str(error)) from error

    def _response(
        self, result: SshCompletedProcess, action: BaseSecurityAction
    ) -> dict[str, object]:
        try:
            response = json.loads(result.stdout)
        except json.JSONDecodeError as error:
            raise ManagementIndeterminateError(
                _response_failure_reason(result), "The remote Base + Security response is invalid."
            ) from error
        if not isinstance(response, dict):
            raise ManagementIndeterminateError(
                "invalid_response", "The remote Base + Security response must be an object."
            )
        error = response.get("error")
        if isinstance(error, str) and error:
            _raise_remote_response_error(result, action, error)
        if result.returncode != 0:
            raise ManagementIndeterminateError(
                _response_failure_reason(result),
                f"Base + Security {action} returned no authoritative result.",
            )
        return response

    @staticmethod
    def _parse_status(response: dict[str, object]) -> BaseSecurityManagementStatus:
        nftables = SshBaseSecurityManagementTransport._parse_service(
            response.get("nftables"), "nftables"
        )
        fail2ban = SshBaseSecurityManagementTransport._parse_service(
            response.get("fail2ban"), "Fail2Ban"
        )
        ports = response.get("allowed_ports")
        if not isinstance(ports, list):
            raise ManagementError("The remote Base + Security response has invalid allowed ports.")
        parsed_ports: list[AllowedInboundPort] = []
        for port in ports:
            if not isinstance(port, dict):
                raise ManagementError(
                    "The remote Base + Security response has invalid allowed ports."
                )
            protocol = port.get("protocol")
            number = port.get("port")
            owner = port.get("owner")
            source = port.get("source")
            if (
                not isinstance(protocol, str)
                or protocol not in _PORT_PROTOCOLS
                or isinstance(number, bool)
                or not isinstance(number, int)
                or not 1 <= number <= 65535
                or (owner is not None and (not isinstance(owner, str) or not owner))
                or not isinstance(source, str)
                or source not in {"nftables", "docker"}
            ):
                raise ManagementError(
                    "The remote Base + Security response has invalid allowed ports."
                )
            parsed_ports.append(AllowedInboundPort(protocol, number, owner, source))
        return BaseSecurityManagementStatus(
            nftables,
            fail2ban,
            tuple(
                sorted(
                    set(parsed_ports),
                    key=lambda item: (item.port, item.protocol, item.source, item.owner or ""),
                )
            ),
        )

    @staticmethod
    def _parse_service(value: object, name: str) -> ServiceManagementStatus:
        if not isinstance(value, dict):
            raise ManagementError(f"The remote Base + Security response has no {name} status.")
        service_state = value.get("service_state")
        startup_state = value.get("startup_state")
        if not isinstance(service_state, str) or service_state not in _SERVICE_STATES:
            raise ManagementError(
                f"The remote Base + Security response has an invalid {name} service state."
            )
        if not isinstance(startup_state, str) or startup_state not in _STARTUP_STATES:
            raise ManagementError(
                f"The remote Base + Security response has an invalid {name} startup state."
            )
        return ServiceManagementStatus(service_state, startup_state)


def manage_base_security(
    project_directory: Path,
    server_ip: str,
    service: BaseSecurityService,
    action: BaseSecurityAction,
    *,
    cancelled: Callable[[], bool] | None = None,
) -> BaseSecurityManagementStatus:
    """Execute one whitelisted Base + Security service action through a fresh SSH call."""
    try:
        connection = primary_ssh_connection(project_directory)
    except SshSettingsError as error:
        raise ManagementError(f"Could not read local SSH configuration: {error}") from error
    return SshBaseSecurityManagementTransport(
        server_ip, connection.private_key_path, connection.port, cancelled=cancelled
    ).execute(service, action)
