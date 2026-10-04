"""Fixed Hysteria2 inspection, service actions, and connection mutation."""

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
    format_ssh_error_detail,
    run_buffered_ssh,
)
from .connection_validation import validate_connection_settings
from .contracts import (
    HYSTERIA2_ACTIONS,
    Hysteria2ManagementStatus,
    ManagementMutationResult,
    ServiceManagementStatus,
    XrayAction,
)
from .errors import (
    ManagementError,
    ManagementIndeterminateError,
    ManagementLaunchError,
    _raise_remote_response_error,
    _response_failure_reason,
)

_MANAGEMENT_MUTATION_OUTCOMES = frozenset({"success", "rolled_back", "partial", "unknown"})
_MANAGEMENT_MUTATION_STATES = frozenset({"applied", "restored", "unknown"})


def _remote_action_set(actions: frozenset[str]) -> str:
    return "{" + ", ".join(repr(action) for action in sorted(actions)) + "}"


def _hysteria2_validator_source() -> str:
    path = (
        Path(__file__).parents[3]
        / "scripts"
        / "ubuntu"
        / "modular-deployment"
        / "lib"
        / "hysteria2_config.py"
    )
    try:
        return path.read_text(encoding="utf-8").partition('\nif __name__ == "__main__":\n')[0]
    except OSError as error:
        raise ManagementError("Could not read the Hysteria2 configuration validator.") from error


REMOTE_HYSTERIA2_MANAGEMENT_SCRIPT = (
    _hysteria2_validator_source()
    + "\n"
    + load_remote_source(
        "manage_hysteria2.py",
        source_kind="Management",
        exception_type=ManagementError,
    ).replace("__MANAGEMENT_ACTIONS__", _remote_action_set(HYSTERIA2_ACTIONS))
)


class SshHysteria2ManagementTransport:
    """Run one fixed Hysteria2 operation and return only non-secret connection data."""

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

    def execute(self, action: XrayAction) -> Hysteria2ManagementStatus:
        if action not in HYSTERIA2_ACTIONS:
            raise ManagementError("Unsupported Hysteria2 action.")
        encoded_script = base64.b64encode(
            REMOTE_HYSTERIA2_MANAGEMENT_SCRIPT.encode("utf-8")
        ).decode("ascii")
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
            raise ManagementLaunchError(
                "SSH Hysteria2 operation could not be launched."
            ) from error
        except (SshCancelledError, SshTimeoutError) as error:
            raise ManagementIndeterminateError(
                "timeout", "Hysteria2 operation timed out; the server state is unknown."
            ) from error
        response = self._response_hysteria(result, action)
        try:
            return self._parse_hysteria_status(response)
        except ManagementError as error:
            raise ManagementIndeterminateError("invalid_response", str(error)) from error

    @staticmethod
    def _response_hysteria(result: SshCompletedProcess, action: str) -> dict[str, object]:
        try:
            response = json.loads(result.stdout)
        except json.JSONDecodeError as error:
            raise ManagementIndeterminateError(
                _response_failure_reason(result), "The remote Hysteria2 response is invalid."
            ) from error
        if not isinstance(response, dict):
            raise ManagementIndeterminateError(
                "invalid_response", "The remote Hysteria2 response must be an object."
            )
        error = response.get("error")
        if isinstance(error, str) and error:
            _raise_remote_response_error(result, action, error)
        if result.returncode != 0:
            raise ManagementIndeterminateError(
                _response_failure_reason(result),
                f"Hysteria2 {action} returned no authoritative result.",
            )
        return response

    @staticmethod
    def _parse_hysteria_status(response: dict[str, object]) -> Hysteria2ManagementStatus:
        service = SshHysteria2ManagementTransport._parse_service(
            response.get("service"), "Hysteria2"
        )
        protocol, port, sni = response.get("protocol"), response.get("port"), response.get("sni")
        if (
            protocol != "Hysteria2 · QUIC · TLS · Salamander"
            or isinstance(port, bool)
            or not isinstance(port, int)
            or not 1 <= port <= 65535
            or not isinstance(sni, str)
            or not sni
        ):
            raise ManagementError("The remote Hysteria2 response has invalid connection details.")
        return Hysteria2ManagementStatus(service, protocol, port, sni)

    @staticmethod
    def _parse_service(value: object, name: str) -> ServiceManagementStatus:
        if not isinstance(value, dict):
            raise ManagementError(f"The remote Base + Security response has no {name} status.")
        service_state = value.get("service_state")
        startup_state = value.get("startup_state")
        service_states = {"active", "inactive", "failed", "activating", "deactivating", "unknown"}
        startup_states = {"enabled", "disabled", "static", "indirect", "masked", "unknown"}
        if not isinstance(service_state, str) or service_state not in service_states:
            raise ManagementError(
                f"The remote Base + Security response has an invalid {name} service state."
            )
        if not isinstance(startup_state, str) or startup_state not in startup_states:
            raise ManagementError(
                f"The remote Base + Security response has an invalid {name} startup state."
            )
        return ServiceManagementStatus(service_state, startup_state)


def manage_hysteria2(
    project_directory: Path,
    server_ip: str,
    action: XrayAction,
    *,
    cancelled: Callable[[], bool] | None = None,
) -> Hysteria2ManagementStatus:
    """Execute one whitelisted Hysteria2 service action through a fresh SSH call."""
    try:
        connection = primary_ssh_connection(project_directory)
    except SshSettingsError as error:
        raise ManagementError(f"Could not read local SSH configuration: {error}") from error
    return SshHysteria2ManagementTransport(
        server_ip, connection.private_key_path, connection.port, cancelled=cancelled
    ).execute(action)


REMOTE_HYSTERIA2_CONNECTION_UPDATE_SCRIPT = (
    _hysteria2_validator_source()
    + "\n"
    + load_remote_source(
        "update_hysteria2_connection.py",
        source_kind="Management",
        exception_type=ManagementError,
    )
)


class SshHysteria2ConnectionUpdateTransport(SshHysteria2ManagementTransport):
    """Apply one fixed, rollback-capable Hysteria2 Port/SNI update over SSH."""

    def execute(self, port: int, sni: str) -> ManagementMutationResult:
        port, sni = validate_connection_settings("Hysteria2", "UDP", port, sni)
        encoded_script = base64.b64encode(
            REMOTE_HYSTERIA2_CONNECTION_UPDATE_SCRIPT.encode("utf-8")
        ).decode("ascii")
        python_command = (
            "import base64;exec(compile(base64.b64decode("
            + repr(encoded_script)
            + "), '<management>', 'exec'))"
        )
        remote_command = f"python3 -c {shlex.quote(python_command)} {port} {shlex.quote(sni)}"
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
        except (SshCancelledError, SshTimeoutError) as error:
            return self._unknown_result(f"SSH Hysteria2 update timed out: {error}")
        except SshLaunchError as error:
            raise ManagementError(f"SSH Hysteria2 update could not run: {error}") from error
        return self._parse_mutation_result(
            result,
            "Hysteria2",
            self._parse_hysteria_status,
        )

    @staticmethod
    def _unknown_result(message: str) -> ManagementMutationResult:
        return ManagementMutationResult("unknown", message, "unknown", "unknown", "unknown")

    @classmethod
    def _parse_mutation_result(
        cls,
        result: SshCompletedProcess,
        component: str,
        parse_status,
    ) -> ManagementMutationResult:
        try:
            response = json.loads(result.stdout)
        except json.JSONDecodeError:
            detail = format_ssh_error_detail(result.stderr)
            suffix = f" Details: {detail}" if detail else ""
            return cls._unknown_result(
                f"The remote {component} update result is unknown "
                f"(exit code {result.returncode}).{suffix}"
            )
        if not isinstance(response, dict):
            return cls._unknown_result(f"The remote {component} update result is not an object.")
        error = response.get("error")
        if isinstance(error, str) and error:
            raise ManagementError(error)
        outcome = response.get("outcome")
        message = response.get("message")
        states = response.get("states")
        if (
            outcome not in _MANAGEMENT_MUTATION_OUTCOMES
            or not isinstance(message, str)
            or not message
            or not isinstance(states, dict)
        ):
            return cls._unknown_result(
                f"The remote {component} update returned an invalid transaction result."
            )
        config_state = states.get("config")
        firewall_state = states.get("firewall")
        service_state = states.get("service")
        if any(
            state not in _MANAGEMENT_MUTATION_STATES
            for state in (config_state, firewall_state, service_state)
        ):
            return cls._unknown_result(
                f"The remote {component} update returned invalid transaction states."
            )
        status = None
        if outcome == "success":
            status_value = response.get("status")
            if not isinstance(status_value, dict):
                return cls._unknown_result(
                    f"The remote {component} update omitted its resulting status."
                )
            try:
                status = parse_status(status_value)
            except ManagementError:
                return cls._unknown_result(
                    f"The remote {component} update returned an invalid resulting status."
                )
        return ManagementMutationResult(
            outcome,  # type: ignore[arg-type]
            message,
            config_state,  # type: ignore[arg-type]
            firewall_state,  # type: ignore[arg-type]
            service_state,  # type: ignore[arg-type]
            status,
        )


def update_hysteria2_connection(
    project_directory: Path,
    server_ip: str,
    port: int,
    sni: str,
    *,
    cancelled: Callable[[], bool] | None = None,
) -> ManagementMutationResult:
    """Apply the server-side Hysteria2 transaction and return its confirmed result."""
    port, sni = validate_connection_settings("Hysteria2", "UDP", port, sni)
    try:
        connection = primary_ssh_connection(project_directory)
        result = SshHysteria2ConnectionUpdateTransport(
            server_ip, connection.private_key_path, connection.port, cancelled=cancelled
        ).execute(port, sni)
    except (SshSettingsError, OSError) as error:
        raise ManagementError(
            f"Could not update Hysteria2 connection settings: {error}"
        ) from error
    if result.outcome == "success":
        if not isinstance(result.status, Hysteria2ManagementStatus):
            raise ManagementError(
                "The successful Hysteria2 update omitted its confirmed server status."
            )
    return result
