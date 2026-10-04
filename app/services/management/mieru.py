"""Fixed Mieru inspection, service actions, and port mutation."""

from __future__ import annotations

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
from .connection_validation import validate_mieru_port
from .contracts import (
    MIERU_ACTIONS,
    ManagementMutationResult,
    MieruAction,
    MieruManagementStatus,
    ServiceManagementStatus,
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


def _mieru_validator_source() -> str:
    path = (
        Path(__file__).parents[3]
        / "scripts"
        / "ubuntu"
        / "modular-deployment"
        / "lib"
        / "mieru_config.py"
    )
    try:
        return (
            path.read_text(encoding="utf-8")
            .replace("from __future__ import annotations\n", "")
            .partition('\nif __name__ == "__main__":\n')[0]
        )
    except OSError as error:
        raise ManagementError("Could not read the Mieru recovery validator.") from error


def _port_contract_source() -> str:
    path = (
        Path(__file__).parents[3]
        / "scripts"
        / "ubuntu"
        / "modular-deployment"
        / "lib"
        / "port_contract.py"
    )
    try:
        return (
            path.read_text(encoding="utf-8")
            .replace("from __future__ import annotations\n", "")
            .partition('\nif __name__ == "__main__":\n')[0]
        )
    except OSError as error:
        raise ManagementError("Could not read the component port contract.") from error


REMOTE_MIERU_MANAGEMENT_SCRIPT = (
    _mieru_validator_source()
    + "\n"
    + _port_contract_source()
    + "\nALLOWED_MIERU_ACTIONS = "
    + _remote_action_set(MIERU_ACTIONS)
    + "\n\n"
    + load_remote_source(
        "manage_mieru.py",
        source_kind="Management",
        exception_type=ManagementError,
    )
)


class SshMieruManagementTransport:
    """Run one fixed Mieru operation and return no credential material."""

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

    def execute(self, action: MieruAction) -> MieruManagementStatus:
        if action not in MIERU_ACTIONS:
            raise ManagementError("Unsupported Mieru action.")
        python_command = (
            "import sys;exec(compile(sys.stdin.buffer.read(), '<management>', 'exec'))"
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
                input_text=REMOTE_MIERU_MANAGEMENT_SCRIPT,
                cancelled=self.cancelled,
            )
        except SshLaunchError as error:
            raise ManagementLaunchError("SSH Mieru operation could not be launched.") from error
        except (SshCancelledError, SshTimeoutError) as error:
            raise ManagementIndeterminateError(
                "timeout", "Mieru operation timed out; the server state is unknown."
            ) from error
        response = self._response_mieru(result, action)
        try:
            return self._parse_mieru_status(response)
        except ManagementError as error:
            raise ManagementIndeterminateError("invalid_response", str(error)) from error

    @staticmethod
    def _response_mieru(result: SshCompletedProcess, action: str) -> dict[str, object]:
        try:
            response = json.loads(result.stdout)
        except json.JSONDecodeError as error:
            raise ManagementIndeterminateError(
                _response_failure_reason(result), "The remote Mieru response is invalid."
            ) from error
        if not isinstance(response, dict):
            raise ManagementIndeterminateError(
                "invalid_response", "The remote Mieru response must be an object."
            )
        error = response.get("error")
        if isinstance(error, str) and error:
            _raise_remote_response_error(result, action, error)
        if result.returncode != 0:
            raise ManagementIndeterminateError(
                _response_failure_reason(result),
                f"Mieru {action} returned no authoritative result.",
            )
        return response

    @staticmethod
    def _parse_mieru_status(response: dict[str, object]) -> MieruManagementStatus:
        service = SshMieruManagementTransport._parse_service(response.get("service"), "Mieru")
        runtime_state = response.get("runtime_state")
        transport = response.get("transport")
        port = response.get("port")
        mtu = response.get("mtu")
        user_count = response.get("user_count")
        if (
            runtime_state not in {"RUNNING", "IDLE", "unknown"}
            or transport not in {"TCP", "UDP"}
            or type(port) is not int
            or not 1025 <= port <= 65535
            or type(mtu) is not int
            or not 1280 <= mtu <= 9000
            or type(user_count) is not int
            or user_count < 1
        ):
            raise ManagementError("The remote Mieru response has invalid public details.")
        return MieruManagementStatus(service, runtime_state, transport, port, mtu, user_count)

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


def manage_mieru(
    project_directory: Path,
    server_ip: str,
    action: MieruAction,
    *,
    cancelled: Callable[[], bool] | None = None,
) -> MieruManagementStatus:
    """Execute one whitelisted Mieru service action through a fresh SSH call."""
    try:
        connection = primary_ssh_connection(project_directory)
    except SshSettingsError as error:
        raise ManagementError(f"Could not read local SSH configuration: {error}") from error
    return SshMieruManagementTransport(
        server_ip,
        connection.private_key_path,
        connection.port,
        cancelled=cancelled,
    ).execute(action)


REMOTE_MIERU_PORT_UPDATE_SCRIPT = (
    _mieru_validator_source()
    + "\n"
    + _port_contract_source()
    + "\n"
    + load_remote_source(
        "update_mieru_port.py",
        source_kind="Management",
        exception_type=ManagementError,
    )
)


class SshMieruPortUpdateTransport(SshMieruManagementTransport):
    """Apply one rollback-capable Mieru Port update over a fresh SSH call."""

    def execute(self, port: int) -> ManagementMutationResult:
        port = validate_mieru_port(port)
        python_command = (
            "import sys;exec(compile(sys.stdin.buffer.read(), '<management>', 'exec'))"
        )
        remote_command = f"python3 -c {shlex.quote(python_command)} {port}"
        try:
            result = run_buffered_ssh(
                SshCommand(
                    self.server_ip,
                    SshConnectionSettings(self.private_key, self.ssh_port),
                    (remote_command,),
                    SshTimeoutProfile.short_operation(self.timeout_seconds),
                ),
                input_text=REMOTE_MIERU_PORT_UPDATE_SCRIPT,
                cancelled=self.cancelled,
            )
        except (SshCancelledError, SshTimeoutError) as error:
            return self._unknown_result(f"SSH Mieru port update timed out: {error}")
        except SshLaunchError as error:
            raise ManagementError(f"SSH Mieru port update could not run: {error}") from error
        return self._parse_mutation_result(
            result,
            "Mieru",
            self._parse_mieru_status,
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


def update_mieru_port(
    project_directory: Path,
    server_ip: str,
    port: int,
    *,
    cancelled: Callable[[], bool] | None = None,
) -> ManagementMutationResult:
    """Apply a server-side Mieru Port transaction and return its confirmed result."""
    port = validate_mieru_port(port)
    try:
        connection = primary_ssh_connection(project_directory)
        result = SshMieruPortUpdateTransport(
            server_ip,
            connection.private_key_path,
            connection.port,
            cancelled=cancelled,
        ).execute(port)
    except (SshSettingsError, OSError) as error:
        raise ManagementError(f"Could not update the Mieru port: {error}") from error
    if result.outcome == "success":
        if not isinstance(result.status, MieruManagementStatus):
            raise ManagementError(
                "The successful Mieru port update omitted its confirmed server status."
            )
    return result
