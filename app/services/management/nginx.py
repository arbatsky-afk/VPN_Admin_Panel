"""Fixed Nginx inspection and service actions."""

from __future__ import annotations

import base64
import ipaddress
import json
import re
import shlex
from collections.abc import Callable
from datetime import datetime, timezone
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
from .contracts import NGINX_ACTIONS, NginxAction, NginxManagementStatus, ServiceManagementStatus
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
_LOWERCASE_DNS_NAME = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"
)


def _valid_lowercase_dns_name(value: str) -> bool:
    return (
        any(character.isalpha() for character in value)
        and _LOWERCASE_DNS_NAME.fullmatch(value) is not None
    )


def _remote_action_set(actions: frozenset[str]) -> str:
    return "{" + ", ".join(repr(action) for action in sorted(actions)) + "}"


REMOTE_NGINX_MANAGEMENT_SCRIPT = load_remote_source(
    "manage_nginx.py",
    source_kind="Management",
    exception_type=ManagementError,
).replace("__MANAGEMENT_ACTIONS__", _remote_action_set(NGINX_ACTIONS))


class SshNginxManagementTransport:
    """Run one fixed Nginx operation and return its narrow typed status."""

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

    def execute(self, action: NginxAction) -> NginxManagementStatus:
        if action not in NGINX_ACTIONS:
            raise ManagementError("Unsupported Nginx action.")
        encoded_script = base64.b64encode(REMOTE_NGINX_MANAGEMENT_SCRIPT.encode("utf-8")).decode(
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
            raise ManagementLaunchError("SSH Nginx operation could not be launched.") from error
        except (SshCancelledError, SshTimeoutError) as error:
            raise ManagementIndeterminateError(
                "timeout", "Nginx operation timed out; the server state is unknown."
            ) from error
        try:
            response = json.loads(result.stdout)
        except json.JSONDecodeError as error:
            if result.returncode != 0:
                raise ManagementIndeterminateError(
                    _response_failure_reason(result),
                    f"Nginx {action} returned no authoritative result.",
                ) from error
            raise ManagementIndeterminateError(
                "invalid_response", "The remote Nginx response is invalid."
            ) from error
        if not isinstance(response, dict):
            raise ManagementIndeterminateError(
                "invalid_response", "The remote Nginx response must be an object."
            )
        remote_error = response.get("error")
        if isinstance(remote_error, str) and remote_error:
            _raise_remote_response_error(result, action, remote_error)
        if result.returncode != 0:
            raise ManagementIndeterminateError(
                _response_failure_reason(result),
                f"Nginx {action} returned no authoritative result.",
            )
        try:
            return self._parse_status(response)
        except ManagementError as error:
            raise ManagementIndeterminateError("invalid_response", str(error)) from error

    @staticmethod
    def _parse_status(response: dict[str, object]) -> NginxManagementStatus:
        expected_keys = {
            "service",
            "http_port",
            "https_port",
            "server_name",
            "tls_mode",
            "certificate_expires_at",
            "http_healthy",
            "https_healthy",
        }
        if set(response) != expected_keys:
            raise ManagementError("The remote Nginx response has unexpected fields.")
        service = response["service"]
        if not isinstance(service, dict) or set(service) != {"service_state", "startup_state"}:
            raise ManagementError("The remote Nginx response has invalid service status.")
        service_state = service.get("service_state")
        startup_state = service.get("startup_state")
        if not isinstance(service_state, str) or service_state not in _SERVICE_STATES:
            raise ManagementError("The remote Nginx response has an invalid service state.")
        if not isinstance(startup_state, str) or startup_state not in _STARTUP_STATES:
            raise ManagementError("The remote Nginx response has an invalid startup state.")
        if response["http_port"] != 80 or isinstance(response["http_port"], bool):
            raise ManagementError("The remote Nginx response has an invalid HTTP port.")
        if response["https_port"] != 443 or isinstance(response["https_port"], bool):
            raise ManagementError("The remote Nginx response has an invalid HTTPS port.")
        tls_mode = response["tls_mode"]
        server_name = response["server_name"]
        if tls_mode not in {"self_signed", "letsencrypt"}:
            raise ManagementError("The remote Nginx response has an invalid TLS mode.")
        if not isinstance(server_name, str):
            raise ManagementError("The remote Nginx response has an invalid server name.")
        if tls_mode == "self_signed":
            if server_name != "default":
                try:
                    if str(ipaddress.IPv4Address(server_name)) != server_name:
                        raise ValueError
                except (ipaddress.AddressValueError, ValueError) as error:
                    raise ManagementError(
                        "The remote Nginx response has an invalid server name."
                    ) from error
        elif not _valid_lowercase_dns_name(server_name):
            raise ManagementError("The remote Nginx response has an invalid server name.")
        if not isinstance(response["http_healthy"], bool) or not isinstance(
            response["https_healthy"], bool
        ):
            raise ManagementError("The remote Nginx response has invalid site health.")
        expiry = response["certificate_expires_at"]
        if expiry is not None:
            if not isinstance(expiry, str) or not expiry.endswith("Z"):
                raise ManagementError(
                    "The remote Nginx response has an invalid certificate expiry."
                )
            try:
                parsed_expiry = datetime.fromisoformat(expiry.removesuffix("Z") + "+00:00")
            except ValueError as error:
                raise ManagementError(
                    "The remote Nginx response has an invalid certificate expiry."
                ) from error
            if parsed_expiry.tzinfo != timezone.utc:
                raise ManagementError(
                    "The remote Nginx response has an invalid certificate expiry."
                )
        return NginxManagementStatus(
            ServiceManagementStatus(service_state, startup_state),
            80,
            443,
            server_name,
            tls_mode,
            expiry,
            response["http_healthy"],
            response["https_healthy"],
        )


def manage_nginx(
    project_directory: Path,
    server_ip: str,
    action: NginxAction,
    *,
    cancelled: Callable[[], bool] | None = None,
) -> NginxManagementStatus:
    """Execute one whitelisted Nginx service action through a fresh SSH call."""
    try:
        connection = primary_ssh_connection(project_directory)
    except SshSettingsError as error:
        raise ManagementError(f"Could not read local SSH configuration: {error}") from error
    return SshNginxManagementTransport(
        server_ip,
        connection.private_key_path,
        connection.port,
        cancelled=cancelled,
    ).execute(action)
