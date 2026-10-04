"""Local Users protocol and handling of returned connection files."""

import base64
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from .app_defaults import load_app_defaults
from .inventory import InventorySnapshot
from .ssh import validate_server_ip

_CONNECTION_NAME_RE = re.compile(r"^[A-Za-z0-9-]+$")
UsersAction = Literal["list", "get", "create", "extend", "delete"]
UsersProtocol = Literal["xray", "hysteria2", "mieru"]
UsersMutationOutcome = Literal["success", "rolled_back", "partial", "unknown"]
UsersConfigMutationState = Literal[
    "unchanged", "applied", "rolled_back", "rollback_failed", "unknown"
]
UsersServiceMutationState = Literal[
    "unchanged",
    "not_verified",
    "restarted",
    "reloaded",
    "restart_failed",
    "rollback_restarted",
    "rollback_reloaded",
    "rollback_restart_failed",
    "unknown",
]

MUTATING_USERS_ACTIONS = {"create", "extend", "delete"}
USERS_PROTOCOLS = ("xray", "hysteria2", "mieru")
USERS_CONFIG_MUTATION_STATES = {
    "unchanged",
    "applied",
    "rolled_back",
    "rollback_failed",
    "unknown",
}
USERS_SERVICE_MUTATION_STATES = {
    "unchanged",
    "not_verified",
    "restarted",
    "reloaded",
    "restart_failed",
    "rollback_restarted",
    "rollback_reloaded",
    "rollback_restart_failed",
    "unknown",
}
REMOTE_USERS_COMMAND = (
    "python3 -c \"import sys; exec(compile(sys.stdin.buffer.read(), '<users>', 'exec'))\""
)


class UsersOperationError(ValueError):
    """A local Users-operation request or response is invalid."""


@dataclass(frozen=True)
class UsersOperationRequest:
    """One fully validated Users request sent through SSH standard input."""

    action: UsersAction
    server_ip: str
    allowed_protocols: tuple[UsersProtocol, ...]
    name: str = ""


@dataclass(frozen=True)
class UsersProtocolMutationResult:
    protocol: str
    config: UsersConfigMutationState
    service: UsersServiceMutationState


@dataclass(frozen=True)
class UsersMutationResult:
    action: Literal["create", "extend", "delete"]
    name: str
    outcome: UsersMutationOutcome
    protocols: tuple[UsersProtocolMutationResult, ...]
    restarted: tuple[str, ...]
    error: str = ""


def unknown_users_mutation_result(
    request: UsersOperationRequest, message: str
) -> UsersMutationResult:
    if request.action not in MUTATING_USERS_ACTIONS:
        raise UsersOperationError("Only a mutating Users request can have an unknown result.")
    return UsersMutationResult(
        request.action,
        request.name,
        "unknown",
        tuple(
            UsersProtocolMutationResult(protocol, "unknown", "unknown")
            for protocol in USERS_PROTOCOLS
        ),
        (),
        message,
    )


def inventory_users_protocols(
    snapshot: InventorySnapshot,
    action: UsersAction,
) -> tuple[UsersProtocol, ...]:
    """Derive an action-specific Users allowlist from one Inventory snapshot."""
    declaration_action = "create" if action == "extend" else action
    allowed: list[UsersProtocol] = []
    for protocol in USERS_PROTOCOLS:
        component = snapshot.component(protocol)
        declaration = component.declaration if component is not None else None
        if (
            declaration is not None
            and declaration.users_supported
            and declaration_action in declaration.user_actions
        ):
            allowed.append(protocol)
    return tuple(allowed)


def build_users_request(
    action: str,
    server_ip: str,
    name: str = "",
    *,
    allowed_protocols: tuple[str, ...],
) -> UsersOperationRequest:
    if action not in {"list", "get", "create", "extend", "delete"}:
        raise UsersOperationError("Unknown Users command.")
    server_ip, error = validate_server_ip(server_ip)
    if error:
        raise UsersOperationError(error)
    if not isinstance(name, str):
        raise UsersOperationError("User name must be a string.")
    if action == "list":
        if name:
            raise UsersOperationError("List Users request must not contain a name.")
    elif not _CONNECTION_NAME_RE.fullmatch(name):
        raise UsersOperationError("Only letters, digits, and hyphens are allowed in a user name.")
    if not isinstance(allowed_protocols, tuple):
        raise UsersOperationError("Users allowed protocols must be an immutable tuple.")
    if len(set(allowed_protocols)) != len(allowed_protocols):
        raise UsersOperationError("Users allowed protocols must not contain duplicates.")
    canonical_protocols = tuple(
        protocol for protocol in USERS_PROTOCOLS if protocol in allowed_protocols
    )
    if canonical_protocols != allowed_protocols:
        raise UsersOperationError("Users allowed protocols are invalid or not in canonical order.")
    return UsersOperationRequest(action, server_ip, canonical_protocols, name)


def render_remote_users_program(project_directory: Path, request: UsersOperationRequest) -> bytes:
    """Return the in-memory program and request for one fixed remote command."""
    helper_path = project_directory / "app" / "services" / "remote_sources" / "manage_users.py"
    validator_path = (
        project_directory
        / "scripts"
        / "ubuntu"
        / "modular-deployment"
        / "lib"
        / "hysteria2_config.py"
    )
    mieru_validator_path = (
        project_directory / "scripts" / "ubuntu" / "modular-deployment" / "lib" / "mieru_config.py"
    )
    if not validator_path.is_file():
        validator_path = (
            Path(__file__).parents[2]
            / "scripts"
            / "ubuntu"
            / "modular-deployment"
            / "lib"
            / "hysteria2_config.py"
        )
    if not mieru_validator_path.is_file():
        mieru_validator_path = (
            Path(__file__).parents[2]
            / "scripts"
            / "ubuntu"
            / "modular-deployment"
            / "lib"
            / "mieru_config.py"
        )
    try:
        helper_source = helper_path.read_text(encoding="utf-8")
        validator_source = validator_path.read_text(encoding="utf-8").partition(
            '\nif __name__ == "__main__":\n'
        )[0]
        mieru_validator_source = (
            mieru_validator_path.read_text(encoding="utf-8")
            .replace("from __future__ import annotations\n", "")
            .partition('\nif __name__ == "__main__":\n')[0]
        )
    except OSError as error:
        raise UsersOperationError(f"Could not read a Users remote source: {error}") from error
    request_json = json.dumps(
        {
            "action": request.action,
            "server_ip": request.server_ip,
            "name": request.name,
            "allowed_protocols": list(request.allowed_protocols),
        },
        separators=(",", ":"),
    )
    encoded_request = base64.b64encode(request_json.encode("utf-8")).decode("ascii")
    program = "\n".join(
        (
            "import base64",
            validator_source,
            mieru_validator_source,
            helper_source.removeprefix("#!/usr/bin/env python3\n"),
            "",
            "try:",
            f"    request = json.loads(base64.b64decode('{encoded_request}'))",
            "    print(json.dumps(execute(request)))",
            "except Exception as error:",
            "    print(json.dumps({'error': str(error)}))",
            "    sys.exit(1)",
            "",
        )
    )
    return program.encode("utf-8")


def parse_users_response(action: UsersAction, output: bytes) -> object:
    try:
        response = json.loads(output.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise UsersOperationError(f"Invalid response from the Users helper: {error}") from error
    if (
        isinstance(response, dict)
        and "outcome" not in response
        and isinstance(response.get("error"), str)
    ):
        raise UsersOperationError(response["error"])
    if action == "list":
        if not isinstance(response, list):
            raise UsersOperationError("Users list response must be an array.")
        return response
    if action in MUTATING_USERS_ACTIONS:
        return _parse_mutation_response(action, response)
    if not isinstance(response, dict):
        raise UsersOperationError("Users operation response must be an object.")
    return response


def _parse_mutation_response(action: UsersAction, response: object) -> UsersMutationResult:
    if not isinstance(response, dict):
        raise UsersOperationError("Users mutation response must be an object.")
    if response.get("action") != action:
        raise UsersOperationError("Users mutation response action does not match the request.")
    name = response.get("name")
    outcome = response.get("outcome")
    protocols = response.get("protocols")
    restarted = response.get("restarted")
    error = response.get("error")
    if not isinstance(name, str) or not _CONNECTION_NAME_RE.fullmatch(name):
        raise UsersOperationError("Users mutation response contains an invalid user name.")
    if outcome not in {"success", "rolled_back", "partial"}:
        raise UsersOperationError("Users mutation response contains an invalid outcome.")
    if not isinstance(protocols, dict) or set(protocols) != set(USERS_PROTOCOLS):
        raise UsersOperationError("Users mutation response contains invalid protocol states.")
    protocol_results: list[UsersProtocolMutationResult] = []
    for protocol in USERS_PROTOCOLS:
        state = protocols[protocol]
        if not isinstance(state, dict):
            raise UsersOperationError("Users mutation response contains invalid protocol states.")
        config = state.get("config")
        service = state.get("service")
        if (
            config not in USERS_CONFIG_MUTATION_STATES
            or service not in USERS_SERVICE_MUTATION_STATES
        ):
            raise UsersOperationError("Users mutation response contains invalid protocol states.")
        protocol_results.append(UsersProtocolMutationResult(protocol, config, service))
    if not isinstance(restarted, list) or any(
        service not in {"xray", "hysteria-server"} for service in restarted
    ):
        raise UsersOperationError("Users mutation response contains invalid restarted services.")
    if len(set(restarted)) != len(restarted):
        raise UsersOperationError("Users mutation response contains duplicate restarted services.")
    if (
        not isinstance(error, str)
        or (outcome == "success" and error)
        or (outcome != "success" and not error)
    ):
        raise UsersOperationError("Users mutation response contains invalid error details.")
    expected_restarted = tuple(
        "xray" if result.protocol == "xray" else "hysteria-server"
        for result in protocol_results
        if result.service == "restarted"
    )
    if tuple(restarted) != expected_restarted:
        raise UsersOperationError(
            "Users mutation response restarted services do not match protocol states."
        )
    if any(
        result.service == "not_verified" and result.config != "applied"
        for result in protocol_results
    ):
        raise UsersOperationError(
            "Users mutation response marks an unchanged configuration as not verified."
        )
    if outcome == "success" and any(
        result.config not in {"unchanged", "applied"}
        or result.service not in {"unchanged", "not_verified", "restarted", "reloaded"}
        for result in protocol_results
    ):
        raise UsersOperationError("Users mutation success contains non-success protocol states.")
    if outcome == "rolled_back" and any(
        result.config not in {"unchanged", "rolled_back"}
        or result.service not in {"unchanged", "rollback_restarted", "rollback_reloaded"}
        for result in protocol_results
    ):
        raise UsersOperationError(
            "Users rolled-back mutation contains incomplete rollback states."
        )
    if outcome == "partial" and not any(
        result.config == "rollback_failed" or result.service == "rollback_restart_failed"
        for result in protocol_results
    ):
        raise UsersOperationError(
            "Users partial mutation does not describe an incomplete rollback."
        )
    return UsersMutationResult(
        action, name, outcome, tuple(protocol_results), tuple(restarted), error
    )


def generated_connections_directory(project_directory: Path) -> Path:
    """Return the application-owned generated-connections destination."""
    return load_app_defaults(project_directory).generated_connections_directory


def save_connection_files(
    output_directory: Path, server_ip: str, data: dict[str, Any]
) -> list[Path]:
    """Save generated connection links and Clash/Mihomo YAML files."""
    server_ip, validation_error = validate_server_ip(server_ip)
    if validation_error:
        raise ValueError(validation_error)

    name = data["name"]
    if not isinstance(name, str) or not _CONNECTION_NAME_RE.fullmatch(name):
        raise ValueError("The connection name may contain only letters, digits, and hyphens.")

    output_directory.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []

    if data.get("xray"):
        link_path = _safe_output_path(output_directory, f"{server_ip}-xray-{name}.txt")
        link_path.write_text(str(data["xray_link"]), encoding="utf-8")
        yaml = data["xray_yaml"]
        yaml_path = _safe_output_path(output_directory, f"{server_ip}-xray-{name}.yaml")
        yaml_path.write_text(
            "\n".join(
                (
                    f'- name: "{yaml["name"]}"',
                    "  type: vless",
                    f"  server: {yaml['server']}",
                    f"  port: {yaml['port']}",
                    f"  uuid: {yaml['uuid']}",
                    "  flow: xtls-rprx-vision",
                    "  encryption: none",
                    "  tls: true",
                    "  skip-cert-verify: true",
                    f"  servername: {yaml['servername']}",
                    "  client-fingerprint: chrome",
                    "  reality-opts:",
                    f"    public-key: {yaml['reality-opts']['public-key']}",
                    f"    short-id: {yaml['reality-opts']['short-id']}",
                    "",
                )
            ),
            encoding="utf-8",
        )
        written.extend((link_path, yaml_path))

    if data.get("hysteria"):
        link_path = _safe_output_path(output_directory, f"{server_ip}-hysteria-{name}.txt")
        link_path.write_text(str(data["hysteria_link"]), encoding="utf-8")
        yaml = data["hysteria_yaml"]
        yaml_path = _safe_output_path(output_directory, f"{server_ip}-hysteria-{name}.yaml")
        yaml_path.write_text(
            "\n".join(
                (
                    f'- name: "{yaml["name"]}"',
                    "  type: hysteria2",
                    f"  server: {yaml['server']}",
                    f"  port: {yaml['port']}",
                    f'  password: "{yaml["password"]}"',
                    f"  sni: {yaml['sni']}",
                    "  skip-cert-verify: true",
                    "  obfs: salamander",
                    f'  obfs-password: "{yaml["obfs-password"]}"',
                    "",
                )
            ),
            encoding="utf-8",
        )
        written.extend((link_path, yaml_path))

    if data.get("mieru"):
        link_path = _safe_output_path(output_directory, f"{server_ip}-mieru-{name}.txt")
        link_path.write_text(str(data["mieru_link"]), encoding="utf-8")
        yaml = data["mieru_yaml"]
        yaml_path = _safe_output_path(output_directory, f"{server_ip}-mieru-{name}.yaml")
        yaml_path.write_text(
            "\n".join(
                (
                    f'- name: "{yaml["name"]}"',
                    "  type: mieru",
                    f"  server: {yaml['server']}",
                    f"  port: {yaml['port']}",
                    f"  transport: {yaml['transport']}",
                    "  udp: true",
                    f'  username: "{yaml["username"]}"',
                    f'  password: "{yaml["password"]}"',
                    "  multiplexing: MULTIPLEXING_LOW",
                    "",
                )
            ),
            encoding="utf-8",
        )
        written.extend((link_path, yaml_path))

    return written


def _safe_output_path(output_directory: Path, filename: str) -> Path:
    """Return a destination-contained path and reject links that escape it."""
    path = output_directory / filename
    output_root = output_directory.resolve()
    try:
        path.resolve().relative_to(output_root)
    except ValueError as error:
        raise ValueError(
            "Connection files must stay inside the configured output directory."
        ) from error
    return path
