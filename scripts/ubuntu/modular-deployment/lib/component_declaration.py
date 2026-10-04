#!/usr/bin/env python3
"""Canonical data-only contract for supported component declarations."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 2
COMPONENT_ID = re.compile(r"^[a-z0-9][a-z0-9-]*$")
REMOTE_PATH = re.compile(r"^/[A-Za-z0-9._/@+-]+$")
SYSTEMD_UNIT = re.compile(r"^[a-zA-Z0-9@_.-]+\.service$")
RESTORE_ACTIONS = frozenset({"restart"})
SERVICE_ACTIONS = frozenset({"inspect", "start", "stop", "restart", "enable", "disable"})
USER_ACTIONS = frozenset({"list", "get", "create", "delete"})

HEALTH_CHECKS_BY_COMPONENT = {
    "base-security": frozenset({"nftables_config", "vpn_filter_table"}),
    "xray": frozenset({"xray_config"}),
    "hysteria2": frozenset({"hysteria2_config", "hysteria2_certificate"}),
    "docker": frozenset({"docker_compose"}),
    "mieru": frozenset({"mieru_config", "mieru_runtime"}),
    "nginx": frozenset(
        {
            "nginx_config",
            "nginx_certificate",
            "nginx_http_site",
            "nginx_https_site",
            "nginx_listeners",
            "nginx_renewal",
        }
    ),
    "netdata": frozenset(
        {
            "netdata_config",
            "netdata_dashboard",
            "netdata_listener",
            "netdata_proxy_bearer",
        }
    ),
}
INSTALLATION_UNITS_BY_COMPONENT = {
    "base-security": frozenset({"nftables.service", "fail2ban.service"}),
    "xray": frozenset({"xray.service"}),
    "hysteria2": frozenset({"hysteria-server.service"}),
    "docker": frozenset({"docker.service"}),
    "mieru": frozenset({"mita.service"}),
    "nginx": frozenset({"nginx.service"}),
    "netdata": frozenset({"netdata.service"}),
}
MANAGEMENT_ACTIONS_BY_HANDLER = {
    "base-security": SERVICE_ACTIONS,
    "xray": SERVICE_ACTIONS | {"update_connection"},
    "hysteria2": SERVICE_ACTIONS | {"update_connection"},
    "docker": SERVICE_ACTIONS,
    "mieru": SERVICE_ACTIONS | {"update_port"},
    "nginx": SERVICE_ACTIONS,
    "netdata": SERVICE_ACTIONS,
}
MANAGEMENT_UNITS_BY_HANDLER = {
    "base-security": frozenset({"nftables.service", "fail2ban.service"}),
    "xray": frozenset({"xray.service"}),
    "hysteria2": frozenset({"hysteria-server.service"}),
    "docker": frozenset({"docker.service"}),
    "mieru": frozenset({"mita.service"}),
    "nginx": frozenset({"nginx.service"}),
    "netdata": frozenset({"netdata.service"}),
}
MANAGEMENT_PARAMETERS_BY_HANDLER = {
    "base-security": {
        "ssh_port": ("integer", False, 1, 65535, None),
    },
    "xray": {
        "listen_port": ("integer", True, 1, 65535, None),
        "masquerade_host": ("string", True, None, None, "hostname"),
    },
    "hysteria2": {
        "listen_port": ("integer", True, 1, 65535, None),
        "masquerade_host": ("string", True, None, None, "hostname"),
    },
    "docker": {},
    "mieru": {
        "transport": ("string", False, None, None, None),
        "listen_port": ("integer", True, 1025, 65535, None),
        "mtu": ("integer", False, 1280, 9000, None),
        "user_count": ("integer", False, 1, None, None),
    },
    "nginx": {
        "http_port": ("integer", False, 80, 80, None),
        "https_port": ("integer", False, 443, 443, None),
        "server_name": ("string", False, None, None, None),
        "tls_mode": ("string", False, None, None, None),
        "certificate_expires_at": ("string", False, None, None, None),
    },
    "netdata": {
        "listen_port": ("integer", False, 19999, 19999, None),
    },
}
USER_ARTIFACTS_BY_COMPONENT = {
    "base-security": frozenset(),
    "xray": frozenset({"vless_link", "clash_yaml"}),
    "hysteria2": frozenset({"hysteria2_link", "clash_yaml"}),
    "docker": frozenset(),
    "mieru": frozenset({"mierus_link", "client_json", "clash_yaml"}),
    "nginx": frozenset(),
    "netdata": frozenset(),
}


class DeclarationError(ValueError):
    """A component declaration violates the supported schema-v2 contract."""


def load_and_validate_declaration(path: Path, component_id: str) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except OSError as error:
        raise DeclarationError(f"Could not read component declaration: {error}") from error
    except json.JSONDecodeError as error:
        raise DeclarationError(f"Invalid JSON in component declaration: {error}") from error
    return validate_declaration_data(data, component_id)


def validate_declaration_text(text: str, component_id: str) -> dict[str, Any]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError as error:
        raise DeclarationError(f"Component declaration contains invalid JSON: {error}") from error
    return validate_declaration_data(data, component_id)


def validate_declaration_data(data: object, component_id: str) -> dict[str, Any]:
    """Validate and return one supported declaration without executing its data."""
    if not isinstance(data, dict):
        raise DeclarationError("Component declaration must contain a JSON object.")
    _exact_keys(
        data,
        {
            "schema_version",
            "component",
            "contract_version",
            "display_name",
            "installation_checks",
            "backup",
            "restore",
        },
        {"management", "users"},
        "Component declaration",
    )
    if type(data.get("schema_version")) is not int or data["schema_version"] != SCHEMA_VERSION:
        raise DeclarationError("Component declaration has an unsupported schema_version.")
    if not isinstance(component_id, str) or not COMPONENT_ID.fullmatch(component_id):
        raise DeclarationError("Component declaration has an unexpected component id.")
    if component_id not in HEALTH_CHECKS_BY_COMPONENT or data.get("component") != component_id:
        raise DeclarationError("Component declaration has an unexpected component id.")
    _non_empty_string(data, "contract_version")
    _non_empty_string(data, "display_name")

    installation = _object(data, "installation_checks")
    _exact_keys(
        installation,
        {"files", "systemd_units", "health_checks"},
        set(),
        "Component installation_checks",
    )
    _paths(installation, "files")
    installation_units = _units(installation, "systemd_units")
    if installation_units != INSTALLATION_UNITS_BY_COMPONENT[component_id]:
        raise DeclarationError(
            "Component declaration has unsupported or missing installation systemd units."
        )
    health_checks = _strings(installation, "health_checks")
    if frozenset(health_checks) != HEALTH_CHECKS_BY_COMPONENT[component_id]:
        raise DeclarationError(
            "Component declaration has unsupported or missing health-check IDs."
        )

    backup = _object(data, "backup")
    _exact_keys(backup, {"paths"}, {"optional_directories"}, "Component backup")
    backup_paths = _paths(backup, "paths")
    optional_directories = _paths(backup, "optional_directories", default=())
    if any(path.endswith("/") for path in backup_paths):
        raise DeclarationError(
            "Component declaration backup.paths must contain files, not directories."
        )
    if any(not path.endswith("/") for path in optional_directories):
        raise DeclarationError(
            "Component declaration backup.optional_directories entries must end with '/'."
        )
    for directory in optional_directories:
        if any(path.startswith(directory) for path in backup_paths):
            raise DeclarationError(
                "Component declaration backup paths overlap an optional directory."
            )
    for index, directory in enumerate(optional_directories):
        if any(
            directory.startswith(other) or other.startswith(directory)
            for other in optional_directories[index + 1 :]
        ):
            raise DeclarationError("Component declaration backup optional directories overlap.")

    restore = _object(data, "restore")
    _exact_keys(restore, {"services"}, {"daemon_reload"}, "Component restore")
    daemon_reload = restore.get("daemon_reload", False)
    if not isinstance(daemon_reload, bool):
        raise DeclarationError("Component declaration restore.daemon_reload must be a boolean.")
    _restore_services(restore, installation_units)

    management = data.get("management")
    if management is not None:
        if not isinstance(management, dict):
            raise DeclarationError("Component management declaration must be an object.")
        _exact_keys(
            management,
            {"handler", "systemd_units", "parameters", "actions"},
            set(),
            "Component management",
        )
        handler = _non_empty_string(management, "handler")
        if handler != component_id or handler not in MANAGEMENT_ACTIONS_BY_HANDLER:
            raise DeclarationError("Component declaration has an unsupported management handler.")
        management_units = frozenset(_units(management, "systemd_units"))
        if management_units != MANAGEMENT_UNITS_BY_HANDLER[
            handler
        ] or not management_units.issubset(installation_units):
            raise DeclarationError(
                "Component declaration has unsupported management systemd units."
            )
        actions = frozenset(_strings(management, "actions"))
        if "inspect" not in actions or not actions.issubset(
            MANAGEMENT_ACTIONS_BY_HANDLER[handler]
        ):
            raise DeclarationError(
                "Component declaration has unsupported management actions or omits inspect."
            )
        _management_parameters(management, handler)

    users = data.get("users", {"supported": False, "actions": [], "artifacts": []})
    if not isinstance(users, dict):
        raise DeclarationError("Component users declaration must be an object.")
    _exact_keys(users, {"supported", "actions", "artifacts"}, set(), "Component users")
    supported = users.get("supported")
    if not isinstance(supported, bool):
        raise DeclarationError("Component users.supported must be a boolean.")
    user_actions = frozenset(_strings(users, "actions"))
    user_artifacts = frozenset(_strings(users, "artifacts"))
    expected_artifacts = USER_ARTIFACTS_BY_COMPONENT[component_id]
    expected_supported = bool(expected_artifacts)
    if supported != expected_supported:
        raise DeclarationError("Component declaration has an unsupported users capability.")
    if user_actions != (USER_ACTIONS if supported else frozenset()):
        raise DeclarationError("Component declaration has unsupported or missing users actions.")
    if user_artifacts != expected_artifacts:
        raise DeclarationError("Component declaration has unsupported or missing users artifacts.")
    return data


def _exact_keys(data: dict[str, Any], required: set[str], optional: set[str], label: str) -> None:
    keys = set(data)
    missing = required - keys
    unknown = keys - required - optional
    if missing:
        raise DeclarationError(
            f"{label} is missing required field(s): {', '.join(sorted(missing))}."
        )
    if unknown:
        raise DeclarationError(
            f"{label} contains unsupported field(s): {', '.join(sorted(unknown))}."
        )


def _object(data: dict[str, Any], key: str) -> dict[str, Any]:
    value = data.get(key)
    if not isinstance(value, dict):
        raise DeclarationError(f"Component declaration is missing the {key} object.")
    return value


def _non_empty_string(data: dict[str, Any], key: str) -> str:
    value = data.get(key)
    if not isinstance(value, str) or not value.strip():
        raise DeclarationError(f"Component declaration field {key} must be a non-empty string.")
    return value


def _strings(
    data: dict[str, Any],
    key: str,
    *,
    default: tuple[str, ...] | None = None,
) -> tuple[str, ...]:
    value = data.get(key, list(default) if default is not None else None)
    if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
        raise DeclarationError(
            f"Component declaration field {key} must be a list of non-empty strings."
        )
    if len(value) != len(set(value)):
        raise DeclarationError(f"Component declaration field {key} contains duplicates.")
    return tuple(value)


def _paths(
    data: dict[str, Any],
    key: str,
    *,
    default: tuple[str, ...] | None = None,
) -> tuple[str, ...]:
    paths = _strings(data, key, default=default)
    for path in paths:
        if not REMOTE_PATH.fullmatch(path) or "/../" in path or path.endswith("/.."):
            raise DeclarationError(f"Component declaration has an invalid path: {path}")
    return paths


def _units(data: dict[str, Any], key: str) -> frozenset[str]:
    units = _strings(data, key)
    if not all(SYSTEMD_UNIT.fullmatch(unit) for unit in units):
        raise DeclarationError("Component declaration has an invalid systemd unit.")
    return frozenset(units)


def _restore_services(restore: dict[str, Any], installation_units: frozenset[str]) -> None:
    services = restore.get("services")
    if not isinstance(services, list):
        raise DeclarationError("Component declaration restore.services must be a list.")
    seen_units: set[str] = set()
    for service in services:
        if not isinstance(service, dict):
            raise DeclarationError(
                "Component declaration restore.services entries must be objects."
            )
        _exact_keys(service, {"unit", "action"}, set(), "Component restore service")
        unit = _non_empty_string(service, "unit")
        action = _non_empty_string(service, "action")
        if not SYSTEMD_UNIT.fullmatch(unit) or unit not in installation_units:
            raise DeclarationError(
                "Component declaration restore service has an invalid systemd unit."
            )
        if action not in RESTORE_ACTIONS:
            raise DeclarationError(
                "Component declaration restore service has an unsupported action."
            )
        if unit in seen_units:
            raise DeclarationError(
                "Component declaration restore.services contains a duplicate systemd unit."
            )
        seen_units.add(unit)


def _management_parameters(management: dict[str, Any], handler: str) -> None:
    value = management.get("parameters")
    if not isinstance(value, list):
        raise DeclarationError("Component management.parameters must be a list.")
    expected = MANAGEMENT_PARAMETERS_BY_HANDLER[handler]
    seen: set[str] = set()
    for parameter in value:
        if not isinstance(parameter, dict):
            raise DeclarationError("Component management parameter must be an object.")
        _exact_keys(
            parameter,
            {"id", "label", "type", "modifiable"},
            {"minimum", "maximum", "format"},
            "Component management parameter",
        )
        parameter_id = _non_empty_string(parameter, "id")
        _non_empty_string(parameter, "label")
        parameter_type = _non_empty_string(parameter, "type")
        modifiable = parameter.get("modifiable")
        minimum = parameter.get("minimum")
        maximum = parameter.get("maximum")
        value_format = parameter.get("format")
        if not isinstance(modifiable, bool):
            raise DeclarationError("Component management parameter modifiable must be a boolean.")
        if minimum is not None and (isinstance(minimum, bool) or not isinstance(minimum, int)):
            raise DeclarationError("Component management parameter minimum must be an integer.")
        if maximum is not None and (isinstance(maximum, bool) or not isinstance(maximum, int)):
            raise DeclarationError("Component management parameter maximum must be an integer.")
        if value_format is not None and (not isinstance(value_format, str) or not value_format):
            raise DeclarationError(
                "Component management parameter format must be a non-empty string."
            )
        actual = (parameter_type, modifiable, minimum, maximum, value_format)
        if parameter_id not in expected or actual != expected[parameter_id]:
            raise DeclarationError(
                "Component declaration has an unsupported management parameter."
            )
        if parameter_id in seen:
            raise DeclarationError("Component declaration has a duplicate management parameter.")
        seen.add(parameter_id)
    if seen != set(expected):
        raise DeclarationError("Component declaration is missing a required management parameter.")
