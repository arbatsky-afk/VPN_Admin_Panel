"""Strict loading of the tracked, read-only application defaults resource."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from ipaddress import AddressValueError, IPv4Address, IPv6Address
from pathlib import Path
from typing import Any

from .project_paths import resolve_project_relative_path

APP_DEFAULTS_SCHEMA_VERSION = 1
_HOSTNAME_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?$")
_HYSTERIA_USER_RE = re.compile(r"^[A-Za-z0-9-]+$")
_MIERU_USER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._@+-]{0,127}$")
_BANDWIDTH_RE = re.compile(r"^[1-9][0-9]*\s+[kKmMgGtT]?[bB][pP][sS]$")


class AppDefaultsError(ValueError):
    """The tracked defaults resource is absent or violates its schema."""


@dataclass(frozen=True, slots=True)
class PortRange:
    start: int
    end: int


@dataclass(frozen=True, slots=True)
class XrayDefaults:
    port_range: PortRange
    masquerade_host: str


@dataclass(frozen=True, slots=True)
class Hysteria2Defaults:
    port_range: PortRange
    initial_user: str
    certificate_days: int
    bandwidth_up: str
    bandwidth_down: str
    masquerade_host: str


@dataclass(frozen=True, slots=True)
class MieruDefaults:
    port_range: PortRange
    protocol: str
    mtu: int
    initial_user: str


@dataclass(frozen=True, slots=True)
class AppDefaults:
    """Validated application-owned paths and first-install Component inputs."""

    schema_version: int
    generated_connections_directory: Path
    backups_directory: Path
    modular_bundle_directory: Path
    xray: XrayDefaults
    hysteria2: Hysteria2Defaults
    mieru: MieruDefaults


def load_app_defaults(
    project_directory: Path,
    *,
    defaults_file: Path | None = None,
) -> AppDefaults:
    """Load and strictly validate ``app/defaults.json`` without fallback values."""
    project_directory = project_directory.resolve()
    path = defaults_file or project_directory / "app" / "defaults.json"
    if not path.is_file() or path.is_symlink():
        raise AppDefaultsError("Application defaults are missing or are not a regular file.")
    try:
        document = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise AppDefaultsError(f"Could not read application defaults: {error}") from error
    except AppDefaultsError:
        raise

    root = _strict_object(document, "defaults", {"schema_version", "paths", "modular_deployment"})
    schema_version = _strict_int(root["schema_version"], "schema_version")
    if schema_version != APP_DEFAULTS_SCHEMA_VERSION:
        raise AppDefaultsError(
            f"Unsupported application defaults schema_version: {schema_version}."
        )

    paths = _strict_object(
        root["paths"],
        "paths",
        {"generated_connections_directory", "backups_directory"},
    )
    generated_directory = _resolved_path(
        project_directory,
        paths["generated_connections_directory"],
        "paths.generated_connections_directory",
    )
    backups_directory = _resolved_path(
        project_directory,
        paths["backups_directory"],
        "paths.backups_directory",
    )

    modular = _strict_object(
        root["modular_deployment"],
        "modular_deployment",
        {"paths", "port_ranges", "xray", "hysteria2", "mieru"},
    )
    modular_paths = _strict_object(
        modular["paths"], "modular_deployment.paths", {"bundle_directory"}
    )
    bundle_directory = _resolved_path(
        project_directory,
        modular_paths["bundle_directory"],
        "modular_deployment.paths.bundle_directory",
    )

    ranges = _strict_object(
        modular["port_ranges"],
        "modular_deployment.port_ranges",
        {"xray", "hysteria2", "mieru"},
    )
    xray_range = _port_range(ranges["xray"], "xray")
    hysteria_range = _port_range(ranges["hysteria2"], "hysteria2")
    mieru_range = _port_range(ranges["mieru"], "mieru")
    ordered_ranges = sorted((xray_range, hysteria_range, mieru_range), key=lambda item: item.start)
    if any(
        current.start <= previous.end
        for previous, current in zip(ordered_ranges, ordered_ranges[1:])
    ):
        raise AppDefaultsError("Application defaults contain overlapping Component port ranges.")

    xray = _strict_object(modular["xray"], "modular_deployment.xray", {"masquerade_host"})
    xray_host = _hostname(xray["masquerade_host"], "modular_deployment.xray.masquerade_host")

    hysteria = _strict_object(
        modular["hysteria2"],
        "modular_deployment.hysteria2",
        {
            "initial_user",
            "certificate_days",
            "bandwidth_up",
            "bandwidth_down",
            "masquerade_host",
        },
    )
    hysteria_user = _matched_text(
        hysteria["initial_user"],
        "modular_deployment.hysteria2.initial_user",
        _HYSTERIA_USER_RE,
    )
    certificate_days = _strict_int(
        hysteria["certificate_days"],
        "modular_deployment.hysteria2.certificate_days",
    )
    if not 1 <= certificate_days <= 36500:
        raise AppDefaultsError(
            "modular_deployment.hysteria2.certificate_days must be between 1 and 36500."
        )
    bandwidth_up = _matched_text(
        hysteria["bandwidth_up"],
        "modular_deployment.hysteria2.bandwidth_up",
        _BANDWIDTH_RE,
    )
    bandwidth_down = _matched_text(
        hysteria["bandwidth_down"],
        "modular_deployment.hysteria2.bandwidth_down",
        _BANDWIDTH_RE,
    )
    hysteria_host = _hostname(
        hysteria["masquerade_host"],
        "modular_deployment.hysteria2.masquerade_host",
    )

    mieru = _strict_object(
        modular["mieru"],
        "modular_deployment.mieru",
        {"protocol", "mtu", "initial_user"},
    )
    protocol = _strict_text(mieru["protocol"], "modular_deployment.mieru.protocol")
    if protocol not in {"TCP", "UDP"}:
        raise AppDefaultsError("modular_deployment.mieru.protocol must be TCP or UDP.")
    mtu = _strict_int(mieru["mtu"], "modular_deployment.mieru.mtu")
    if not 1280 <= mtu <= 9000:
        raise AppDefaultsError("modular_deployment.mieru.mtu must be between 1280 and 9000.")
    mieru_user = _matched_text(
        mieru["initial_user"],
        "modular_deployment.mieru.initial_user",
        _MIERU_USER_RE,
    )

    return AppDefaults(
        schema_version,
        generated_directory,
        backups_directory,
        bundle_directory,
        XrayDefaults(xray_range, xray_host),
        Hysteria2Defaults(
            hysteria_range,
            hysteria_user,
            certificate_days,
            bandwidth_up,
            bandwidth_down,
            hysteria_host,
        ),
        MieruDefaults(mieru_range, protocol, mtu, mieru_user),
    )


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise AppDefaultsError(f"Application defaults contain duplicate field: {key}.")
        result[key] = value
    return result


def _strict_object(value: object, name: str, fields: set[str]) -> dict[str, Any]:
    if type(value) is not dict:
        raise AppDefaultsError(f"{name} must be a JSON object.")
    actual = set(value)
    missing = sorted(fields - actual)
    unsupported = sorted(actual - fields)
    if missing:
        raise AppDefaultsError(f"{name} is missing fields: {', '.join(missing)}.")
    if unsupported:
        raise AppDefaultsError(f"{name} contains unsupported fields: {', '.join(unsupported)}.")
    return value


def _strict_int(value: object, name: str) -> int:
    if type(value) is not int:
        raise AppDefaultsError(f"{name} must be an integer.")
    return value


def _strict_text(value: object, name: str) -> str:
    if not isinstance(value, str) or not value:
        raise AppDefaultsError(f"{name} must be non-empty text.")
    return value


def _matched_text(value: object, name: str, pattern: re.Pattern[str]) -> str:
    text = _strict_text(value, name)
    if pattern.fullmatch(text) is None:
        raise AppDefaultsError(f"{name} has an invalid value.")
    return text


def _hostname(value: object, name: str) -> str:
    hostname = _matched_text(value, name, _HOSTNAME_RE)
    if ".." in hostname or "." not in hostname:
        raise AppDefaultsError(f"{name} has an invalid value.")
    try:
        IPv4Address(hostname)
        raise AppDefaultsError(f"{name} must be a DNS hostname, not an IP address.")
    except AddressValueError:
        try:
            IPv6Address(hostname)
            raise AppDefaultsError(f"{name} must be a DNS hostname, not an IP address.")
        except AddressValueError:
            pass
    return hostname


def _port_range(value: object, component: str) -> PortRange:
    name = f"modular_deployment.port_ranges.{component}"
    data = _strict_object(value, name, {"start", "end"})
    start = _strict_int(data["start"], f"{name}.start")
    end = _strict_int(data["end"], f"{name}.end")
    if not 1 <= start <= end <= 65535:
        raise AppDefaultsError(f"{name} must be a valid TCP/UDP port range.")
    return PortRange(start, end)


def _resolved_path(project_directory: Path, value: object, name: str) -> Path:
    configured = _strict_text(value, name)
    try:
        return resolve_project_relative_path(project_directory, configured)
    except ValueError as error:
        raise AppDefaultsError(f"{name}: {error}") from error
