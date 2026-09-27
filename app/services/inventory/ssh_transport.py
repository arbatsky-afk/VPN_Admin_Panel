"""One-shot SSH transport and assembled Inventory remote program."""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path

from .._remote_source import load_remote_source
from ..declaration_contract import (
    HEALTH_CHECKS_BY_COMPONENT,
    REMOTE_PATH_PATTERN,
    SYSTEMD_UNIT_PATTERN,
    contract_source,
)
from ..ssh import validate_server_ip
from ..ssh_settings import SshConnectionSettings
from ..ssh_transport import (
    SshCommand,
    SshTimeoutProfile,
    SshTransportError,
    format_ssh_error_detail,
    run_buffered_ssh,
)
from .contracts import (
    INVENTORY_PROFILES,
    InventoryError,
    InventoryProfile,
    InventoryTransportError,
)


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
        source = path.read_text(encoding="utf-8")
    except OSError as error:
        raise RuntimeError("Could not read the Hysteria2 configuration validator.") from error
    return source.partition('\nif __name__ == "__main__":\n')[0]


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
        source = path.read_text(encoding="utf-8")
    except OSError as error:
        raise RuntimeError("Could not read the Mieru recovery validator.") from error
    return source.replace("from __future__ import annotations\n", "").partition(
        '\nif __name__ == "__main__":\n'
    )[0]


INVENTORY_HEALTH_COMMANDS = {
    ("base-security", "nftables_config"): ("nft", "-c", "-f", "/etc/nftables.conf"),
    ("base-security", "vpn_filter_table"): ("nft", "list", "table", "inet", "vpn_filter"),
    ("xray", "xray_config"): (
        "xray",
        "run",
        "-test",
        "-config",
        "/usr/local/etc/xray/config.json",
    ),
    ("hysteria2", "hysteria2_config"): None,
    ("hysteria2", "hysteria2_certificate"): (
        "openssl",
        "x509",
        "-in",
        "/etc/hysteria/server.crt",
        "-noout",
    ),
    ("docker", "docker_compose"): ("docker", "compose", "version"),
    ("mieru", "mieru_config"): None,
    ("mieru", "mieru_runtime"): ("mita", "status"),
    ("nginx", "nginx_config"): ("nginx", "-t"),
    ("nginx", "nginx_certificate"): None,
    ("nginx", "nginx_http_site"): (
        "curl",
        "--fail",
        "--silent",
        "--show-error",
        "--output",
        "/dev/null",
        "--max-time",
        "5",
        "http://127.0.0.1/",
    ),
    ("nginx", "nginx_https_site"): (
        "curl",
        "--fail",
        "--silent",
        "--show-error",
        "--insecure",
        "--output",
        "/dev/null",
        "--max-time",
        "5",
        "https://127.0.0.1/",
    ),
    ("nginx", "nginx_listeners"): None,
    ("nginx", "nginx_renewal"): None,
    ("netdata", "netdata_config"): None,
    ("netdata", "netdata_dashboard"): (
        "curl",
        "--fail",
        "--silent",
        "--show-error",
        "--output",
        "/dev/null",
        "--max-time",
        "5",
        "http://127.0.0.1:19999/api/v3/info",
    ),
    ("netdata", "netdata_listener"): None,
    ("netdata", "netdata_proxy_bearer"): None,
}
SOFTWARE_VERSION_COMMANDS = {
    "xray": ("xray", "version"),
    "hysteria2": ("hysteria", "version"),
    "docker": ("dockerd", "--version"),
    "mieru": ("mita", "version"),
    "nginx": ("nginx", "-v"),
    "netdata": ("netdata", "-v"),
}
_inventory_health_checks = {
    component_id: frozenset(
        check_id
        for registered_component, check_id in INVENTORY_HEALTH_COMMANDS
        if registered_component == component_id
    )
    for component_id in HEALTH_CHECKS_BY_COMPONENT
}
if _inventory_health_checks != HEALTH_CHECKS_BY_COMPONENT:
    raise RuntimeError("Inventory health commands do not match the declaration contract.")


def _render_remote_inventory_script(profile: InventoryProfile) -> str:
    if profile not in INVENTORY_PROFILES:
        raise InventoryError(f"Unsupported Inventory profile: {profile}")
    return (
        _hysteria2_validator_source()
        + _mieru_validator_source()
        + contract_source()
        + "\ninventory_profile = "
        + repr(profile)
        + "\nhealth_commands = "
        + repr(INVENTORY_HEALTH_COMMANDS)
        + "\n"
        + "software_version_commands = "
        + repr(SOFTWARE_VERSION_COMMANDS)
        + "\n\n"
        + load_remote_source(
            "collect_inventory.py",
            source_kind="Inventory",
            exception_type=RuntimeError,
        )
    )


REMOTE_INVENTORY_SCRIPT = _render_remote_inventory_script("full")


class SshInventoryTransport:
    """Collect one fixed-profile read-only response through one SSH connection."""

    def __init__(
        self,
        server_ip: str,
        private_key: Path,
        ssh_port: int = 22,
        timeout_seconds: int = 15,
        cancelled: Callable[[], bool] | None = None,
        profile: InventoryProfile = "full",
    ) -> None:
        server_ip, validation_error = validate_server_ip(server_ip)
        if validation_error:
            raise InventoryError(validation_error)
        if not private_key.is_file():
            raise InventoryError("The configured SSH private key could not be found.")
        if not 1 <= ssh_port <= 65535:
            raise InventoryError("The SSH port is outside the valid range.")
        if profile not in INVENTORY_PROFILES:
            raise InventoryError(f"Unsupported Inventory profile: {profile}")
        self.server_ip = server_ip
        self.private_key = private_key
        self.ssh_port = ssh_port
        self.timeout_seconds = timeout_seconds
        self.cancelled = cancelled
        self.profile = profile
        self._snapshot_data: dict[str, object] | None = None

    def read_text(self, path: str) -> str:
        self._validate_remote_path(path)
        entry = self._entry("texts", path)
        content = entry.get("content")
        if not isinstance(content, str):
            raise InventoryTransportError(f"Could not read remote file: {path}")
        return content

    def file_exists(self, path: str) -> bool:
        self._validate_remote_path(path)
        entry = self._entry("files", path)
        exists = entry.get("exists")
        if not isinstance(exists, bool):
            raise InventoryTransportError(f"Could not inspect remote file: {path}")
        return exists

    def directory_exists(self, path: str) -> bool:
        self._validate_remote_path(path)
        exists = self._entry("directories", path).get("exists")
        if not isinstance(exists, bool):
            raise InventoryTransportError(f"Could not inspect remote directory: {path}")
        return exists

    def systemd_state(self, unit: str) -> str:
        if not SYSTEMD_UNIT_PATTERN.fullmatch(unit):
            raise InventoryError(f"Invalid systemd unit in declaration: {unit}")
        entry = self._entry("systemd", unit)
        state = entry.get("state")
        if not isinstance(state, str):
            raise InventoryTransportError(f"Could not inspect systemd unit: {unit}")
        return state if state in {"active", "inactive", "failed"} else "unknown"

    def health_check(self, component_id: str, check_id: str) -> tuple[bool, str]:
        if (component_id, check_id) not in INVENTORY_HEALTH_COMMANDS:
            raise InventoryError(f"Unsupported health check: {component_id}.{check_id}")
        snapshot = self._snapshot()
        health = snapshot.get("health")
        if not isinstance(health, dict):
            raise InventoryTransportError("Inventory SSH response has no health results.")
        component_health = health.get(component_id)
        if not isinstance(component_health, dict):
            raise InventoryTransportError(f"Could not run health check: {component_id}.{check_id}")
        entry = component_health.get(check_id)
        if not isinstance(entry, dict):
            raise InventoryTransportError(f"Could not run health check: {component_id}.{check_id}")
        passed = entry.get("passed")
        detail = entry.get("detail")
        if not isinstance(passed, bool) or not isinstance(detail, str):
            raise InventoryTransportError(f"Could not run health check: {component_id}.{check_id}")
        return passed, detail

    def software_version(self, component_id: str) -> str | None:
        if component_id != "base-security" and component_id not in SOFTWARE_VERSION_COMMANDS:
            raise InventoryError(f"Unsupported software version check: {component_id}")
        snapshot = self._snapshot()
        versions = snapshot.get("versions")
        if not isinstance(versions, dict):
            raise InventoryTransportError("Inventory SSH response has no software versions.")
        entry = versions.get(component_id)
        if not isinstance(entry, dict) or "version" not in entry:
            raise InventoryTransportError(f"Could not determine software version: {component_id}")
        version = entry["version"]
        if component_id == "base-security" and version is None:
            return None
        if not isinstance(version, str) or not version.strip():
            raise InventoryTransportError(f"Could not determine software version: {component_id}")
        return version

    def _snapshot(self) -> dict[str, object]:
        if self._snapshot_data is not None:
            return self._snapshot_data
        try:
            result = run_buffered_ssh(
                SshCommand(
                    self.server_ip,
                    SshConnectionSettings(self.private_key, self.ssh_port),
                    ("python3", "-"),
                    SshTimeoutProfile.short_operation(self.timeout_seconds),
                ),
                input_text=_render_remote_inventory_script(self.profile),
                cancelled=self.cancelled,
            )
        except SshTransportError as error:
            raise InventoryTransportError(
                f"SSH Inventory command could not run: {error}"
            ) from error
        if result.returncode != 0:
            detail = format_ssh_error_detail(result.stderr)
            suffix = f" Details: {detail}" if detail else ""
            raise InventoryTransportError(
                f"The remote Inventory command failed (exit code {result.returncode}).{suffix}"
            )
        try:
            response = json.loads(result.stdout)
        except json.JSONDecodeError as error:
            raise InventoryTransportError(
                f"The remote Inventory response is invalid: {error}"
            ) from error
        if not isinstance(response, dict):
            raise InventoryTransportError("The remote Inventory response must be an object.")
        self._snapshot_data = response
        return response

    def _entry(self, section: str, key: str) -> dict[str, object]:
        snapshot = self._snapshot()
        values = snapshot.get(section)
        if not isinstance(values, dict):
            raise InventoryTransportError(f"Inventory SSH response has no {section} results.")
        entry = values.get(key)
        if not isinstance(entry, dict):
            raise InventoryTransportError(f"Inventory SSH response has no result for {key}.")
        return entry

    @staticmethod
    def _validate_remote_path(path: str) -> None:
        if not REMOTE_PATH_PATTERN.fullmatch(path) or "/../" in path or path.endswith("/.."):
            raise InventoryError(f"Invalid remote path in declaration: {path}")
