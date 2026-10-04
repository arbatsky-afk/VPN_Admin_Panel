"""Local validation and planning for configuration Restore archives."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import shlex
import tarfile
import zlib
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, BinaryIO, Literal

from .backup import BACKUP_ARCHIVE_SCHEMA_VERSION
from .declaration_contract import (
    COMPONENT_ID_PATTERN,
    REMOTE_PATH_PATTERN,
    RESTORE_ACTIONS,
    SYSTEMD_UNIT_PATTERN,
)
from .inventory import (
    InventorySnapshot,
    RestoreService,
)

MANIFEST_NAME = "vpn-backup-manifest.json"
MAX_UNCOMPRESSED_ARCHIVE_BYTES = 64 * 1024 * 1024
NGINX_CROSS_SERVER_EXCLUSION_REASON = "source_target_ipv4_mismatch"
RestoreExclusionReason = Literal["source_target_ipv4_mismatch"]


class RestoreError(ValueError):
    """Raised when a local archive is not safe to restore."""


@dataclass(frozen=True)
class RestoreComponent:
    """Validated restore details for one component in a Backup archive."""

    component_id: str
    contract_version: str
    paths: tuple[str, ...]
    daemon_reload: bool
    services: tuple[RestoreService, ...]
    source_status: str = "unknown"
    software_version: str | None = None


@dataclass(frozen=True)
class RestorePlan:
    """Immutable result of validating one local Backup archive."""

    archive_path: Path
    source_server_ip: str
    created_at: str
    components: tuple[RestoreComponent, ...]
    archive_sha256: str

    @property
    def paths(self) -> tuple[str, ...]:
        return tuple(path for component in self.components for path in component.paths)

    @property
    def requires_daemon_reload(self) -> bool:
        return any(component.daemon_reload for component in self.components)

    @property
    def service_actions(self) -> tuple[RestoreService, ...]:
        return tuple(service for component in self.components for service in component.services)


@dataclass(frozen=True, slots=True)
class RestorePolicyExclusion:
    """One Component intentionally omitted from an effective Restore plan."""

    component_id: str
    reason: RestoreExclusionReason


@dataclass(frozen=True, slots=True)
class EffectiveRestorePlan:
    """Immutable executable projection of a fully validated Restore archive."""

    full_plan: RestorePlan
    target_server_ip: str
    applied_components: tuple[RestoreComponent, ...]
    skipped_components: tuple[RestorePolicyExclusion, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.full_plan, RestorePlan):
            raise RestoreError("Effective Restore plan requires a full Restore plan.")
        try:
            normalized_target = str(ipaddress.IPv4Address(self.target_server_ip))
        except ipaddress.AddressValueError as error:
            raise RestoreError("Restore target server must be an IPv4 address.") from error
        if normalized_target != self.target_server_ip:
            raise RestoreError("Restore target server IPv4 must be normalized.")
        if not self.applied_components:
            raise RestoreError(
                "Restore cannot start: no Components remain after policy exclusions."
            )

        full_components = {
            component.component_id: component for component in self.full_plan.components
        }
        applied_ids = tuple(component.component_id for component in self.applied_components)
        skipped_ids = tuple(exclusion.component_id for exclusion in self.skipped_components)
        if len(set(applied_ids)) != len(applied_ids) or len(set(skipped_ids)) != len(skipped_ids):
            raise RestoreError("Effective Restore plan contains duplicate Components.")
        if set(applied_ids) & set(skipped_ids) or set((*applied_ids, *skipped_ids)) != set(
            full_components
        ):
            raise RestoreError(
                "Effective Restore plan does not exactly cover the full Restore plan."
            )
        if self.applied_components != tuple(
            component
            for component in self.full_plan.components
            if component.component_id in applied_ids
        ):
            raise RestoreError(
                "Effective Restore plan changed an applied Component from the full plan."
            )
        if skipped_ids != tuple(
            component.component_id
            for component in self.full_plan.components
            if component.component_id in skipped_ids
        ):
            raise RestoreError("Effective Restore plan changed the order of skipped Components.")

        cross_server = self.full_plan.source_server_ip != self.target_server_ip
        expected_skipped = tuple(
            component.component_id
            for component in self.full_plan.components
            if cross_server and component.component_id == "nginx"
        )
        if skipped_ids != expected_skipped or any(
            exclusion.reason != NGINX_CROSS_SERVER_EXCLUSION_REASON
            for exclusion in self.skipped_components
        ):
            raise RestoreError(
                "Effective Restore plan does not match the cross-server Nginx policy."
            )

    @property
    def archive_path(self) -> Path:
        return self.full_plan.archive_path

    @property
    def source_server_ip(self) -> str:
        return self.full_plan.source_server_ip

    @property
    def created_at(self) -> str:
        return self.full_plan.created_at

    @property
    def archive_sha256(self) -> str:
        return self.full_plan.archive_sha256

    @property
    def paths(self) -> tuple[str, ...]:
        return tuple(path for component in self.applied_components for path in component.paths)

    @property
    def requires_daemon_reload(self) -> bool:
        return any(component.daemon_reload for component in self.applied_components)

    @property
    def service_actions(self) -> tuple[RestoreService, ...]:
        return tuple(
            service for component in self.applied_components for service in component.services
        )

    @property
    def has_policy_exclusions(self) -> bool:
        return bool(self.skipped_components)


def build_effective_restore_plan(plan: RestorePlan, target_server_ip: str) -> EffectiveRestorePlan:
    """Apply fixed cross-server policy to one fully validated archive plan."""
    if not isinstance(plan, RestorePlan):
        raise RestoreError("Effective Restore plan requires a full Restore plan.")
    try:
        normalized_target = str(ipaddress.IPv4Address(target_server_ip))
    except ipaddress.AddressValueError as error:
        raise RestoreError("Restore target server must be an IPv4 address.") from error
    if normalized_target != target_server_ip:
        raise RestoreError("Restore target server IPv4 must be normalized.")
    cross_server = plan.source_server_ip != target_server_ip
    applied_components = tuple(
        component
        for component in plan.components
        if not (cross_server and component.component_id == "nginx")
    )
    skipped_components = tuple(
        RestorePolicyExclusion(component.component_id, NGINX_CROSS_SERVER_EXCLUSION_REASON)
        for component in plan.components
        if cross_server and component.component_id == "nginx"
    )
    return EffectiveRestorePlan(
        plan,
        target_server_ip,
        applied_components,
        skipped_components,
    )


def restore_plan_from_archive(
    archive_path: Path, *, archive_file: BinaryIO | None = None
) -> RestorePlan:
    """Read and strictly validate a local gzip-compressed Backup archive."""
    if not archive_path.is_file():
        raise RestoreError("The selected Backup archive could not be found.")
    try:
        if archive_file is not None:
            return _restore_plan_from_file(archive_path.resolve(), archive_file)
        with archive_path.open("rb") as opened_archive:
            return _restore_plan_from_file(archive_path.resolve(), opened_archive)
    except (OSError, EOFError, tarfile.TarError, zlib.error) as error:
        raise RestoreError(f"Could not read the selected Backup archive: {error}") from error


def authorize_restore_plan(
    plan: EffectiveRestorePlan, snapshot: InventorySnapshot
) -> EffectiveRestorePlan:
    """Build an executable Restore plan only from matching target declarations."""
    if not isinstance(plan, EffectiveRestorePlan):
        raise RestoreError("Restore authorization requires an effective Restore plan.")
    if snapshot.server_ip != plan.target_server_ip:
        raise RestoreError("Restore target Inventory does not match the effective Restore plan.")
    components = {component.component_id: component for component in snapshot.components}
    missing = [
        restored.component_id
        for restored in plan.applied_components
        if (component := components.get(restored.component_id)) is None
        or component.declaration is None
    ]
    if missing:
        raise RestoreError(
            "Restore cannot start: install the missing target component(s) first: "
            + ", ".join(missing)
            + "."
        )

    authorized_components: list[RestoreComponent] = []
    for restored in plan.applied_components:
        declaration = components[restored.component_id].declaration
        if declaration is None:  # Covered above; keeps the type narrowing explicit.
            raise RestoreError(
                f"Restore cannot start: {restored.component_id} has no valid target declaration."
            )
        if restored.contract_version != declaration.contract_version:
            raise RestoreError(
                f"Restore cannot start: {restored.component_id} contract_version does "
                "not match the target declaration "
                f"(archive {restored.contract_version}, target {declaration.contract_version})."
            )
        authorized_paths = (
            *declaration.backup_paths,
            *(
                directory
                for directory in declaration.optional_backup_directories
                if directory in restored.paths
            ),
        )
        if restored.paths != authorized_paths:
            raise RestoreError(
                f"Restore cannot start: {restored.component_id} paths do not exactly "
                "match the target declaration."
            )
        if restored.daemon_reload != declaration.restore_daemon_reload:
            raise RestoreError(
                f"Restore cannot start: {restored.component_id} daemon-reload policy "
                "does not match the target declaration."
            )
        if restored.services != declaration.restore_services:
            raise RestoreError(
                f"Restore cannot start: {restored.component_id} service actions do not "
                "exactly match the target declaration."
            )
        authorized_components.append(
            RestoreComponent(
                declaration.component_id,
                declaration.contract_version,
                authorized_paths,
                declaration.restore_daemon_reload,
                declaration.restore_services,
                restored.source_status,
                restored.software_version,
            )
        )
    return EffectiveRestorePlan(
        plan.full_plan,
        plan.target_server_ip,
        tuple(authorized_components),
        plan.skipped_components,
    )


def _restore_plan_from_file(archive_path: Path, archive_file: BinaryIO) -> RestorePlan:
    archive_file.seek(0)
    archive_sha256 = hashlib.file_digest(archive_file, "sha256").hexdigest()
    archive_file.seek(0)
    with tarfile.open(fileobj=archive_file, mode="r:gz") as archive:
        members = archive.getmembers()
        _validate_archive_size(members)
        manifest = _read_manifest(archive, members)
        plan = _plan_from_manifest(archive_path, manifest, archive_sha256)
        _validate_archive_members(archive, members, plan)
        _read_all_members(archive, members)
    return plan


def render_streaming_restore_command(plan: EffectiveRestorePlan) -> str:
    """Build a fixed Bash command that restores one validated archive from stdin."""
    if not isinstance(plan, EffectiveRestorePlan):
        raise RestoreError("Restore command requires an effective Restore plan.")
    if not plan.paths:
        raise RestoreError("Restore plan does not contain any files.")
    if len(plan.archive_sha256) != 64 or any(
        character not in "0123456789abcdef" for character in plan.archive_sha256
    ):
        raise RestoreError("Restore plan contains an invalid archive SHA-256 digest.")
    relative_paths: list[str] = []
    for path in plan.paths:
        if not REMOTE_PATH_PATTERN.fullmatch(path) or "/../" in path or path.endswith("/.."):
            raise RestoreError("Restore plan contains an unsafe remote path.")
        relative_paths.append(path.removeprefix("/"))
    paths = " ".join(shlex.quote(path) for path in relative_paths)
    actions: list[str] = []
    if plan.requires_daemon_reload:
        actions.extend(
            (
                "printf '%s\\n' 'Reloading systemd unit definitions.' >&2",
                "systemctl daemon-reload",
            )
        )
    for service in plan.service_actions:
        if service.action != "restart" or not SYSTEMD_UNIT_PATTERN.fullmatch(service.unit):
            raise RestoreError("Restore plan contains an unsupported systemd action.")
        actions.extend(
            (
                f"printf '%s\\n' {shlex.quote(f'Restarting {service.unit}.')} >&2",
                f"systemctl restart -- {shlex.quote(service.unit)}",
            )
        )
    actions_text = "\n".join(actions)
    script = f"""set -euo pipefail
umask 077
restore_phase=pre_apply
restore_failure() {{
    code=$?
    printf 'VPN_RESTORE_RESULT failure %s %s\\n' "$restore_phase" "$code" >&2
    exit "$code"
}}
trap restore_failure ERR
if [ "$(id -u)" -ne 0 ]; then
    printf '%s\\n' 'Restore must run as root.' >&2
    printf '%s\\n' 'VPN_RESTORE_RESULT failure pre_apply 1' >&2
    exit 1
fi
for command in tar systemctl mktemp sha256sum cat; do
    command -v "$command" >/dev/null 2>&1 || {{ printf 'Required command is unavailable: %s\\n' "$command" >&2; printf '%s\\n' 'VPN_RESTORE_RESULT failure pre_apply 1' >&2; exit 1; }}
done
workdir="$(mktemp -d /tmp/vpn-restore.XXXXXX)"
trap 'rm -rf -- "$workdir"' EXIT
archive="$workdir/archive.tar.gz"
payload="$workdir/payload"
mkdir -- "$payload"
printf '%s\\n' 'Extracting archive into a temporary staging directory.' >&2
cat > "$archive"
printf '%s  %s\\n' {shlex.quote(plan.archive_sha256)} "$archive" | sha256sum --check --status --
tar --extract --gzip --file "$archive" --numeric-owner --same-owner --same-permissions --acls --xattrs -C "$payload"
restore_phase=validated
printf '%s\\n' 'VPN_RESTORE_PHASE validated' >&2
printf '%s\\n' 'Applying declared files to their absolute paths.' >&2
restore_phase=apply_started
printf '%s\\n' 'VPN_RESTORE_PHASE apply_started' >&2
tar --create --file - --numeric-owner --acls --xattrs -C "$payload" -- {paths} | \\
    tar --extract --file - --numeric-owner --same-owner --same-permissions --acls --xattrs -C /
restore_phase=files_applied
printf '%s\\n' 'VPN_RESTORE_PHASE files_applied' >&2
{actions_text}
restore_phase=services_applied
printf '%s\\n' 'VPN_RESTORE_PHASE services_applied' >&2
trap - ERR
printf '%s\\n' 'VPN_RESTORE_RESULT success complete 0' >&2
printf '%s\\n' 'Restore completed.' >&2
"""  # noqa: E501 -- embedded shell command lines must remain intact
    return "bash -c " + shlex.quote(script)


def _validate_archive_size(members: list[tarfile.TarInfo]) -> None:
    if sum(member.size for member in members) > MAX_UNCOMPRESSED_ARCHIVE_BYTES:
        raise RestoreError("Backup archive exceeds the maximum allowed uncompressed size.")


def _read_manifest(archive: tarfile.TarFile, members: list[tarfile.TarInfo]) -> dict[str, Any]:
    manifests = [member for member in members if member.name == MANIFEST_NAME]
    if len(manifests) != 1 or not manifests[0].isreg():
        raise RestoreError("Backup archive must contain exactly one regular manifest file.")
    handle = archive.extractfile(manifests[0])
    if handle is None:
        raise RestoreError("Backup archive manifest could not be read.")
    try:
        content = handle.read()
        value = json.loads(content.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RestoreError(f"Backup archive manifest is invalid: {error}") from error
    if not isinstance(value, dict):
        raise RestoreError("Backup archive manifest must be a JSON object.")
    return value


def _plan_from_manifest(
    archive_path: Path, manifest: dict[str, Any], archive_sha256: str
) -> RestorePlan:
    if manifest.get("schema_version") != BACKUP_ARCHIVE_SCHEMA_VERSION:
        raise RestoreError("Backup archive has an unsupported schema version.")
    source_server_ip = _ipv4(manifest.get("server_ip"), "server_ip")
    created_at = manifest.get("created_at")
    if not isinstance(created_at, str) or not created_at:
        raise RestoreError("Backup archive manifest created_at must be a non-empty string.")
    try:
        datetime.fromisoformat(created_at.replace("Z", "+00:00"))
    except ValueError as error:
        raise RestoreError("Backup archive manifest created_at is invalid.") from error
    components_data = manifest.get("components")
    if not isinstance(components_data, list) or not components_data:
        raise RestoreError("Backup archive manifest components must be a non-empty list.")
    components: list[RestoreComponent] = []
    component_ids: set[str] = set()
    paths: set[str] = set()
    units: set[str] = set()
    for component_data in components_data:
        if not isinstance(component_data, dict):
            raise RestoreError("Backup archive manifest component entries must be objects.")
        component_id = component_data.get("id")
        if not isinstance(component_id, str) or not COMPONENT_ID_PATTERN.fullmatch(component_id):
            raise RestoreError("Backup archive manifest has an invalid component id.")
        if component_id in component_ids:
            raise RestoreError("Backup archive manifest contains a duplicate component id.")
        component_ids.add(component_id)
        contract_version = component_data.get("contract_version")
        if not isinstance(contract_version, str) or not contract_version:
            raise RestoreError(
                "Backup archive manifest component contract_version must be a non-empty string."
            )
        if "software_version" not in component_data:
            raise RestoreError("Backup archive manifest component is missing software_version.")
        software_version = component_data["software_version"]
        if software_version is not None and (
            not isinstance(software_version, str) or not software_version
        ):
            raise RestoreError("Backup archive manifest component software_version is invalid.")
        source_status = component_data.get("source_status", "unknown")
        if source_status not in {"active", "inactive", "failed", "degraded", "unknown"}:
            raise RestoreError("Backup archive manifest component source_status is invalid.")
        component_paths = _component_paths(component_data.get("paths"), paths)
        daemon_reload, services = _restore_details(component_data.get("restore"), units)
        components.append(
            RestoreComponent(
                component_id,
                contract_version,
                component_paths,
                daemon_reload,
                services,
                source_status,
                software_version,
            )
        )
    return RestorePlan(
        archive_path, source_server_ip, created_at, tuple(components), archive_sha256
    )


def _ipv4(value: object, field: str) -> str:
    if not isinstance(value, str):
        raise RestoreError(f"Backup archive manifest {field} must be an IPv4 address.")
    try:
        address = ipaddress.IPv4Address(value)
    except ipaddress.AddressValueError as error:
        raise RestoreError(f"Backup archive manifest {field} must be an IPv4 address.") from error
    return str(address)


def _component_paths(value: object, seen_paths: set[str]) -> tuple[str, ...]:
    if not isinstance(value, list) or not value:
        raise RestoreError("Backup archive manifest component paths must be a non-empty list.")
    paths: list[str] = []
    for path in value:
        if (
            not isinstance(path, str)
            or not REMOTE_PATH_PATTERN.fullmatch(path)
            or "/../" in path
            or path.endswith("/..")
        ):
            raise RestoreError("Backup archive manifest contains an unsafe path.")
        if path in seen_paths:
            raise RestoreError("Backup archive manifest contains a duplicate path.")
        seen_paths.add(path)
        paths.append(path)
    return tuple(paths)


def _restore_details(
    value: object, seen_units: set[str]
) -> tuple[bool, tuple[RestoreService, ...]]:
    if not isinstance(value, dict):
        raise RestoreError("Backup archive manifest component restore must be an object.")
    daemon_reload = value.get("daemon_reload", False)
    if not isinstance(daemon_reload, bool):
        raise RestoreError("Backup archive manifest restore.daemon_reload must be a boolean.")
    services_value = value.get("services")
    if not isinstance(services_value, list):
        raise RestoreError("Backup archive manifest restore.services must be a list.")
    services: list[RestoreService] = []
    for service_value in services_value:
        if not isinstance(service_value, dict):
            raise RestoreError("Backup archive manifest restore service entries must be objects.")
        unit = service_value.get("unit")
        action = service_value.get("action")
        if not isinstance(unit, str) or not SYSTEMD_UNIT_PATTERN.fullmatch(unit):
            raise RestoreError("Backup archive manifest has an invalid restore systemd unit.")
        if action not in RESTORE_ACTIONS:
            raise RestoreError("Backup archive manifest has an unsupported restore action.")
        if unit in seen_units:
            raise RestoreError(
                "Backup archive manifest contains a duplicate restore systemd unit."
            )
        seen_units.add(unit)
        services.append(RestoreService(unit, action))
    return daemon_reload, tuple(services)


def _validate_archive_members(
    archive: tarfile.TarFile, members: list[tarfile.TarInfo], plan: RestorePlan
) -> None:
    declared_files = {path.removeprefix("/") for path in plan.paths if not path.endswith("/")}
    declared_directories = {
        path.removeprefix("/").rstrip("/") for path in plan.paths if path.endswith("/")
    }
    found_files: set[str] = set()
    found_directories: set[str] = set()
    canonical_names: set[str] = set()
    for member in members:
        if member.name == MANIFEST_NAME:
            if not member.isreg():
                raise RestoreError(
                    "Backup archive must contain exactly one regular manifest file."
                )
            canonical_name = MANIFEST_NAME
        else:
            name = member.name.rstrip("/") if member.isdir() else member.name
            if (
                not name
                or member.name.startswith("/")
                or "\x00" in member.name
                or any(part in {"", ".", ".."} for part in name.split("/"))
            ):
                raise RestoreError("Backup archive contains an unsafe member path.")
            canonical_name = name
            if name in declared_files:
                if not member.isreg():
                    raise RestoreError("Backup archive contains an unsupported member type.")
                found_files.add(name)
            else:
                directory = next(
                    (
                        root
                        for root in declared_directories
                        if name == root or name.startswith(root + "/")
                    ),
                    None,
                )
                if directory is None or not (member.isdir() or member.isreg()):
                    raise RestoreError(
                        "Backup archive contents do not exactly match its manifest."
                    )
                if name == directory:
                    if not member.isdir():
                        raise RestoreError(
                            "Backup archive directory root has an unsupported type."
                        )
                    found_directories.add(directory)
        if canonical_name in canonical_names:
            raise RestoreError("Backup archive contains a duplicate member path.")
        canonical_names.add(canonical_name)
    if found_files != declared_files or found_directories != declared_directories:
        raise RestoreError("Backup archive contents do not exactly match its manifest.")


def _read_all_members(archive: tarfile.TarFile, members: list[tarfile.TarInfo]) -> None:
    for member in members:
        if member.isdir():
            continue
        handle = archive.extractfile(member)
        if handle is None:
            raise RestoreError(f"Backup archive file could not be read: {member.name}")
        while handle.read(64 * 1024):
            pass
