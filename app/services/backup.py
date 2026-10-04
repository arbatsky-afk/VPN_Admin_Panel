"""Preparation of a local backup request from an Inventory snapshot."""

from __future__ import annotations

import base64
import json
import re
import shlex
from dataclasses import dataclass
from datetime import UTC, datetime
from ipaddress import AddressValueError, IPv4Address
from pathlib import Path

from .app_defaults import AppDefaultsError, load_app_defaults
from .declaration_contract import REMOTE_PATH_PATTERN
from .inventory import InventorySnapshot

BACKUP_ARCHIVE_SCHEMA_VERSION = 3
BACKUP_COMPONENT_STATUSES = {"active", "inactive", "failed", "degraded"}
_BACKUP_ARCHIVE_NAME = re.compile(
    r"^vpn-backup-(?P<server_ip>\d{1,3}(?:\.\d{1,3}){3})-"
    r"(?P<created_at>\d{8}-\d{6})"
    r"(?:-(?P<sequence>[2-9]|[1-9]\d+))?\.tar\.gz$"
)


class BackupError(ValueError):
    """Raised when Inventory cannot safely define a backup."""


@dataclass(frozen=True)
class BackupPlan:
    """Validated, serializable archive contents for one server."""

    server_ip: str
    created_at: str
    components: tuple[dict[str, object], ...]

    def encoded_manifest(self) -> str:
        """Return the archive manifest in a command-line safe encoding."""
        manifest = {
            "schema_version": BACKUP_ARCHIVE_SCHEMA_VERSION,
            "server_ip": self.server_ip,
            "created_at": self.created_at,
            "components": list(self.components),
        }
        encoded = json.dumps(manifest, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        return base64.b64encode(encoded).decode("ascii")

    @property
    def paths(self) -> tuple[str, ...]:
        return tuple(
            path
            for component in self.components
            for path in component["paths"]
            if isinstance(path, str)
        )


@dataclass(frozen=True)
class LocalBackupArchive:
    """A local archive whose name follows the Backup naming contract."""

    path: Path
    source_server_ip: str
    created_at: datetime
    size_bytes: int


def backup_plan_from_snapshot(snapshot: InventorySnapshot) -> BackupPlan:
    """Select the declared files of every installed component from Inventory."""
    components: list[dict[str, object]] = []
    seen_paths: set[str] = set()
    invalid_declarations = [
        component.component_id
        for component in snapshot.components
        if component.declaration is None
    ]
    if invalid_declarations:
        raise BackupError(
            "Backup cannot start: registered component(s) have no valid declaration: "
            + ", ".join(invalid_declarations)
            + "."
        )
    for component in snapshot.components:
        declaration = component.declaration
        if declaration is None:  # Rejected above; keeps type narrowing explicit.
            raise BackupError(
                f"Backup cannot start: {component.component_id} has no valid declaration."
            )
        if component.status not in BACKUP_COMPONENT_STATUSES:
            raise BackupError(
                f"Backup cannot start: {component.component_id} has an unsupported "
                f"Inventory status: {component.status}."
            )
        optional_checks = {
            check.target: check
            for check in component.checks
            if check.category == "optional_directory"
        }
        selected_optional_directories: list[str] = []
        for path in declaration.optional_backup_directories:
            check = optional_checks.get(path)
            if check is None or not check.passed or check.detail not in {"present", "absent"}:
                raise BackupError(
                    f"Backup cannot start: {component.component_id} optional backup "
                    "directory could not be inspected: "
                    f"{path}."
                )
            if check.detail == "present":
                selected_optional_directories.append(path)
        selected_paths = (*declaration.backup_paths, *selected_optional_directories)
        if not selected_paths:
            continue
        file_checks = {
            check.target: check.passed for check in component.checks if check.category == "file"
        }
        unavailable_paths = [
            path for path in declaration.backup_paths if file_checks.get(path) is not True
        ]
        if unavailable_paths:
            raise BackupError(
                f"Backup cannot start: {component.component_id} has unavailable "
                "declared backup file(s): " + ", ".join(unavailable_paths) + "."
            )
        overlapping_paths = [
            path
            for path in selected_paths
            if any(_backup_paths_overlap(path, owned_path) for owned_path in seen_paths)
        ]
        if overlapping_paths:
            raise BackupError(
                f"Backup cannot start: {component.component_id} declares backup path(s) "
                "already owned by another component: " + ", ".join(overlapping_paths) + "."
            )
        seen_paths.update(selected_paths)
        components.append(
            {
                "id": declaration.component_id,
                "contract_version": declaration.contract_version,
                "software_version": component.software_version,
                "source_status": component.status,
                "paths": list(selected_paths),
                "restore": {
                    "daemon_reload": declaration.restore_daemon_reload,
                    "services": [
                        {"unit": service.unit, "action": service.action}
                        for service in declaration.restore_services
                    ],
                },
            }
        )
    if not components:
        raise BackupError("Inventory reports no installed components with backup files.")
    return BackupPlan(
        server_ip=snapshot.server_ip,
        created_at=datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        components=tuple(components),
    )


def _backup_paths_overlap(left: str, right: str) -> bool:
    if left == right:
        return True
    if left.endswith("/") and right.startswith(left):
        return True
    return right.endswith("/") and left.startswith(right)


def configured_backups_directory(project_directory: Path) -> Path:
    """Return the application-owned backup destination without creating it."""
    try:
        return load_app_defaults(project_directory).backups_directory
    except AppDefaultsError as error:
        raise BackupError(
            f"Could not resolve the application backup directory: {error}"
        ) from error


def list_local_backup_archives(backups_directory: Path) -> tuple[LocalBackupArchive, ...]:
    """Return recognised local archives, newest first, without opening them."""
    if not backups_directory.exists():
        return ()
    if not backups_directory.is_dir():
        raise BackupError(f"Backup path is not a directory: {backups_directory}")
    try:
        candidates = tuple(backups_directory.iterdir())
    except OSError as error:
        raise BackupError(f"Could not list backup directory: {error}") from error

    archives: list[tuple[LocalBackupArchive, int]] = []
    for candidate in candidates:
        if candidate.is_symlink() or not candidate.is_file():
            continue
        match = _BACKUP_ARCHIVE_NAME.fullmatch(candidate.name)
        if match is None:
            continue
        try:
            source_server_ip = str(IPv4Address(match.group("server_ip")))
            created_at = datetime.strptime(match.group("created_at"), "%Y%m%d-%H%M%S")
            size_bytes = candidate.stat().st_size
        except (AddressValueError, OSError, ValueError):
            continue
        sequence = int(match.group("sequence") or 1)
        archive = LocalBackupArchive(candidate, source_server_ip, created_at, size_bytes)
        archives.append((archive, sequence))
    archives.sort(key=lambda item: (item[0].created_at, item[1]), reverse=True)
    return tuple(archive for archive, _sequence in archives)


def delete_local_backup_archive(backups_directory: Path, archive_path: Path) -> None:
    """Delete one recognised, non-symlink archive from the configured directory."""
    try:
        directory = backups_directory.resolve(strict=True)
    except OSError as error:
        raise BackupError(f"Could not resolve backup directory: {error}") from error
    if not directory.is_dir():
        raise BackupError(f"Backup path is not a directory: {backups_directory}")
    if archive_path.parent.resolve(strict=False) != directory:
        raise BackupError("Selected archive is outside the configured backup directory.")
    if _BACKUP_ARCHIVE_NAME.fullmatch(archive_path.name) is None:
        raise BackupError("Selected file is not a recognised Backup archive.")
    try:
        if archive_path.is_symlink() or not archive_path.is_file():
            raise BackupError("Selected Backup archive no longer exists as a regular file.")
        archive_path.unlink()
    except OSError as error:
        raise BackupError(f"Could not delete Backup archive: {error}") from error


def render_streaming_backup_script(plan: BackupPlan) -> str:
    """Build the one-time Bash program sent directly to ``ssh`` standard input."""
    if not plan.paths:
        raise BackupError("Backup plan does not contain any files.")
    relative_paths: list[str] = []
    for path in plan.paths:
        if not REMOTE_PATH_PATTERN.fullmatch(path) or "/../" in path or path.endswith("/.."):
            raise BackupError("Backup plan contains an unsafe remote path.")
        relative_paths.append(path.removeprefix("/"))
    path_arguments = " ".join(shlex.quote(path) for path in relative_paths)
    file_validations = "\n".join(
        (
            f"file={shlex.quote(path)}\n"
            '[[ -f "$file" && ! -L "$file" ]] || { '
            "printf 'Declared backup file is no longer a regular non-symlink file: %s\\n' "
            '"$file" >&2; exit 1; }'
        )
        for path in plan.paths
        if not path.endswith("/")
    )
    directory_validations = "\n".join(
        (
            f"directory={shlex.quote(path.rstrip('/'))}\n"
            '[[ -d "$directory" && ! -L "$directory" ]] || { '
            "printf 'Optional backup directory is no longer a real directory: %s\\n' "
            '"$directory" >&2; exit 1; }\n'
            'if find "$directory" -mindepth 1 ! -type f ! -type d -print -quit | grep -q .; then\n'
            "  printf 'Optional backup directory contains an unsupported entry: %s\\n' "
            '"$directory" >&2\n'
            "  exit 1\n"
            "fi"
        )
        for path in plan.paths
        if path.endswith("/")
    )
    return f"""#!/usr/bin/env bash
set -euo pipefail
umask 077
{file_validations}
{directory_validations}
workdir="$(mktemp -d /tmp/vpn-backup.XXXXXX)"
trap 'rm -rf -- "$workdir"' EXIT
archive="$workdir/backup.tar.gz"
printf '%s' '{plan.encoded_manifest()}' | base64 --decode > "$workdir/vpn-backup-manifest.json"
tar --create --gzip --file "$archive" --numeric-owner --acls --xattrs -C "$workdir" vpn-backup-manifest.json -C / -- {path_arguments}
checksum=$(sha256sum -- "$archive" | awk '{{print $1}}')
printf 'SHA256=%s\\n' "$checksum" >&2
printf '%s\\n' 'Streaming backup archive.' >&2
cat -- "$archive"
"""  # noqa: E501 -- embedded shell command lines must remain intact
