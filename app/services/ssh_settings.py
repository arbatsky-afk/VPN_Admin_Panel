"""Central access to panel-owned SSH connection settings."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from .project_paths import panel_settings_path
from .settings_manager import SettingsManager

SSH_SETTINGS_KEY = "ssh"
DEFAULT_SSH_PORT = 22


class SshSettingsError(ValueError):
    """The local SSH-key configuration cannot be used safely."""


@dataclass(frozen=True)
class SshKeyRecord:
    """One validated SSH identity from the current list-based configuration."""

    name: str
    private_key_path: Path
    is_primary: bool


@dataclass(frozen=True)
class SshConnectionSettings:
    """The primary SSH identity and port used by regular panel operations."""

    private_key_path: Path
    port: int


def primary_ssh_connection(project_directory: Path) -> SshConnectionSettings:
    """Return the validated primary identity and configured SSH port."""
    settings = _read_panel_ssh_settings(project_directory)
    primary_key = _primary_key(_ssh_key_records({"ssh": settings}))
    ssh_port = _validated_port(settings.get("port", DEFAULT_SSH_PORT))
    return SshConnectionSettings(primary_key.private_key_path, ssh_port)


def ssh_fix_private_keys(project_directory: Path) -> tuple[Path, ...]:
    """Return every configured private key for SSH Fix, without duplicates."""
    key_paths: list[Path] = []
    settings = _read_panel_ssh_settings(project_directory)
    for key in _ssh_key_records({"ssh": settings}):
        if key.private_key_path not in key_paths:
            key_paths.append(key.private_key_path)
    return tuple(key_paths)


def configured_ssh_keys(project_directory: Path) -> tuple[SshKeyRecord, ...]:
    """Return the validated non-empty SSH key list for safe operations."""
    return _ssh_key_records({"ssh": _read_panel_ssh_settings(project_directory)})


def save_ssh_settings(
    settings_manager: SettingsManager,
    key_records: Sequence[SshKeyRecord],
    port: int,
    *,
    save: bool = True,
) -> tuple[SshKeyRecord, ...]:
    """Replace panel-owned SSH settings, optionally deferring the atomic save."""
    validated_records = _validate_key_records(key_records)
    validated_port = _validated_port(port)
    updated_ssh_settings: dict[str, object] = {"port": validated_port}
    updated_ssh_settings["keys"] = [
        {
            "name": record.name,
            "private_key_path": str(record.private_key_path),
            "is_primary": record.is_primary,
        }
        for record in validated_records
    ]
    settings_manager.set(SSH_SETTINGS_KEY, updated_ssh_settings)
    if save:
        settings_manager.save()
    return validated_records


def editable_ssh_settings(
    settings_manager: SettingsManager,
) -> tuple[int, tuple[SshKeyRecord, ...]]:
    """Return the editable SSH port and key list, allowing an empty bootstrap list."""
    value = settings_manager.get(SSH_SETTINGS_KEY)
    if value is None:
        return DEFAULT_SSH_PORT, ()
    if not isinstance(value, dict):
        raise SshSettingsError("Panel settings contain an invalid ssh section.")
    port = _validated_port(value.get("port", DEFAULT_SSH_PORT))
    if value.get("keys") == []:
        return port, ()
    return port, _ssh_key_records({"ssh": value})


def _read_panel_ssh_settings(project_directory: Path) -> dict[str, object]:
    manager = SettingsManager(panel_settings_path(project_directory))
    value = manager.get(SSH_SETTINGS_KEY)
    if not isinstance(value, dict):
        raise SshSettingsError("Panel settings are missing SSH configuration.")
    return value


def _validated_port(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 65535:
        raise SshSettingsError("SSH port must be between 1 and 65535.")
    return value


def _ssh_key_records(settings: dict[str, object]) -> tuple[SshKeyRecord, ...]:
    ssh_settings = _ssh_settings(settings)
    if "keys" in ssh_settings:
        return _list_key_records(ssh_settings["keys"])
    return _legacy_key_records(ssh_settings)


def _list_key_records(configured_keys: object) -> tuple[SshKeyRecord, ...]:
    if not isinstance(configured_keys, list) or not configured_keys:
        raise SshSettingsError("Local configuration must contain a non-empty ssh.keys list.")
    key_records: list[SshKeyRecord] = []
    for index, configured_key in enumerate(configured_keys):
        if not isinstance(configured_key, dict):
            raise SshSettingsError(f"Local configuration has an invalid ssh.keys[{index}] entry.")
        name = configured_key.get("name")
        if not isinstance(name, str) or not name.strip():
            raise SshSettingsError(f"Local configuration has an invalid ssh.keys[{index}].name.")
        is_primary = configured_key.get("is_primary")
        if not isinstance(is_primary, bool):
            raise SshSettingsError(
                f"Local configuration has an invalid ssh.keys[{index}].is_primary."
            )
        configured_path = configured_key.get("private_key_path")
        if not isinstance(configured_path, str) or not configured_path.strip():
            raise SshSettingsError(
                f"Local configuration has an invalid ssh.keys[{index}].private_key_path."
            )
        key_records.append(SshKeyRecord(name.strip(), Path(configured_path), is_primary))
    return _validate_key_records(key_records)


def _legacy_key_records(ssh_settings: dict[str, object]) -> tuple[SshKeyRecord, ...]:
    """Read the temporary two-field schema until the UI migrates it."""
    primary_key = _required_private_key(ssh_settings, "private_key_path")
    key_records = [SshKeyRecord("Primary", primary_key, True)]
    optional_key = _optional_private_key(ssh_settings, "amnezia_private_key_path")
    if optional_key is not None and optional_key != primary_key:
        key_records.append(SshKeyRecord("Amnezia", optional_key, False))
    return tuple(key_records)


def _primary_key(key_records: tuple[SshKeyRecord, ...]) -> SshKeyRecord:
    primary_keys = [key for key in key_records if key.is_primary]
    if len(primary_keys) != 1:
        raise SshSettingsError(
            "Local configuration must mark exactly one ssh.keys entry as primary."
        )
    return primary_keys[0]


def _validate_key_records(key_records: Sequence[SshKeyRecord]) -> tuple[SshKeyRecord, ...]:
    if not key_records:
        raise SshSettingsError("Local configuration must contain a non-empty ssh.keys list.")
    validated_records: list[SshKeyRecord] = []
    known_paths: set[Path] = set()
    for index, record in enumerate(key_records):
        if not isinstance(record, SshKeyRecord):
            raise SshSettingsError(f"Local configuration has an invalid ssh.keys[{index}] entry.")
        if not isinstance(record.name, str) or not record.name.strip():
            raise SshSettingsError(f"Local configuration has an invalid ssh.keys[{index}].name.")
        if not isinstance(record.is_primary, bool):
            raise SshSettingsError(
                f"Local configuration has an invalid ssh.keys[{index}].is_primary."
            )
        private_key_path = _existing_private_key(
            str(record.private_key_path), f"keys[{index}].private_key_path"
        )
        normalized_path = private_key_path.resolve()
        if normalized_path in known_paths:
            raise SshSettingsError(
                "Local configuration must not contain duplicate ssh.keys private key paths."
            )
        known_paths.add(normalized_path)
        validated_records.append(
            SshKeyRecord(record.name.strip(), private_key_path, record.is_primary)
        )
    _primary_key(tuple(validated_records))
    return tuple(validated_records)


def _required_private_key(ssh_settings: dict[str, object], field_name: str) -> Path:
    configured_path = ssh_settings.get(field_name)
    if not isinstance(configured_path, str) or not configured_path.strip():
        raise SshSettingsError(f"Local configuration is missing ssh.{field_name}.")
    return _existing_private_key(configured_path, field_name)


def _optional_private_key(ssh_settings: dict[str, object], field_name: str) -> Path | None:
    configured_path = ssh_settings.get(field_name)
    if configured_path is None or configured_path == "":
        return None
    if not isinstance(configured_path, str) or not configured_path.strip():
        raise SshSettingsError(f"Local configuration has an invalid ssh.{field_name}.")
    return _existing_private_key(configured_path, field_name)


def _ssh_settings(settings: dict[str, object]) -> dict[str, object]:
    ssh_settings = settings.get("ssh")
    if not isinstance(ssh_settings, dict):
        raise SshSettingsError("Local configuration is missing ssh.")
    return ssh_settings


def _existing_private_key(configured_path: str, field_name: str) -> Path:
    private_key_path = Path(configured_path)
    if not private_key_path.is_file():
        raise SshSettingsError(
            f"The SSH private key configured by ssh.{field_name} could not be found."
        )
    return private_key_path
