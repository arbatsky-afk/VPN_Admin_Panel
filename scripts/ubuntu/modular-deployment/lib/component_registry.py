#!/usr/bin/env python3
"""Safe state-registry operations for modular deployment components."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import sys
import tempfile
from pathlib import Path
from typing import Any

LIBRARY_DIRECTORY = Path(__file__).resolve().parent
if str(LIBRARY_DIRECTORY) not in sys.path:
    sys.path.insert(0, str(LIBRARY_DIRECTORY))

from component_declaration import (  # noqa: E402 -- import follows local sys.path setup
    DeclarationError,
    load_and_validate_declaration,
)

try:
    import fcntl
except ImportError:  # pragma: no cover - Windows is used only for local tests.
    fcntl = None


REGISTRY_SCHEMA_VERSION = 2
COMPONENT_ID = re.compile(r"^[a-z0-9][a-z0-9-]*$")


class RegistryError(ValueError):
    """Raised when registry or declaration data is invalid."""


def _load_json(path: Path, label: str) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except OSError as error:
        raise RegistryError(f"Could not read {label}: {error}") from error
    except json.JSONDecodeError as error:
        raise RegistryError(f"Invalid JSON in {label}: {error}") from error
    if not isinstance(data, dict):
        raise RegistryError(f"{label} must contain a JSON object.")
    return data


def validate_declaration(path: Path, component_id: str) -> dict[str, Any]:
    """Validate the stable, data-only contract required before registration."""
    try:
        return load_and_validate_declaration(path, component_id)
    except DeclarationError as error:
        raise RegistryError(str(error)) from error


def load_registry(path: Path) -> dict[str, Any]:
    """Return the registry or an empty schema-v2 registry when it is absent."""
    if not path.exists():
        return {"schema_version": REGISTRY_SCHEMA_VERSION, "components": {}}
    data = _load_json(path, "component state registry")
    if data.get("schema_version") != REGISTRY_SCHEMA_VERSION:
        raise RegistryError("Component state registry has an unsupported schema_version.")
    components = data.get("components")
    if not isinstance(components, dict):
        raise RegistryError("Component state registry must contain a components object.")
    for component_id, record in components.items():
        if not isinstance(component_id, str) or not COMPONENT_ID.fullmatch(component_id):
            raise RegistryError("Component state registry contains an invalid component id.")
        if not isinstance(record, dict):
            raise RegistryError(
                f"Component state registry record {component_id!r} must be an object."
            )
        contract_version = record.get("contract_version")
        if not isinstance(contract_version, str) or not contract_version.strip():
            raise RegistryError(
                f"Component state registry record {component_id!r} has an invalid "
                "contract_version."
            )
    return data


def _valid_timestamp(value: str | None) -> str | None:
    if not isinstance(value, str):
        return None
    try:
        dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return value


def _now() -> str:
    return (
        dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    )


def _write_registry(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    descriptor, temporary_name = tempfile.mkstemp(prefix=".components.", dir=path.parent)
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(data, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary_path, 0o600)
        os.replace(temporary_path, path)
        if os.name != "nt":
            directory_descriptor = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(directory_descriptor)
            finally:
                os.close(directory_descriptor)
    finally:
        if temporary_path.exists():
            temporary_path.unlink()


def register_component(
    registry_path: Path,
    declaration_path: Path,
    component_directory: Path,
    component_id: str,
    state: dict[str, Any] | None = None,
    legacy_installed_at: str | None = None,
) -> dict[str, Any]:
    """Create or update one component State registry record atomically."""
    if not COMPONENT_ID.fullmatch(component_id):
        raise RegistryError("Component id is invalid.")
    expected_declaration = component_directory / "declaration.json"
    if declaration_path != expected_declaration:
        raise RegistryError("Component declaration path is outside its component directory.")
    declaration = validate_declaration(declaration_path, component_id)
    registry_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(registry_path.parent, 0o700)
    lock_path = registry_path.parent / ".components.lock"
    lock_descriptor = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        os.chmod(lock_path, 0o600)
        if fcntl is not None:
            fcntl.flock(lock_descriptor, fcntl.LOCK_EX)
        registry = load_registry(registry_path)
        components = registry["components"]
        existing = components.get(component_id)
        if existing is not None and not isinstance(existing, dict):
            raise RegistryError(f"Existing {component_id} registry record is invalid.")
        existing_installed_at = _valid_timestamp(
            existing.get("installed_at") if existing else None
        )
        installed_at = existing_installed_at or _valid_timestamp(legacy_installed_at) or _now()
        record = {
            "installed": True,
            "contract_version": declaration["contract_version"],
            "declaration_path": str(declaration_path),
            "installed_at": installed_at,
            "last_updated_at": _now(),
        }
        if state is not None:
            record["state"] = state
        components[component_id] = record
        _write_registry(registry_path, registry)
        return record
    finally:
        if fcntl is not None:
            fcntl.flock(lock_descriptor, fcntl.LOCK_UN)
        os.close(lock_descriptor)


def register_base_security(
    registry_path: Path,
    declaration_path: Path,
    component_directory: Path,
    ssh_port: int,
    legacy_installed_at: str | None,
) -> dict[str, Any]:
    """Register Base + Security with the non-secret state used by Xray."""
    if not 1 <= ssh_port <= 65535:
        raise RegistryError("Base + Security SSH port must be between 1 and 65535.")
    return register_component(
        registry_path,
        declaration_path,
        component_directory,
        "base-security",
        {"ssh_port": ssh_port},
        legacy_installed_at,
    )


def base_security_record(registry_path: Path) -> dict[str, Any] | None:
    registry = load_registry(registry_path)
    record = registry["components"].get("base-security")
    if record is None:
        return None
    if record.get("installed") is not True:
        raise RegistryError("Base + Security registry record is not marked installed.")
    if not isinstance(record.get("declaration_path"), str):
        raise RegistryError("Base + Security registry record has no declaration path.")
    return record


def base_security_ssh_port(registry_path: Path) -> int | None:
    record = base_security_record(registry_path)
    if record is None:
        return None
    state = record.get("state")
    if (
        not isinstance(state, dict)
        or isinstance(state.get("ssh_port"), bool)
        or not isinstance(state.get("ssh_port"), int)
    ):
        raise RegistryError("Base + Security registry record has an invalid SSH port.")
    ssh_port = state["ssh_port"]
    if not 1 <= ssh_port <= 65535:
        raise RegistryError("Base + Security registry SSH port is outside the valid range.")
    return ssh_port


def component_present(registry_path: Path, component_id: str) -> bool:
    """Return whether one registered component has a valid installed record."""
    if not isinstance(component_id, str) or not COMPONENT_ID.fullmatch(component_id):
        raise RegistryError("Component id is invalid.")
    registry = load_registry(registry_path)
    record = registry["components"].get(component_id)
    if record is None:
        return False
    if not isinstance(record, dict):
        raise RegistryError(f"Component state registry record {component_id!r} must be an object.")
    if record.get("installed") is not True:
        raise RegistryError(
            f"Component state registry record {component_id!r} is not marked installed."
        )
    contract_version = record.get("contract_version")
    if not isinstance(contract_version, str) or not contract_version.strip():
        raise RegistryError(
            f"Component state registry record {component_id!r} has an invalid contract_version."
        )
    declaration_path = record.get("declaration_path")
    expected_declaration_path = f"/opt/vpn/components/{component_id}/declaration.json"
    if declaration_path != expected_declaration_path:
        raise RegistryError(
            f"Component state registry record {component_id!r} has an invalid declaration path."
        )
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    validate = commands.add_parser("validate-declaration")
    validate.add_argument("declaration", type=Path)
    validate.add_argument("component")

    register = commands.add_parser("register-base-security")
    register.add_argument("--registry", required=True, type=Path)
    register.add_argument("--declaration", required=True, type=Path)
    register.add_argument("--component-directory", required=True, type=Path)
    register.add_argument("--ssh-port", required=True, type=int)
    register.add_argument("--legacy-installed-at")

    register_component_parser = commands.add_parser("register-component")
    register_component_parser.add_argument("--registry", required=True, type=Path)
    register_component_parser.add_argument("--declaration", required=True, type=Path)
    register_component_parser.add_argument("--component-directory", required=True, type=Path)
    register_component_parser.add_argument("--component", required=True)

    present = commands.add_parser("base-security-present")
    present.add_argument("--registry", required=True, type=Path)

    component_present_parser = commands.add_parser("component-present")
    component_present_parser.add_argument("--registry", required=True, type=Path)
    component_present_parser.add_argument("--component", required=True)

    port = commands.add_parser("base-security-ssh-port")
    port.add_argument("--registry", required=True, type=Path)

    arguments = parser.parse_args()
    try:
        if arguments.command == "validate-declaration":
            validate_declaration(arguments.declaration, arguments.component)
        elif arguments.command == "register-base-security":
            register_base_security(
                arguments.registry,
                arguments.declaration,
                arguments.component_directory,
                arguments.ssh_port,
                arguments.legacy_installed_at,
            )
        elif arguments.command == "register-component":
            register_component(
                arguments.registry,
                arguments.declaration,
                arguments.component_directory,
                arguments.component,
                None,
                None,
            )
        elif arguments.command == "base-security-present":
            if base_security_record(arguments.registry) is None:
                return 1
        elif arguments.command == "component-present":
            if not component_present(arguments.registry, arguments.component):
                return 1
        elif arguments.command == "base-security-ssh-port":
            ssh_port = base_security_ssh_port(arguments.registry)
            if ssh_port is None:
                return 1
            print(ssh_port)
        return 0
    except RegistryError as error:
        print(f"Component registry error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
