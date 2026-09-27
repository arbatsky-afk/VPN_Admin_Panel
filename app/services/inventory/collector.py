"""Validation and collection of immutable Inventory snapshots."""

from __future__ import annotations

import json

from ..declaration_contract import (
    COMPONENT_ID_PATTERN,
    REMOTE_PATH_PATTERN,
    RESTORE_ACTIONS,
    SYSTEMD_UNIT_PATTERN,
    DeclarationError,
    validate_declaration_text,
)
from ..ssh import validate_server_ip
from .contracts import (
    INVENTORY_PROFILES,
    CheckResult,
    ComponentDeclaration,
    ComponentInventory,
    InventoryError,
    InventoryProfile,
    InventorySnapshot,
    InventoryTransport,
    InventoryTransportError,
    ManagementParameter,
    RestoreService,
)

REGISTRY_PATH = "/opt/vpn/state/components.json"
COMPONENTS_DIRECTORY = "/opt/vpn/components"
REGISTRY_SCHEMA_VERSION = 2


class InventoryCollector:
    """Collect one immutable, fixed-profile Inventory snapshot through a transport."""

    def __init__(
        self,
        server_ip: str,
        transport: InventoryTransport,
        *,
        profile: InventoryProfile = "full",
    ) -> None:
        server_ip, validation_error = validate_server_ip(server_ip)
        if validation_error:
            raise InventoryError(validation_error)
        if profile not in INVENTORY_PROFILES:
            raise InventoryError(f"Unsupported Inventory profile: {profile}")
        self.server_ip = server_ip
        self.transport = transport
        self.profile = profile

    def collect_snapshot(self) -> InventorySnapshot:
        registry = self._load_registry(self.transport.read_text(REGISTRY_PATH))
        collected = (
            self._collect_component(component_id, record)
            for component_id, record in sorted(registry["components"].items())
            if record["installed"] is True
        )
        components = tuple(
            component for component in collected if self._includes_component(component)
        )
        return InventorySnapshot(self.server_ip, components, self.profile)

    def _collect_component(
        self, component_id: str, record: dict[str, object]
    ) -> ComponentInventory:
        expected_declaration_path = f"{COMPONENTS_DIRECTORY}/{component_id}/declaration.json"
        try:
            declaration_path = self._declaration_path(component_id, record)
            declaration = self._load_declaration(
                self.transport.read_text(declaration_path), component_id
            )
            if record.get("contract_version") != declaration.contract_version:
                raise InventoryError(
                    f"Component {component_id} registry contract_version does not match "
                    "its declaration."
                )
        except (InventoryError, InventoryTransportError) as error:
            return ComponentInventory(
                component_id,
                "degraded",
                None,
                (CheckResult("declaration", expected_declaration_path, False, str(error)),),
                None,
            )

        if self.profile != "full":
            return ComponentInventory(
                component_id,
                "registered",
                declaration,
                (),
                None,
            )

        checks: list[CheckResult] = []
        software_version: str | None = None
        try:
            software_version = self.transport.software_version(component_id)
            checks.append(
                CheckResult(
                    "software_version",
                    component_id,
                    True,
                    software_version or "not applicable",
                )
            )
        except (InventoryError, InventoryTransportError) as error:
            checks.append(CheckResult("software_version", component_id, False, str(error)))
        checked_paths = tuple(
            dict.fromkeys((*declaration.installation_files, *declaration.backup_paths))
        )
        for path in checked_paths:
            try:
                exists = self.transport.file_exists(path)
                checks.append(
                    CheckResult("file", path, exists, "present" if exists else "missing")
                )
            except (InventoryError, InventoryTransportError) as error:
                checks.append(CheckResult("file", path, False, str(error)))

        for path in declaration.optional_backup_directories:
            try:
                exists = self.transport.directory_exists(path)
                checks.append(
                    CheckResult(
                        "optional_directory", path, True, "present" if exists else "absent"
                    )
                )
            except (InventoryError, InventoryTransportError) as error:
                checks.append(CheckResult("optional_directory", path, False, str(error)))

        for unit in declaration.systemd_units:
            try:
                state = self.transport.systemd_state(unit)
                checks.append(CheckResult("systemd", unit, state == "active", state))
            except (InventoryError, InventoryTransportError) as error:
                checks.append(CheckResult("systemd", unit, False, str(error)))

        for check_id in declaration.health_checks:
            try:
                passed, detail = self.transport.health_check(component_id, check_id)
                checks.append(CheckResult("health", check_id, passed, detail))
            except (InventoryError, InventoryTransportError) as error:
                checks.append(CheckResult("health", check_id, False, str(error)))

        return ComponentInventory(
            component_id,
            self._status(checks),
            declaration,
            tuple(checks),
            software_version,
        )

    def _includes_component(self, component: ComponentInventory) -> bool:
        if self.profile == "full":
            return True
        if self.profile == "subscriptions":
            return component.component_id == "nginx"
        return component.declaration is not None and component.declaration.users_supported

    @staticmethod
    def _load_registry(text: str) -> dict[str, object]:
        try:
            registry = json.loads(text)
        except json.JSONDecodeError as error:
            raise InventoryError(
                f"Component state registry contains invalid JSON: {error}"
            ) from error
        if (
            not isinstance(registry, dict)
            or registry.get("schema_version") != REGISTRY_SCHEMA_VERSION
        ):
            raise InventoryError("Component state registry has an unsupported schema_version.")
        components = registry.get("components")
        if not isinstance(components, dict):
            raise InventoryError("Component state registry must contain a components object.")
        for component_id, record in components.items():
            if not isinstance(component_id, str) or not COMPONENT_ID_PATTERN.fullmatch(
                component_id
            ):
                raise InventoryError("Component state registry contains an invalid component id.")
            if not isinstance(record, dict) or not isinstance(record.get("installed"), bool):
                raise InventoryError(
                    f"Component state registry record {component_id!r} is invalid."
                )
            contract_version = record.get("contract_version")
            if not isinstance(contract_version, str) or not contract_version.strip():
                raise InventoryError(
                    f"Component state registry record {component_id!r} has an invalid "
                    "contract_version."
                )
        return {"components": components}

    @staticmethod
    def _declaration_path(component_id: str, record: dict[str, object]) -> str:
        expected_path = f"{COMPONENTS_DIRECTORY}/{component_id}/declaration.json"
        if record.get("declaration_path") != expected_path:
            raise InventoryError(f"Component {component_id} has an invalid declaration path.")
        return expected_path

    @staticmethod
    def _load_declaration(text: str, component_id: str) -> ComponentDeclaration:
        try:
            declaration = validate_declaration_text(text, component_id)
        except DeclarationError as error:
            raise InventoryError(str(error)) from error
        contract_version = InventoryCollector._string(declaration, "contract_version")

        installation_checks = InventoryCollector._object(declaration, "installation_checks")
        backup = InventoryCollector._object(declaration, "backup")
        restore = InventoryCollector._object(declaration, "restore")
        management = declaration.get("management", {})
        if not isinstance(management, dict):
            raise InventoryError("Component management declaration must be an object.")
        users = declaration.get("users", {})
        if not isinstance(users, dict):
            raise InventoryError("Component users declaration must be an object.")

        installation_files = InventoryCollector._paths(installation_checks, "files")
        systemd_units = InventoryCollector._units(installation_checks, "systemd_units")
        health_checks = InventoryCollector._strings(installation_checks, "health_checks")
        backup_paths = InventoryCollector._paths(backup, "paths")
        optional_backup_directories = InventoryCollector._paths(backup, "optional_directories")
        restore_services = InventoryCollector._restore_services(restore)
        restore_daemon_reload = InventoryCollector._restore_daemon_reload(restore)
        management_handler = (
            InventoryCollector._string(management, "handler") if management else ""
        )
        management_parameters = InventoryCollector._parameters(management) if management else ()
        management_actions = (
            InventoryCollector._strings(management, "actions") if management else ()
        )
        users_supported = users.get("supported", False)
        if not isinstance(users_supported, bool):
            raise InventoryError("Component users.supported must be a boolean.")

        return ComponentDeclaration(
            component_id=component_id,
            contract_version=contract_version,
            display_name=InventoryCollector._string(declaration, "display_name"),
            installation_files=installation_files,
            systemd_units=systemd_units,
            health_checks=health_checks,
            backup_paths=backup_paths,
            restore_services=restore_services,
            management_handler=management_handler,
            management_parameters=management_parameters,
            management_actions=management_actions,
            users_supported=users_supported,
            user_actions=InventoryCollector._strings(users, "actions"),
            user_artifacts=InventoryCollector._strings(users, "artifacts"),
            restore_daemon_reload=restore_daemon_reload,
            optional_backup_directories=optional_backup_directories,
        )

    @staticmethod
    def _object(data: dict[str, object], key: str) -> dict[str, object]:
        value = data.get(key)
        if not isinstance(value, dict):
            raise InventoryError(f"Component declaration is missing the {key} object.")
        return value

    @staticmethod
    def _string(data: dict[str, object], key: str) -> str:
        value = data.get(key)
        if not isinstance(value, str) or not value:
            raise InventoryError(f"Component declaration field {key} must be a non-empty string.")
        return value

    @staticmethod
    def _strings(data: dict[str, object], key: str) -> tuple[str, ...]:
        value = data.get(key, [])
        if not isinstance(value, list) or not all(
            isinstance(item, str) and item for item in value
        ):
            raise InventoryError(
                f"Component declaration field {key} must be a list of non-empty strings."
            )
        return tuple(value)

    @staticmethod
    def _paths(data: dict[str, object], key: str) -> tuple[str, ...]:
        paths = InventoryCollector._strings(data, key) if key in data else ()
        for path in paths:
            if not REMOTE_PATH_PATTERN.fullmatch(path) or "/../" in path or path.endswith("/.."):
                raise InventoryError(f"Component declaration has an invalid path: {path}")
        return paths

    @staticmethod
    def _units(data: dict[str, object], key: str) -> tuple[str, ...]:
        units = InventoryCollector._strings(data, key)
        if not all(SYSTEMD_UNIT_PATTERN.fullmatch(unit) for unit in units):
            raise InventoryError("Component declaration has an invalid systemd unit.")
        return units

    @staticmethod
    def _restore_services(restore: dict[str, object]) -> tuple[RestoreService, ...]:
        value = restore.get("services")
        if not isinstance(value, list):
            raise InventoryError("Component declaration restore.services must be a list.")
        services: list[RestoreService] = []
        units: set[str] = set()
        for item in value:
            if not isinstance(item, dict):
                raise InventoryError(
                    "Component declaration restore.services entries must be objects."
                )
            unit = InventoryCollector._string(item, "unit")
            action = InventoryCollector._string(item, "action")
            if not SYSTEMD_UNIT_PATTERN.fullmatch(unit):
                raise InventoryError(
                    "Component declaration restore service has an invalid systemd unit."
                )
            if action not in RESTORE_ACTIONS:
                raise InventoryError(
                    "Component declaration restore service has an unsupported action."
                )
            if unit in units:
                raise InventoryError(
                    "Component declaration restore.services contains a duplicate systemd unit."
                )
            units.add(unit)
            services.append(RestoreService(unit, action))
        return tuple(services)

    @staticmethod
    def _restore_daemon_reload(restore: dict[str, object]) -> bool:
        value = restore.get("daemon_reload", False)
        if not isinstance(value, bool):
            raise InventoryError("Component declaration restore.daemon_reload must be a boolean.")
        return value

    @staticmethod
    def _parameters(management: dict[str, object]) -> tuple[ManagementParameter, ...]:
        value = management.get("parameters", [])
        if not isinstance(value, list):
            raise InventoryError("Component management.parameters must be a list.")
        parameters: list[ManagementParameter] = []
        for item in value:
            if not isinstance(item, dict):
                raise InventoryError("Component management parameter must be an object.")
            parameter_id = InventoryCollector._string(item, "id")
            label = InventoryCollector._string(item, "label")
            parameter_type = InventoryCollector._string(item, "type")
            modifiable = item.get("modifiable")
            if not isinstance(modifiable, bool):
                raise InventoryError(
                    "Component management parameter modifiable must be a boolean."
                )
            minimum = item.get("minimum")
            maximum = item.get("maximum")
            value_format = item.get("format")
            if minimum is not None and (isinstance(minimum, bool) or not isinstance(minimum, int)):
                raise InventoryError("Component management parameter minimum must be an integer.")
            if maximum is not None and (isinstance(maximum, bool) or not isinstance(maximum, int)):
                raise InventoryError("Component management parameter maximum must be an integer.")
            if value_format is not None and (
                not isinstance(value_format, str) or not value_format
            ):
                raise InventoryError(
                    "Component management parameter format must be a non-empty string."
                )
            parameters.append(
                ManagementParameter(
                    parameter_id, label, parameter_type, modifiable, minimum, maximum, value_format
                )
            )
        return tuple(parameters)

    @staticmethod
    def _status(checks: list[CheckResult]) -> str:
        systemd_states = [check.detail for check in checks if check.category == "systemd"]
        if "failed" in systemd_states:
            return "failed"
        if "inactive" in systemd_states:
            return "inactive"
        return "active" if all(check.passed for check in checks) else "degraded"
