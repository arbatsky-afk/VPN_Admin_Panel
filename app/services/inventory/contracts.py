"""Immutable Inventory contracts shared by collectors and consumers."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, Protocol

InventoryProfile = Literal["full", "users", "subscriptions"]
INVENTORY_PROFILES: frozenset[InventoryProfile] = frozenset({"full", "users", "subscriptions"})


class InventoryError(ValueError):
    """Raised when an Inventory snapshot cannot be collected safely."""


class InventoryTransportError(RuntimeError):
    """Raised when a read-only remote Inventory command cannot run."""


@dataclass(frozen=True)
class ManagementParameter:
    """One parameter declared by a component for the future Management service."""

    parameter_id: str
    label: str
    parameter_type: str
    modifiable: bool
    minimum: int | None = None
    maximum: int | None = None
    value_format: str | None = None


@dataclass(frozen=True)
class RestoreService:
    """One fixed service action that follows a successful Restore."""

    unit: str
    action: str


@dataclass(frozen=True)
class ComponentDeclaration:
    """Validated, immutable capability contract read from a component declaration."""

    component_id: str
    contract_version: str
    display_name: str
    installation_files: tuple[str, ...]
    systemd_units: tuple[str, ...]
    health_checks: tuple[str, ...]
    backup_paths: tuple[str, ...]
    restore_services: tuple[RestoreService, ...]
    management_handler: str
    management_parameters: tuple[ManagementParameter, ...]
    management_actions: tuple[str, ...]
    users_supported: bool
    user_actions: tuple[str, ...]
    user_artifacts: tuple[str, ...]
    restore_daemon_reload: bool = False
    optional_backup_directories: tuple[str, ...] = ()


@dataclass(frozen=True)
class CheckResult:
    """One read-only check included in a component Inventory result."""

    category: str
    target: str
    passed: bool
    detail: str


@dataclass(frozen=True)
class ComponentInventory:
    """Current state of one registered component."""

    component_id: str
    status: str
    declaration: ComponentDeclaration | None
    checks: tuple[CheckResult, ...]
    software_version: str | None = None


@dataclass(frozen=True)
class InventorySnapshot:
    """Immutable fixed-profile Inventory state for one server at one moment."""

    server_ip: str
    components: tuple[ComponentInventory, ...]
    profile: InventoryProfile = "full"

    def component(self, component_id: str) -> ComponentInventory | None:
        return next((item for item in self.components if item.component_id == component_id), None)


class InventoryTransport(Protocol):
    """Minimal remote operations used by the local Inventory collector."""

    def read_text(self, path: str) -> str: ...

    def file_exists(self, path: str) -> bool: ...

    def directory_exists(self, path: str) -> bool: ...

    def systemd_state(self, unit: str) -> str: ...

    def health_check(self, component_id: str, check_id: str) -> tuple[bool, str]: ...

    def software_version(self, component_id: str) -> str | None: ...
