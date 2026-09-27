"""Public facade for the Inventory subsystem."""

from .collector import (
    COMPONENTS_DIRECTORY,
    REGISTRY_PATH,
    REGISTRY_SCHEMA_VERSION,
    InventoryCollector,
)
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
from .ssh_transport import (
    INVENTORY_HEALTH_COMMANDS,
    REMOTE_INVENTORY_SCRIPT,
    SOFTWARE_VERSION_COMMANDS,
    SshInventoryTransport,
)

# Preserve the public runtime type path used before the module became a package.
for _public_type in (
    InventoryError,
    InventoryTransportError,
    ManagementParameter,
    RestoreService,
    ComponentDeclaration,
    CheckResult,
    ComponentInventory,
    InventorySnapshot,
    InventoryTransport,
    SshInventoryTransport,
    InventoryCollector,
):
    _public_type.__module__ = __name__
del _public_type

__all__ = (
    "REGISTRY_PATH",
    "COMPONENTS_DIRECTORY",
    "REGISTRY_SCHEMA_VERSION",
    "INVENTORY_HEALTH_COMMANDS",
    "SOFTWARE_VERSION_COMMANDS",
    "REMOTE_INVENTORY_SCRIPT",
    "INVENTORY_PROFILES",
    "InventoryError",
    "InventoryProfile",
    "InventoryTransportError",
    "ManagementParameter",
    "RestoreService",
    "ComponentDeclaration",
    "CheckResult",
    "ComponentInventory",
    "InventorySnapshot",
    "InventoryTransport",
    "SshInventoryTransport",
    "InventoryCollector",
)
