"""Background collection of a local Inventory snapshot."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from PySide6.QtCore import QThread, Signal

from app.services.inventory import (
    InventoryCollector,
    InventoryError,
    InventoryProfile,
    InventoryTransportError,
    SshInventoryTransport,
)
from app.services.restore import EffectiveRestorePlan
from app.services.ssh import validate_server_ip
from app.services.ssh_settings import primary_ssh_connection

InventoryPurpose = Literal[
    "management",
    "management_reconciliation",
    "backup",
    "restore_compatibility",
    "restore_verification",
    "telegram",
    "telegram_reconciliation",
    "users",
    "subscriptions",
    "nginx_deploy",
]


@dataclass(frozen=True, slots=True)
class InventoryRequestContext:
    """Immutable identity and routing data for one Inventory run."""

    operation_token: int
    purpose: InventoryPurpose
    requester: str
    server_ip: str
    restore_plan: EffectiveRestorePlan | None = None

    @property
    def inventory_profile(self) -> InventoryProfile:
        if self.purpose == "users":
            return "users"
        if self.purpose == "subscriptions":
            return "subscriptions"
        return "full"


class InventoryRunner(QThread):
    """Collect a read-only Inventory snapshot without blocking the GUI thread."""

    completed = Signal(object, object)
    failed = Signal(object, str)

    def __init__(self, project_directory: Path, parent=None) -> None:
        super().__init__(parent)
        self.project_directory = project_directory
        self.request: InventoryRequestContext | None = None
        self._cancelled_request: InventoryRequestContext | None = None
        self.finished.connect(self._publish_cancellation)

    @property
    def is_running(self) -> bool:
        return self.isRunning()

    def start_collection(self, request: InventoryRequestContext) -> bool:
        if self.isRunning() or self._cancelled_request is not None:
            return False
        server_ip, error = validate_server_ip(request.server_ip)
        if error:
            self.failed.emit(request, error)
            return False
        if request.operation_token <= 0:
            self.failed.emit(request, "Inventory operation token must be positive.")
            return False
        if server_ip != request.server_ip:
            self.failed.emit(request, "Inventory server IP must already be normalized.")
            return False
        self.request = request
        self.start()
        return True

    def run(self) -> None:
        request = self.request
        if request is None:
            return
        try:
            connection = primary_ssh_connection(self.project_directory)
            transport = SshInventoryTransport(
                request.server_ip,
                connection.private_key_path,
                ssh_port=connection.port,
                cancelled=self.isInterruptionRequested,
                profile=request.inventory_profile,
            )
            snapshot = InventoryCollector(
                request.server_ip,
                transport,
                profile=request.inventory_profile,
            ).collect_snapshot()
        except (InventoryError, InventoryTransportError, OSError, TypeError, ValueError) as error:
            if self.isInterruptionRequested():
                self._cancelled_request = request
                return
            self.failed.emit(request, f"Could not collect Inventory: {error}")
            return
        except Exception:  # noqa: BLE001 - terminal runner boundary must always publish.
            if self.isInterruptionRequested():
                self._cancelled_request = request
                return
            self.failed.emit(request, "An unexpected Inventory service failure occurred.")
            return
        if self.isInterruptionRequested():
            self._cancelled_request = request
            return
        self.completed.emit(request, snapshot)

    def _publish_cancellation(self) -> None:
        request = self._cancelled_request
        self._cancelled_request = None
        if request is not None:
            self.failed.emit(request, "Inventory collection was cancelled.")
