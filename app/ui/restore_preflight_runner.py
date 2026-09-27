"""Background local validation of a selected Restore archive."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from PySide6.QtCore import QThread, Signal

from app.services.restore import RestoreError, restore_plan_from_archive
from app.services.ssh import validate_server_ip

RestorePreflightPhase = Literal["preflight"]


@dataclass(frozen=True, slots=True)
class RestorePreflightRequest:
    """Immutable input and signal identity for one local Restore preflight."""

    operation_token: int
    server_ip: str
    archive_path: Path
    phase: RestorePreflightPhase = "preflight"


class RestorePreflightRunner(QThread):
    """Run archive validation outside the GUI thread without opening SSH."""

    completed = Signal(object, object)
    failed = Signal(object, str)

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.request: RestorePreflightRequest | None = None

    @property
    def is_running(self) -> bool:
        return self.isRunning()

    def start_preflight(self, request: RestorePreflightRequest) -> bool:
        if self.isRunning():
            return False
        try:
            request = self._validated_request(request)
        except (TypeError, ValueError) as error:
            self.failed.emit(request, str(error))
            return False
        self.request = request
        self.start()
        return True

    @staticmethod
    def _validated_request(request: RestorePreflightRequest) -> RestorePreflightRequest:
        if not isinstance(request, RestorePreflightRequest):
            raise TypeError("Invalid Restore preflight request.")
        if (
            not isinstance(request.operation_token, int)
            or isinstance(request.operation_token, bool)
            or request.operation_token <= 0
        ):
            raise ValueError("Invalid Restore preflight operation token.")
        if request.phase != "preflight":
            raise ValueError("Unsupported Restore preflight phase.")
        server_ip, error = validate_server_ip(request.server_ip)
        if error:
            raise ValueError(error)
        if server_ip != request.server_ip:
            raise ValueError("Restore target server IP must be normalized.")
        if not isinstance(request.archive_path, Path):
            raise TypeError("Restore preflight archive path must be a Path.")
        return request

    def run(self) -> None:
        request = self.request
        if request is None:
            return
        try:
            self.completed.emit(request, restore_plan_from_archive(request.archive_path))
        except RestoreError as error:
            self.failed.emit(request, str(error))
        except Exception:  # noqa: BLE001 - terminal runner boundary must always publish.
            self.failed.emit(
                request,
                "An unexpected Restore preflight service failure occurred.",
            )
