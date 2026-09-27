"""Background execution for fixed Management and server operations."""

from __future__ import annotations

from dataclasses import dataclass, replace
from pathlib import Path
from typing import Literal

from PySide6.QtCore import QThread, Signal

from app.services.management import (
    BASE_SECURITY_ACTIONS,
    BASE_SECURITY_SERVICES,
    DOCKER_ACTIONS,
    HYSTERIA2_ACTIONS,
    MIERU_ACTIONS,
    NETDATA_ACTIONS,
    NGINX_ACTIONS,
    XRAY_ACTIONS,
    ManagementError,
    ManagementIndeterminateError,
    ManagementLaunchError,
    ManagementRemoteRejectedError,
    manage_base_security,
    manage_docker,
    manage_hysteria2,
    manage_mieru,
    manage_netdata,
    manage_nginx,
    manage_xray,
    schedule_server_reboot,
    update_hysteria2_connection,
    update_mieru_port,
    update_xray_connection,
)
from app.services.ssh import validate_server_ip

ManagementOperationKind = Literal[
    "docker",
    "base-security",
    "xray",
    "xray-connection-update",
    "hysteria2",
    "hysteria2-connection-update",
    "mieru",
    "mieru-port-update",
    "server-reboot",
    "nginx",
    "netdata",
]
MANAGEMENT_OPERATION_KINDS = frozenset(
    {
        "docker",
        "base-security",
        "xray",
        "xray-connection-update",
        "hysteria2",
        "hysteria2-connection-update",
        "mieru",
        "mieru-port-update",
        "server-reboot",
        "nginx",
        "netdata",
    }
)
COMPONENT_MANAGEMENT_OPERATION_KINDS = MANAGEMENT_OPERATION_KINDS - {"server-reboot"}


@dataclass(frozen=True, slots=True)
class ManagementOperationRequest:
    """Immutable runner input and signal identity for one fixed operation."""

    token: int
    kind: ManagementOperationKind
    server_ip: str
    action: str = ""
    service: str = ""
    port: int = 0
    sni: str = ""


ManagementFailureOutcome = Literal["error", "unknown"]
ManagementFailureReason = Literal[
    "validation_failed",
    "launch_failed",
    "remote_rejected",
    "timeout",
    "connection_lost",
    "invalid_response",
    "cancelled",
]


@dataclass(frozen=True, slots=True)
class ManagementOperationFailure:
    """Safe typed failure returned with the immutable operation request."""

    outcome: ManagementFailureOutcome
    reason_code: ManagementFailureReason
    safe_message: str

    def __str__(self) -> str:
        return self.safe_message

    def __contains__(self, value: str) -> bool:
        return value in self.safe_message


class ManagementRunner(QThread):
    """Run one typed Management request without blocking the GUI."""

    completed = Signal(object, object)
    failed = Signal(object, object)

    def __init__(self, project_directory: Path, parent=None) -> None:
        super().__init__(parent)
        self.project_directory = project_directory
        self.request: ManagementOperationRequest | None = None
        self._cancelled_request: ManagementOperationRequest | None = None
        self.finished.connect(self._publish_cancellation)

    @property
    def is_running(self) -> bool:
        return self.isRunning()

    def start_operation(self, request: ManagementOperationRequest) -> bool:
        if self.isRunning() or self._cancelled_request is not None:
            return False
        try:
            request = self._validated_request(request)
        except (TypeError, ValueError) as error:
            self.failed.emit(
                request,
                ManagementOperationFailure("error", "validation_failed", str(error)),
            )
            return False
        self.request = request
        self.start()
        return True

    @staticmethod
    def _validated_request(request: ManagementOperationRequest) -> ManagementOperationRequest:
        if not isinstance(request, ManagementOperationRequest):
            raise TypeError("Invalid Management operation request.")
        if (
            not isinstance(request.token, int)
            or isinstance(request.token, bool)
            or request.token <= 0
        ):
            raise ValueError("Invalid Management operation token.")
        if request.kind not in MANAGEMENT_OPERATION_KINDS:
            raise ValueError("Unsupported Management operation kind.")
        server_ip, error = validate_server_ip(request.server_ip)
        if error:
            raise ValueError(error)
        if request.kind == "docker" and request.action not in DOCKER_ACTIONS:
            raise ValueError("Unsupported Docker action.")
        if request.kind == "base-security" and (
            request.service not in BASE_SECURITY_SERVICES
            or request.action not in BASE_SECURITY_ACTIONS
        ):
            raise ValueError("Unsupported Base + Security action.")
        if request.kind == "xray" and request.action not in XRAY_ACTIONS:
            raise ValueError("Unsupported Xray action.")
        if request.kind == "hysteria2" and request.action not in HYSTERIA2_ACTIONS:
            raise ValueError("Unsupported Hysteria2 action.")
        if request.kind == "mieru" and request.action not in MIERU_ACTIONS:
            raise ValueError("Unsupported Mieru action.")
        if request.kind == "nginx" and request.action not in NGINX_ACTIONS:
            raise ValueError("Unsupported Nginx action.")
        if request.kind == "netdata" and request.action not in NETDATA_ACTIONS:
            raise ValueError("Unsupported Netdata action.")
        if request.kind in {"nginx", "netdata"} and any(
            (request.service, request.port, request.sni)
        ):
            raise ValueError(f"Invalid {request.kind.title()} request.")
        if request.kind == "mieru-port-update" and (
            request.action
            or request.service
            or request.sni
            or type(request.port) is not int
            or not 1025 <= request.port <= 65535
        ):
            raise ValueError("Invalid Mieru port update request.")
        if request.kind == "server-reboot" and any(
            (request.action, request.service, request.port, request.sni)
        ):
            raise ValueError("Invalid Server reboot request.")
        if request.kind in {"xray-connection-update", "hysteria2-connection-update"} and (
            request.action or request.service
        ):
            raise ValueError("Invalid connection update request.")
        return replace(request, server_ip=server_ip)

    def run(self) -> None:
        request = self.request
        if request is None:
            return
        try:
            status = self._execute(request)
        except (ManagementError, OSError, TypeError, ValueError) as error:
            if self.isInterruptionRequested():
                self._cancelled_request = request
                return
            self.failed.emit(request, self._failure(error))
            return
        except Exception:  # noqa: BLE001 - terminal runner boundary must always publish.
            if self.isInterruptionRequested():
                self._cancelled_request = request
                return
            self.failed.emit(
                request,
                ManagementOperationFailure(
                    "unknown",
                    "invalid_response",
                    "An unexpected Management service failure occurred; the server "
                    "state is unknown.",
                ),
            )
            return
        if self.isInterruptionRequested():
            self._cancelled_request = request
            return
        self.completed.emit(request, status)

    def _publish_cancellation(self) -> None:
        request = self._cancelled_request
        self._cancelled_request = None
        if request is not None:
            self.failed.emit(
                request,
                ManagementOperationFailure(
                    "unknown",
                    "cancelled",
                    "Management operation was cancelled; the server state is unknown.",
                ),
            )

    @staticmethod
    def _failure(error: BaseException) -> ManagementOperationFailure:
        if isinstance(error, ManagementIndeterminateError):
            reason = error.reason_code
            if reason not in {"timeout", "connection_lost", "invalid_response"}:
                reason = "invalid_response"
            return ManagementOperationFailure("unknown", reason, str(error))  # type: ignore[arg-type]
        if isinstance(error, ManagementRemoteRejectedError):
            return ManagementOperationFailure("error", "remote_rejected", str(error))
        if isinstance(error, (ManagementLaunchError, OSError)):
            return ManagementOperationFailure("error", "launch_failed", str(error))
        return ManagementOperationFailure("error", "validation_failed", str(error))

    def _execute(self, request: ManagementOperationRequest) -> object:
        if request.kind == "server-reboot":
            schedule_server_reboot(
                self.project_directory,
                request.server_ip,
                cancelled=self.isInterruptionRequested,
            )
            return None
        if request.kind == "base-security":
            return manage_base_security(
                self.project_directory,
                request.server_ip,
                request.service,  # type: ignore[arg-type]
                request.action,  # type: ignore[arg-type]
                cancelled=self.isInterruptionRequested,
            )
        if request.kind == "xray":
            return manage_xray(
                self.project_directory,
                request.server_ip,
                request.action,  # type: ignore[arg-type]
                cancelled=self.isInterruptionRequested,
            )
        if request.kind == "xray-connection-update":
            return update_xray_connection(
                self.project_directory,
                request.server_ip,
                request.port,
                request.sni,
                cancelled=self.isInterruptionRequested,
            )
        if request.kind == "hysteria2":
            return manage_hysteria2(
                self.project_directory,
                request.server_ip,
                request.action,  # type: ignore[arg-type]
                cancelled=self.isInterruptionRequested,
            )
        if request.kind == "hysteria2-connection-update":
            return update_hysteria2_connection(
                self.project_directory,
                request.server_ip,
                request.port,
                request.sni,
                cancelled=self.isInterruptionRequested,
            )
        if request.kind == "mieru":
            return manage_mieru(
                self.project_directory,
                request.server_ip,
                request.action,  # type: ignore[arg-type]
                cancelled=self.isInterruptionRequested,
            )
        if request.kind == "mieru-port-update":
            return update_mieru_port(
                self.project_directory,
                request.server_ip,
                request.port,
                cancelled=self.isInterruptionRequested,
            )
        if request.kind == "nginx":
            return manage_nginx(
                self.project_directory,
                request.server_ip,
                request.action,  # type: ignore[arg-type]
                cancelled=self.isInterruptionRequested,
            )
        if request.kind == "netdata":
            return manage_netdata(
                self.project_directory,
                request.server_ip,
                request.action,  # type: ignore[arg-type]
                cancelled=self.isInterruptionRequested,
            )
        if request.kind == "docker":
            return manage_docker(
                self.project_directory,
                request.server_ip,
                request.action,  # type: ignore[arg-type]
                cancelled=self.isInterruptionRequested,
            )
        raise ManagementError("Unsupported Management operation kind.")


def management_failure_message(failure: object) -> str:
    """Read typed failures while accepting legacy test doubles during migration."""
    if isinstance(failure, ManagementOperationFailure):
        return failure.safe_message
    return str(failure)
