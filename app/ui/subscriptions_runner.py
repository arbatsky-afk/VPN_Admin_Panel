"""Background runner for one immutable Subscriptions operation."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from PySide6.QtCore import QThread, Signal

from app.services.subscriptions import (
    FinalizedSubscriptionDelete,
    SubscriptionDeleteRequest,
    SubscriptionError,
    SubscriptionInspectRequest,
    SubscriptionReconciliation,
    delete_subscription,
    inspect_subscription_server,
    prepare_subscription,
    publish_prepared_subscription,
    reconcile_subscription_server,
)


@dataclass(frozen=True, slots=True)
class SubscriptionRunnerRequest:
    operation_token: int
    request_id: int
    server_ip: str
    name: str
    source_filenames: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class SubscriptionDeleteCompletion:
    """Delete outcome and the best authoritative post-operation projection."""

    finalized: FinalizedSubscriptionDelete
    reconciliation: SubscriptionReconciliation | None = None
    reconciliation_error: str = ""


SubscriptionsRunnerRequest = (
    SubscriptionRunnerRequest | SubscriptionInspectRequest | SubscriptionDeleteRequest
)


class SubscriptionsRunner(QThread):
    """Perform one cancellable, finite publication, inspection, or deletion."""

    completed = Signal(object, object)
    failed = Signal(object, str)

    def __init__(self, project_directory: Path, parent=None) -> None:
        super().__init__(parent)
        self.project_directory = project_directory
        self.request: SubscriptionsRunnerRequest | None = None

    @property
    def is_running(self) -> bool:
        return self.isRunning()

    def start_operation(self, request: SubscriptionsRunnerRequest) -> bool:
        if self.isRunning():
            return False
        self.request = request
        self.start()
        return True

    def stop(self) -> None:
        self.requestInterruption()

    def run(self) -> None:
        request = self.request
        if request is None:
            return
        try:
            if isinstance(request, SubscriptionRunnerRequest):
                result = self._publish(request)
            elif isinstance(request, SubscriptionInspectRequest):
                snapshot = inspect_subscription_server(
                    self.project_directory,
                    request,
                    cancelled=self.isInterruptionRequested,
                )
                result = reconcile_subscription_server(self.project_directory, snapshot)
            elif isinstance(request, SubscriptionDeleteRequest):
                result = self._delete(request)
            else:
                raise SubscriptionError("Unsupported Subscriptions runner request.")
        except SubscriptionError as error:
            self.failed.emit(request, str(error))
            return
        except OSError:
            self.failed.emit(request, "A local subscription file operation failed.")
            return
        except Exception:
            self.failed.emit(request, "An unexpected subscription service failure occurred.")
            return
        self.completed.emit(request, result)

    def _publish(self, request: SubscriptionRunnerRequest):
        prepared = prepare_subscription(
            self.project_directory,
            request.operation_token,
            request.request_id,
            request.server_ip,
            request.name,
            request.source_filenames,
        )
        if (
            prepared.request.operation_token != request.operation_token
            or prepared.request.request_id != request.request_id
            or prepared.request.server_ip != request.server_ip
            or prepared.request.name != request.name
            or prepared.request.source_filenames != request.source_filenames
        ):
            raise SubscriptionError(
                "Prepared subscription identity differs from its runner request."
            )
        return publish_prepared_subscription(
            self.project_directory,
            prepared,
            cancelled=self.isInterruptionRequested,
        )

    def _delete(self, request: SubscriptionDeleteRequest) -> SubscriptionDeleteCompletion:
        finalized = delete_subscription(
            self.project_directory,
            request,
            cancelled=self.isInterruptionRequested,
        )
        snapshot = finalized.snapshot
        reconciliation_error = ""
        if snapshot is None and finalized.result.outcome in {"partial", "unknown"}:
            try:
                snapshot = inspect_subscription_server(
                    self.project_directory,
                    SubscriptionInspectRequest(
                        request.operation_token,
                        request.request_id,
                        request.server_ip,
                    ),
                    cancelled=self.isInterruptionRequested,
                )
            except SubscriptionError as error:
                reconciliation_error = str(error)
        reconciliation = (
            reconcile_subscription_server(self.project_directory, snapshot)
            if snapshot is not None
            else None
        )
        return SubscriptionDeleteCompletion(
            finalized,
            reconciliation,
            reconciliation_error,
        )
