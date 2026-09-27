from __future__ import annotations

import math
import threading
import uuid
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone

from monitor.domain import (
    CheckRequest,
    Connection,
    ConnectionSnapshot,
    ConnectionStatus,
    FailureKind,
    MihomoStartOutcome,
    ProbeResult,
    utc_now_iso,
)
from monitor.information import (
    InformationConnection,
    MonitorMessageFormatter,
    MonitorStateDetector,
    OperationLogInformationOutput,
    StateTransition,
    information_state,
)
from monitor.logs import JsonlLog
from monitor.repository import ConnectionRepository
from monitor.settings import MonitorSettings

SnapshotCallback = Callable[[ConnectionSnapshot], None]
CycleCallback = Callable[[bool, str | None], None]
ProbeCallable = Callable[[Connection, threading.Event], ProbeResult]


class MonitoringScheduler:
    def __init__(
        self,
        repository: ConnectionRepository,
        settings: MonitorSettings,
        probe: ProbeCallable,
        operation_log: JsonlLog,
        event_log: JsonlLog,
        on_snapshot: SnapshotCallback | None = None,
        on_cycle: CycleCallback | None = None,
        information_transport: Callable[[str], None] | None = None,
    ) -> None:
        self._repository = repository
        self._settings = settings
        self._probe = probe
        self._operation_log = operation_log
        self._event_log = event_log
        self._on_snapshot = on_snapshot or (lambda _snapshot: None)
        self._on_cycle = on_cycle or (lambda _running, _last: None)
        self._stop = threading.Event()
        self._wake = threading.Event()
        self._thread: threading.Thread | None = None
        self._lock = threading.RLock()
        self._snapshots: dict[str, ConnectionSnapshot] = {}
        self._active_requests: dict[str, CheckRequest] = {}
        self._checking = False
        self._information_detector = MonitorStateDetector()
        self._information_formatter = MonitorMessageFormatter()
        self._information_output = OperationLogInformationOutput(
            operation_log,
            information_transport,
        )

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start(self) -> None:
        with self._lock:
            if self.running:
                return
            self._stop.clear()
            self._wake.clear()
            self.refresh_connections()
            self._thread = threading.Thread(
                target=self._run, name="monitor-scheduler", daemon=False
            )
            self._thread.start()

    def stop(self, timeout: float | None = None) -> bool:
        self._stop.set()
        self._wake.set()
        thread = self._thread
        if thread is None:
            return True
        thread.join(timeout)
        return not thread.is_alive()

    def request_check_now(self) -> bool:
        with self._lock:
            if not self.running or self._checking:
                return False
            self._wake.set()
            return True

    def refresh_connections(self) -> tuple[ConnectionSnapshot, ...]:
        connections = self._repository.load()
        with self._lock:
            current_connections = {item.connection_id: item for item in connections}
            self._snapshots = {
                connection_id: snapshot
                for connection_id, snapshot in self._snapshots.items()
                if connection_id in current_connections
            }
            self._active_requests = {
                connection_id: request
                for connection_id, request in self._active_requests.items()
                if (current := current_connections.get(connection_id)) is not None
                and current.enabled
                and current.version == request.connection_version
            }
            for connection in connections:
                current = self._snapshots.get(connection.connection_id)
                if current is None or current.connection.version != connection.version:
                    status = (
                        ConnectionStatus.UNKNOWN
                        if connection.enabled
                        else ConnectionStatus.DISABLED
                    )
                    snapshot = ConnectionSnapshot(connection, status)
                    self._snapshots[connection.connection_id] = snapshot
                    self._on_snapshot(snapshot)
            return tuple(self._snapshots[item.connection_id] for item in connections)

    def snapshots(self) -> tuple[ConnectionSnapshot, ...]:
        connections = self._repository.load()
        with self._lock:
            return tuple(
                self._snapshots.get(
                    item.connection_id,
                    ConnectionSnapshot(
                        item,
                        ConnectionStatus.UNKNOWN if item.enabled else ConnectionStatus.DISABLED,
                    ),
                )
                for item in connections
            )

    def _run(self) -> None:
        self._operation_log.write("scheduler_started")
        self._publish_startup_information()
        try:
            while not self._stop.is_set():
                with self._lock:
                    self._checking = True
                self._on_cycle(True, None)
                try:
                    self._run_cycle()
                except Exception as error:  # noqa: BLE001 - scheduler must survive one bad cycle
                    self._operation_log.write("cycle_error", error_type=type(error).__name__)
                finally:
                    self._wake.clear()
                    with self._lock:
                        self._checking = False
                if self._stop.is_set():
                    break
                next_check_at = (
                    datetime.now(timezone.utc)
                    + timedelta(seconds=self._settings.check_interval_seconds)
                ).isoformat()
                self._on_cycle(True, next_check_at)
                self._wake.wait(self._settings.check_interval_seconds)
        finally:
            with self._lock:
                self._checking = False
            self._operation_log.write("scheduler_stopped")
            self._on_cycle(False, None)

    def _run_cycle(self) -> None:
        connections = self._repository.load()
        cycle_signature = self._connection_signature(connections)
        enabled = [item for item in connections if item.enabled]
        failures = 0
        for connection in connections:
            if self._stop.is_set():
                return
            if not connection.enabled:
                self._publish(ConnectionSnapshot(connection, ConnectionStatus.DISABLED))
        workers = min(self._settings.parallel_checks, len(enabled))
        if workers:
            with ThreadPoolExecutor(
                max_workers=workers, thread_name_prefix="monitor-check"
            ) as executor:
                futures = {
                    executor.submit(self._check_connection, connection): connection
                    for connection in enabled
                }
                for future in as_completed(futures):
                    if self._stop.is_set():
                        for pending in futures:
                            pending.cancel()
                    if future.cancelled():
                        continue
                    connection = futures[future]
                    try:
                        result = future.result()
                    except Exception as error:  # noqa: BLE001 - isolate one worker
                        self._operation_log.write(
                            "connection_task_error",
                            connection_id=connection.connection_id,
                            error_type=type(error).__name__,
                        )
                        failures += 1
                        continue
                    if result is not None and result.status == ConnectionStatus.FAIL:
                        failures += 1
        if self._stop.is_set():
            return
        if enabled and failures >= max(2, math.floor(len(enabled) / 2) + 1):
            self._operation_log.write(
                "possible_common_network_failure", failed=failures, enabled=len(enabled)
            )
        self._operation_log.write(
            "cycle_finished", enabled=len(enabled), failed=failures, workers=workers
        )
        current_connections = self._repository.load()
        if self._connection_signature(current_connections) != cycle_signature:
            return
        cycle_snapshots = self._snapshots_for(current_connections)
        if self._connection_signature(self._repository.load()) != cycle_signature:
            return
        transition = self._information_detector.compare_and_accept(
            information_state(cycle_snapshots)
        )
        if transition is not None:
            self._publish_information_transition(transition)

    def _check_connection(self, connection: Connection) -> ProbeResult | None:
        if self._stop.is_set():
            return None
        request = CheckRequest(str(uuid.uuid4()), connection.connection_id, connection.version)
        if not self._activate_request(request):
            self._log_stale_request(request)
            return None
        try:
            if not self._publish_if_current(
                request,
                ConnectionSnapshot(
                    connection,
                    ConnectionStatus.CHECKING,
                    request_id=request.request_id,
                ),
            ):
                self._log_stale_request(request)
                return None
            result: ProbeResult | None = None
            for attempt in range(1, self._settings.max_attempts + 1):
                if self._stop.is_set():
                    return None
                try:
                    result = self._probe(connection, self._stop)
                except Exception as error:  # noqa: BLE001 - plugin-like probe boundary
                    self._operation_log.write(
                        "probe_error",
                        connection_id=connection.connection_id,
                        error_type=type(error).__name__,
                    )
                    result = ProbeResult.failure(
                        FailureKind.PROBE_NETWORK, "Unexpected probe failure."
                    )
                attempt_fields: dict[str, object] = {
                    "connection_id": connection.connection_id,
                    "protocol": connection.protocol,
                    "expected_ipv4": connection.expected_ipv4,
                    "attempt": attempt,
                    "status": result.status.value,
                    "failure_kind": (result.failure_kind.value if result.failure_kind else None),
                    "latency_ms": result.latency_ms,
                }
                if diagnostics := result.mihomo_start:
                    attempt_fields.update(
                        mihomo_start_outcome=diagnostics.outcome.value,
                        mihomo_start_ms=diagnostics.start_ms,
                    )
                    if diagnostics.outcome != MihomoStartOutcome.READY:
                        attempt_fields.update(
                            mihomo_spawn_ms=diagnostics.spawn_ms,
                            mihomo_readiness_ms=diagnostics.readiness_ms,
                            mihomo_pid=diagnostics.pid,
                            mihomo_proxy_ready_ms=diagnostics.proxy_ready_ms,
                            mihomo_controller_ready_ms=diagnostics.controller_ready_ms,
                            mihomo_process_alive=diagnostics.process_alive,
                            mihomo_exit_code=diagnostics.exit_code,
                            mihomo_proxy_socket_error=diagnostics.proxy_socket_error,
                            mihomo_controller_socket_error=(diagnostics.controller_socket_error),
                            mihomo_os_error_type=diagnostics.os_error_type,
                            mihomo_errno=diagnostics.errno,
                            mihomo_winerror=diagnostics.winerror,
                        )
                self._operation_log.write("connection_attempt", **attempt_fields)
                if result.status != ConnectionStatus.FAIL:
                    break
                if result.failure_kind == FailureKind.CANCELLED:
                    return None
                if attempt < self._settings.max_attempts:
                    if not self._publish_if_current(
                        request,
                        ConnectionSnapshot(
                            connection,
                            ConnectionStatus.RETRYING,
                            request_id=request.request_id,
                        ),
                    ):
                        self._log_stale_request(request)
                        return None
                    if self._stop.wait(self._settings.retry_delay_seconds):
                        return None
            if result is None:
                self._log_stale_request(request)
                return None
            final = ConnectionSnapshot(
                connection,
                result.status,
                utc_now_iso(),
                result,
                request.request_id,
            )
            if not self._publish_if_current(request, final):
                self._log_stale_request(request)
                return None
            return result
        finally:
            self._deactivate_request(request)

    def _activate_request(self, request: CheckRequest) -> bool:
        if not self._request_is_current(request):
            self.refresh_connections()
            return False
        with self._lock:
            current = self._snapshots.get(request.connection_id)
            if current is not None and current.connection.version > request.connection_version:
                return False
            self._active_requests[request.connection_id] = request
            return True

    def _deactivate_request(self, request: CheckRequest) -> None:
        with self._lock:
            if self._active_requests.get(request.connection_id) == request:
                del self._active_requests[request.connection_id]

    def _publish_if_current(
        self,
        request: CheckRequest,
        snapshot: ConnectionSnapshot,
    ) -> bool:
        if (
            snapshot.connection.connection_id != request.connection_id
            or snapshot.connection.version != request.connection_version
            or snapshot.request_id != request.request_id
        ):
            return False
        if not self._request_is_current(request):
            self._deactivate_request(request)
            self.refresh_connections()
            return False
        with self._lock:
            if self._active_requests.get(request.connection_id) != request:
                return False
            current = self._snapshots.get(request.connection_id)
            if current is not None and current.connection.version > request.connection_version:
                return False
            self._snapshots[request.connection_id] = snapshot
            self._on_snapshot(snapshot)
            return True

    def _request_is_current(self, request: CheckRequest) -> bool:
        for item in self._repository.load():
            if item.connection_id == request.connection_id:
                return item.enabled and item.version == request.connection_version
        return False

    def _publish(self, snapshot: ConnectionSnapshot) -> bool:
        current_connection = next(
            (
                item
                for item in self._repository.load()
                if item.connection_id == snapshot.connection.connection_id
            ),
            None,
        )
        if (
            current_connection is None
            or current_connection.version != snapshot.connection.version
            or current_connection.enabled != snapshot.connection.enabled
        ):
            self.refresh_connections()
            return False
        with self._lock:
            current = self._snapshots.get(snapshot.connection.connection_id)
            if current is not None and current.connection.version > snapshot.connection.version:
                return False
            self._snapshots[snapshot.connection.connection_id] = snapshot
            self._on_snapshot(snapshot)
            return True

    def _log_stale_request(self, request: CheckRequest) -> None:
        self._operation_log.write(
            "stale_result_ignored",
            connection_id=request.connection_id,
            request_id=request.request_id,
        )

    def _publish_startup_information(self) -> None:
        connections = self._repository.load()
        state = information_state(self._snapshots_for(connections))
        self._information_detector.reset(state)
        self._information_output.write(self._information_formatter.format_started(state))

    def _publish_information_transition(self, transition: StateTransition) -> None:
        self._information_output.write(self._information_formatter.format_transition(transition))
        previous = {item.connection_id: item for item in transition.previous}
        self._event_log.write(
            "monitor_state_changed",
            status_changed=[
                {
                    **self._event_connection(item),
                    "previous": previous[item.connection_id].status.value,
                    "current": item.status.value,
                }
                for item in transition.status_changed
            ],
            added=[
                {**self._event_connection(item), "current": item.status.value}
                for item in transition.added
            ],
            removed=[
                {**self._event_connection(item), "previous": item.status.value}
                for item in transition.removed
            ],
        )

    def _snapshots_for(
        self,
        connections: tuple[Connection, ...],
    ) -> tuple[ConnectionSnapshot, ...]:
        with self._lock:
            snapshots: list[ConnectionSnapshot] = []
            for item in connections:
                snapshot = self._snapshots.get(item.connection_id)
                if snapshot is None or snapshot.connection.version != item.version:
                    snapshot = ConnectionSnapshot(
                        item,
                        ConnectionStatus.UNKNOWN if item.enabled else ConnectionStatus.DISABLED,
                    )
                snapshots.append(snapshot)
            return tuple(snapshots)

    @staticmethod
    def _connection_signature(
        connections: tuple[Connection, ...],
    ) -> tuple[tuple[str, int, bool], ...]:
        return tuple((item.connection_id, item.version, item.enabled) for item in connections)

    @staticmethod
    def _event_connection(item: InformationConnection) -> dict[str, str | None]:
        return {
            "server_ipv4": item.server_ipv4,
            "protocol": item.protocol,
            "failure_kind": item.failure_kind.value if item.failure_kind else None,
        }
