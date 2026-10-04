from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any


class ConnectionStatus(StrEnum):
    UNKNOWN = "unknown"
    CHECKING = "checking"
    RETRYING = "retrying"
    OK = "ok"
    OK_NO_IP = "ok_no_ip"
    FAIL = "fail"
    DISABLED = "disabled"


class FailureKind(StrEnum):
    CANCELLED = "cancelled"
    INVALID_CONFIG = "invalid_config"
    MIHOMO_MISSING = "mihomo_missing"
    MIHOMO_INTEGRITY = "mihomo_integrity"
    MIHOMO_START = "mihomo_start"
    MIHOMO_EXITED = "mihomo_exited"
    PROBE_TIMEOUT = "probe_timeout"
    PROBE_NETWORK = "probe_network"
    IP_INVALID = "ip_invalid"
    IP_MISMATCH = "ip_mismatch"


class MihomoStartOutcome(StrEnum):
    READY = "ready"
    PORT_ALLOCATION_FAILED = "port_allocation_failed"
    SPAWN_FAILED = "spawn_failed"
    EXITED_BEFORE_READY = "exited_before_ready"
    READINESS_TIMEOUT = "readiness_timeout"
    CANCELLED = "cancelled"


@dataclass(frozen=True, slots=True)
class MihomoStartDiagnostics:
    outcome: MihomoStartOutcome
    start_ms: int
    spawn_ms: int | None = None
    readiness_ms: int | None = None
    pid: int | None = None
    proxy_ready_ms: int | None = None
    controller_ready_ms: int | None = None
    process_alive: bool | None = None
    exit_code: int | None = None
    proxy_socket_error: int | None = None
    controller_socket_error: int | None = None
    os_error_type: str | None = None
    errno: int | None = None
    winerror: int | None = None
    proxy_port: int | None = None
    controller_port: int | None = None
    proxy_probe_error_type: str | None = None
    controller_version: str | None = None
    controller_mixed_port: int | None = None
    controller_query_error: str | None = None
    log_tail: str | None = None


@dataclass(frozen=True, slots=True)
class Connection:
    connection_id: str
    enabled: bool
    source_kind: str
    original: str
    proxy: dict[str, Any]
    protocol: str
    expected_ipv4: str
    fingerprint: str
    version: int = 1

    @property
    def display_name(self) -> str:
        return f"{self.protocol} · {self.expected_ipv4}"


@dataclass(frozen=True, slots=True)
class ProbeResult:
    status: ConnectionStatus
    latency_ms: int | None = None
    observed_ipv4: str | None = None
    failure_kind: FailureKind | None = None
    message: str = ""
    mihomo_start: MihomoStartDiagnostics | None = None

    @classmethod
    def failure(
        cls,
        kind: FailureKind,
        message: str,
        mihomo_start: MihomoStartDiagnostics | None = None,
    ) -> ProbeResult:
        return cls(
            ConnectionStatus.FAIL,
            failure_kind=kind,
            message=message,
            mihomo_start=mihomo_start,
        )


@dataclass(frozen=True, slots=True)
class CheckRequest:
    request_id: str
    connection_id: str
    connection_version: int


@dataclass(frozen=True, slots=True)
class ConnectionSnapshot:
    connection: Connection
    status: ConnectionStatus
    checked_at: str | None = None
    result: ProbeResult | None = None
    request_id: str | None = None


@dataclass(frozen=True, slots=True)
class ImportSummary:
    imported: int = 0
    duplicate: int = 0
    invalid: int = 0
    unsupported: int = 0
    connections: tuple[Connection, ...] = field(default_factory=tuple)


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")
