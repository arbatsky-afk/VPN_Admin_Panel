from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from ipaddress import IPv4Address

from monitor.domain import ConnectionSnapshot, ConnectionStatus, FailureKind
from monitor.logs import JsonlLog

TELEGRAM_MESSAGE_LIMIT = 4096


@dataclass(frozen=True, slots=True)
class InformationConnection:
    connection_id: str
    server_ipv4: str
    protocol: str
    status: ConnectionStatus
    latency_ms: int | None = None
    failure_kind: FailureKind | None = None


@dataclass(frozen=True, slots=True)
class StateTransition:
    previous: tuple[InformationConnection, ...]
    current: tuple[InformationConnection, ...]
    status_changed: tuple[InformationConnection, ...]
    added: tuple[InformationConnection, ...]
    removed: tuple[InformationConnection, ...]


class MonitorStateDetector:
    """Compare complete Monitor states without treating input order or ping as state."""

    def __init__(self) -> None:
        self._previous: dict[str, InformationConnection] | None = None

    def reset(self, state: tuple[InformationConnection, ...]) -> None:
        self._previous = self._index(state)

    def compare_and_accept(
        self,
        state: tuple[InformationConnection, ...],
    ) -> StateTransition | None:
        current = self._index(state)
        previous = self._previous
        self._previous = current
        if previous is None:
            return None

        status_changed = tuple(
            item
            for connection_id, item in current.items()
            if connection_id in previous and item.status != previous[connection_id].status
        )
        added = tuple(
            item for connection_id, item in current.items() if connection_id not in previous
        )
        removed = tuple(
            item for connection_id, item in previous.items() if connection_id not in current
        )
        if not status_changed and not added and not removed:
            return None
        return StateTransition(
            previous=tuple(previous.values()),
            current=tuple(current.values()),
            status_changed=status_changed,
            added=added,
            removed=removed,
        )

    @staticmethod
    def _index(
        state: tuple[InformationConnection, ...],
    ) -> dict[str, InformationConnection]:
        indexed = {item.connection_id: item for item in state}
        if len(indexed) != len(state):
            raise ValueError("Information state contains duplicate connection IDs.")
        return indexed


class MonitorMessageFormatter:
    _EMOJI = {
        ConnectionStatus.OK: "🟢",
        ConnectionStatus.OK_NO_IP: "🟡",
        ConnectionStatus.CHECKING: "🟡",
        ConnectionStatus.RETRYING: "🟡",
        ConnectionStatus.FAIL: "🔴",
        ConnectionStatus.UNKNOWN: "⚪",
        ConnectionStatus.DISABLED: "⚪",
    }
    _STATUS_TEXT = {
        ConnectionStatus.OK: "OK",
        ConnectionStatus.UNKNOWN: "UNKNOWN",
        ConnectionStatus.CHECKING: "CHECKING",
        ConnectionStatus.RETRYING: "RETRYING",
        ConnectionStatus.OK_NO_IP: "OK_NO_IP",
        ConnectionStatus.FAIL: "FAIL",
        ConnectionStatus.DISABLED: "DISABLED",
    }
    _PROTOCOL_TEXT = {
        "amneziawg": "AmneziaWG",
        "hysteria2": "Hysteria2",
        "mieru": "Mieru",
        "vless": "VLESS",
    }

    def format_started(self, state: tuple[InformationConnection, ...]) -> str:
        return self._format_bounded(("▶️ Monitoring started", ""), state)

    def format_transition(self, transition: StateTransition) -> str:
        changes: list[str] = []
        if transition.added:
            changes.append(f"➕ Added: {self._format_connections(transition.added)}")
        if transition.removed:
            changes.append(f"➖ Removed: {self._format_connections(transition.removed)}")
        state = self._format_state(transition.current)
        message = "\n".join(changes + ([""] if changes else []) + [state])
        if self._telegram_length(message) <= TELEGRAM_MESSAGE_LIMIT:
            return message

        compact_changes: list[str] = []
        if transition.added:
            compact_changes.append(f"➕ Added: {len(transition.added)} connections")
        if transition.removed:
            compact_changes.append(f"➖ Removed: {len(transition.removed)} connections")
        compact_prefix = tuple(compact_changes + ([""] if compact_changes else []))
        return self._format_bounded(compact_prefix, transition.current)

    def _format_state(self, state: tuple[InformationConnection, ...]) -> str:
        if not state:
            return "⚪ No connections"
        return "\n".join(self._format_item(item) for item in self._sorted(state))

    def _format_bounded(
        self,
        prefix: tuple[str, ...],
        state: tuple[InformationConnection, ...],
    ) -> str:
        rows = (
            [self._format_item(item) for item in self._sorted(state)]
            if state
            else ["⚪ No connections"]
        )
        full_message = "\n".join((*prefix, *rows))
        if self._telegram_length(full_message) <= TELEGRAM_MESSAGE_LIMIT:
            return full_message

        low = 0
        high = len(rows)
        while low < high:
            kept = (low + high + 1) // 2
            if (
                self._telegram_length(self._bounded_candidate(prefix, rows, kept))
                <= TELEGRAM_MESSAGE_LIMIT
            ):
                low = kept
            else:
                high = kept - 1
        return self._bounded_candidate(prefix, rows, low)

    @staticmethod
    def _bounded_candidate(prefix: tuple[str, ...], rows: list[str], kept: int) -> str:
        omitted = len(rows) - kept
        suffix = f"… {omitted} connections omitted (Telegram limit)"
        return "\n".join((*prefix, *rows[:kept], suffix))

    @staticmethod
    def _telegram_length(message: str) -> int:
        return len(message.encode("utf-16-le")) // 2

    def _format_connections(self, state: tuple[InformationConnection, ...]) -> str:
        return ", ".join(self._label(item) for item in self._sorted(state))

    def _format_item(self, item: InformationConnection) -> str:
        latency = str(item.latency_ms) if item.latency_ms is not None else "-"
        protocol = self._protocol(item)
        return (
            f"{self._EMOJI[item.status]} │ {latency:>5} │ "
            f"{item.server_ipv4:<15} │ {protocol:<9} │ "
            f"{self._STATUS_TEXT[item.status]}"
        )

    def _label(self, item: InformationConnection) -> str:
        return f"{item.server_ipv4} · {self._protocol(item)}"

    def _protocol(self, item: InformationConnection) -> str:
        return self._PROTOCOL_TEXT.get(item.protocol.casefold(), item.protocol.upper())

    @staticmethod
    def _sorted(
        state: tuple[InformationConnection, ...],
    ) -> list[InformationConnection]:
        return sorted(state, key=lambda item: IPv4Address(item.server_ipv4))


class OperationLogInformationOutput:
    EVENT = "telegram_information"

    def __init__(
        self,
        operation_log: JsonlLog,
        transport: Callable[[str], None] | None = None,
    ) -> None:
        self._operation_log = operation_log
        self._transport = transport

    def write(self, message: str) -> None:
        prefixed = "\n".join(
            f"[Telegram] {line}" if line else "[Telegram]" for line in message.splitlines()
        )
        self._operation_log.write(self.EVENT, message=prefixed)
        if self._transport is not None:
            try:
                self._transport(message)
            except Exception as error:  # noqa: BLE001 - optional delivery boundary
                self._operation_log.write(
                    "telegram_submit_error",
                    error_type=type(error).__name__,
                )


def information_state(
    snapshots: tuple[ConnectionSnapshot, ...],
) -> tuple[InformationConnection, ...]:
    return tuple(
        InformationConnection(
            connection_id=snapshot.connection.connection_id,
            server_ipv4=snapshot.connection.expected_ipv4,
            protocol=snapshot.connection.protocol,
            status=snapshot.status,
            latency_ms=snapshot.result.latency_ms if snapshot.result else None,
            failure_kind=snapshot.result.failure_kind if snapshot.result else None,
        )
        for snapshot in snapshots
    )
