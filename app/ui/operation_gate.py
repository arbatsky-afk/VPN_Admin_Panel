"""Typed ownership for the single foreground operation in the application."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

OperationScope = Literal[
    "inventory",
    "management",
    "process",
    "server",
    "backup",
    "restore",
    "subscriptions",
]


@dataclass(frozen=True, slots=True)
class OperationContext:
    """Immutable identity and routing data for one foreground operation."""

    token: int
    title: str
    scope: OperationScope
    server_ip: str = ""


class OperationGate:
    """Allow one foreground operation and reject stale owners on completion."""

    def __init__(self) -> None:
        self._current: OperationContext | None = None
        self._next_token = 1

    @property
    def current(self) -> OperationContext | None:
        return self._current

    @property
    def title(self) -> str:
        return self._current.title if self._current is not None else ""

    @property
    def busy(self) -> bool:
        return self._current is not None

    def begin(
        self,
        title: str,
        *,
        scope: OperationScope,
        server_ip: str = "",
    ) -> OperationContext | None:
        """Acquire an idle gate and return the new immutable operation identity."""
        if self._current is not None:
            return None
        return self._replace(title, scope=scope, server_ip=server_ip)

    def transition(
        self,
        current: OperationContext,
        title: str,
        *,
        scope: OperationScope,
        server_ip: str = "",
    ) -> OperationContext | None:
        """Change routing fields while preserving the current operation token."""
        if not self.matches(current):
            return None
        normalized_title = title.strip()
        if not normalized_title:
            raise ValueError("Operation title cannot be empty.")
        context = OperationContext(current.token, normalized_title, scope, server_ip)
        self._current = context
        return context

    def matches(
        self,
        context: OperationContext | None = None,
        *,
        title: str | None = None,
        scope: OperationScope | None = None,
        server_ip: str | None = None,
    ) -> bool:
        """Match either an exact token owner or explicit routing fields."""
        current = self._current
        if current is None:
            return False
        if context is not None and current != context:
            return False
        if title is not None and current.title != title:
            return False
        if scope is not None and current.scope != scope:
            return False
        if server_ip is not None and current.server_ip != server_ip:
            return False
        return True

    def finish(self, context: OperationContext) -> bool:
        """Release the gate only for its exact current token owner."""
        if not self.matches(context):
            return False
        self._current = None
        return True

    def _replace(
        self,
        title: str,
        *,
        scope: OperationScope,
        server_ip: str = "",
    ) -> OperationContext:
        normalized_title = title.strip()
        if not normalized_title:
            raise ValueError("Operation title cannot be empty.")
        context = OperationContext(self._next_token, normalized_title, scope, server_ip)
        self._next_token += 1
        self._current = context
        return context
