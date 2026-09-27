"""In-memory callback authorization sessions for operational Telegram menus."""

from __future__ import annotations

import secrets
import time
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum

from .operational_telegram_menu import (
    CallbackKind,
    ServerCatalogBinding,
    TelegramServiceTarget,
)

SERVICE_MENU_TTL_SECONDS = 300
ACTION_CALLBACK_TTL_SECONDS = 60
_ONE_SHOT_KINDS = frozenset({"action", "confirm_reboot"})
_SHORT_LIVED_KINDS = frozenset({"action", "confirm_reboot"})
_PRESERVED_SERVER_KINDS = frozenset({"server", "reboot", "cancel"})


@dataclass(frozen=True, slots=True)
class CallbackContext:
    kind: CallbackKind
    chat_id: int
    user_id: int
    expires_at: float
    server_ip: str = ""
    target: TelegramServiceTarget | None = None
    targets: tuple[TelegramServiceTarget, ...] = ()
    action: str = ""
    generation: int = 0
    one_shot: bool = False
    server_catalog: ServerCatalogBinding = frozenset()


class CallbackResolutionKind(StrEnum):
    ACCEPTED = "accepted"
    EXPIRED = "expired"
    SERVER_REMOVED = "server_removed"
    STALE_SERVICES = "stale_services"


@dataclass(frozen=True, slots=True)
class CallbackResolution:
    kind: CallbackResolutionKind
    context: CallbackContext | None = None


class OperationalTelegramCallbackStore:
    """Issue and consume opaque callbacks bound to their authorization context."""

    def __init__(
        self,
        *,
        clock: Callable[[], float] = time.monotonic,
        token_factory: Callable[[], str] | None = None,
    ) -> None:
        self._clock = clock
        self._token_factory = token_factory or self._new_token
        self._callbacks: dict[str, CallbackContext] = {}
        self._server_generation: dict[str, int] = {}

    def issue(
        self,
        kind: CallbackKind,
        *,
        chat_id: int,
        user_id: int,
        server_catalog: ServerCatalogBinding,
        server_ip: str = "",
        target: TelegramServiceTarget | None = None,
        targets: tuple[TelegramServiceTarget, ...] = (),
        action: str = "",
        generation: int = 0,
    ) -> str:
        token = self._token_factory()
        ttl = (
            ACTION_CALLBACK_TTL_SECONDS if kind in _SHORT_LIVED_KINDS else SERVICE_MENU_TTL_SECONDS
        )
        self._callbacks[token] = CallbackContext(
            kind=kind,
            chat_id=chat_id,
            user_id=user_id,
            expires_at=self._clock() + ttl,
            server_ip=server_ip,
            target=target,
            targets=targets,
            action=action,
            generation=generation,
            one_shot=kind in _ONE_SHOT_KINDS,
            server_catalog=server_catalog,
        )
        return token

    def resolve(
        self,
        token: str,
        *,
        chat_id: int,
        user_id: int,
        server_catalog: ServerCatalogBinding,
    ) -> CallbackResolution:
        context = self._callbacks.get(token)
        if (
            context is None
            or context.chat_id != chat_id
            or context.user_id != user_id
            or self._clock() > context.expires_at
            or context.server_catalog != server_catalog
        ):
            return CallbackResolution(CallbackResolutionKind.EXPIRED)
        if context.server_ip and context.server_ip not in server_catalog:
            self._callbacks.pop(token, None)
            return CallbackResolution(CallbackResolutionKind.SERVER_REMOVED)
        if context.generation and context.generation != self.services_generation(
            context.server_ip
        ):
            return CallbackResolution(CallbackResolutionKind.STALE_SERVICES)
        if context.one_shot:
            self._callbacks.pop(token, None)
        return CallbackResolution(CallbackResolutionKind.ACCEPTED, context)

    def advance_services_generation(self, server_ip: str) -> int:
        generation = self.services_generation(server_ip) + 1
        self._server_generation[server_ip] = generation
        return generation

    def services_generation(self, server_ip: str) -> int:
        return self._server_generation.get(server_ip, 0)

    def invalidate_server_callbacks(self, server_ip: str) -> None:
        self._callbacks = {
            token: context
            for token, context in self._callbacks.items()
            if context.server_ip != server_ip or context.kind in _PRESERVED_SERVER_KINDS
        }

    def recent_servers_changed(self, valid_server_ips: set[str]) -> None:
        self._callbacks.clear()
        self._server_generation = {
            server_ip: generation
            for server_ip, generation in self._server_generation.items()
            if server_ip in valid_server_ips
        }

    def clear(self) -> None:
        self._callbacks.clear()
        self._server_generation.clear()

    def purge_expired(self) -> None:
        now = self._clock()
        self._callbacks = {
            token: context
            for token, context in self._callbacks.items()
            if context.expires_at >= now
        }

    @staticmethod
    def _new_token() -> str:
        return secrets.token_urlsafe(18)
