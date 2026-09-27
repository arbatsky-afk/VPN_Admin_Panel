"""Pure menu projections for the operational Telegram controller."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Literal

from app.services.inventory import InventorySnapshot
from app.services.ssh import validate_server_ip

ALLOWED_ACTIONS = frozenset({"start", "stop", "restart"})
CallbackKind = Literal[
    "servers",
    "server",
    "services",
    "service_group",
    "service",
    "action",
    "reboot",
    "confirm_reboot",
    "cancel",
    "home",
]


@dataclass(frozen=True, slots=True)
class TelegramServiceTarget:
    component_id: str
    display_name: str
    unit: str
    kind: str
    service: str
    actions: frozenset[str]


@dataclass(frozen=True, slots=True)
class TelegramServer:
    ip: str
    alias: str


@dataclass(frozen=True, slots=True)
class TelegramButtonIntent:
    text: str
    kind: CallbackKind
    server_ip: str = ""
    target: TelegramServiceTarget | None = None
    targets: tuple[TelegramServiceTarget, ...] = ()
    action: str = ""
    generation: int = 0


@dataclass(frozen=True, slots=True)
class TelegramMenu:
    text: str
    rows: tuple[tuple[TelegramButtonIntent, ...], ...]


ServerCatalog = tuple[TelegramServer, ...]
ServerCatalogBinding = frozenset[str]


def compact_label(value: str, limit: int = 60) -> str:
    """Normalize whitespace and bound a Telegram-facing label."""
    normalized = " ".join(value.split())
    return normalized if len(normalized) <= limit else f"{normalized[: limit - 1]}…"


def server_catalog(servers: Sequence[dict[str, str]]) -> ServerCatalog:
    """Project the first ten valid, unique Recent servers in MRU order."""
    result: list[TelegramServer] = []
    seen: set[str] = set()
    for server in servers[:10]:
        if not isinstance(server, dict):
            continue
        ip, error = validate_server_ip(server.get("ip", ""))
        alias = server.get("alias")
        if error or ip in seen or not isinstance(alias, str):
            continue
        seen.add(ip)
        result.append(TelegramServer(ip, alias))
    return tuple(result)


def catalog_binding(catalog: ServerCatalog) -> ServerCatalogBinding:
    """Return the unordered canonical server identities used by callbacks."""
    return frozenset(server.ip for server in catalog)


def server_exists(catalog: ServerCatalog, server_ip: str) -> bool:
    return any(server.ip == server_ip for server in catalog)


def server_label(catalog: ServerCatalog, server_ip: str) -> str:
    server = next((item for item in catalog if item.ip == server_ip), None)
    if server is None or not server.alias:
        return server_ip
    return f"{server_ip} — {compact_label(server.alias, 256)}"


def home_menu() -> TelegramMenu:
    return TelegramMenu(
        "Operations Bot",
        ((TelegramButtonIntent("Servers", "servers"),),),
    )


def servers_menu(catalog: ServerCatalog) -> TelegramMenu:
    rows = [
        (
            TelegramButtonIntent(
                compact_label(server_label(catalog, server.ip)),
                "server",
                server_ip=server.ip,
            ),
        )
        for server in catalog
    ]
    rows.append((TelegramButtonIntent("Home", "home"),))
    text = "Servers" if catalog else "No valid servers are available in Admin Panel."
    return TelegramMenu(text, tuple(rows))


def server_menu(catalog: ServerCatalog, server_ip: str) -> TelegramMenu:
    return TelegramMenu(
        server_label(catalog, server_ip),
        (
            (TelegramButtonIntent("Services", "services", server_ip=server_ip),),
            (TelegramButtonIntent("Reboot", "reboot", server_ip=server_ip),),
            (
                TelegramButtonIntent("Back", "servers"),
                TelegramButtonIntent("Home", "home"),
            ),
        ),
    )


def services_menu(
    catalog: ServerCatalog,
    server_ip: str,
    targets: tuple[TelegramServiceTarget, ...],
    generation: int,
) -> TelegramMenu:
    rows: list[tuple[TelegramButtonIntent, ...]] = []
    base_security_targets = tuple(target for target in targets if target.kind == "base-security")
    base_security_added = False
    for target in targets:
        if target.kind == "base-security":
            if base_security_added:
                continue
            base_security_added = True
            rows.append(
                (
                    TelegramButtonIntent(
                        "Base + Security",
                        "service_group",
                        server_ip=server_ip,
                        targets=base_security_targets,
                        generation=generation,
                    ),
                )
            )
            continue
        rows.append(
            (
                TelegramButtonIntent(
                    target.display_name,
                    "service",
                    server_ip=server_ip,
                    target=target,
                    generation=generation,
                ),
            )
        )
    rows.append(
        (
            TelegramButtonIntent("Back", "server", server_ip=server_ip),
            TelegramButtonIntent("Home", "home"),
        )
    )
    label = server_label(catalog, server_ip)
    text = (
        f"Services — {label}" if targets else f"No manageable installed services found on {label}."
    )
    return TelegramMenu(text, tuple(rows))


def service_menu(
    catalog: ServerCatalog,
    server_ip: str,
    target: TelegramServiceTarget,
    generation: int,
) -> TelegramMenu:
    rows = [
        (
            TelegramButtonIntent(
                action.capitalize(),
                "action",
                server_ip=server_ip,
                target=target,
                action=action,
                generation=generation,
            ),
        )
        for action in ("start", "stop", "restart")
        if action in target.actions
    ]
    rows.append(
        (
            TelegramButtonIntent("Back", "services", server_ip=server_ip),
            TelegramButtonIntent("Home", "home"),
        )
    )
    return TelegramMenu(
        f"{target.display_name} — {server_label(catalog, server_ip)}",
        tuple(rows),
    )


def service_group_menu(
    catalog: ServerCatalog,
    server_ip: str,
    targets: tuple[TelegramServiceTarget, ...],
    generation: int,
) -> TelegramMenu:
    rows = [
        (
            TelegramButtonIntent(
                "nftables" if target.service == "nftables" else "Fail2Ban",
                "service",
                server_ip=server_ip,
                target=target,
                generation=generation,
            ),
        )
        for target in targets
    ]
    rows.append(
        (
            TelegramButtonIntent("Back", "services", server_ip=server_ip),
            TelegramButtonIntent("Home", "home"),
        )
    )
    return TelegramMenu(
        f"Base + Security — {server_label(catalog, server_ip)}",
        tuple(rows),
    )


def reboot_menu(catalog: ServerCatalog, server_ip: str) -> TelegramMenu:
    return TelegramMenu(
        f"Reboot {server_label(catalog, server_ip)}?",
        (
            (
                TelegramButtonIntent(
                    "Confirm reboot",
                    "confirm_reboot",
                    server_ip=server_ip,
                ),
            ),
            (TelegramButtonIntent("Cancel", "cancel", server_ip=server_ip),),
        ),
    )


def service_targets(snapshot: InventorySnapshot) -> tuple[TelegramServiceTarget, ...]:
    """Build the fixed Telegram management allowlist from an Inventory snapshot."""
    targets: list[TelegramServiceTarget] = []
    for component in snapshot.components:
        if component.status == "not_installed" or component.declaration is None:
            continue
        declaration = component.declaration
        actions = frozenset(declaration.management_actions) & ALLOWED_ACTIONS
        handler = declaration.management_handler
        if not handler or not actions:
            continue
        if handler == "base-security":
            for unit in declaration.systemd_units:
                service = unit.removesuffix(".service")
                if service in {"nftables", "fail2ban"}:
                    targets.append(
                        TelegramServiceTarget(
                            component.component_id,
                            compact_label(f"{declaration.display_name} / {unit}"),
                            unit,
                            handler,
                            service,
                            actions,
                        )
                    )
            continue
        expected_unit = {
            "docker": "docker.service",
            "xray": "xray.service",
            "hysteria2": "hysteria-server.service",
            "mieru": "mita.service",
            "nginx": "nginx.service",
            "netdata": "netdata.service",
        }.get(handler)
        if expected_unit is None or expected_unit not in declaration.systemd_units:
            continue
        targets.append(
            TelegramServiceTarget(
                component.component_id,
                compact_label(declaration.display_name),
                expected_unit,
                handler,
                "",
                actions,
            )
        )
    return tuple(targets)
