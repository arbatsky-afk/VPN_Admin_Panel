"""Typed public contracts and fixed action sets for Management."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from ..declaration_contract import MANAGEMENT_ACTIONS_BY_HANDLER

DockerAction = Literal["inspect", "start", "stop", "restart", "enable", "disable"]
DOCKER_ACTIONS = MANAGEMENT_ACTIONS_BY_HANDLER["docker"]
XrayAction = Literal["inspect", "start", "stop", "restart", "enable", "disable"]
XRAY_ACTIONS = MANAGEMENT_ACTIONS_BY_HANDLER["xray"] - {"update_connection"}
HYSTERIA2_ACTIONS = MANAGEMENT_ACTIONS_BY_HANDLER["hysteria2"] - {"update_connection"}
MieruAction = Literal["inspect", "start", "stop", "restart", "enable", "disable"]
MIERU_ACTIONS = MANAGEMENT_ACTIONS_BY_HANDLER["mieru"] - {"update_port"}
NginxAction = Literal["inspect", "start", "stop", "restart", "enable", "disable"]
NGINX_ACTIONS = MANAGEMENT_ACTIONS_BY_HANDLER["nginx"]
NetdataAction = Literal["inspect", "start", "stop", "restart", "enable", "disable"]
NETDATA_ACTIONS = MANAGEMENT_ACTIONS_BY_HANDLER["netdata"]


ManagementMutationOutcome = Literal["success", "rolled_back", "partial", "unknown"]
_MANAGEMENT_MUTATION_OUTCOMES = frozenset({"success", "rolled_back", "partial", "unknown"})
_MANAGEMENT_MUTATION_STATES = frozenset({"applied", "restored", "unknown"})


@dataclass(frozen=True)
class ManagementMutationResult:
    """Structured result of a server-changing Management transaction."""

    outcome: ManagementMutationOutcome
    message: str
    config_state: str
    firewall_state: str
    service_state: str
    status: object | None = None


@dataclass(frozen=True)
class PublishedUdpPort:
    """One UDP host-port published by the supported Amnezia container."""

    host_address: str
    port: int


@dataclass(frozen=True)
class DockerManagementStatus:
    """The Docker service state and read-only AmneziaWG detection result."""

    service_state: str
    startup_state: str
    amnezia_state: str
    amnezia_container_state: str | None
    amnezia_udp_ports: tuple[PublishedUdpPort, ...]


BaseSecurityService = Literal["nftables", "fail2ban"]
BaseSecurityAction = Literal["inspect", "start", "stop", "restart", "enable", "disable"]
BASE_SECURITY_SERVICES = frozenset({"nftables", "fail2ban"})
BASE_SECURITY_ACTIONS = MANAGEMENT_ACTIONS_BY_HANDLER["base-security"]


@dataclass(frozen=True)
class ServiceManagementStatus:
    """The runtime and boot state of one fixed systemd service."""

    service_state: str
    startup_state: str


@dataclass(frozen=True)
class NginxManagementStatus:
    """Nginx service and fixed non-secret static-site health."""

    service: ServiceManagementStatus
    http_port: int
    https_port: int
    server_name: str
    tls_mode: str
    certificate_expires_at: str | None
    http_healthy: bool
    https_healthy: bool


@dataclass(frozen=True)
class NetdataManagementStatus:
    """Netdata service and fixed localhost/proxy health."""

    service: ServiceManagementStatus
    listen_port: int
    bind_mode: str
    dashboard_healthy: bool
    cloud_online: bool
    proxy_bearer_protected: bool


@dataclass(frozen=True)
class NetdataAccessDetails:
    """Local dashboard entry point protected by Netdata Cloud SSO."""

    url: str


@dataclass(frozen=True)
class AllowedInboundPort:
    """One active inbound port rule owned by nftables or Docker."""

    protocol: str
    port: int
    owner: str | None
    source: str


@dataclass(frozen=True)
class BaseSecurityManagementStatus:
    """Read-only firewall ports plus management state for Base + Security services."""

    nftables: ServiceManagementStatus
    fail2ban: ServiceManagementStatus
    allowed_ports: tuple[AllowedInboundPort, ...]


@dataclass(frozen=True)
class XrayManagementStatus:
    """The Xray service state and non-secret connection parameters."""

    service: ServiceManagementStatus
    protocol: str
    port: int
    sni: str


@dataclass(frozen=True)
class Hysteria2ManagementStatus:
    """The Hysteria2 service state and non-secret connection parameters."""

    service: ServiceManagementStatus
    protocol: str
    port: int
    sni: str


@dataclass(frozen=True)
class MieruManagementStatus:
    """Mita service/runtime state and public settings from the recovery contract."""

    service: ServiceManagementStatus
    runtime_state: str
    transport: str
    port: int
    mtu: int
    user_count: int
