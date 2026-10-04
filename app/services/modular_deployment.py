from __future__ import annotations

import base64
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from .app_defaults import AppDefaults, load_app_defaults

project_directory = Path(__file__).resolve().parents[2]
modular_deployment_script = project_directory / "scripts" / "windows" / "invoke-modular-deploy.ps1"
base_security_component = "base-security"
xray_component = "xray"
hysteria2_component = "hysteria2"
mieru_component = "mieru"
docker_component = "docker"
nginx_component = "nginx"
netdata_component = "netdata"

ModularComponent = Literal[
    "base-security",
    "xray",
    "hysteria2",
    "mieru",
    "docker",
    "nginx",
    "netdata",
]
NginxTlsMode = Literal["self_signed", "letsencrypt"]
_NGINX_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?=.*[a-z])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"
)


@dataclass(frozen=True, slots=True)
class NginxTlsSettings:
    mode: NginxTlsMode
    domain: str


@dataclass(frozen=True, slots=True)
class ModularDeployRequest:
    """Validated immutable inputs for one modular Deploy operation."""

    component: ModularComponent
    bundle_directory: Path
    environment: tuple[tuple[str, str], ...]

    def powershell_arguments(self) -> tuple[str, str, str]:
        payload = json.dumps(dict(self.environment), separators=(",", ":"), sort_keys=True)
        encoded = base64.b64encode(payload.encode("utf-8")).decode("ascii")
        return self.component, str(self.bundle_directory), encoded


def validate_nginx_tls_settings(mode: object, domain: object) -> NginxTlsSettings:
    """Normalize the one-shot Nginx TLS selection for a Deploy request."""
    if mode not in {"self_signed", "letsencrypt"}:
        raise ValueError("Nginx TLS mode must be self_signed or letsencrypt.")
    if not isinstance(domain, str):
        raise ValueError("Nginx domain must be text.")
    normalized_domain = domain.strip()
    if mode == "self_signed":
        if normalized_domain:
            raise ValueError("Nginx domain must be empty for self_signed TLS.")
        return NginxTlsSettings("self_signed", "")
    if _NGINX_DOMAIN_RE.fullmatch(normalized_domain) is None:
        raise ValueError("Nginx domain must be a valid lowercase DNS name.")
    return NginxTlsSettings("letsencrypt", normalized_domain)


def build_modular_deploy_request(
    project_directory: Path,
    component: ModularComponent,
    *,
    nginx_tls: NginxTlsSettings | None = None,
) -> ModularDeployRequest:
    """Build one request from the tracked defaults before any external process."""
    if component not in {
        base_security_component,
        xray_component,
        hysteria2_component,
        mieru_component,
        docker_component,
        nginx_component,
        netdata_component,
    }:
        raise ValueError("Unsupported modular Deploy Component.")
    defaults = load_app_defaults(project_directory)
    environment = _component_environment(component, defaults, nginx_tls)
    return ModularDeployRequest(component, defaults.modular_bundle_directory, environment)


def _component_environment(
    component: ModularComponent,
    defaults: AppDefaults,
    nginx_tls: NginxTlsSettings | None,
) -> tuple[tuple[str, str], ...]:
    if component == "nginx":
        if not isinstance(nginx_tls, NginxTlsSettings):
            raise ValueError("Nginx Deploy requires a one-shot TLS selection.")
        nginx_tls = validate_nginx_tls_settings(nginx_tls.mode, nginx_tls.domain)
        return (
            ("NGINX_TLS_MODE", nginx_tls.mode),
            ("NGINX_SERVER_NAME", nginx_tls.domain),
        )
    if nginx_tls is not None:
        raise ValueError("Nginx TLS settings are only valid for Nginx Deploy.")
    if component == "xray":
        return (
            ("XRAY_PORT_RANGE_START", str(defaults.xray.port_range.start)),
            ("XRAY_PORT_RANGE_END", str(defaults.xray.port_range.end)),
            ("MASQUERADE_HOST", defaults.xray.masquerade_host),
        )
    if component == "hysteria2":
        return (
            ("HYSTERIA_PORT_RANGE_START", str(defaults.hysteria2.port_range.start)),
            ("HYSTERIA_PORT_RANGE_END", str(defaults.hysteria2.port_range.end)),
            ("HYSTERIA_INITIAL_USER", defaults.hysteria2.initial_user),
            ("HYSTERIA_CERTIFICATE_DAYS", str(defaults.hysteria2.certificate_days)),
            ("HYSTERIA_BANDWIDTH_UP", defaults.hysteria2.bandwidth_up),
            ("HYSTERIA_BANDWIDTH_DOWN", defaults.hysteria2.bandwidth_down),
            ("HYSTERIA_MASQUERADE_HOST", defaults.hysteria2.masquerade_host),
        )
    if component == "mieru":
        return (
            ("MIERU_PORT_RANGE_START", str(defaults.mieru.port_range.start)),
            ("MIERU_PORT_RANGE_END", str(defaults.mieru.port_range.end)),
            ("MIERU_PROTOCOL", defaults.mieru.protocol),
            ("MIERU_MTU", str(defaults.mieru.mtu)),
            ("MIERU_INITIAL_USER", defaults.mieru.initial_user),
        )
    return ()
