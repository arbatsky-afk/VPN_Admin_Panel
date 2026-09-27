#!/usr/bin/env python3
"""Validate the managed Nginx TLS state without exposing certificate secrets."""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import subprocess
from pathlib import Path
from typing import NamedTuple

NGINX_CONFIG = Path("/etc/nginx/conf.d/vpn-admin-site.conf")
NGINX_SUBSCRIPTIONS_LOCATION = Path("/etc/nginx/vpn-admin-locations/subscriptions.conf")
NGINX_TLS_STATE = Path("/etc/nginx/vpn-admin-tls/state")
NGINX_CERTIFICATE = Path("/etc/nginx/vpn-admin-tls/server.crt")
NGINX_PRIVATE_KEY = Path("/etc/nginx/vpn-admin-tls/server.key")

TLS_MODES = frozenset({"self_signed", "letsencrypt"})
DOMAIN_PATTERN = re.compile(
    r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$"
)

SELF_SIGNED_VHOST = """server {
    listen 80 default_server;
    listen 443 ssl default_server;
    server_name _;

    root /var/www/vpn-admin-site;
    index index.html;
    autoindex off;
    server_tokens off;
    add_header X-VPN-Admin-Component "nginx/1" always;

    ssl_certificate /etc/nginx/vpn-admin-tls/server.crt;
    ssl_certificate_key /etc/nginx/vpn-admin-tls/server.key;
    ssl_protocols TLSv1.2 TLSv1.3;

    location / {
        try_files $uri $uri/ =404;
    }

    include /etc/nginx/vpn-admin-locations/*.conf;
}
"""

LETSENCRYPT_VHOST = """server {
    listen 80 default_server;
    server_name __SERVER_NAME__;

    root /var/www/vpn-admin-site;
    server_tokens off;
    add_header X-VPN-Admin-Component "nginx/1" always;

    location ^~ /.well-known/acme-challenge/ {
        default_type text/plain;
        try_files $uri =404;
    }

    location / {
        return 308 https://$host$request_uri;
    }
}

server {
    listen 443 ssl default_server;
    server_name __SERVER_NAME__;

    root /var/www/vpn-admin-site;
    index index.html;
    autoindex off;
    server_tokens off;
    add_header X-VPN-Admin-Component "nginx/1" always;

    ssl_certificate /etc/nginx/vpn-admin-tls/server.crt;
    ssl_certificate_key /etc/nginx/vpn-admin-tls/server.key;
    ssl_protocols TLSv1.2 TLSv1.3;

    location / {
        try_files $uri $uri/ =404;
    }

    include /etc/nginx/vpn-admin-locations/*.conf;
}
"""

SUBSCRIPTIONS_LOCATION = """location = /subscriptions/ {
    if ($scheme != https) { return 404; }
    access_log off;
    log_not_found off;
    add_header Cache-Control "no-store" always;
    default_type "text/plain; charset=utf-8";
    autoindex off;
    return 404;
}

location ~ ^/subscriptions/[A-Za-z0-9_-]+\\.txt$ {
    if ($scheme != https) { return 404; }
    access_log off;
    log_not_found off;
    add_header Cache-Control "no-store" always;
    default_type "text/plain; charset=utf-8";
    autoindex off;
    disable_symlinks on;
    try_files $uri =404;
}

location /subscriptions/ {
    if ($scheme != https) { return 404; }
    access_log off;
    log_not_found off;
    add_header Cache-Control "no-store" always;
    default_type "text/plain; charset=utf-8";
    autoindex off;
    return 404;
}
"""


class ContractError(ValueError):
    """Raised when managed Nginx state is incomplete or inconsistent."""


class TlsState(NamedTuple):
    mode: str
    server_name: str
    server_address: str


def valid_domain(value: str) -> bool:
    return (
        len(value) <= 253
        and any(character.isalpha() for character in value)
        and DOMAIN_PATTERN.fullmatch(value) is not None
    )


def _regular_file(path: Path) -> bool:
    return path.is_file() and not path.is_symlink()


def load_tls_state(path: Path = NGINX_TLS_STATE) -> TlsState:
    if not _regular_file(path):
        raise ContractError("Nginx TLS state is not a regular file.")
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as error:
        raise ContractError("Nginx TLS state cannot be read.") from error
    if len(lines) != 4 or lines[0] != "version=1":
        raise ContractError("Nginx TLS state has an unsupported format.")
    expected_prefixes = ("tls_mode=", "server_name=", "server_address=")
    if any(
        not line.startswith(prefix)
        for line, prefix in zip(lines[1:], expected_prefixes, strict=True)
    ):
        raise ContractError("Nginx TLS state has invalid fields.")
    mode = lines[1].removeprefix("tls_mode=")
    server_name = lines[2].removeprefix("server_name=")
    server_address = lines[3].removeprefix("server_address=")
    if mode not in TLS_MODES:
        raise ContractError("Nginx TLS state has an invalid mode.")
    try:
        parsed_address = str(ipaddress.IPv4Address(server_address))
    except ipaddress.AddressValueError as error:
        raise ContractError("Nginx TLS state has an invalid server address.") from error
    if parsed_address != server_address:
        raise ContractError("Nginx TLS state server address is not canonical.")
    if mode == "self_signed" and server_name != server_address:
        raise ContractError("Self-signed Nginx TLS state must use the server IPv4.")
    if mode == "letsencrypt" and not valid_domain(server_name):
        raise ContractError("Let's Encrypt Nginx TLS state has an invalid domain.")
    return TlsState(mode, server_name, server_address)


def expected_vhost(state: TlsState) -> str:
    if state.mode == "self_signed":
        return SELF_SIGNED_VHOST
    return LETSENCRYPT_VHOST.replace("__SERVER_NAME__", state.server_name)


def _run(
    arguments: tuple[str, ...], *, input_bytes: bytes | None = None
) -> subprocess.CompletedProcess[bytes]:
    try:
        return subprocess.run(
            arguments,
            input=input_bytes,
            capture_output=True,
            check=False,
            timeout=15,
        )
    except (OSError, subprocess.TimeoutExpired):
        return subprocess.CompletedProcess(arguments, 127, b"", b"")


def validate_certificate(
    certificate: Path,
    private_key: Path,
    mode: str,
    name: str,
    *,
    allow_expired: bool = False,
) -> bool:
    if mode not in TLS_MODES or not _regular_file(certificate) or not _regular_file(private_key):
        return False
    if mode == "self_signed":
        try:
            ipaddress.IPv4Address(name)
        except ipaddress.AddressValueError:
            return False
        identity_arguments = (
            "openssl",
            "x509",
            "-in",
            str(certificate),
            "-noout",
            "-checkip",
            name,
        )
    else:
        if not valid_domain(name):
            return False
        identity_arguments = (
            "openssl",
            "x509",
            "-in",
            str(certificate),
            "-noout",
            "-checkhost",
            name,
        )
    if _run(identity_arguments).returncode != 0:
        return False
    if (
        not allow_expired
        and _run(
            ("openssl", "x509", "-in", str(certificate), "-noout", "-checkend", "0")
        ).returncode
        != 0
    ):
        return False
    certificate_public = _run(("openssl", "x509", "-in", str(certificate), "-pubkey", "-noout"))
    certificate_der = _run(
        ("openssl", "pkey", "-pubin", "-outform", "DER"),
        input_bytes=certificate_public.stdout,
    )
    private_der = _run(("openssl", "pkey", "-in", str(private_key), "-pubout", "-outform", "DER"))
    return (
        certificate_public.returncode == 0
        and certificate_der.returncode == 0
        and private_der.returncode == 0
        and certificate_der.stdout == private_der.stdout
    )


def verify_owned(
    *,
    config: Path = NGINX_CONFIG,
    subscriptions_location: Path = NGINX_SUBSCRIPTIONS_LOCATION,
    state_path: Path = NGINX_TLS_STATE,
    certificate: Path = NGINX_CERTIFICATE,
    private_key: Path = NGINX_PRIVATE_KEY,
    allow_expired: bool = False,
    allow_legacy_v4: bool = False,
) -> TlsState:
    state = load_tls_state(state_path)
    if not _regular_file(config):
        raise ContractError("Managed Nginx vhost is not a regular file.")
    try:
        config_text = config.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise ContractError("Managed Nginx vhost cannot be read.") from error
    if config_text != expected_vhost(state):
        raise ContractError("Managed Nginx vhost differs from its TLS state.")
    if _regular_file(subscriptions_location):
        try:
            location_text = subscriptions_location.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as error:
            raise ContractError("Managed subscriptions location cannot be read.") from error
        if location_text != SUBSCRIPTIONS_LOCATION:
            raise ContractError("Managed subscriptions location differs from its contract.")
    elif not allow_legacy_v4:
        raise ContractError("Managed subscriptions location is not a regular file.")
    elif subscriptions_location.exists() or subscriptions_location.is_symlink():
        raise ContractError("Legacy Nginx state contains an unsafe subscriptions location.")
    if not validate_certificate(
        certificate,
        private_key,
        state.mode,
        state.server_name,
        allow_expired=allow_expired,
    ):
        raise ContractError("Managed Nginx certificate is invalid.")
    return state


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(add_help=False)
    subparsers = parser.add_subparsers(dest="command", required=True)
    for command in ("inspect", "state", "verify-owned"):
        command_parser = subparsers.add_parser(command, add_help=False)
        command_parser.add_argument("--allow-expired", action="store_true")
        if command == "verify-owned":
            command_parser.add_argument("--allow-legacy-v4", action="store_true")
    certificate_parser = subparsers.add_parser("verify-certificate", add_help=False)
    certificate_parser.add_argument("--certificate", required=True)
    certificate_parser.add_argument("--private-key", required=True)
    certificate_parser.add_argument("--mode", choices=sorted(TLS_MODES), required=True)
    certificate_parser.add_argument("--name", required=True)
    certificate_parser.add_argument("--allow-expired", action="store_true")
    return parser


def main(arguments: list[str] | None = None) -> int:
    parsed = _parser().parse_args(arguments)
    try:
        if parsed.command == "verify-certificate":
            valid = validate_certificate(
                Path(parsed.certificate),
                Path(parsed.private_key),
                parsed.mode,
                parsed.name,
                allow_expired=parsed.allow_expired,
            )
            return 0 if valid else 1
        state = (
            verify_owned(
                allow_expired=parsed.allow_expired,
                allow_legacy_v4=getattr(parsed, "allow_legacy_v4", False),
            )
            if parsed.command == "verify-owned"
            else load_tls_state()
        )
        if parsed.command == "state":
            print(state.mode, state.server_name, state.server_address)
        else:
            print(
                json.dumps(
                    {
                        "tls_mode": state.mode,
                        "server_name": state.server_name,
                        "server_address": state.server_address,
                    },
                    separators=(",", ":"),
                )
            )
        return 0
    except ContractError:
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
