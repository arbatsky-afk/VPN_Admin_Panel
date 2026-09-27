#!/usr/bin/env python3
"""Safe validator for the Hysteria2 YAML profile managed by this panel."""

import re
import sys
from urllib.parse import urlparse

_KEY = re.compile(r"^[A-Za-z0-9_-]+$")
_USER = re.compile(r"^[A-Za-z0-9-]+$")
_BANDWIDTH = re.compile(r"^[1-9][0-9]*\s+[kKmMgGtT]?[bB][pP][sS]$")
_HOSTNAME = re.compile(
    r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)"
    r"(?:\.(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?))*$"
)


class Hysteria2ConfigError(ValueError):
    """The configuration is not valid for the panel-managed Hysteria2 profile."""


def _scalar(value: str, line_number: int) -> object:
    if not value:
        raise Hysteria2ConfigError(f"line {line_number}: empty scalar")
    if value in {"true", "false"}:
        return value == "true"
    if value.startswith(("!", "&", "*", "[", "{", "|", ">")):
        raise Hysteria2ConfigError(f"line {line_number}: unsupported YAML construct")
    if " #" in value:
        value = value.split(" #", 1)[0].rstrip()
    if (value.startswith("'") and value.endswith("'")) or (
        value.startswith('"') and value.endswith('"')
    ):
        value = value[1:-1]
    if not value or any(character in value for character in "\r\n\0"):
        raise Hysteria2ConfigError(f"line {line_number}: invalid scalar")
    return value


def parse_hysteria2_config(text: str) -> dict[str, object]:
    """Parse the deliberately small, mapping-only YAML subset emitted by the panel."""
    if not isinstance(text, str) or not text.strip():
        raise Hysteria2ConfigError("configuration is empty")
    root: dict[str, object] = {}
    stack: list[tuple[int, dict[str, object]]] = [(-2, root)]
    for line_number, raw_line in enumerate(text.splitlines(), 1):
        if not raw_line.strip() or raw_line.lstrip().startswith("#"):
            continue
        if "\t" in raw_line:
            raise Hysteria2ConfigError(f"line {line_number}: tabs are not allowed")
        indent = len(raw_line) - len(raw_line.lstrip(" "))
        if indent % 2:
            raise Hysteria2ConfigError(f"line {line_number}: indentation must use two spaces")
        content = raw_line[indent:]
        if ":" not in content:
            raise Hysteria2ConfigError(f"line {line_number}: expected a mapping entry")
        key, value = content.split(":", 1)
        key = key.strip()
        if not _KEY.fullmatch(key):
            raise Hysteria2ConfigError(f"line {line_number}: invalid mapping key")
        while stack and indent <= stack[-1][0]:
            stack.pop()
        if not stack or indent != stack[-1][0] + 2:
            raise Hysteria2ConfigError(f"line {line_number}: invalid indentation")
        mapping = stack[-1][1]
        if key in mapping:
            raise Hysteria2ConfigError(f"line {line_number}: duplicate key {key}")
        if value.strip():
            mapping[key] = _scalar(value.strip(), line_number)
        else:
            child: dict[str, object] = {}
            mapping[key] = child
            stack.append((indent, child))
    return root


def _mapping(value: object, field: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise Hysteria2ConfigError(f"{field} must be a mapping")
    return value


def _string(value: object, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise Hysteria2ConfigError(f"{field} must be a non-empty scalar")
    return value


def validate_hysteria2_config_text(text: str) -> dict[str, object]:
    """Validate syntax and the complete structure required by panel operations."""
    config = parse_hysteria2_config(text)
    listen = _string(config.get("listen"), "listen")
    listen_match = re.fullmatch(r":(\d{1,5})", listen)
    if listen_match is None or not 1 <= int(listen_match.group(1)) <= 65535:
        raise Hysteria2ConfigError("listen must contain one valid UDP port")

    tls = _mapping(config.get("tls"), "tls")
    if _string(tls.get("cert"), "tls.cert") != "/etc/hysteria/server.crt":
        raise Hysteria2ConfigError("tls.cert has an unexpected path")
    if _string(tls.get("key"), "tls.key") != "/etc/hysteria/server.key":
        raise Hysteria2ConfigError("tls.key has an unexpected path")

    bandwidth = _mapping(config.get("bandwidth"), "bandwidth")
    for field in ("up", "down"):
        if not _BANDWIDTH.fullmatch(_string(bandwidth.get(field), f"bandwidth.{field}")):
            raise Hysteria2ConfigError(f"bandwidth.{field} has an invalid format")

    auth = _mapping(config.get("auth"), "auth")
    if auth.get("type") != "userpass":
        raise Hysteria2ConfigError("auth.type must be userpass")
    users = _mapping(auth.get("userpass"), "auth.userpass")
    if not users:
        raise Hysteria2ConfigError("auth.userpass must contain at least one user")
    for name, password in users.items():
        if not _USER.fullmatch(name) or not isinstance(password, str) or not password:
            raise Hysteria2ConfigError("auth.userpass contains an invalid entry")

    masquerade = _mapping(config.get("masquerade"), "masquerade")
    if masquerade.get("type") != "proxy":
        raise Hysteria2ConfigError("masquerade.type must be proxy")
    proxy = _mapping(masquerade.get("proxy"), "masquerade.proxy")
    parsed_url = urlparse(_string(proxy.get("url"), "masquerade.proxy.url"))
    try:
        parsed_port = parsed_url.port
    except ValueError as error:
        raise Hysteria2ConfigError("masquerade.proxy.url is invalid") from error
    if (
        parsed_url.scheme != "https"
        or parsed_url.path not in {"", "/"}
        or parsed_port is not None
        or parsed_url.username is not None
        or parsed_url.query
        or parsed_url.fragment
    ):
        raise Hysteria2ConfigError("masquerade.proxy.url must be an HTTPS origin")
    if not parsed_url.hostname or not _HOSTNAME.fullmatch(parsed_url.hostname):
        raise Hysteria2ConfigError("masquerade.proxy.url contains an invalid hostname")
    if proxy.get("rewriteHost") is not True:
        raise Hysteria2ConfigError("masquerade.proxy.rewriteHost must be true")

    obfs = _mapping(config.get("obfs"), "obfs")
    if obfs.get("type") != "salamander":
        raise Hysteria2ConfigError("obfs.type must be salamander")
    salamander = _mapping(obfs.get("salamander"), "obfs.salamander")
    _string(salamander.get("password"), "obfs.salamander.password")
    return config


def hysteria2_connection_details(text: str) -> tuple[int, str, dict[str, str], str]:
    config = validate_hysteria2_config_text(text)
    port = int(str(config["listen"])[1:])
    users = _mapping(_mapping(config["auth"], "auth")["userpass"], "auth.userpass")
    proxy = _mapping(_mapping(config["masquerade"], "masquerade")["proxy"], "masquerade.proxy")
    salamander = _mapping(_mapping(config["obfs"], "obfs")["salamander"], "obfs.salamander")
    hostname = urlparse(str(proxy["url"])).hostname
    return (
        port,
        str(hostname),
        {str(name): str(password) for name, password in users.items()},
        str(salamander["password"]),
    )


def validate_hysteria2_config_file(path: str) -> None:
    with open(path, encoding="utf-8") as source:
        validate_hysteria2_config_text(source.read())


if __name__ == "__main__":
    try:
        if len(sys.argv) != 2:
            raise Hysteria2ConfigError("usage: hysteria2_config.py CONFIG")
        validate_hysteria2_config_file(sys.argv[1])
    except (Hysteria2ConfigError, OSError, UnicodeError, ValueError) as error:
        print(f"Invalid Hysteria2 configuration: {error}", file=sys.stderr)
        raise SystemExit(1)
