from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import uuid
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, unquote, urlsplit

import yaml
from yaml.events import AliasEvent

from monitor.domain import Connection, ImportSummary

MAX_IMPORT_BYTES = 2 * 1024 * 1024
MAX_CANDIDATE_CHARS = 64 * 1024
URI_PATTERN = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*://")
SUPPORTED_URI_SCHEMES = {"vless", "hysteria2", "hy2", "mierus"}
SUPPORTED_YAML_TYPES = {"vless", "hysteria2", "mieru", "wireguard"}


class ImportFileError(ValueError):
    pass


class InvalidCandidateError(ValueError):
    pass


class UnsupportedCandidateError(ValueError):
    pass


class _UniqueKeyLoader(yaml.SafeLoader):
    pass


def _construct_unique_mapping(
    loader: _UniqueKeyLoader, node: yaml.MappingNode, deep: bool = False
) -> dict[Any, Any]:
    loader.flatten_mapping(node)
    result: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in result:
            raise InvalidCandidateError("YAML contains a duplicate key.")
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


_UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_unique_mapping
)


class ConnectionImporter:
    def parse_file(self, path: Path, existing: tuple[Connection, ...] = ()) -> ImportSummary:
        raw = path.read_bytes()
        if len(raw) > MAX_IMPORT_BYTES:
            raise ImportFileError("Import file exceeds 2 MiB.")
        try:
            text = raw.decode("utf-8-sig", errors="strict")
        except UnicodeDecodeError as error:
            raise ImportFileError("Import file must be UTF-8 with an optional BOM.") from error
        return self.parse_text(text, existing)

    def parse_text(self, text: str, existing: tuple[Connection, ...] = ()) -> ImportSummary:
        candidates = _split_candidates(text)
        fingerprints = {item.fingerprint for item in existing}
        accepted: list[Connection] = []
        duplicate = invalid = unsupported = 0
        for kind, candidate in candidates:
            try:
                connection = _parse_uri(candidate) if kind == "uri" else _parse_yaml(candidate)
            except UnsupportedCandidateError:
                unsupported += 1
                continue
            except (InvalidCandidateError, ValueError, TypeError, yaml.YAMLError):
                invalid += 1
                continue
            if connection.fingerprint in fingerprints:
                duplicate += 1
                continue
            fingerprints.add(connection.fingerprint)
            accepted.append(connection)
        return ImportSummary(
            imported=len(accepted),
            duplicate=duplicate,
            invalid=invalid,
            unsupported=unsupported,
            connections=tuple(accepted),
        )


def connection_user_name(connection: Connection) -> str:
    """Return a safe user-facing name without exposing UUIDs or password tokens."""
    if connection.source_kind == "uri":
        parsed = urlsplit(connection.original)
        fragment = unquote(parsed.fragment).strip()
        if fragment:
            return fragment
        if parsed.scheme.lower() == "mierus":
            profile = _query_one(parse_qs(parsed.query, keep_blank_values=True), "profile").strip()
            return profile or unquote(parsed.username or "").strip()
        if parsed.scheme.lower() in {"hysteria2", "hy2"} and parsed.password is not None:
            return unquote(parsed.username or "").strip()
        return ""

    if connection.source_kind == "yaml":
        try:
            source = json.loads(connection.original)
        except (TypeError, json.JSONDecodeError):
            return ""
        if not isinstance(source, dict):
            return ""
        name = source.get("name")
        if isinstance(name, str) and name.strip():
            return name.strip()
        if str(source.get("type", "")).lower() == "mieru":
            username = source.get("username")
            if isinstance(username, str):
                return username.strip()
    return ""


def validate_persisted_connection(connection: Connection) -> None:
    rebuilt = _build_connection(
        dict(connection.proxy), connection.source_kind, connection.original
    )
    immutable_fields = (
        "connection_id",
        "protocol",
        "expected_ipv4",
        "fingerprint",
    )
    if any(getattr(rebuilt, field) != getattr(connection, field) for field in immutable_fields):
        raise InvalidCandidateError(
            "Persisted connection metadata does not match its proxy mapping."
        )


def _split_candidates(text: str) -> list[tuple[str, str]]:
    normalized = text.replace("\r\n", "\n").replace("\r", "\n")
    candidates: list[tuple[str, str]] = []
    yaml_lines: list[str] = []

    def flush_yaml() -> None:
        if yaml_lines:
            value = "\n".join(yaml_lines).strip()
            yaml_lines.clear()
            if value:
                candidates.append(("yaml", value))

    for line in normalized.split("\n"):
        stripped = line.strip()
        if not stripped:
            flush_yaml()
            continue
        if not yaml_lines and stripped.startswith("#"):
            continue
        if not yaml_lines and URI_PATTERN.match(stripped):
            if len(stripped) > MAX_CANDIDATE_CHARS:
                candidates.append(("yaml", "invalid: oversized"))
            else:
                candidates.append(("uri", stripped))
            continue
        yaml_lines.append(line)
        if sum(len(item) + 1 for item in yaml_lines) > MAX_CANDIDATE_CHARS:
            flush_yaml()
    flush_yaml()
    return candidates


def _parse_yaml(text: str) -> Connection:
    if any(isinstance(event, AliasEvent) for event in yaml.parse(text, Loader=_UniqueKeyLoader)):
        raise InvalidCandidateError("YAML aliases are not accepted.")
    value = yaml.load(text, Loader=_UniqueKeyLoader)
    if isinstance(value, list):
        if len(value) != 1 or not isinstance(value[0], dict):
            raise InvalidCandidateError(
                "YAML list candidate must contain exactly one proxy mapping."
            )
        value = value[0]
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise InvalidCandidateError("YAML candidate must be one mapping with string keys.")
    proxy = dict(value)
    return _build_connection(proxy, "yaml", _canonical(proxy))


def _parse_uri(value: str) -> Connection:
    parsed = urlsplit(value)
    scheme = parsed.scheme.lower()
    if scheme not in SUPPORTED_URI_SCHEMES:
        raise UnsupportedCandidateError("URI scheme is not supported by Monitor.")
    if scheme == "vless":
        proxy = _vless_uri(parsed)
    elif scheme in {"hysteria2", "hy2"}:
        proxy = _hysteria2_uri(parsed)
    else:
        proxy = _mieru_uri(parsed)
    return _build_connection(proxy, "uri", value.strip())


def _vless_uri(parsed: Any) -> dict[str, Any]:
    query = parse_qs(parsed.query, keep_blank_values=True)
    if _query_one(query, "security", "").lower() != "reality":
        raise UnsupportedCandidateError("Only VLESS/Reality is supported.")
    network = _query_one(query, "type", "tcp").lower()
    if network != "tcp":
        raise UnsupportedCandidateError(
            "VLESS URI transports other than TCP require a standalone Mihomo YAML mapping."
        )
    public_key = _query_one(query, "pbk") or _query_one(query, "public-key")
    short_id = _query_one(query, "sid") or _query_one(query, "short-id")
    proxy: dict[str, Any] = {
        "name": unquote(parsed.fragment) or "VLESS",
        "type": "vless",
        "server": parsed.hostname,
        "port": parsed.port,
        "uuid": unquote(parsed.username or ""),
        "tls": True,
        "servername": _query_one(query, "sni") or _query_one(query, "servername"),
        "client-fingerprint": _query_one(query, "fp", "chrome"),
        "network": network,
        "reality-opts": {"public-key": public_key, "short-id": short_id},
    }
    flow = _query_one(query, "flow")
    if flow:
        proxy["flow"] = flow
    return proxy


def _hysteria2_uri(parsed: Any) -> dict[str, Any]:
    query = parse_qs(parsed.query, keep_blank_values=True)
    username = unquote(parsed.username or "")
    password_part = unquote(parsed.password or "")
    password = f"{username}:{password_part}" if password_part else username
    proxy: dict[str, Any] = {
        "name": unquote(parsed.fragment) or "Hysteria2",
        "type": "hysteria2",
        "server": parsed.hostname,
        "port": parsed.port,
        "password": password,
        "sni": _query_one(query, "sni"),
        "skip-cert-verify": _query_one(query, "insecure", "0").lower() in {"1", "true"},
    }
    for source, target in (("obfs", "obfs"), ("obfs-password", "obfs-password")):
        item = _query_one(query, source)
        if item:
            proxy[target] = item
    return proxy


def _mieru_uri(parsed: Any) -> dict[str, Any]:
    query = parse_qs(parsed.query, keep_blank_values=True)
    return {
        "name": _query_one(query, "profile", "Mieru"),
        "type": "mieru",
        "server": parsed.hostname,
        "port": _query_int(query, "port"),
        "transport": _query_one(query, "protocol", "TCP").upper(),
        "username": unquote(parsed.username or ""),
        "password": unquote(parsed.password or ""),
        "multiplexing": _query_one(query, "multiplexing", "MULTIPLEXING_LOW"),
    }


def _build_connection(proxy: dict[str, Any], source_kind: str, original: str) -> Connection:
    proxy_type = str(proxy.get("type", "")).lower()
    if proxy_type not in SUPPORTED_YAML_TYPES:
        raise UnsupportedCandidateError("Proxy type is not supported by Monitor.")
    proxy["type"] = proxy_type
    if proxy_type == "wireguard" and "amnezia-wg-option" not in proxy:
        raise UnsupportedCandidateError("Only AmneziaWG WireGuard mappings are supported.")
    if proxy_type == "vless" and not isinstance(proxy.get("reality-opts"), dict):
        raise UnsupportedCandidateError("Only VLESS/Reality mappings are supported.")
    server = _strict_ipv4(proxy.get("server"))
    proxy["server"] = server
    _validate_proxy(proxy_type, proxy)
    if not isinstance(proxy.get("name"), str) or not proxy["name"].strip():
        proxy["name"] = proxy_type.upper()
    normalized = _canonical(proxy)
    fingerprint = hashlib.sha256(normalized.encode("utf-8")).hexdigest()
    protocol = "amneziawg" if proxy_type == "wireguard" else proxy_type
    return Connection(
        connection_id=str(uuid.uuid5(uuid.NAMESPACE_URL, fingerprint)),
        enabled=True,
        source_kind=source_kind,
        original=original,
        proxy=proxy,
        protocol=protocol,
        expected_ipv4=server,
        fingerprint=fingerprint,
    )


def _validate_proxy(proxy_type: str, proxy: dict[str, Any]) -> None:
    if proxy_type == "vless":
        _port(proxy.get("port"))
        try:
            uuid.UUID(str(proxy.get("uuid", "")))
        except ValueError as error:
            raise InvalidCandidateError("VLESS uuid is invalid.") from error
        reality = proxy["reality-opts"]
        _required_text(reality, "public-key")
        _required_text(reality, "short-id")
        if proxy.get("tls") is not True:
            raise InvalidCandidateError("VLESS/Reality requires tls: true.")
    elif proxy_type == "hysteria2":
        _port(proxy.get("port"))
        _required_text(proxy, "password")
    elif proxy_type == "mieru":
        _port(proxy.get("port"))
        _required_text(proxy, "username")
        _required_text(proxy, "password")
        if str(proxy.get("transport", "")).upper() not in {"TCP", "UDP"}:
            raise InvalidCandidateError("Mieru transport must be TCP or UDP.")
        proxy["transport"] = str(proxy["transport"]).upper()
    else:
        _port(proxy.get("port"))
        for field in ("ip", "private-key", "public-key"):
            _required_text(proxy, field)
        options = proxy.get("amnezia-wg-option")
        if not isinstance(options, dict) or not options:
            raise InvalidCandidateError("AmneziaWG options must be a non-empty mapping.")


def _strict_ipv4(value: Any) -> str:
    if not isinstance(value, str):
        raise InvalidCandidateError("Proxy server must be an IPv4 string.")
    try:
        address = ipaddress.ip_address(value)
    except ValueError as error:
        raise InvalidCandidateError("Proxy server must be IPv4.") from error
    if not isinstance(address, ipaddress.IPv4Address):
        raise InvalidCandidateError("Proxy server must be IPv4.")
    return str(address)


def _port(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 65535:
        raise InvalidCandidateError("Proxy port is invalid.")
    return value


def _required_text(mapping: dict[str, Any], field: str) -> str:
    value = mapping.get(field)
    if not isinstance(value, str) or not value:
        raise InvalidCandidateError(f"Required field {field} is missing.")
    return value


def _query_one(query: dict[str, list[str]], key: str, default: str = "") -> str:
    values = query.get(key)
    if not values or len(values) != 1:
        return default
    return values[0]


def _query_int(query: dict[str, list[str]], key: str) -> int:
    try:
        return int(_query_one(query, key))
    except ValueError as error:
        raise InvalidCandidateError(f"URI field {key} is invalid.") from error


def _canonical(value: dict[str, Any]) -> str:
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    except (TypeError, ValueError) as error:
        raise InvalidCandidateError("Proxy mapping contains unsupported values.") from error
