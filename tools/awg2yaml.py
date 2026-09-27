"""Convert an AmneziaWG 3.1 client config into a mihomo proxy mapping.

Accepts either an ``awg-quick`` ``.conf`` file or an Amnezia ``vpn://`` export
(both carry the same information) and writes a single ``proxies`` entry, in the
shape mihomo v1.19.x expects for AmneziaWG, next to the source file under the
same name with a ``.yaml`` suffix.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import ipaddress
import json
import re
import sys
import zlib
from pathlib import Path
from typing import Any

import yaml

VPN_SCHEME = "vpn://"
BASE64_URLSAFE = str.maketrans("-_", "+/")
CONF_MARKER = "[Interface]"
TRUE_WORDS = {"on", "true", "1", "yes"}
FALSE_WORDS = {"off", "false", "0", "no"}

# .conf key -> amnezia-wg-option key, grouped by the value shape.
AWG_INT_KEYS = {
    "jc": "jc",
    "jmin": "jmin",
    "jmax": "jmax",
    "s1": "s1",
    "s2": "s2",
    "s3": "s3",
    "s4": "s4",
}
AWG_HEADER_KEYS = {"h1": "h1", "h2": "h2", "h3": "h3", "h4": "h4"}
AWG_TEXT_KEYS = {
    "i1": "i1",
    "i2": "i2",
    "i3": "i3",
    "i4": "i4",
    "i5": "i5",
    "headerprotectionkey": "header-protection-key",
    "contentpaddingaddition": "content-padding-addition",
    "rekeyaftertime": "rekey-after-time",
    "rekeytimeout": "rekey-timeout",
    "rejectaftertime": "reject-after-time",
    "keepalivetimeout": "keepalive-timeout",
    "maxhandshakeattempts": "max-handshake-attempts",
}
AWG_BOOL_KEYS = {"randomtrailers": "random-trailers", "disablecookies": "disable-cookies"}


class ConversionError(RuntimeError):
    """A converter failure with a message meant for the operator."""


def _load_source(path: Path) -> str:
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise ConversionError(f"Cannot read {path}: {error.strerror or error}.") from error
    try:
        return raw.decode("utf-8-sig")
    except UnicodeDecodeError as error:
        raise ConversionError(f"{path} is not UTF-8 text.") from error


def _config_text(source: str) -> str:
    """Return the awg-quick config text, unwrapping a vpn:// export if needed."""
    stripped = source.strip()
    if CONF_MARKER in stripped:
        return stripped
    if not stripped.lower().startswith(VPN_SCHEME):
        raise ConversionError(
            "Input is neither an awg-quick config (no [Interface] section) nor a vpn:// export."
        )
    return _decode_vpn_export(stripped[len(VPN_SCHEME) :])


def _decode_vpn_export(payload: str) -> str:
    packed = "".join(payload.split()).rstrip("=")
    if not re.fullmatch(r"[A-Za-z0-9+/_-]+", packed):
        raise ConversionError("vpn:// payload is not valid base64.")
    padding = "=" * (-len(packed) % 4)
    try:
        blob = base64.b64decode(packed.translate(BASE64_URLSAFE) + padding, validate=True)
    except (binascii.Error, ValueError) as error:
        raise ConversionError("vpn:// payload is not valid base64.") from error
    document = _inflate(blob)
    try:
        parsed = json.loads(document)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ConversionError("vpn:// payload does not contain JSON.") from error
    found = _find_config(parsed)
    if found is None:
        raise ConversionError("vpn:// export contains no AmneziaWG config section.")
    return found.strip()


def _inflate(blob: bytes) -> bytes:
    """Decompress the zlib body, tolerating the 4-byte big-endian length prefix."""
    for candidate in (blob[4:], blob):
        try:
            return zlib.decompress(candidate)
        except zlib.error:
            continue
    raise ConversionError("vpn:// payload is not zlib-compressed.")


def _find_config(node: Any) -> str | None:
    """Walk the export looking for the embedded awg-quick text."""
    if isinstance(node, str):
        # Nested JSON comes first: an escaped document also contains the marker.
        text = node.strip()
        if text.startswith(("{", "[")):
            try:
                nested = json.loads(text)
            except json.JSONDecodeError:
                nested = None
            if nested is not None:
                found = _find_config(nested)
                if found is not None:
                    return found
        return node if CONF_MARKER in node else None
    if isinstance(node, dict):
        children: Any = node.values()
    elif isinstance(node, list):
        children = node
    else:
        return None
    for child in children:
        found = _find_config(child)
        if found is not None:
            return found
    return None


def _parse_sections(text: str) -> tuple[dict[str, str], dict[str, str]]:
    interface: dict[str, str] = {}
    peers: list[dict[str, str]] = []
    current: dict[str, str] | None = None
    for number, line in enumerate(text.splitlines(), start=1):
        entry = line.split("#", 1)[0].strip()
        if not entry:
            continue
        if entry.startswith("["):
            name = entry.strip("[]").strip().lower()
            if name == "interface":
                current = interface
            elif name == "peer":
                current = {}
                peers.append(current)
            else:
                raise ConversionError(f"Line {number}: unknown section {entry}.")
            continue
        if current is None:
            raise ConversionError(f"Line {number}: setting outside of a section.")
        key, separator, value = entry.partition("=")
        if not separator:
            raise ConversionError(f"Line {number}: expected 'Key = value'.")
        current[key.strip().lower()] = value.strip()
    if not interface:
        raise ConversionError("Config has no [Interface] section.")
    if not peers:
        raise ConversionError("Config has no [Peer] section.")
    if len(peers) > 1:
        raise ConversionError(
            f"Config has {len(peers)} [Peer] sections; a proxy mapping holds exactly one."
        )
    return interface, peers[0]


def _required(section: dict[str, str], key: str, label: str) -> str:
    value = section.get(key, "")
    if not value:
        raise ConversionError(f"Required setting {label} is missing or empty.")
    return value


def _split_list(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


def _integer(value: str, label: str) -> int:
    try:
        return int(value)
    except ValueError as error:
        raise ConversionError(f"{label} must be an integer, got {value!r}.") from error


def _boolean(value: str, label: str) -> bool:
    lowered = value.lower()
    if lowered in TRUE_WORDS:
        return True
    if lowered in FALSE_WORDS:
        return False
    raise ConversionError(f"{label} must be on/off, got {value!r}.")


def _addresses(value: str) -> tuple[str, str | None]:
    ipv4: str | None = None
    ipv6: str | None = None
    for item in _split_list(value):
        host = item.split("/", 1)[0]
        try:
            address = ipaddress.ip_address(host)
        except ValueError as error:
            raise ConversionError(f"Address {item!r} is not a valid IP address.") from error
        if isinstance(address, ipaddress.IPv4Address) and ipv4 is None:
            ipv4 = str(address)
        elif isinstance(address, ipaddress.IPv6Address) and ipv6 is None:
            ipv6 = str(address)
    if ipv4 is None:
        raise ConversionError("[Interface] Address holds no IPv4 address.")
    return ipv4, ipv6


def _endpoint(value: str) -> tuple[str, int]:
    host, separator, port = value.rpartition(":")
    if not separator:
        raise ConversionError(f"[Peer] Endpoint {value!r} has no port.")
    try:
        address = ipaddress.ip_address(host.strip("[]"))
    except ValueError as error:
        raise ConversionError(
            f"[Peer] Endpoint host {host!r} is not an IPv4 address; "
            "the converter does not resolve names."
        ) from error
    if not isinstance(address, ipaddress.IPv4Address):
        raise ConversionError(f"[Peer] Endpoint host {host!r} is not an IPv4 address.")
    number = _integer(port, "[Peer] Endpoint port")
    if not 1 <= number <= 65535:
        raise ConversionError(f"[Peer] Endpoint port {number} is out of range.")
    return str(address), number


def _keepalive(value: str) -> int:
    """AmneziaWG v3 allows a randomized range; mihomo takes one number, so keep the lower bound."""
    lower = value.split("-", 1)[0].strip()
    number = _integer(lower, "[Peer] PersistentKeepalive")
    if not 0 <= number <= 65535:
        raise ConversionError(f"[Peer] PersistentKeepalive {number} is out of range.")
    return number


def _header(value: str) -> int | str:
    """Keep header values verbatim; v2+ allows ranges, so only plain numbers become ints."""
    if re.fullmatch(r"\d+", value):
        return int(value)
    return value


def _amnezia_options(interface: dict[str, str]) -> dict[str, Any]:
    options: dict[str, Any] = {"version": 3}
    for source, target in AWG_INT_KEYS.items():
        if interface.get(source):
            options[target] = _integer(interface[source], source.upper())
    for source, target in AWG_HEADER_KEYS.items():
        if interface.get(source):
            options[target] = _header(interface[source])
    for source, target in AWG_TEXT_KEYS.items():
        if interface.get(source):
            options[target] = interface[source]
    for source, target in AWG_BOOL_KEYS.items():
        if interface.get(source) and _boolean(interface[source], source):
            options[target] = True
    return options


def build_proxy(text: str, name: str) -> dict[str, Any]:
    interface, peer = _parse_sections(text)
    server, port = _endpoint(_required(peer, "endpoint", "[Peer] Endpoint"))
    ipv4, ipv6 = _addresses(_required(interface, "address", "[Interface] Address"))
    proxy: dict[str, Any] = {
        "name": name,
        "type": "wireguard",
        "server": server,
        "port": port,
        "ip": ipv4,
    }
    if ipv6:
        proxy["ipv6"] = ipv6
    proxy["private-key"] = _required(interface, "privatekey", "[Interface] PrivateKey")
    proxy["public-key"] = _required(peer, "publickey", "[Peer] PublicKey")
    if peer.get("presharedkey"):
        proxy["pre-shared-key"] = peer["presharedkey"]
    if interface.get("mtu"):
        proxy["mtu"] = _integer(interface["mtu"], "[Interface] MTU")
    if interface.get("dns"):
        proxy["dns"] = _split_list(interface["dns"])
    if peer.get("allowedips"):
        proxy["allowed-ips"] = _split_list(peer["allowedips"])
    if peer.get("persistentkeepalive"):
        proxy["persistent-keepalive"] = _keepalive(peer["persistentkeepalive"])
    proxy["amnezia-wg-option"] = _amnezia_options(interface)
    return proxy


def _render(proxy: dict[str, Any]) -> str:
    return yaml.safe_dump(proxy, allow_unicode=True, sort_keys=False, default_flow_style=False)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Convert an AmneziaWG 3.1 .conf or vpn:// export into a mihomo proxy mapping "
            "written next to the source as <name>.yaml."
        )
    )
    parser.add_argument("source", type=Path, help="Path to the .conf or vpn:// file.")
    arguments = parser.parse_args(argv)
    destination = arguments.source.with_suffix(".yaml")
    try:
        text = _config_text(_load_source(arguments.source))
        proxy = build_proxy(text, arguments.source.stem)
    except ConversionError as error:
        sys.stderr.write(f"{error}\n")
        return 2
    try:
        destination.write_text(_render(proxy), encoding="utf-8")
    except OSError as error:
        sys.stderr.write(f"Cannot write {destination}: {error.strerror or error}\n")
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
