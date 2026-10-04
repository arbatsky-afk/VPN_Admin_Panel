"""Build the mihomo proxy tree from the yaml files in the working directory.

Reads every yaml file in ``tools\\in`` except its own output, groups the proxies
by ``server`` and writes ``proxies`` plus ``proxy-groups`` into
``tools\\in\\proxy-tree.yaml``. Everything else — dns, tun, ports, rules — lives
in the base config and is merged there; this generator knows nothing about it.
"""

from __future__ import annotations

import ipaddress
import json
import sys
from pathlib import Path
from typing import Any

import yaml

INBOX = Path(__file__).resolve().parent / "in"
OUTPUT_NAME = "proxy-tree.yaml"
ROOT_NAME = "Bypass"
HEALTH_URL = "https://cp.cloudflare.com/generate_204"
HEALTH_INTERVAL = 60
HEALTH_TOLERANCE = 10
GROUP_TYPES = ("fallback", "url-test", "select")
DEFAULT_GROUP_TYPE = "url-test"


class GeneratorError(RuntimeError):
    """A failure with a message meant for the operator."""


def _load_document(path: Path) -> Any:
    try:
        raw = path.read_text(encoding="utf-8-sig")
    except OSError as error:
        raise GeneratorError(f"{path.name}: cannot read ({error.strerror or error}).") from error
    except UnicodeDecodeError as error:
        raise GeneratorError(f"{path.name}: not UTF-8 text.") from error
    try:
        return yaml.safe_load(raw)
    except yaml.YAMLError as error:
        raise GeneratorError(f"{path.name}: not valid YAML.") from error


def _proxies_of(document: Any, name: str) -> list[dict[str, Any]]:
    """Accept the three shapes a proxy file comes in; anything else is an error."""
    if isinstance(document, dict):
        if "proxies" in document:
            listed = document["proxies"]
            if not isinstance(listed, list):
                raise GeneratorError(f"{name}: 'proxies' is not a list.")
            candidates = listed
        else:
            candidates = [document]
    elif isinstance(document, list):
        candidates = document
    else:
        raise GeneratorError(
            f"{name}: root is neither a proxy mapping, a list of proxies, nor a 'proxies' key."
        )
    proxies: list[dict[str, Any]] = []
    for candidate in candidates:
        if not isinstance(candidate, dict):
            raise GeneratorError(f"{name}: proxy entry is not a mapping.")
        for field in ("server", "type"):
            value = candidate.get(field)
            if not isinstance(value, str) or not value:
                raise GeneratorError(f"{name}: proxy entry has no usable '{field}'.")
        server = candidate["server"]
        try:
            ipaddress.ip_address(server)
        except ValueError:
            raise GeneratorError(f"{name}: 'server' is not an IP address: {server!r}.") from None
        proxies.append(candidate)
    return proxies


def _collect(directory: Path) -> list[dict[str, Any]]:
    sources = sorted(
        path
        for path in directory.iterdir()
        if path.is_file() and path.suffix.lower() in {".yaml", ".yml"} and path.name != OUTPUT_NAME
    )
    proxies: list[dict[str, Any]] = []
    for path in sources:
        proxies.extend(_proxies_of(_load_document(path), path.name))
    return proxies


def _fingerprint(proxy: dict[str, Any]) -> str:
    body = {key: value for key, value in proxy.items() if key != "name"}
    return json.dumps(body, ensure_ascii=False, sort_keys=True, default=str)


def _deduplicate(proxies: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[str] = set()
    unique: list[dict[str, Any]] = []
    for proxy in proxies:
        fingerprint = _fingerprint(proxy)
        if fingerprint in seen:
            continue
        seen.add(fingerprint)
        unique.append(proxy)
    return unique


def _group(proxies: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    """Group by server, then give every node a name of its own."""
    servers: dict[str, list[dict[str, Any]]] = {}
    for proxy in proxies:
        servers.setdefault(str(proxy["server"]), []).append(proxy)
    if ROOT_NAME in servers:
        raise GeneratorError(
            f"Server {ROOT_NAME!r} collides with the root group name; the tree would be broken."
        )
    grouped: dict[str, list[dict[str, Any]]] = {}
    for server in sorted(servers):
        taken: set[str] = set()
        named: list[dict[str, Any]] = []
        for proxy in servers[server]:
            base = f"{server}-{proxy['type']}"
            name = base
            suffix = 2
            while name in taken:
                name = f"{base}-{suffix}"
                suffix += 1
            taken.add(name)
            body = {key: value for key, value in proxy.items() if key != "name"}
            named.append({"name": name, **body})
        grouped[server] = sorted(named, key=lambda item: item["name"])
    return grouped


def _previous_types(path: Path) -> dict[str, str]:
    """The previous output doubles as the settings file: it holds the chosen group types."""
    if not path.exists():
        return {}
    document = _load_document(path)
    if not isinstance(document, dict):
        return {}
    groups = document.get("proxy-groups")
    if not isinstance(groups, list):
        return {}
    chosen: dict[str, str] = {}
    for group in groups:
        if not isinstance(group, dict):
            continue
        name = group.get("name")
        group_type = group.get("type")
        if isinstance(name, str) and group_type in GROUP_TYPES:
            chosen[name] = group_type
    return chosen


def _node_block(proxy: dict[str, Any]) -> str:
    dumped = yaml.safe_dump([proxy], allow_unicode=True, sort_keys=False, default_flow_style=False)
    return "\n".join(f"  {line}" if line else line for line in dumped.rstrip("\n").splitlines())


def _group_block(server: str, group_type: str, names: list[str]) -> str:
    lines = [f'  - name: "{server}"']
    for candidate in GROUP_TYPES:
        prefix = "    " if candidate == group_type else "    # "
        lines.append(f"{prefix}type: {candidate}")
    lines.append(f"    url: {HEALTH_URL}")
    lines.append(f"    interval: {HEALTH_INTERVAL}")
    lines.append(f"    tolerance: {HEALTH_TOLERANCE}")
    lines.append("    proxies:")
    lines.extend(f'      - "{name}"' for name in names)
    return "\n".join(lines)


def render(grouped: dict[str, list[dict[str, Any]]], chosen: dict[str, str]) -> str:
    root = [
        f'  - name: "{ROOT_NAME}"',
        "    type: select",
        "    proxies:",
        *(f'      - "{server}"' for server in grouped),
    ]
    blocks = ["\n".join(root)]
    for server, nodes in grouped.items():
        group_type = chosen.get(server, DEFAULT_GROUP_TYPE)
        blocks.append(_group_block(server, group_type, [proxy["name"] for proxy in nodes]))
    nodes_blocks = [_node_block(proxy) for nodes in grouped.values() for proxy in nodes]
    return (
        "proxy-groups:\n\n"
        + "\n\n".join(blocks)
        + "\n\nproxies:\n\n"
        + "\n\n".join(nodes_blocks)
        + "\n"
    )


def main(argv: list[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv[1:]
    if argv:
        sys.stderr.write("This generator takes no arguments; it always works on tools\\in.\n")
        return 2
    destination = INBOX / OUTPUT_NAME
    try:
        if not INBOX.is_dir():
            raise GeneratorError(f"Working directory {INBOX} does not exist.")
        proxies = _collect(INBOX)
        if not proxies:
            sys.stderr.write(f"No proxy files in {INBOX}; nothing to build.\n")
            return 0
        chosen = _previous_types(destination)
        grouped = _group(_deduplicate(proxies))
        rendered = render(grouped, chosen)
    except GeneratorError as error:
        sys.stderr.write(f"{error}\n")
        return 2
    try:
        destination.write_text(rendered, encoding="utf-8")
    except OSError as error:
        sys.stderr.write(f"Cannot write {destination}: {error.strerror or error}\n")
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
