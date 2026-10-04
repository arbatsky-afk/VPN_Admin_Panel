#!/usr/bin/env python3
"""Allocate and strictly verify one modular component listening port."""

from __future__ import annotations

import argparse
import json
import re
import secrets
import shutil
import subprocess
import sys
from collections.abc import Callable, Iterable
from pathlib import Path

PORT_PROTOCOLS = frozenset({"tcp", "udp"})
PORT_MINIMUM = 1
PORT_MAXIMUM = 65535
DEFAULT_MAX_ATTEMPTS = 128
RESERVED_SERVICE_PORTS = frozenset({80, 443, 19999})
_DPORT = re.compile(r"\b(tcp|udp)\s+dport\s+(\d{1,5})\b", re.IGNORECASE)
_DOCKER_PUBLISHED = re.compile(r'(?:^|[\s,"])(?:\[[0-9a-fA-F:]+\]|[0-9a-fA-F:.]+):(\d{1,5})->')


class PortContractError(ValueError):
    """Port allocation or strict verification could not be completed safely."""


def _port(value: object, label: str) -> int:
    if type(value) is not int or not PORT_MINIMUM <= value <= PORT_MAXIMUM:
        raise PortContractError(f"{label} must be an integer between 1 and 65535.")
    return value


def _protocol(value: object) -> str:
    if not isinstance(value, str) or value.lower() not in PORT_PROTOCOLS:
        raise PortContractError("Protocol must be TCP or UDP.")
    return value.lower()


def _normalized_port_pairs(values: Iterable[tuple[str, int]], label: str) -> set[tuple[str, int]]:
    normalized: set[tuple[str, int]] = set()
    for protocol, port in values:
        normalized.add((_protocol(protocol), _port(port, label)))
    return normalized


def choose_port(
    protocol: str,
    range_start: int,
    range_end: int,
    ssh_port: int,
    listeners: Iterable[tuple[str, int]],
    nft_ports: Iterable[tuple[str, int]],
    docker_ports: Iterable[int],
    ephemeral_range: tuple[int, int],
    *,
    randbelow: Callable[[int], int] = secrets.randbelow,
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
) -> int:
    """Select one cryptographically random candidate outside every conflict set."""
    protocol = _protocol(protocol)
    range_start = _port(range_start, "Port range start")
    range_end = _port(range_end, "Port range end")
    ssh_port = _port(ssh_port, "SSH port")
    if range_start > range_end:
        raise PortContractError("Port range start must not exceed its end.")
    if type(max_attempts) is not int or max_attempts < 1 or max_attempts > 4096:
        raise PortContractError("Port allocation attempt count is invalid.")
    if not isinstance(ephemeral_range, tuple) or len(ephemeral_range) != 2:
        raise PortContractError("Kernel ephemeral port range is invalid.")
    ephemeral_start = _port(ephemeral_range[0], "Ephemeral range start")
    ephemeral_end = _port(ephemeral_range[1], "Ephemeral range end")
    if ephemeral_start > ephemeral_end:
        raise PortContractError("Kernel ephemeral port range is invalid.")

    listener_ports = _normalized_port_pairs(listeners, "Listener port")
    nft_port_pairs = _normalized_port_pairs(nft_ports, "nftables port")
    published_ports = {_port(port, "Docker published port") for port in docker_ports}
    nft_port_numbers = {port for _transport, port in nft_port_pairs}
    width = range_end - range_start + 1

    for _attempt in range(max_attempts):
        offset = randbelow(width)
        if type(offset) is not int or not 0 <= offset < width:
            raise PortContractError("Random port source returned an invalid offset.")
        candidate = range_start + offset
        if candidate in RESERVED_SERVICE_PORTS:
            continue
        if candidate == ssh_port:
            continue
        if ephemeral_start <= candidate <= ephemeral_end:
            continue
        if (protocol, candidate) in listener_ports:
            continue
        if candidate in nft_port_numbers or candidate in published_ports:
            continue
        return candidate
    raise PortContractError("Could not find an available port within the assigned range.")


def verify_fixed_service_port_available(
    port: int,
    ssh_port: int,
    listeners: Iterable[tuple[str, int]],
    nft_ports: Iterable[tuple[str, int]],
    docker_ports: Iterable[int],
    *,
    allowed_listeners: Iterable[tuple[str, int]] = (),
) -> None:
    """Reject a fixed service port used by any other managed or live endpoint."""
    port = _port(port, "Fixed service port")
    ssh_port = _port(ssh_port, "SSH port")
    listener_pairs = _normalized_port_pairs(listeners, "Listener port")
    allowed_pairs = _normalized_port_pairs(allowed_listeners, "Allowed listener port")
    nft_pairs = _normalized_port_pairs(nft_ports, "nftables port")
    published_ports = {_port(value, "Docker published port") for value in docker_ports}
    if port == ssh_port:
        raise PortContractError("The fixed service port conflicts with SSH.")
    if any(pair[1] == port and pair not in allowed_pairs for pair in listener_pairs):
        raise PortContractError("The fixed service port already has a listener.")
    if any(value == port for _protocol_name, value in nft_pairs):
        raise PortContractError("The fixed service port is already present in nftables.")
    if port in published_ports:
        raise PortContractError("The fixed service port is published by Docker.")


def parse_fragment_ports(text: str) -> set[tuple[str, int]]:
    if not isinstance(text, str):
        raise PortContractError("nftables fragment text is invalid.")
    return {
        (match.group(1).lower(), _port(int(match.group(2)), "nftables fragment port"))
        for match in _DPORT.finditer(text)
    }


def parse_ss_listeners(text: str, protocol: str) -> set[tuple[str, int]]:
    protocol = _protocol(protocol)
    if not isinstance(text, str):
        raise PortContractError("Listener output is invalid.")
    listeners: set[tuple[str, int]] = set()
    for line in text.splitlines():
        columns = line.split()
        if len(columns) < 5:
            continue
        local_address = columns[3]
        match = re.search(r"(?::|\])(\d{1,5})$", local_address)
        if match is None:
            continue
        listeners.add((protocol, _port(int(match.group(1)), "Listener port")))
    return listeners


def _right_ports(value: object) -> set[int]:
    if type(value) is int:
        return {_port(value, "nftables port")}
    if isinstance(value, list):
        ports: set[int] = set()
        for item in value:
            ports.update(_right_ports(item))
        return ports
    if not isinstance(value, dict):
        return set()
    if isinstance(value.get("set"), list):
        return _right_ports(value["set"])
    interval = value.get("range")
    if (
        isinstance(interval, list)
        and len(interval) == 2
        and all(type(item) is int for item in interval)
    ):
        start, end = interval
        _port(start, "nftables range start")
        _port(end, "nftables range end")
        if start > end:
            raise PortContractError("nftables port range is invalid.")
        return set(range(start, end + 1))
    return set()


def parse_nft_ports(text: str) -> set[tuple[str, int]]:
    try:
        payload = json.loads(text)
    except (TypeError, json.JSONDecodeError) as error:
        raise PortContractError("Active nftables JSON is invalid.") from error
    records = payload.get("nftables") if isinstance(payload, dict) else None
    if not isinstance(records, list):
        raise PortContractError("Active nftables JSON has no ruleset.")
    ports: set[tuple[str, int]] = set()
    for record in records:
        rule = record.get("rule") if isinstance(record, dict) else None
        expressions = rule.get("expr") if isinstance(rule, dict) else None
        if not isinstance(expressions, list):
            continue
        if not any(
            isinstance(expression, dict) and "accept" in expression for expression in expressions
        ):
            continue
        for expression in expressions:
            match = expression.get("match") if isinstance(expression, dict) else None
            left = match.get("left") if isinstance(match, dict) else None
            payload_match = left.get("payload") if isinstance(left, dict) else None
            protocol = payload_match.get("protocol") if isinstance(payload_match, dict) else None
            field = payload_match.get("field") if isinstance(payload_match, dict) else None
            if protocol not in PORT_PROTOCOLS or field != "dport":
                continue
            for port in _right_ports(match.get("right")):
                ports.add((protocol, port))
    return ports


def parse_docker_ports(text: str) -> set[int]:
    if not isinstance(text, str):
        raise PortContractError("Docker port output is invalid.")
    return {
        _port(int(match.group(1)), "Docker published port")
        for match in _DOCKER_PUBLISHED.finditer(text)
    }


def verify_port_contract(
    protocol: str,
    expected_port: int,
    config_port: int,
    recovery_port: int,
    fragment_text: str,
    active_nft_ports: Iterable[tuple[str, int]],
    listeners: Iterable[tuple[str, int]],
) -> None:
    """Require one identical protocol/port across persistent and live state."""
    protocol = _protocol(protocol)
    expected_port = _port(expected_port, "Expected port")
    config_port = _port(config_port, "Config port")
    recovery_port = _port(recovery_port, "Recovery port")
    expected = (protocol, expected_port)
    if config_port != expected_port or recovery_port != expected_port:
        raise PortContractError("Config, recovery, and expected ports do not match.")
    if parse_fragment_ports(fragment_text) != {expected}:
        raise PortContractError(
            "The component nftables fragment does not contain exactly the expected port."
        )
    if expected not in _normalized_port_pairs(active_nft_ports, "Active nftables port"):
        raise PortContractError("The active nftables ruleset does not allow the expected port.")
    if expected not in _normalized_port_pairs(listeners, "Listener port"):
        raise PortContractError("The expected component listener is not active.")


def _run(arguments: list[str], label: str) -> str:
    try:
        result = subprocess.run(arguments, capture_output=True, text=True, check=False)
    except OSError as error:
        raise PortContractError(f"Could not inspect {label}.") from error
    if result.returncode != 0:
        raise PortContractError(f"Could not inspect {label}.")
    return result.stdout


def collect_listeners(protocol: str) -> set[tuple[str, int]]:
    protocol = _protocol(protocol)
    option = "-lnt" if protocol == "tcp" else "-lnu"
    return parse_ss_listeners(
        _run(["ss", "-H", option], f"{protocol.upper()} listeners"), protocol
    )


def collect_active_nft_ports() -> set[tuple[str, int]]:
    return parse_nft_ports(_run(["nft", "-j", "list", "ruleset"], "active nftables rules"))


def collect_fragment_ports(directory: Path) -> set[tuple[str, int]]:
    try:
        paths = sorted(directory.glob("*.nft"))
        return (
            set().union(
                *(parse_fragment_ports(path.read_text(encoding="utf-8")) for path in paths)
            )
            if paths
            else set()
        )
    except (OSError, UnicodeError) as error:
        raise PortContractError("Could not inspect nftables fragments.") from error


def collect_docker_ports() -> set[int]:
    if shutil.which("docker") is None:
        return set()
    return parse_docker_ports(
        _run(["docker", "ps", "-a", "--format", "{{json .Ports}}"], "Docker published ports")
    )


def read_ephemeral_range(
    path: Path = Path("/proc/sys/net/ipv4/ip_local_port_range"),
) -> tuple[int, int]:
    try:
        values = path.read_text(encoding="ascii").split()
    except (OSError, UnicodeError) as error:
        raise PortContractError("Could not read the kernel ephemeral port range.") from error
    if len(values) != 2 or not all(value.isdigit() for value in values):
        raise PortContractError("Kernel ephemeral port range is invalid.")
    start, end = (int(value) for value in values)
    _port(start, "Ephemeral range start")
    _port(end, "Ephemeral range end")
    if start > end:
        raise PortContractError("Kernel ephemeral port range is invalid.")
    return start, end


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    allocate = commands.add_parser("allocate")
    allocate.add_argument("--protocol", choices=sorted(PORT_PROTOCOLS), required=True)
    allocate.add_argument("--range-start", type=int, required=True)
    allocate.add_argument("--range-end", type=int, required=True)
    allocate.add_argument("--ssh-port", type=int, required=True)
    allocate.add_argument("--fragment-directory", type=Path, default=Path("/etc/nftables.d"))
    verify = commands.add_parser("verify")
    verify.add_argument("--protocol", choices=sorted(PORT_PROTOCOLS), required=True)
    verify.add_argument("--port", type=int, required=True)
    verify.add_argument("--config-port", type=int, required=True)
    verify.add_argument("--recovery-port", type=int, required=True)
    verify.add_argument("--fragment", type=Path, required=True)
    fixed = commands.add_parser("check-fixed")
    fixed.add_argument("--port", type=int, required=True)
    fixed.add_argument("--ssh-port", type=int, required=True)
    fixed.add_argument("--allow-listener", choices=sorted(PORT_PROTOCOLS))
    fixed.add_argument("--fragment-directory", type=Path, default=Path("/etc/nftables.d"))
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        if arguments.command == "allocate":
            active_nft = collect_active_nft_ports()
            fragments = collect_fragment_ports(arguments.fragment_directory)
            selected = choose_port(
                arguments.protocol,
                arguments.range_start,
                arguments.range_end,
                arguments.ssh_port,
                collect_listeners(arguments.protocol),
                active_nft | fragments,
                collect_docker_ports(),
                read_ephemeral_range(),
            )
            print(selected)
        elif arguments.command == "verify":
            try:
                fragment_text = arguments.fragment.read_text(encoding="utf-8")
            except (OSError, UnicodeError) as error:
                raise PortContractError(
                    "Could not read the component nftables fragment."
                ) from error
            verify_port_contract(
                arguments.protocol,
                arguments.port,
                arguments.config_port,
                arguments.recovery_port,
                fragment_text,
                collect_active_nft_ports(),
                collect_listeners(arguments.protocol),
            )
        else:
            listeners = collect_listeners("tcp") | collect_listeners("udp")
            allowed = (
                {(arguments.allow_listener, arguments.port)} if arguments.allow_listener else set()
            )
            verify_fixed_service_port_available(
                arguments.port,
                arguments.ssh_port,
                listeners,
                collect_active_nft_ports() | collect_fragment_ports(arguments.fragment_directory),
                collect_docker_ports(),
                allowed_listeners=allowed,
            )
    except PortContractError as error:
        print(str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
