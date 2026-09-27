#!/usr/bin/env python3
"""Strict recovery/config contract for the supported Mieru server profile."""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import secrets
import sys
from pathlib import Path
from urllib.parse import quote, urlencode

MIERU_SCHEMA_VERSION = 1
MIERU_COMPONENT = "mieru"
MIERU_SOFTWARE_VERSION = "3.35.0"
MIERU_USER_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._@+-]{0,127}$")
MIERU_PASSWORD = re.compile(r"^[0-9a-f]{64}$")
MIERU_PROTOCOLS = frozenset({"TCP", "UDP"})


class MieruConfigError(ValueError):
    """The recovery document is outside the supported Mieru profile."""


def validate_recovery_data(data: object) -> dict[str, object]:
    if not isinstance(data, dict):
        raise MieruConfigError("Mieru recovery document must be an object.")
    _mieru_exact_keys(
        data,
        {"schema_version", "component", "software_version", "server", "users"},
        "recovery document",
    )
    if (
        type(data.get("schema_version")) is not int
        or data["schema_version"] != MIERU_SCHEMA_VERSION
    ):
        raise MieruConfigError("Mieru recovery document has an unsupported schema_version.")
    if data.get("component") != MIERU_COMPONENT:
        raise MieruConfigError("Mieru recovery document has an unexpected component id.")
    if data.get("software_version") != MIERU_SOFTWARE_VERSION:
        raise MieruConfigError("Mieru recovery document has an unexpected software version.")

    server = data.get("server")
    if not isinstance(server, dict):
        raise MieruConfigError("Mieru recovery document is missing server settings.")
    _mieru_exact_keys(
        server, {"port", "protocol", "mtu", "user_hint_is_mandatory"}, "server settings"
    )
    port = server.get("port")
    if type(port) is not int or not 1025 <= port <= 65535:
        raise MieruConfigError("Mieru port must be an integer between 1025 and 65535.")
    if server.get("protocol") not in MIERU_PROTOCOLS:
        raise MieruConfigError("Mieru protocol must be TCP or UDP.")
    mtu = server.get("mtu")
    if type(mtu) is not int or not 1280 <= mtu <= 9000:
        raise MieruConfigError("Mieru MTU must be an integer between 1280 and 9000.")
    if server.get("user_hint_is_mandatory") is not True:
        raise MieruConfigError("Mieru user hint must be mandatory for this profile.")

    users = data.get("users")
    if not isinstance(users, list) or not users:
        raise MieruConfigError("Mieru recovery document must contain at least one user.")
    names: set[str] = set()
    for user in users:
        if not isinstance(user, dict):
            raise MieruConfigError("Mieru user must be an object.")
        _mieru_exact_keys(user, {"name", "password"}, "user")
        name = user.get("name")
        password = user.get("password")
        if not isinstance(name, str) or not MIERU_USER_NAME.fullmatch(name):
            raise MieruConfigError("Mieru user name contains unsupported characters.")
        if name in names:
            raise MieruConfigError("Mieru recovery document contains duplicate users.")
        names.add(name)
        if not isinstance(password, str) or not MIERU_PASSWORD.fullmatch(password):
            raise MieruConfigError("Mieru password has an unsupported format.")
    return data


def load_recovery(path: Path) -> dict[str, object]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except OSError as error:
        raise MieruConfigError(f"Could not read Mieru recovery document: {error}") from error
    except json.JSONDecodeError as error:
        raise MieruConfigError(
            f"Mieru recovery document contains invalid JSON: {error}"
        ) from error
    return validate_recovery_data(data)


def new_recovery(port: int, protocol: str, mtu: int, user_name: str) -> dict[str, object]:
    data: dict[str, object] = {
        "schema_version": MIERU_SCHEMA_VERSION,
        "component": MIERU_COMPONENT,
        "software_version": MIERU_SOFTWARE_VERSION,
        "server": {
            "port": port,
            "protocol": protocol,
            "mtu": mtu,
            "user_hint_is_mandatory": True,
        },
        "users": [{"name": user_name, "password": secrets.token_hex(32)}],
    }
    return validate_recovery_data(data)


def assert_deployment_parameters(
    data: dict[str, object], *, port: int, protocol: str, mtu: int, user_name: str
) -> None:
    server = data["server"]
    users = data["users"]
    assert isinstance(server, dict) and isinstance(users, list) and isinstance(users[0], dict)
    actual_server = (server["port"], server["protocol"], server["mtu"])
    expected_server = (port, protocol, mtu)
    user_names = {user["name"] for user in users if isinstance(user, dict)}
    if actual_server != expected_server or user_name not in user_names:
        raise MieruConfigError("Mieru is already prepared with different deployment parameters.")


def server_config(data: dict[str, object]) -> dict[str, object]:
    server = data["server"]
    users = data["users"]
    assert isinstance(server, dict) and isinstance(users, list)
    return {
        "portBindings": [{"port": server["port"], "protocol": server["protocol"]}],
        "users": users,
        "advancedSettings": {"userHintIsMandatory": True},
        "loggingLevel": "INFO",
        "mtu": server["mtu"],
    }


def user_record(data: dict[str, object], user_name: str) -> dict[str, str]:
    validate_recovery_data(data)
    users = data["users"]
    assert isinstance(users, list)
    for user in users:
        if isinstance(user, dict) and user.get("name") == user_name:
            return {"name": str(user["name"]), "password": str(user["password"])}
    raise MieruConfigError("Mieru user does not exist.")


def client_config(
    data: dict[str, object],
    server_ip: str,
    user_name: str,
    *,
    rpc_port: int = 8964,
    socks5_port: int = 1080,
) -> dict[str, object]:
    user = user_record(data, user_name)
    try:
        ipaddress.ip_address(server_ip)
    except ValueError as error:
        raise MieruConfigError("Mieru client server address is invalid.") from error
    if (
        not 1025 <= rpc_port <= 65535
        or not 1025 <= socks5_port <= 65535
        or rpc_port == socks5_port
    ):
        raise MieruConfigError("Mieru client proxy ports are invalid.")
    server = data["server"]
    assert isinstance(server, dict)
    return {
        "profiles": [
            {
                "profileName": user_name,
                "user": user,
                "servers": [
                    {
                        "ipAddress": server_ip,
                        "domainName": "",
                        "portBindings": [{"port": server["port"], "protocol": server["protocol"]}],
                    }
                ],
                "mtu": server["mtu"],
                "multiplexing": {"level": "MULTIPLEXING_LOW"},
                "handshakeMode": "HANDSHAKE_STANDARD",
            }
        ],
        "activeProfile": user_name,
        "rpcPort": rpc_port,
        "socks5Port": socks5_port,
        "loggingLevel": "INFO",
        "socks5ListenLAN": False,
    }


def simple_share_link(data: dict[str, object], server_ip: str, user_name: str) -> str:
    user = user_record(data, user_name)
    try:
        address = str(ipaddress.ip_address(server_ip))
    except ValueError as error:
        raise MieruConfigError("Mieru client server address is invalid.") from error
    server = data["server"]
    assert isinstance(server, dict)
    authority = f"{quote(user['name'], safe='')}:{quote(user['password'], safe='')}@{address}"
    query = urlencode(
        (
            ("profile", user_name),
            ("mtu", str(server["mtu"])),
            ("multiplexing", "MULTIPLEXING_LOW"),
            ("handshake-mode", "HANDSHAKE_STANDARD"),
            ("port", str(server["port"])),
            ("protocol", str(server["protocol"])),
        )
    )
    return f"mierus://{authority}?{query}"


def write_private_json(path: Path, data: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    encoded = (json.dumps(data, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        try:
            path.unlink()
        except OSError:
            pass
        raise


def commit_candidate(candidate: Path, destination: Path) -> None:
    data = load_recovery(candidate)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.parent / f".{destination.name}.{secrets.token_hex(8)}.tmp"
    try:
        write_private_json(temporary, data)
        os.replace(temporary, destination)
        os.chmod(destination, 0o600)
        directory_fd = os.open(destination.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _mieru_exact_keys(data: dict[str, object], expected: set[str], label: str) -> None:
    if set(data) != expected:
        raise MieruConfigError(f"Mieru {label} has missing or unsupported fields.")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    prepare = subparsers.add_parser("prepare")
    prepare.add_argument("--recovery", type=Path, required=True)
    prepare.add_argument("--recovery-candidate", type=Path, required=True)
    prepare.add_argument("--config-candidate", type=Path, required=True)
    prepare.add_argument("--port", type=int, required=True)
    prepare.add_argument("--protocol", choices=sorted(MIERU_PROTOCOLS), required=True)
    prepare.add_argument("--mtu", type=int, required=True)
    prepare.add_argument("--user", required=True)
    validate = subparsers.add_parser("validate")
    validate.add_argument("path", type=Path)
    show_server = subparsers.add_parser("show-server")
    show_server.add_argument("path", type=Path)
    commit = subparsers.add_parser("commit")
    commit.add_argument("--candidate", type=Path, required=True)
    commit.add_argument("--destination", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        if arguments.command == "validate":
            load_recovery(arguments.path)
        elif arguments.command == "show-server":
            recovery = load_recovery(arguments.path)
            server = recovery["server"]
            assert isinstance(server, dict)
            print(
                json.dumps(
                    {"port": server["port"], "protocol": server["protocol"], "mtu": server["mtu"]},
                    separators=(",", ":"),
                )
            )
        elif arguments.command == "prepare":
            if arguments.recovery.exists():
                recovery = load_recovery(arguments.recovery)
            else:
                recovery = new_recovery(
                    arguments.port, arguments.protocol, arguments.mtu, arguments.user
                )
            write_private_json(arguments.recovery_candidate, recovery)
            write_private_json(arguments.config_candidate, server_config(recovery))
        elif arguments.command == "commit":
            commit_candidate(arguments.candidate, arguments.destination)
    except (MieruConfigError, OSError) as error:
        print(str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
