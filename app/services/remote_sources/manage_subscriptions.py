#!/usr/bin/env python3
"""Fixed server-side inspection and deletion of managed subscription files."""

from __future__ import annotations

import ipaddress
import json
import os
import re
import stat
import subprocess
from pathlib import Path

EXPECTED_CONTRACT_VERSION = "5"
REGISTRY = Path("/opt/vpn/state/components.json")
DECLARATION = Path("/opt/vpn/components/nginx/declaration.json")
CONTRACT = Path("/usr/local/lib/vpn-admin/nginx_contract.py")
SUBSCRIPTIONS_LOCATION = Path("/etc/nginx/vpn-admin-locations/subscriptions.conf")
SUBSCRIPTIONS_DIRECTORY = Path("/var/www/vpn-admin-site/subscriptions")
NAME = re.compile(r"^[A-Za-z0-9-]+$")
TOKEN = re.compile(r"^[A-Za-z0-9_-]{32,128}$")
DOMAIN = re.compile(
    r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    r"(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$"
)


class SubscriptionManagementError(ValueError):
    pass


def _regular_file(path):
    try:
        metadata = path.lstat()
    except OSError:
        return False
    return not path.is_symlink() and stat.S_ISREG(metadata.st_mode)


def _safe_directory(path):
    try:
        metadata = path.lstat()
    except OSError:
        return False
    return (
        not path.is_symlink()
        and stat.S_ISDIR(metadata.st_mode)
        and (
            os.name == "nt"
            or (metadata.st_uid == 0 and metadata.st_gid == 0 and metadata.st_mode & 0o022 == 0)
        )
    )


def _run(arguments, *, timeout=15):
    try:
        return subprocess.run(
            arguments,
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired):
        return subprocess.CompletedProcess(arguments, 127, "", "")


def _load_json(path, label):
    if not _regular_file(path):
        raise SubscriptionManagementError(label + " is missing or unsafe.")
    try:
        value = json.loads(path.read_text(encoding="utf-8", errors="strict"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise SubscriptionManagementError(label + " is invalid.") from error
    if not isinstance(value, dict):
        raise SubscriptionManagementError(label + " is invalid.")
    return value


def _validate_request(request, expected_action):
    if not isinstance(request, dict) or set(request) != {
        "schema_version",
        "action",
        "server_ip",
        "nginx_contract_version",
    }:
        raise SubscriptionManagementError("The subscription management request is invalid.")
    if request["schema_version"] != 1 or request["action"] != expected_action:
        raise SubscriptionManagementError("The subscription management request is unsupported.")
    try:
        address = str(ipaddress.IPv4Address(request["server_ip"]))
    except (TypeError, ipaddress.AddressValueError) as error:
        raise SubscriptionManagementError("The selected server IPv4 is invalid.") from error
    if address != request["server_ip"]:
        raise SubscriptionManagementError("The selected server IPv4 is not canonical.")
    if request["nginx_contract_version"] != EXPECTED_CONTRACT_VERSION:
        raise SubscriptionManagementError("Managed Nginx contract v5 is required.")
    return address


def _validate_delete_request(request):
    expected = {
        "schema_version",
        "action",
        "server_ip",
        "nginx_contract_version",
        "kind",
        "name",
        "tokens",
    }
    if not isinstance(request, dict) or set(request) != expected:
        raise SubscriptionManagementError("The subscription deletion request is invalid.")
    base_request = {
        "schema_version": request["schema_version"],
        "action": request["action"],
        "server_ip": request["server_ip"],
        "nginx_contract_version": request["nginx_contract_version"],
    }
    address = _validate_request(base_request, "delete")
    kind = request["kind"]
    name = request["name"]
    tokens = request["tokens"]
    if kind not in {"orphan", "active"}:
        raise SubscriptionManagementError("The subscription deletion kind is invalid.")
    if not isinstance(name, str) or NAME.fullmatch(name) is None:
        raise SubscriptionManagementError("The subscription deletion name is invalid.")
    if (
        not isinstance(tokens, list)
        or any(not isinstance(token, str) or TOKEN.fullmatch(token) is None for token in tokens)
        or len(tokens) != len(set(tokens))
        or tokens != sorted(tokens)
    ):
        raise SubscriptionManagementError("The subscription deletion tokens are invalid.")
    if kind == "orphan" and not tokens:
        raise SubscriptionManagementError("Delete orphan requires exact server tokens.")
    if kind == "active" and tokens:
        raise SubscriptionManagementError(
            "Delete active does not accept individual server tokens."
        )
    return address


def _validate_component_contract():
    registry = _load_json(REGISTRY, "The component registry")
    components = registry.get("components")
    if registry.get("schema_version") != 2 or not isinstance(components, dict):
        raise SubscriptionManagementError("The component registry has an unsupported schema.")
    record = components.get("nginx")
    if not isinstance(record, dict) or record.get("installed") is not True:
        raise SubscriptionManagementError("Managed Nginx is not registered on this server.")
    if record.get("contract_version") != EXPECTED_CONTRACT_VERSION:
        raise SubscriptionManagementError("Managed Nginx contract v5 must be deployed first.")
    if record.get("declaration_path") != str(DECLARATION):
        raise SubscriptionManagementError("The registered Nginx declaration path is invalid.")
    declaration = _load_json(DECLARATION, "The managed Nginx declaration")
    if (
        declaration.get("schema_version") != 2
        or declaration.get("component") != "nginx"
        or declaration.get("contract_version") != EXPECTED_CONTRACT_VERSION
    ):
        raise SubscriptionManagementError("The managed Nginx declaration is incompatible.")
    installation = declaration.get("installation_checks")
    files = installation.get("files") if isinstance(installation, dict) else None
    if not isinstance(files, list) or str(SUBSCRIPTIONS_LOCATION) not in files:
        raise SubscriptionManagementError("Managed Nginx does not declare subscription delivery.")
    if not _regular_file(SUBSCRIPTIONS_LOCATION):
        raise SubscriptionManagementError(
            "The managed subscriptions location is missing or unsafe."
        )


def _inspect_owned_nginx(selected_address):
    if not _regular_file(CONTRACT):
        raise SubscriptionManagementError(
            "The managed Nginx contract helper is missing or unsafe."
        )
    verified = _run(["python3", str(CONTRACT), "verify-owned", "--allow-expired"])
    if verified.returncode != 0:
        raise SubscriptionManagementError("Managed Nginx ownership validation failed.")
    inspected = _run(["python3", str(CONTRACT), "inspect"])
    try:
        state = json.loads(inspected.stdout)
    except (TypeError, json.JSONDecodeError) as error:
        raise SubscriptionManagementError("Managed Nginx TLS state is invalid.") from error
    if (
        inspected.returncode != 0
        or not isinstance(state, dict)
        or set(state) != {"tls_mode", "server_name", "server_address"}
    ):
        raise SubscriptionManagementError("Managed Nginx TLS state is invalid.")
    if state["tls_mode"] not in {"self_signed", "letsencrypt"}:
        raise SubscriptionManagementError("Managed Nginx TLS mode is invalid.")
    if state["server_address"] != selected_address:
        raise SubscriptionManagementError(
            "Managed Nginx TLS state does not match the selected server IPv4."
        )
    server_name = state["server_name"]
    if state["tls_mode"] == "self_signed":
        if server_name != selected_address:
            raise SubscriptionManagementError("Managed self-signed Nginx state is invalid.")
    elif (
        not isinstance(server_name, str)
        or len(server_name) > 253
        or not any(character.isalpha() for character in server_name)
        or DOMAIN.fullmatch(server_name) is None
    ):
        raise SubscriptionManagementError("Managed Nginx domain is invalid.")
    return state


def _parse_artifact_filename(filename):
    prefix, separator, remainder = filename.partition("-")
    if not separator or not prefix.isdigit():
        return None
    name_length = int(prefix)
    if name_length < 1 or len(remainder) <= name_length or remainder[name_length] != "-":
        return None
    name = remainder[:name_length]
    token_filename = remainder[name_length + 1 :]
    if not token_filename.endswith(".txt"):
        return None
    token = token_filename[:-4]
    if NAME.fullmatch(name) is None or TOKEN.fullmatch(token) is None:
        return None
    return {"name": name, "token": token}


def _inspect_artifacts():
    if not SUBSCRIPTIONS_DIRECTORY.exists() and not SUBSCRIPTIONS_DIRECTORY.is_symlink():
        return []
    if not _safe_directory(SUBSCRIPTIONS_DIRECTORY):
        raise SubscriptionManagementError("The managed subscriptions directory is unsafe.")
    try:
        paths = list(SUBSCRIPTIONS_DIRECTORY.iterdir())
    except OSError as error:
        raise SubscriptionManagementError(
            "The managed subscriptions directory cannot be inspected."
        ) from error
    artifacts = []
    for path in paths:
        artifact = _parse_artifact_filename(path.name)
        if artifact is None:
            continue
        if not _regular_file(path):
            raise SubscriptionManagementError("A managed subscription artifact is unsafe.")
        artifacts.append(artifact)
    identities = [(item["name"], item["token"]) for item in artifacts]
    if len(identities) != len(set(identities)):
        raise SubscriptionManagementError("Managed subscription artifacts contain duplicates.")
    artifacts.sort(key=lambda item: (item["name"].casefold(), item["name"], item["token"]))
    return artifacts


def _sync_directory():
    if os.name == "nt" or not SUBSCRIPTIONS_DIRECTORY.exists():
        return
    descriptor = os.open(
        SUBSCRIPTIONS_DIRECTORY,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
    )
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _failure(action, message):
    return {
        "schema_version": 1,
        "action": action,
        "outcome": "failure",
        "availability": "",
        "server_name": "",
        "tls_mode": "",
        "artifacts": [],
        "error": message,
    }


def execute_inspect(request):
    """Return one authoritative read-only snapshot for the selected server."""
    try:
        selected_address = _validate_request(request, "inspect")
        _validate_component_contract()
        state = _inspect_owned_nginx(selected_address)
        ready = state["tls_mode"] == "letsencrypt"
        artifacts = _inspect_artifacts() if ready else []
    except SubscriptionManagementError as error:
        return _failure("inspect", str(error))
    return {
        "schema_version": 1,
        "action": "inspect",
        "outcome": "success",
        "availability": "ready" if ready else "letsencrypt_required",
        "server_name": state["server_name"],
        "tls_mode": state["tls_mode"],
        "artifacts": artifacts,
        "error": "",
    }


def _delete_failure(outcome, message, deleted_count=0):
    return {
        "schema_version": 1,
        "action": "delete",
        "outcome": outcome,
        "availability": "",
        "server_name": "",
        "tls_mode": "",
        "artifacts": [],
        "deleted_count": deleted_count,
        "remaining_count": 0,
        "error": message,
    }


def execute_delete(request):
    """Delete only validated managed artifacts and return an authoritative result."""
    deleted_count = 0
    mutation_started = False
    try:
        selected_address = _validate_delete_request(request)
        _validate_component_contract()
        state = _inspect_owned_nginx(selected_address)
        if state["tls_mode"] != "letsencrypt":
            raise SubscriptionManagementError(
                "Subscription deletion requires managed Nginx in Let's Encrypt mode."
            )
        before = _inspect_artifacts()
        requested_tokens = set(request["tokens"])
        selected = [
            artifact
            for artifact in before
            if artifact["name"] == request["name"]
            and (request["kind"] == "active" or artifact["token"] in requested_tokens)
        ]
        failed_count = 0
        for artifact in selected:
            path = SUBSCRIPTIONS_DIRECTORY / (
                str(len(artifact["name"]))
                + "-"
                + artifact["name"]
                + "-"
                + artifact["token"]
                + ".txt"
            )
            mutation_started = True
            try:
                path.unlink()
                deleted_count += 1
            except FileNotFoundError:
                pass
            except OSError:
                failed_count += 1
        try:
            _sync_directory()
        except OSError:
            failed_count += 1
        after = _inspect_artifacts()
        remaining = [
            artifact
            for artifact in after
            if artifact["name"] == request["name"]
            and (request["kind"] == "active" or artifact["token"] in requested_tokens)
        ]
        if remaining:
            failed_count += len(remaining)
    except SubscriptionManagementError as error:
        return _delete_failure(
            "partial" if mutation_started else "failure",
            str(error),
            deleted_count,
        )
    outcome = "partial" if failed_count else "success"
    return {
        "schema_version": 1,
        "action": "delete",
        "outcome": outcome,
        "availability": "ready",
        "server_name": state["server_name"],
        "tls_mode": state["tls_mode"],
        "artifacts": after,
        "deleted_count": deleted_count,
        "remaining_count": len(remaining),
        "error": (
            "One or more managed subscription artifacts could not be removed."
            if failed_count
            else ""
        ),
    }
