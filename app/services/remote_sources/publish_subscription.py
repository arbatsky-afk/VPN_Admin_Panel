#!/usr/bin/env python3
"""One-shot remote source for atomic subscription publication; never installed."""

import hashlib
import ipaddress
import json
import os
import re
import socket
import stat
import subprocess
import tempfile
from pathlib import Path

REGISTRY = Path("/opt/vpn/state/components.json")
DECLARATION = Path("/opt/vpn/components/nginx/declaration.json")
CONTRACT = Path("/usr/local/lib/vpn-admin/nginx_contract.py")
SUBSCRIPTIONS_LOCATION = Path("/etc/nginx/vpn-admin-locations/subscriptions.conf")
SITE_DIRECTORY = Path("/var/www/vpn-admin-site")
SUBSCRIPTIONS_DIRECTORY = SITE_DIRECTORY / "subscriptions"
RENEWAL_TIMER = "vpn-admin-nginx-renew.timer"
NGINX_SERVICE = "nginx.service"
EXPECTED_CONTRACT_VERSION = "5"

NAME = re.compile(r"^[A-Za-z0-9-]+$")
TOKEN = re.compile(r"^[A-Za-z0-9_-]{32,128}$")
DIGEST = re.compile(r"^[0-9a-f]{64}$")
DOMAIN = re.compile(
    r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    r"(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$"
)


class PublicationError(ValueError):
    """A confirmed preflight or recoverable publication failure."""


class UncertainPublicationError(RuntimeError):
    """The new target may be visible and authoritative output is unsafe."""


def _regular_file(path):
    try:
        metadata = path.lstat()
    except OSError:
        return False
    return stat.S_ISREG(metadata.st_mode) and not path.is_symlink()


def _safe_directory(path):
    try:
        metadata = path.lstat()
    except OSError:
        return False
    return stat.S_ISDIR(metadata.st_mode) and not path.is_symlink()


def _run(arguments, *, input_bytes=None, timeout=15):
    try:
        return subprocess.run(
            arguments,
            input=input_bytes,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise PublicationError("A required server check could not be completed.") from error


def _load_json(path, label):
    if not _regular_file(path):
        raise PublicationError(label + " is missing or unsafe.")
    try:
        value = json.loads(path.read_text(encoding="utf-8", errors="strict"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise PublicationError(label + " is invalid.") from error
    if not isinstance(value, dict):
        raise PublicationError(label + " is invalid.")
    return value


def _validate_request(request, content):
    expected = {
        "schema_version",
        "server_ip",
        "name",
        "token",
        "content_sha256",
        "content_size",
        "nginx_contract_version",
    }
    if not isinstance(request, dict) or set(request) != expected or request["schema_version"] != 1:
        raise PublicationError("The subscription request schema is invalid.")
    try:
        address = str(ipaddress.IPv4Address(request["server_ip"]))
    except (TypeError, ipaddress.AddressValueError) as error:
        raise PublicationError("The selected server IPv4 is invalid.") from error
    if address != request["server_ip"]:
        raise PublicationError("The selected server IPv4 is not canonical.")
    if not isinstance(request["name"], str) or NAME.fullmatch(request["name"]) is None:
        raise PublicationError("The subscription name is invalid.")
    if not isinstance(request["token"], str) or TOKEN.fullmatch(request["token"]) is None:
        raise PublicationError("The subscription token is invalid.")
    if (
        not isinstance(request["content_sha256"], str)
        or DIGEST.fullmatch(request["content_sha256"]) is None
    ):
        raise PublicationError("The subscription content digest is invalid.")
    size = request["content_size"]
    if isinstance(size, bool) or not isinstance(size, int) or size < 1:
        raise PublicationError("The subscription content size is invalid.")
    if request["nginx_contract_version"] != EXPECTED_CONTRACT_VERSION:
        raise PublicationError("The publisher requires managed Nginx contract v5.")
    if not isinstance(content, bytes) or len(content) != size:
        raise PublicationError("The subscription content size does not match its request.")
    if hashlib.sha256(content).hexdigest() != request["content_sha256"]:
        raise PublicationError("The subscription content digest does not match its request.")
    return address


def _validate_component_contract():
    registry = _load_json(REGISTRY, "The component registry")
    components = registry.get("components")
    if registry.get("schema_version") != 2 or not isinstance(components, dict):
        raise PublicationError("The component registry has an unsupported schema.")
    record = components.get("nginx")
    if not isinstance(record, dict) or record.get("installed") is not True:
        raise PublicationError("Managed Nginx is not registered on this server.")
    if record.get("contract_version") != EXPECTED_CONTRACT_VERSION:
        raise PublicationError("Managed Nginx contract v5 must be deployed first.")
    if record.get("declaration_path") != str(DECLARATION):
        raise PublicationError("The registered Nginx declaration path is invalid.")
    declaration = _load_json(DECLARATION, "The managed Nginx declaration")
    if (
        declaration.get("schema_version") != 2
        or declaration.get("component") != "nginx"
        or declaration.get("contract_version") != EXPECTED_CONTRACT_VERSION
    ):
        raise PublicationError("The managed Nginx declaration is not contract v5.")
    installation_checks = declaration.get("installation_checks")
    files = installation_checks.get("files") if isinstance(installation_checks, dict) else None
    if (
        not isinstance(files, list)
        or "/etc/nginx/vpn-admin-locations/subscriptions.conf" not in files
    ):
        raise PublicationError("The managed Nginx declaration lacks subscription delivery.")
    if not _regular_file(SUBSCRIPTIONS_LOCATION):
        raise PublicationError("The managed Nginx subscriptions location is missing or unsafe.")


def _inspect_owned_nginx(selected_address):
    if not _regular_file(CONTRACT):
        raise PublicationError("The managed Nginx contract helper is missing or unsafe.")
    verified = _run(["python3", str(CONTRACT), "verify-owned"])
    if verified.returncode != 0:
        raise PublicationError(
            "Managed Nginx ownership, configuration, or certificate validation failed."
        )
    inspected = _run(["python3", str(CONTRACT), "inspect"])
    try:
        state = json.loads(inspected.stdout)
    except (TypeError, json.JSONDecodeError) as error:
        raise PublicationError("Managed Nginx TLS state could not be inspected.") from error
    if (
        inspected.returncode != 0
        or not isinstance(state, dict)
        or set(state) != {"tls_mode", "server_name", "server_address"}
    ):
        raise PublicationError("Managed Nginx TLS state is invalid.")
    if state["tls_mode"] != "letsencrypt":
        raise PublicationError("Subscription publication requires trusted Let's Encrypt TLS.")
    domain = state["server_name"]
    if (
        not isinstance(domain, str)
        or len(domain) > 253
        or not any(c.isalpha() for c in domain)
        or DOMAIN.fullmatch(domain) is None
    ):
        raise PublicationError("Managed Nginx TLS state contains an invalid domain.")
    if state["server_address"] != selected_address:
        raise PublicationError("Managed Nginx TLS state does not match the selected server IPv4.")
    return domain


def _check_runtime(domain, selected_address):
    for arguments, message in (
        (["nginx", "-t"], "The active Nginx configuration is invalid."),
        (["systemctl", "is-active", "--quiet", NGINX_SERVICE], "Nginx is not active."),
        (
            ["systemctl", "is-active", "--quiet", RENEWAL_TIMER],
            "Managed certificate renewal is not active.",
        ),
        (
            ["systemctl", "is-enabled", "--quiet", RENEWAL_TIMER],
            "Managed certificate renewal is not enabled.",
        ),
    ):
        if _run(arguments).returncode != 0:
            raise PublicationError(message)
    try:
        ipv4_addresses = {
            item[4][0]
            for item in socket.getaddrinfo(domain, 443, type=socket.SOCK_STREAM)
            if item[0] == socket.AF_INET
        }
    except OSError as error:
        raise PublicationError("The managed TLS domain could not be resolved.") from error
    if selected_address not in ipv4_addresses:
        raise PublicationError(
            "The managed TLS domain does not resolve to the selected server IPv4."
        )
    _trusted_https(domain, selected_address, "/", expected=None)


def _trusted_https(domain, selected_address, path, expected):
    result = _run(
        [
            "curl",
            "--proto",
            "=https",
            "--tlsv1.2",
            "--fail",
            "--silent",
            "--show-error",
            "--max-time",
            "10",
            "--noproxy",
            "*",
            "--resolve",
            domain + ":443:" + selected_address,
            "https://" + domain + path,
        ],
        timeout=15,
    )
    if result.returncode != 0:
        raise PublicationError("Trusted HTTPS verification failed.")
    if expected is not None and result.stdout != expected:
        raise PublicationError("HTTPS returned content different from the published subscription.")


def _prepare_directory():
    if not _safe_directory(SITE_DIRECTORY):
        raise PublicationError("The managed Nginx site directory is missing or unsafe.")
    if SUBSCRIPTIONS_DIRECTORY.exists() or SUBSCRIPTIONS_DIRECTORY.is_symlink():
        if not _safe_directory(SUBSCRIPTIONS_DIRECTORY):
            raise PublicationError("The managed subscriptions path is unsafe.")
    else:
        try:
            SUBSCRIPTIONS_DIRECTORY.mkdir(mode=0o755)
        except OSError as error:
            raise PublicationError(
                "The managed subscriptions directory could not be created safely."
            ) from error
    try:
        metadata = SUBSCRIPTIONS_DIRECTORY.lstat()
    except OSError as error:
        raise PublicationError(
            "The managed subscriptions directory cannot be inspected."
        ) from error
    if os.name != "nt" and (
        metadata.st_uid != 0 or metadata.st_gid != 0 or metadata.st_mode & 0o022
    ):
        raise PublicationError(
            "The managed subscriptions directory has unsafe ownership or permissions."
        )


def _publication_files(name, current_filename):
    pattern = re.compile(
        r"^" + str(len(name)) + "-" + re.escape(name) + r"-[A-Za-z0-9_-]{32,128}\.txt$"
    )
    old_files = []
    try:
        entries = list(SUBSCRIPTIONS_DIRECTORY.iterdir())
    except OSError as error:
        raise PublicationError(
            "The managed subscriptions directory cannot be inspected."
        ) from error
    for entry in entries:
        if pattern.fullmatch(entry.name) is None:
            continue
        try:
            metadata = entry.lstat()
        except OSError as error:
            raise PublicationError("A subscription file cannot be inspected safely.") from error
        if entry.is_symlink() or not stat.S_ISREG(metadata.st_mode):
            raise PublicationError("A subscription path is a symlink or special file.")
        if entry.name != current_filename:
            old_files.append(entry)
    return old_files


def _sync_directory():
    if os.name == "nt":  # Remote execution is Linux; Windows is local unit-test only.
        return
    descriptor = os.open(SUBSCRIPTIONS_DIRECTORY, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _publish(domain, selected_address, request, content):
    filename = str(len(request["name"])) + "-" + request["name"] + "-" + request["token"] + ".txt"
    target = SUBSCRIPTIONS_DIRECTORY / filename
    old_files = _publication_files(request["name"], filename)
    if target.exists() or target.is_symlink():
        if not _regular_file(target):
            raise PublicationError("The current subscription target is unsafe.")

    candidate_name = None
    rollback_path = None
    replaced = False
    had_target = target.exists()
    try:
        descriptor, candidate_name = tempfile.mkstemp(
            prefix=".subscription-", suffix=".tmp", dir=SUBSCRIPTIONS_DIRECTORY
        )
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fchmod(stream.fileno(), 0o644)
            os.fsync(stream.fileno())
        candidate = Path(candidate_name)
        if had_target:
            rollback_descriptor, rollback_name = tempfile.mkstemp(
                prefix=".subscription-rollback-", dir=SUBSCRIPTIONS_DIRECTORY
            )
            os.close(rollback_descriptor)
            os.unlink(rollback_name)
            rollback_path = Path(rollback_name)
            os.link(target, rollback_path)
        os.replace(candidate, target)
        candidate_name = None
        replaced = True
        _sync_directory()
        metadata = target.lstat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size != request["content_size"]:
            raise PublicationError("The published subscription has an invalid local size.")
        if hashlib.sha256(target.read_bytes()).hexdigest() != request["content_sha256"]:
            raise PublicationError("The published subscription has an invalid local digest.")
        _trusted_https(
            domain,
            selected_address,
            "/subscriptions/" + filename,
            expected=content,
        )
    except PublicationError:
        if replaced:
            try:
                if rollback_path is not None:
                    os.replace(rollback_path, target)
                    rollback_path = None
                else:
                    target.unlink()
                _sync_directory()
            except OSError as error:
                raise UncertainPublicationError(
                    "The subscription result is uncertain after rollback failed."
                ) from error
        raise
    except OSError as error:
        if replaced:
            try:
                if rollback_path is not None:
                    os.replace(rollback_path, target)
                    rollback_path = None
                else:
                    target.unlink()
                _sync_directory()
            except OSError as rollback_error:
                raise UncertainPublicationError(
                    "The subscription result is uncertain after rollback failed."
                ) from rollback_error
        raise PublicationError(
            "The subscription could not be replaced atomically; the previous file was preserved."
        ) from error
    finally:
        if candidate_name is not None:
            try:
                Path(candidate_name).unlink(missing_ok=True)
            except OSError:
                pass
        if not replaced and rollback_path is not None:
            try:
                rollback_path.unlink(missing_ok=True)
            except OSError:
                pass

    cleanup_failed = 0
    cleanup_paths = old_files + ([rollback_path] if rollback_path is not None else [])
    for old_path in cleanup_paths:
        try:
            old_path.unlink(missing_ok=True)
        except OSError:
            cleanup_failed += 1
    try:
        _sync_directory()
    except OSError:
        cleanup_failed += 1
    return cleanup_failed


def _failure(message):
    return {
        "schema_version": 1,
        "outcome": "failure",
        "server_name": "",
        "content_sha256": "",
        "content_size": 0,
        "cleanup_failed_count": 0,
        "error": message,
    }


def execute(request, content):
    """Validate, publish once, and return the sole authoritative JSON result."""
    try:
        selected_address = _validate_request(request, content)
        _validate_component_contract()
        domain = _inspect_owned_nginx(selected_address)
        _check_runtime(domain, selected_address)
        _prepare_directory()
        cleanup_failed = _publish(domain, selected_address, request, content)
    except PublicationError as error:
        return _failure(str(error))
    outcome = "partial" if cleanup_failed else "success"
    return {
        "schema_version": 1,
        "outcome": outcome,
        "server_name": domain,
        "content_sha256": request["content_sha256"],
        "content_size": request["content_size"],
        "cleanup_failed_count": cleanup_failed,
        "error": "One or more obsolete subscription files could not be removed."
        if cleanup_failed
        else "",
    }
