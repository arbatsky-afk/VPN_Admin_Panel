"""Safe catalog and deterministic collection of subscription sources."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import stat
from pathlib import Path
from urllib.parse import urlsplit

from ..users import generated_connections_directory
from .contracts import (
    SubscriptionCandidate,
    SubscriptionError,
    SubscriptionSource,
    SubscriptionSourceFile,
)

_NAME = re.compile(r"^[A-Za-z0-9-]+$")
_SOURCE_ID = re.compile(r"^[a-z0-9]+$")
_SOURCE_FILENAME = re.compile(
    r"^(?P<server_ip>[0-9]{1,3}(?:\.[0-9]{1,3}){3})-"
    r"(?P<source_id>[a-z0-9]+)-(?P<name>[A-Za-z0-9-]+)\.txt$"
)
_URI_SCHEME = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*$")
_URI_CHARACTERS = re.compile(r"^[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+$")
_PERCENT_ESCAPE = re.compile(r"%[0-9A-Fa-f]{2}")


def validate_subscription_name(name: str) -> str:
    if not isinstance(name, str) or _NAME.fullmatch(name) is None:
        raise SubscriptionError(
            "Only letters, digits, and hyphens are allowed in a subscription name."
        )
    return name


def list_subscription_source_files(project_directory: Path) -> tuple[SubscriptionSourceFile, ...]:
    """Return the strict root `.txt` catalog without reading connection content."""
    source_directory = _subscription_source_directory(project_directory)
    return _list_subscription_source_files(source_directory)


def _list_subscription_source_files(
    source_directory: Path,
) -> tuple[SubscriptionSourceFile, ...]:
    try:
        entries = list(source_directory.iterdir())
    except OSError as error:
        raise SubscriptionError("Could not inspect generated connection files.") from error

    sources: list[SubscriptionSourceFile] = []
    for path in entries:
        if path.suffix.lower() != ".txt":
            continue
        source = _parse_subscription_source_filename(path.name)
        _validate_subscription_source_path(path)
        sources.append(source)
    sources.sort(
        key=lambda item: (
            item.name.casefold(),
            item.name,
            int(ipaddress.IPv4Address(item.server_ip)),
            item.source_id,
            item.filename,
        )
    )
    return tuple(sources)


def collect_subscription_candidate(
    project_directory: Path,
    name: str,
    source_filenames: tuple[str, ...],
) -> SubscriptionCandidate:
    """Collect the selected exact-name sources into deterministic UTF-8/LF content."""
    name = validate_subscription_name(name)
    if (
        not isinstance(source_filenames, tuple)
        or not source_filenames
        or any(not isinstance(filename, str) or not filename for filename in source_filenames)
        or len(source_filenames) != len(set(source_filenames))
    ):
        raise SubscriptionError("At least one unique connection filename must be selected.")
    source_directory = _subscription_source_directory(project_directory)
    catalog = _list_subscription_source_files(source_directory)
    by_filename = {source.filename: source for source in catalog}

    try:
        selected = [by_filename[filename] for filename in source_filenames]
    except KeyError as error:
        raise SubscriptionError("A selected connection file is no longer available.") from error
    if any(source.name != name for source in selected):
        raise SubscriptionError("A selected connection file does not match the subscription name.")

    sources: list[SubscriptionSource] = []
    for source in selected:
        path = source_directory / source.filename
        _validate_subscription_source_path(path)
        try:
            text = path.read_text(encoding="utf-8", errors="strict")
        except (OSError, UnicodeError) as error:
            raise SubscriptionError(f"Connection file is not valid UTF-8: {path.name}") from error
        uris = tuple(line for line in text.splitlines() if line)
        if not uris:
            raise SubscriptionError(f"Connection file contains no URI: {path.name}")
        for uri in uris:
            _validate_uri(uri, path.name)
        sources.append(SubscriptionSource(source.server_ip, source.source_id, path, uris))

    sources.sort(
        key=lambda item: (
            int(ipaddress.IPv4Address(item.server_ip)),
            item.source_id,
            item.path.name,
        )
    )
    content = ("\n".join(uri for source in sources for uri in source.uris) + "\n").encode("utf-8")
    return SubscriptionCandidate(
        name, content, hashlib.sha256(content).hexdigest(), tuple(sources)
    )


def _subscription_source_directory(project_directory: Path) -> Path:
    try:
        source_directory = generated_connections_directory(project_directory)
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as error:
        raise SubscriptionError("Could not resolve generated connection files.") from error
    if not source_directory.is_dir() or source_directory.is_symlink():
        raise SubscriptionError("The generated connections directory is unavailable or unsafe.")
    return source_directory


def _parse_subscription_source_filename(filename: str) -> SubscriptionSourceFile:
    match = _SOURCE_FILENAME.fullmatch(filename)
    if match is None:
        raise SubscriptionError(f"Connection file has an invalid name: {filename}")
    try:
        parsed_ip = str(ipaddress.IPv4Address(match.group("server_ip")))
    except ipaddress.AddressValueError as error:
        raise SubscriptionError(
            f"Connection file has an invalid IPv4 address: {filename}"
        ) from error
    if parsed_ip != match.group("server_ip"):
        raise SubscriptionError(f"Connection file IPv4 is not canonical: {filename}")
    source_id = match.group("source_id")
    if _SOURCE_ID.fullmatch(source_id) is None:
        raise SubscriptionError(f"Connection file has an invalid source id: {filename}")
    return SubscriptionSourceFile(filename, parsed_ip, source_id, match.group("name"))


def _validate_subscription_source_path(path: Path) -> None:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise SubscriptionError(f"Connection file cannot be inspected: {path.name}") from error
    if path.is_symlink() or not stat.S_ISREG(metadata.st_mode):
        raise SubscriptionError(f"Connection file is not a regular file: {path.name}")


def _validate_uri(uri: str, filename: str) -> None:
    if (
        uri != uri.strip()
        or _URI_CHARACTERS.fullmatch(uri) is None
        or any(
            character == "%" and _PERCENT_ESCAPE.match(uri, position) is None
            for position, character in enumerate(uri)
        )
    ):
        raise SubscriptionError(f"Connection file contains an invalid URI: {filename}")
    scheme, separator, remainder = uri.partition(":")
    if not separator or not remainder or _URI_SCHEME.fullmatch(scheme) is None:
        raise SubscriptionError(f"Connection file contains an invalid URI: {filename}")
    try:
        parsed = urlsplit(uri)
        _ = parsed.port
    except ValueError as error:
        raise SubscriptionError(f"Connection file contains an invalid URI: {filename}") from error
    if parsed.scheme != scheme.lower():
        raise SubscriptionError(f"Connection file contains an invalid URI: {filename}")
