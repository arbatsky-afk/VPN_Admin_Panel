"""Versioned subscription Registry with locking and atomic recovery."""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import stat
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from tempfile import NamedTemporaryFile

from ..ssh import validate_server_ip
from .contracts import (
    PreparedSubscription,
    SubscriptionCandidate,
    SubscriptionError,
    SubscriptionPublishRequest,
    SubscriptionPublishResult,
    SubscriptionRegistryEntry,
)
from .sources import validate_subscription_name

SUBSCRIPTION_REGISTRY_SCHEMA_VERSION = 2
_READABLE_REGISTRY_SCHEMA_VERSIONS = frozenset({1, SUBSCRIPTION_REGISTRY_SCHEMA_VERSION})


_TOKEN = re.compile(r"^[A-Za-z0-9_-]{32,128}$")
_DOMAIN = re.compile(
    r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    r"(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$"
)


class SubscriptionRegistry:
    """Versioned registry guarded by an inter-process exclusive lock."""

    def __init__(
        self,
        project_directory: Path,
        *,
        clock: Callable[[], datetime] | None = None,
        token_factory: Callable[[], str] | None = None,
    ) -> None:
        self.directory = project_directory / "runtime" / "subscriptions"
        self.path = self.directory / "registry.json"
        self.backup_path = self.directory / "registry.json.bak"
        self.lock_path = self.directory / "registry.lock"
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._token_factory = token_factory or (lambda: secrets.token_urlsafe(32))

    def prepare(
        self,
        operation_token: int,
        request_id: int,
        server_ip: str,
        candidate: SubscriptionCandidate,
    ) -> PreparedSubscription:
        if (
            isinstance(operation_token, bool)
            or not isinstance(operation_token, int)
            or operation_token < 1
        ):
            raise SubscriptionError("Operation token must be a positive integer.")
        if isinstance(request_id, bool) or not isinstance(request_id, int) or request_id < 1:
            raise SubscriptionError("Request id must be a positive integer.")
        server_ip, error = validate_server_ip(server_ip)
        if error:
            raise SubscriptionError(error)
        validate_subscription_name(candidate.name)
        if (
            not isinstance(candidate.content, bytes)
            or not candidate.content
            or re.fullmatch(r"[0-9a-f]{64}", candidate.content_sha256) is None
            or hashlib.sha256(candidate.content).hexdigest() != candidate.content_sha256
        ):
            raise SubscriptionError("Subscription candidate content or digest is invalid.")
        with self._locked():
            entries = self._load_or_recover()
            index = next(
                (
                    position
                    for position, entry in enumerate(entries)
                    if (entry.server_ip, entry.name) == (server_ip, candidate.name)
                ),
                None,
            )
            if index is None:
                existing_tokens = {item.token for item in entries}
                token = ""
                for _attempt in range(16):
                    candidate_token = self._token_factory()
                    if (
                        not isinstance(candidate_token, str)
                        or _TOKEN.fullmatch(candidate_token) is None
                    ):
                        raise SubscriptionError("Generated subscription token is invalid.")
                    if candidate_token not in existing_tokens:
                        token = candidate_token
                        break
                if not token:
                    raise SubscriptionError("Could not generate a unique subscription token.")
                entry = SubscriptionRegistryEntry(
                    server_ip,
                    candidate.name,
                    token,
                    "pending",
                    None,
                    self._timestamp(),
                    None,
                    None,
                )
                entries.append(entry)
            else:
                if entries[index].state == "deleting":
                    raise SubscriptionError(
                        "Subscription deletion must be completed before publication."
                    )
                entry = replace(entries[index], state="pending")
                entries[index] = entry
            self._write(entries)
        request = SubscriptionPublishRequest(
            operation_token,
            request_id,
            server_ip,
            candidate.name,
            entry.token,
            candidate.content_sha256,
            len(candidate.content),
            tuple(source.path.name for source in candidate.sources),
        )
        return PreparedSubscription(request, candidate.content)

    def confirmed_url(self, server_ip: str, name: str) -> str:
        """Return the last confirmed bearer URL for one exact registry identity."""
        server_ip, error = validate_server_ip(server_ip)
        if error:
            raise SubscriptionError(error)
        name = validate_subscription_name(name)
        if not (
            self.path.exists()
            or self.path.is_symlink()
            or self.backup_path.exists()
            or self.backup_path.is_symlink()
        ):
            return ""
        with self._locked():
            entries = self._load_or_recover()
            entry = next(
                (
                    item
                    for item in entries
                    if (item.server_ip, item.name) == (server_ip, name)
                    and item.state in {"active", "pending"}
                    and item.server_name is not None
                ),
                None,
            )
        return _subscription_url(entry) if entry is not None else ""

    def entries(self, server_ip: str) -> tuple[SubscriptionRegistryEntry, ...]:
        """Return every desired or deleting identity for one exact server."""
        server_ip, error = validate_server_ip(server_ip)
        if error:
            raise SubscriptionError(error)
        if not (
            self.path.exists()
            or self.path.is_symlink()
            or self.backup_path.exists()
            or self.backup_path.is_symlink()
        ):
            return ()
        with self._locked():
            entries = self._load_or_recover()
        return tuple(item for item in entries if item.server_ip == server_ip)

    def begin_deletion(self, server_ip: str, name: str) -> SubscriptionRegistryEntry:
        """Persist delete intent while retaining the exact token for recovery."""
        server_ip, error = validate_server_ip(server_ip)
        if error:
            raise SubscriptionError(error)
        name = validate_subscription_name(name)
        with self._locked():
            entries = self._load_or_recover()
            index = next(
                (
                    position
                    for position, entry in enumerate(entries)
                    if (entry.server_ip, entry.name) == (server_ip, name)
                ),
                None,
            )
            if index is None:
                raise SubscriptionError("The active subscription is absent from Registry.")
            previous = entries[index]
            if previous.state != "deleting":
                entries[index] = replace(previous, state="deleting")
                self._write(entries)
            return previous

    def restore_deletion(self, previous: SubscriptionRegistryEntry) -> None:
        """Restore the pre-delete entry after authoritative pre-mutation failure."""
        if previous.state == "deleting":
            return
        with self._locked():
            entries = self._load_or_recover()
            index = next(
                (
                    position
                    for position, entry in enumerate(entries)
                    if (entry.server_ip, entry.name) == (previous.server_ip, previous.name)
                ),
                None,
            )
            if (
                index is None
                or entries[index].token != previous.token
                or entries[index].state != "deleting"
            ):
                raise SubscriptionError(
                    "Subscription Registry changed before delete intent could be restored."
                )
            entries[index] = previous
            self._write(entries)

    def complete_deletion(self, server_ip: str, name: str, token: str) -> bool:
        """Remove one exact deleting entry after confirmed server absence."""
        server_ip, error = validate_server_ip(server_ip)
        if error:
            raise SubscriptionError(error)
        name = validate_subscription_name(name)
        if not isinstance(token, str) or _TOKEN.fullmatch(token) is None:
            raise SubscriptionError("Subscription deletion token is invalid.")
        with self._locked():
            entries = self._load_or_recover()
            index = next(
                (
                    position
                    for position, entry in enumerate(entries)
                    if (entry.server_ip, entry.name) == (server_ip, name)
                ),
                None,
            )
            if index is None:
                return False
            entry = entries[index]
            if entry.token != token or entry.state != "deleting":
                raise SubscriptionError(
                    "Subscription Registry does not contain the expected delete intent."
                )
            del entries[index]
            self._write(entries)
            return True

    def confirm(
        self,
        request: SubscriptionPublishRequest,
        result: SubscriptionPublishResult,
    ) -> SubscriptionRegistryEntry:
        if result.outcome not in {"success", "partial"}:
            raise SubscriptionError(
                "Only a confirmed publication can activate the registry entry."
            )
        if (
            result.content_sha256 != request.content_sha256
            or result.content_size != request.content_size
        ):
            raise SubscriptionError("Confirmed publication does not match the prepared content.")
        if not _valid_domain(result.server_name):
            raise SubscriptionError("Confirmed publication contains an invalid server name.")
        with self._locked():
            entries = self._load_or_recover()
            index = next(
                (
                    position
                    for position, entry in enumerate(entries)
                    if (entry.server_ip, entry.name) == (request.server_ip, request.name)
                ),
                None,
            )
            if (
                index is None
                or entries[index].token != request.token
                or entries[index].state == "deleting"
            ):
                raise SubscriptionError(
                    "Subscription registry ownership changed before confirmation."
                )
            entry = replace(
                entries[index],
                state="active",
                server_name=result.server_name,
                last_published_at=self._timestamp(),
                content_sha256=request.content_sha256,
            )
            entries[index] = entry
            self._write(entries)
            return entry

    @contextmanager
    def _locked(self) -> Iterator[None]:
        self.directory.mkdir(parents=True, exist_ok=True)
        if self.directory.is_symlink():
            raise SubscriptionError("Subscription registry directory is unsafe.")
        if self.lock_path.exists() or self.lock_path.is_symlink():
            try:
                lock_metadata = self.lock_path.lstat()
            except OSError as error:
                raise SubscriptionError(
                    "Subscription registry lock cannot be inspected."
                ) from error
            if self.lock_path.is_symlink() or not stat.S_ISREG(lock_metadata.st_mode):
                raise SubscriptionError("Subscription registry lock is unsafe.")
        with self.lock_path.open("a+b") as lock_file:
            lock_file.seek(0, os.SEEK_END)
            if lock_file.tell() == 0:
                lock_file.write(b"0")
                lock_file.flush()
            try:
                if os.name == "nt":
                    import msvcrt

                    lock_file.seek(0)
                    msvcrt.locking(lock_file.fileno(), msvcrt.LK_LOCK, 1)
                else:
                    import fcntl

                    fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
                yield
            finally:
                if os.name == "nt":
                    import msvcrt

                    lock_file.seek(0)
                    msvcrt.locking(lock_file.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl

                    fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)

    def _load_or_recover(self) -> list[SubscriptionRegistryEntry]:
        if self.path.exists() or self.path.is_symlink():
            return self._read(self.path)
        if self.backup_path.exists() or self.backup_path.is_symlink():
            entries = self._read(self.backup_path)
            self._write_atomic(self.path, self._encode(entries))
            return entries
        return []

    def _read(self, path: Path) -> list[SubscriptionRegistryEntry]:
        try:
            metadata = path.lstat()
            if path.is_symlink() or not stat.S_ISREG(metadata.st_mode):
                raise SubscriptionError("Subscription registry is not a regular file.")
            data = json.loads(path.read_text(encoding="utf-8", errors="strict"))
        except SubscriptionError:
            raise
        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            raise SubscriptionError(
                "Subscription registry is damaged and was not overwritten."
            ) from error
        if not isinstance(data, dict) or set(data) != {"schema_version", "subscriptions"}:
            raise SubscriptionError("Subscription registry has an unsupported schema.")
        schema_version = data["schema_version"]
        if (
            type(schema_version) is not int
            or schema_version not in _READABLE_REGISTRY_SCHEMA_VERSIONS
            or not isinstance(data["subscriptions"], list)
        ):
            raise SubscriptionError("Subscription registry has an unsupported schema.")
        entries = [self._entry(value, schema_version) for value in data["subscriptions"]]
        identities = [(entry.server_ip, entry.name) for entry in entries]
        if len(identities) != len(set(identities)):
            raise SubscriptionError("Subscription registry contains duplicate identities.")
        tokens = [entry.token for entry in entries]
        if len(tokens) != len(set(tokens)):
            raise SubscriptionError("Subscription registry contains duplicate tokens.")
        return entries

    @staticmethod
    def _entry(value: object, schema_version: int) -> SubscriptionRegistryEntry:
        expected = {
            "server_ip",
            "name",
            "token",
            "state",
            "server_name",
            "created_at",
            "last_published_at",
            "content_sha256",
        }
        if not isinstance(value, dict) or set(value) != expected:
            raise SubscriptionError("Subscription registry contains an invalid entry.")
        server_ip, error = validate_server_ip(
            value["server_ip"] if isinstance(value["server_ip"], str) else ""
        )
        if error or server_ip != value["server_ip"]:
            raise SubscriptionError("Subscription registry contains an invalid server address.")
        name = validate_subscription_name(value["name"])
        token = value["token"]
        state_value = value["state"]
        allowed_states = {"pending", "active"} | ({"deleting"} if schema_version >= 2 else set())
        if (
            not isinstance(token, str)
            or _TOKEN.fullmatch(token) is None
            or state_value not in allowed_states
        ):
            raise SubscriptionError("Subscription registry contains an invalid token or state.")
        server_name = value["server_name"]
        published_at = value["last_published_at"]
        content_sha256 = value["content_sha256"]
        created_at = value["created_at"]
        if not isinstance(created_at, str) or not created_at:
            raise SubscriptionError("Subscription registry contains an invalid creation time.")
        if server_name is not None and (
            not isinstance(server_name, str) or not _valid_domain(server_name)
        ):
            raise SubscriptionError("Subscription registry contains an invalid server name.")
        if published_at is not None and (not isinstance(published_at, str) or not published_at):
            raise SubscriptionError("Subscription registry contains an invalid publication time.")
        if content_sha256 is not None and (
            not isinstance(content_sha256, str)
            or re.fullmatch(r"[0-9a-f]{64}", content_sha256) is None
        ):
            raise SubscriptionError("Subscription registry contains an invalid content digest.")
        if state_value == "active" and (
            server_name is None or published_at is None or content_sha256 is None
        ):
            raise SubscriptionError("Active subscription registry entry is incomplete.")
        if any(item is not None for item in (server_name, published_at, content_sha256)) and any(
            item is None for item in (server_name, published_at, content_sha256)
        ):
            raise SubscriptionError("Subscription registry confirmation fields are inconsistent.")
        for timestamp in (created_at, published_at):
            if timestamp is None:
                continue
            try:
                parsed_timestamp = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
            except ValueError as error:
                raise SubscriptionError(
                    "Subscription registry contains an invalid timestamp."
                ) from error
            if parsed_timestamp.tzinfo is None:
                raise SubscriptionError("Subscription registry timestamp has no timezone.")
        return SubscriptionRegistryEntry(
            server_ip,
            name,
            token,
            state_value,
            server_name,
            created_at,
            published_at,
            content_sha256,
        )

    def _write(self, entries: list[SubscriptionRegistryEntry]) -> None:
        rendered = self._encode(entries)
        if self.path.exists():
            existing = self.path.read_bytes()
            self._write_atomic(self.backup_path, existing)
        self._write_atomic(self.path, rendered)

    @staticmethod
    def _encode(entries: list[SubscriptionRegistryEntry]) -> bytes:
        value = {
            "schema_version": SUBSCRIPTION_REGISTRY_SCHEMA_VERSION,
            "subscriptions": [
                {
                    "server_ip": entry.server_ip,
                    "name": entry.name,
                    "token": entry.token,
                    "state": entry.state,
                    "server_name": entry.server_name,
                    "created_at": entry.created_at,
                    "last_published_at": entry.last_published_at,
                    "content_sha256": entry.content_sha256,
                }
                for entry in entries
            ],
        }
        return (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode("utf-8")

    @staticmethod
    def _write_atomic(path: Path, content: bytes) -> None:
        temporary_path: Path | None = None
        try:
            with NamedTemporaryFile(
                "wb", dir=path.parent, prefix=f".{path.name}-", suffix=".tmp", delete=False
            ) as stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
                temporary_path = Path(stream.name)
            os.replace(temporary_path, path)
            temporary_path = None
        except OSError as error:
            raise SubscriptionError(
                "Could not save the subscription registry atomically."
            ) from error
        finally:
            if temporary_path is not None:
                temporary_path.unlink(missing_ok=True)

    def _timestamp(self) -> str:
        value = self._clock()
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _subscription_url(entry: SubscriptionRegistryEntry) -> str:
    if entry.state not in {"active", "pending"} or entry.server_name is None:
        raise SubscriptionError("Subscription registry entry has no confirmed URL.")
    filename = f"{len(entry.name)}-{entry.name}-{entry.token}.txt"
    return f"https://{entry.server_name}/subscriptions/{filename}"


def _valid_domain(value: str) -> bool:
    return (
        isinstance(value, str)
        and len(value) <= 253
        and any(character.isalpha() for character in value)
        and _DOMAIN.fullmatch(value) is not None
    )
