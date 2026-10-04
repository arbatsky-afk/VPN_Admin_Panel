from __future__ import annotations

import json
import threading
from dataclasses import asdict, replace
from pathlib import Path
from typing import Any

from monitor.domain import Connection
from monitor.importer import InvalidCandidateError, validate_persisted_connection
from monitor.io_utils import atomic_write_json
from monitor.path_security import ManagedPathGuard


class RepositoryError(ValueError):
    pass


class ConnectionRepository:
    SCHEMA_VERSION = 1

    def __init__(self, path: Path, guard: ManagedPathGuard | None = None) -> None:
        self._path = path
        self._guard = guard or ManagedPathGuard(path.parent)
        self._lock = threading.RLock()

    def load(self) -> tuple[Connection, ...]:
        with self._lock:
            self._path = self._guard.validate(self._path, kind="file")
            if not self._path.exists():
                self.save(())
                return ()
            try:
                self._path = self._guard.validate(self._path, kind="file", allow_missing=False)
                payload = json.loads(self._path.read_text(encoding="utf-8"))
            except (OSError, UnicodeError, json.JSONDecodeError) as error:
                raise RepositoryError("Connections file is not valid UTF-8 JSON.") from error
            if (
                not isinstance(payload, dict)
                or payload.get("schema_version") != self.SCHEMA_VERSION
            ):
                raise RepositoryError("Unsupported connections schema.")
            items = payload.get("connections")
            if not isinstance(items, list):
                raise RepositoryError("Connections must be an array.")
            connections = tuple(self._decode(item) for item in items)
            ids = {item.connection_id for item in connections}
            fingerprints = {item.fingerprint for item in connections}
            if len(ids) != len(connections) or len(fingerprints) != len(connections):
                raise RepositoryError("Connections file contains duplicates.")
            return connections

    def save(self, connections: tuple[Connection, ...]) -> None:
        with self._lock:
            atomic_write_json(
                self._path,
                {
                    "schema_version": self.SCHEMA_VERSION,
                    "connections": [asdict(item) for item in connections],
                },
                self._guard,
            )

    def append(self, additions: tuple[Connection, ...]) -> tuple[Connection, ...]:
        with self._lock:
            current = self.load()
            updated = current + additions
            self.save(updated)
            return updated

    def delete(self, connection_id: str) -> tuple[Connection, ...]:
        with self._lock:
            current = self.load()
            updated = tuple(item for item in current if item.connection_id != connection_id)
            if len(updated) == len(current):
                raise RepositoryError("Connection does not exist.")
            self.save(updated)
            return updated

    def set_enabled(self, connection_id: str, enabled: bool) -> tuple[Connection, ...]:
        with self._lock:
            current = self.load()
            found = False
            updated: list[Connection] = []
            for item in current:
                if item.connection_id == connection_id:
                    found = True
                    updated.append(replace(item, enabled=enabled, version=item.version + 1))
                else:
                    updated.append(item)
            if not found:
                raise RepositoryError("Connection does not exist.")
            result = tuple(updated)
            self.save(result)
            return result

    @staticmethod
    def _decode(value: Any) -> Connection:
        if not isinstance(value, dict):
            raise RepositoryError("Connection entry must be an object.")
        allowed = set(Connection.__dataclass_fields__)
        if set(value) != allowed:
            raise RepositoryError("Connection entry has an unexpected shape.")
        try:
            result = Connection(**value)
        except TypeError as error:
            raise RepositoryError("Connection entry is invalid.") from error
        if (
            not isinstance(result.connection_id, str)
            or not isinstance(result.enabled, bool)
            or not isinstance(result.proxy, dict)
            or not isinstance(result.version, int)
            or result.version < 1
        ):
            raise RepositoryError("Connection entry types are invalid.")
        try:
            validate_persisted_connection(result)
        except InvalidCandidateError as error:
            raise RepositoryError("Persisted connection validation failed.") from error
        return result
