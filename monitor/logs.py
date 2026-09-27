from __future__ import annotations

import json
import os
import re
import threading
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from monitor.path_security import ManagedPathGuard

MAX_RECORD_BYTES = 64 * 1024
SENSITIVE_KEYS = {
    "original",
    "uri",
    "url_with_credentials",
    "password",
    "private-key",
    "private_key",
    "public-key",
    "uuid",
    "token",
    "authorization",
    "bot_token",
}
URI_RE = re.compile(r"\b(?:vless|hysteria2|hy2|mierus)://[^\s\"']+", re.IGNORECASE)


class JsonlLog:
    def __init__(
        self,
        directory: Path,
        prefix: str,
        retention_days: int,
        guard: ManagedPathGuard | None = None,
    ) -> None:
        if retention_days < 1:
            raise ValueError("Log retention must be positive.")
        self._directory = directory
        self._guard = guard or ManagedPathGuard(directory)
        self._prefix = prefix
        self._retention_days = retention_days
        self._lock = threading.Lock()

    def write(self, event: str, **fields: Any) -> dict[str, Any]:
        record = {
            "timestamp": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
            "event": event,
            **_redact(fields),
        }
        encoded = (json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n").encode(
            "utf-8"
        )
        if len(encoded) > MAX_RECORD_BYTES:
            record = {
                "timestamp": record["timestamp"],
                "event": event,
                "truncated": True,
                "message": "Record exceeded the 64 KiB limit.",
            }
            encoded = (json.dumps(record, separators=(",", ":")) + "\n").encode("utf-8")
        with self._lock:
            self._directory = self._guard.ensure_directory(self._directory)
            local_today = datetime.now().astimezone().date()
            target = self._directory / f"{self._prefix}-{local_today.isoformat()}.jsonl"
            target = self._guard.validate(target, kind="file")
            flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT
            descriptor = self._guard.open_file(target, flags)
            try:
                with os.fdopen(descriptor, "ab") as stream:
                    stream.write(encoded)
                    stream.flush()
                    os.fsync(stream.fileno())
            finally:
                self.cleanup()
        return record

    def cleanup(self, today: date | None = None) -> None:
        self._directory = self._guard.validate(self._directory, kind="directory")
        if not self._directory.exists():
            return
        local_today = datetime.now().astimezone().date()
        cutoff = (today or local_today) - timedelta(days=self._retention_days - 1)
        pattern = re.compile(rf"^{re.escape(self._prefix)}-(\d{{4}}-\d{{2}}-\d{{2}})\.jsonl$")
        for path in self._directory.iterdir():
            match = pattern.fullmatch(path.name)
            if not match or not path.is_file():
                continue
            try:
                file_date = date.fromisoformat(match.group(1))
            except ValueError:
                continue
            if file_date < cutoff:
                self._guard.validate(path, kind="file", allow_missing=False)
                path.unlink(missing_ok=True)

    def read_recent(self, limit: int = 200) -> list[dict[str, Any]]:
        self._directory = self._guard.validate(self._directory, kind="directory")
        if limit < 1 or not self._directory.exists():
            return []
        records: list[dict[str, Any]] = []
        files = sorted(self._directory.glob(f"{self._prefix}-????-??-??.jsonl"), reverse=True)
        for path in files:
            try:
                self._guard.validate(path, kind="file", allow_missing=False)
                lines = path.read_text(encoding="utf-8", errors="strict").splitlines()
            except (OSError, UnicodeError):
                continue
            for line in reversed(lines):
                try:
                    value = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(value, dict):
                    records.append(value)
                    if len(records) >= limit:
                        return list(reversed(records))
        return list(reversed(records))


def _redact(value: Any, key: str = "") -> Any:
    if key.lower() in SENSITIVE_KEYS:
        return "[REDACTED]"
    if isinstance(value, dict):
        return {str(item_key): _redact(item, str(item_key)) for item_key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_redact(item) for item in value]
    if isinstance(value, str):
        return URI_RE.sub("[REDACTED_URI]", value)
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return str(value)
