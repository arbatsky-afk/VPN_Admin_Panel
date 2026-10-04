"""Redacted durable audit log for operational Telegram administration."""

from __future__ import annotations

import json
import os
import re
import threading
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any

MAX_TELEGRAM_AUDIT_RECORD_BYTES = 64 * 1024
_PREFIX = "telegram-audit"
_SENSITIVE_KEYS = frozenset(
    {
        "authorization",
        "bot_token",
        "callback_data",
        "callback_payload",
        "code",
        "command_text",
        "exception",
        "original",
        "password",
        "path",
        "private_key",
        "private-key",
        "raw_output",
        "ssh_credentials",
        "token",
        "update_text",
        "uri",
        "url_with_credentials",
        "uuid",
    }
)
_URI_RE = re.compile(r"\b(?:vless|hysteria2|hy2|mierus)://[^\s\"']+", re.IGNORECASE)


class TelegramAuditLog:
    """Append redacted events to daily 0600 JSONL files and enforce retention."""

    def __init__(self, directory: Path, retention_days: int) -> None:
        if (
            isinstance(retention_days, bool)
            or not isinstance(retention_days, int)
            or not 1 <= retention_days <= 3650
        ):
            raise ValueError("Telegram audit retention must be between 1 and 3650 days.")
        self._directory = directory
        self._retention_days = retention_days
        self._lock = threading.Lock()

    def write(self, event: str, **fields: Any) -> dict[str, Any]:
        record = {
            "timestamp": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
            "event": event,
            **_redact(fields),
        }
        encoded = _encode_record(record)
        if len(encoded) > MAX_TELEGRAM_AUDIT_RECORD_BYTES:
            record = {
                "timestamp": record["timestamp"],
                "event": event,
                "truncated": True,
                "safe_message": "Record exceeded the 64 KiB limit.",
            }
            encoded = _encode_record(record)
        with self._lock:
            try:
                self._directory.mkdir(parents=True, exist_ok=True)
                today = datetime.now().astimezone().date()
                target = self._directory / f"{_PREFIX}-{today.isoformat()}.jsonl"
                descriptor = os.open(target, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
                with os.fdopen(descriptor, "ab") as stream:
                    stream.write(encoded)
                    stream.flush()
                    os.fsync(stream.fileno())
                self.cleanup(today)
            except OSError:
                # Audit persistence is best-effort: a full disk or a locked
                # retention file must not break Telegram operations.
                pass
        return record

    def cleanup(self, today: date | None = None) -> None:
        if not self._directory.exists():
            return
        local_today = today or datetime.now().astimezone().date()
        cutoff = local_today - timedelta(days=self._retention_days - 1)
        pattern = re.compile(rf"^{_PREFIX}-(\d{{4}}-\d{{2}}-\d{{2}})\.jsonl$")
        for path in self._directory.iterdir():
            match = pattern.fullmatch(path.name)
            if not match or not path.is_file():
                continue
            try:
                file_date = date.fromisoformat(match.group(1))
            except ValueError:
                continue
            if file_date < cutoff:
                path.unlink(missing_ok=True)


def _encode_record(record: dict[str, Any]) -> bytes:
    return (json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")


def _redact(value: Any, key: str = "") -> Any:
    if key.lower() in _SENSITIVE_KEYS:
        return "[REDACTED]"
    if isinstance(value, dict):
        return {str(item_key): _redact(item, str(item_key)) for item_key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_redact(item) for item in value]
    if isinstance(value, str):
        return _URI_RE.sub("[REDACTED_URI]", value)
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return str(value)
