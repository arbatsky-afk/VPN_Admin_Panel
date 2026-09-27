from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from urllib.parse import urlsplit

from common.ui.theme import DEFAULT_THEME_KEY, THEMES
from monitor.io_utils import atomic_write_json
from monitor.path_security import ManagedPathGuard


class SettingsError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class MonitorPaths:
    base: Path
    connections: Path
    settings: Path
    work: Path
    operation_logs: Path
    event_logs: Path
    mihomo: Path
    mihomo_digest: Path
    project_root: Path | None = None

    @classmethod
    def default(cls) -> MonitorPaths:
        package_root = Path(__file__).resolve().parent
        project_root = package_root.parent
        base = project_root / "runtime" / "monitor"
        return cls(
            base=base,
            connections=base / "connections.json",
            settings=base / "settings.json",
            work=base / "work",
            operation_logs=base / "logs",
            event_logs=base / "events",
            mihomo=package_root / "bin" / "mihomo.exe",
            mihomo_digest=package_root / "bin" / "mihomo.sha256",
            project_root=project_root,
        )

    def validate(self) -> tuple[ManagedPathGuard, ManagedPathGuard]:
        project_root = self.project_root or self.base.parent
        project_guard = ManagedPathGuard(project_root)
        project_guard.validate(project_root, kind="directory", allow_missing=False)
        project_guard.validate(self.base, kind="directory")
        project_guard.ensure_directory(self.base)

        runtime_guard = ManagedPathGuard(self.base)
        runtime_guard.validate(self.base, kind="directory", allow_missing=False)
        for path, kind in (
            (self.connections, "file"),
            (self.settings, "file"),
            (self.work, "directory"),
            (self.operation_logs, "directory"),
            (self.event_logs, "directory"),
        ):
            runtime_guard.validate(path, kind=kind)
        project_guard.validate(self.mihomo, kind="file")
        project_guard.validate(self.mihomo_digest, kind="file")
        return project_guard, runtime_guard


@dataclass(frozen=True, slots=True)
class MonitorSettings:
    schema_version: int = 1
    theme_key: str = DEFAULT_THEME_KEY
    start_minimized_to_tray: bool = False
    bot_token: str = ""
    chat_id: int | None = None
    check_interval_seconds: int = 180
    parallel_checks: int = 5
    retry_delay_seconds: int = 15
    max_attempts: int = 2
    mihomo_start_timeout_seconds: int = 10
    probe_timeout_seconds: int = 20
    mihomo_stop_grace_seconds: int = 5
    operation_log_retention_days: int = 7
    event_log_retention_days: int = 30
    primary_ip_url: str = "https://api.ipify.org"
    secondary_ip_url: str = "https://ifconfig.me/ip"
    connectivity_check_url: str = "https://www.gstatic.com/generate_204"
    max_redirects: int = 3
    window_x: int | None = None
    window_y: int | None = None
    window_width: int = 920
    window_height: int = 560

    def validate(self) -> MonitorSettings:
        if self.schema_version != 1:
            raise SettingsError("Unsupported settings schema version.")
        if not isinstance(self.theme_key, str) or self.theme_key not in THEMES:
            raise SettingsError("theme_key must name an available visual theme.")
        if not isinstance(self.start_minimized_to_tray, bool):
            raise SettingsError("start_minimized_to_tray must be a boolean.")
        ranges = {
            "check_interval_seconds": (10, 86400),
            "parallel_checks": (1, 8),
            "retry_delay_seconds": (1, 3600),
            "max_attempts": (1, 5),
            "mihomo_start_timeout_seconds": (1, 120),
            "probe_timeout_seconds": (1, 300),
            "mihomo_stop_grace_seconds": (1, 60),
            "operation_log_retention_days": (1, 365),
            "event_log_retention_days": (1, 3650),
            "max_redirects": (0, 10),
            "window_width": (320, 10000),
            "window_height": (240, 10000),
        }
        for name, (minimum, maximum) in ranges.items():
            value = getattr(self, name)
            if (
                isinstance(value, bool)
                or not isinstance(value, int)
                or not minimum <= value <= maximum
            ):
                raise SettingsError(f"{name} must be between {minimum} and {maximum}.")
        if (self.window_x is None) != (self.window_y is None):
            raise SettingsError("window_x and window_y must both be set or both be null.")
        for name in ("window_x", "window_y"):
            value = getattr(self, name)
            if value is not None and (
                isinstance(value, bool)
                or not isinstance(value, int)
                or not -100000 <= value <= 100000
            ):
                raise SettingsError(f"{name} must be null or a valid screen coordinate.")
        for name in ("primary_ip_url", "secondary_ip_url", "connectivity_check_url"):
            value = getattr(self, name)
            parsed = urlsplit(value)
            if (
                parsed.scheme != "https"
                or not parsed.hostname
                or parsed.username
                or parsed.password
            ):
                raise SettingsError(f"{name} must be an HTTPS URL without credentials.")
        return self


class SettingsRepository:
    def __init__(self, path: Path, guard: ManagedPathGuard | None = None) -> None:
        self._path = path
        self._guard = guard or ManagedPathGuard(path.parent)

    def load(self) -> MonitorSettings:
        self._path = self._guard.validate(self._path, kind="file")
        if not self._path.exists():
            settings = MonitorSettings().validate()
            self.save(settings)
            return settings
        try:
            self._path = self._guard.validate(self._path, kind="file", allow_missing=False)
            raw = json.loads(self._path.read_text(encoding="utf-8"))
            if not isinstance(raw, dict):
                raise SettingsError("Settings root must be an object.")
            raw.pop("log_expanded", None)
            allowed = set(MonitorSettings.__dataclass_fields__)
            unknown = set(raw) - allowed
            if unknown:
                raise SettingsError(f"Unknown settings fields: {', '.join(sorted(unknown))}.")
            return MonitorSettings(**raw).validate()
        except (OSError, json.JSONDecodeError, TypeError) as error:
            raise SettingsError("Settings file is not valid UTF-8 JSON.") from error

    def save(self, settings: MonitorSettings) -> None:
        atomic_write_json(self._path, asdict(settings.validate()), self._guard)
