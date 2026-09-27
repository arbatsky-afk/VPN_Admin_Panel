from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import replace
from pathlib import Path

from monitor.domain import ConnectionSnapshot, ImportSummary
from monitor.importer import ConnectionImporter
from monitor.logs import JsonlLog
from monitor.mihomo import MihomoAdapter
from monitor.probe import ProbeService
from monitor.repository import ConnectionRepository
from monitor.scheduler import MonitoringScheduler
from monitor.settings import MonitorPaths, MonitorSettings, SettingsRepository
from monitor.telegram import (
    RECONNECT_BACKOFF_SECONDS,
    TelegramClientFactory,
    TelegramManager,
    TelegramStatus,
)


class MonitorCoordinator:
    def __init__(
        self,
        paths: MonitorPaths,
        on_snapshot: Callable[[ConnectionSnapshot], None] | None = None,
        on_cycle: Callable[[bool, str | None], None] | None = None,
        on_telegram_status: Callable[[TelegramStatus], None] | None = None,
        telegram_client_factory: TelegramClientFactory | None = None,
        telegram_reconnect_delays: Sequence[float] = RECONNECT_BACKOFF_SECONDS,
    ) -> None:
        self.paths = paths
        self._project_guard, self._runtime_guard = paths.validate()
        self.settings_repository = SettingsRepository(paths.settings, self._runtime_guard)
        self.connection_repository = ConnectionRepository(paths.connections, self._runtime_guard)
        self.importer = ConnectionImporter()
        self._on_snapshot = on_snapshot
        self._on_cycle = on_cycle
        self._on_telegram_status = on_telegram_status
        self._telegram_client_factory = telegram_client_factory
        self._telegram_reconnect_delays = tuple(telegram_reconnect_delays)
        self.settings = self.settings_repository.load()
        self.settings_recovery_error: str | None = None
        self._build_runtime()

    def _build_runtime(self) -> None:
        operation_log = JsonlLog(
            self.paths.operation_logs,
            "operations",
            self.settings.operation_log_retention_days,
            self._runtime_guard,
        )
        event_log = JsonlLog(
            self.paths.event_logs,
            "events",
            self.settings.event_log_retention_days,
            self._runtime_guard,
        )
        telegram = TelegramManager(
            self.settings.bot_token,
            self.settings.chat_id,
            operation_log,
            self._on_telegram_status,
            self._telegram_client_factory,
            self._telegram_reconnect_delays,
        )
        mihomo = MihomoAdapter(
            self.paths.mihomo,
            self.paths.mihomo_digest,
            self.paths.work,
            self.settings.mihomo_start_timeout_seconds,
            self.settings.mihomo_stop_grace_seconds,
            self._runtime_guard,
            self._project_guard,
        )
        mihomo.prepare()
        mihomo.cleanup_stale_directories()
        probe = ProbeService(mihomo, self.settings)
        scheduler = MonitoringScheduler(
            self.connection_repository,
            self.settings,
            probe.check,
            operation_log,
            event_log,
            self._on_snapshot,
            self._on_cycle,
            telegram.submit,
        )
        # Constructors do not start workers. Publish only a complete runtime.
        self.operation_log, self.event_log = operation_log, event_log
        self.telegram, self.mihomo, self.scheduler = telegram, mihomo, scheduler

    def start(self) -> None:
        if self.settings_recovery_error is not None:
            raise RuntimeError(self.settings_recovery_error)
        self.telegram.start()
        self.scheduler.start()

    def stop(self) -> bool:
        timeout = self.settings.probe_timeout_seconds + self.settings.mihomo_stop_grace_seconds + 5
        try:
            scheduler_stopped = self.scheduler.stop(timeout)
        finally:
            telegram_stopped = self.telegram.stop()
        return scheduler_stopped and telegram_stopped

    def import_file(self, path: Path) -> ImportSummary:
        existing = self.connection_repository.load()
        summary = self.importer.parse_file(path, existing)
        if summary.connections:
            self.connection_repository.append(summary.connections)
            self.scheduler.refresh_connections()
        self.operation_log.write(
            "connections_imported",
            imported=summary.imported,
            duplicate=summary.duplicate,
            invalid=summary.invalid,
            unsupported=summary.unsupported,
        )
        return summary

    def delete(self, connection_id: str) -> None:
        self.connection_repository.delete(connection_id)
        self.scheduler.refresh_connections()
        self.operation_log.write("connection_deleted", connection_id=connection_id)

    def set_enabled(self, connection_id: str, enabled: bool) -> None:
        self.connection_repository.set_enabled(connection_id, enabled)
        self.scheduler.refresh_connections()
        self.operation_log.write(
            "connection_enabled_changed", connection_id=connection_id, enabled=enabled
        )

    def save_settings(self, settings: MonitorSettings) -> None:
        settings = settings.validate()
        if self.settings_recovery_error is not None:
            raise RuntimeError(self.settings_recovery_error)
        was_running = self.scheduler.running
        telegram_was_running = self.telegram.running
        previous_settings = self.settings
        previous_runtime = (
            self.operation_log,
            self.event_log,
            self.telegram,
            self.mihomo,
            self.scheduler,
        )
        try:
            stopped = self.stop()
        except Exception as error:
            raise self._settings_restart_required("Runtime stop failed.") from error
        if not stopped:
            raise self._settings_restart_required("Runtime stop did not complete in time.")

        self.settings = settings
        save_attempted = False
        start_attempted = False
        try:
            self._build_runtime()
            save_attempted = True
            self.settings_repository.save(settings)
            start_attempted = True
            self._resume_runtime(was_running, telegram_was_running)
        except Exception as error:
            # Keep ownership of any candidate workers until their stop is confirmed.
            candidate_stopped = True
            if start_attempted:
                try:
                    candidate_stopped = self.stop()
                except Exception:
                    candidate_stopped = False
            disk_restored = True
            if save_attempted:
                try:
                    # A save can fail after os.replace; inspect before retrying writes.
                    try:
                        disk_restored = self.settings_repository.load() == previous_settings
                    except Exception:
                        disk_restored = False
                    if not disk_restored:
                        self.settings_repository.save(previous_settings)
                        disk_restored = True
                except Exception:
                    disk_restored = False
            if not candidate_stopped:
                raise self._settings_restart_required(
                    "The replacement runtime could not be stopped."
                    + (
                        " Previous settings could not be restored on disk."
                        if not disk_restored
                        else ""
                    )
                ) from error
            self.settings = previous_settings
            (
                self.operation_log,
                self.event_log,
                self.telegram,
                self.mihomo,
                self.scheduler,
            ) = previous_runtime
            if not disk_restored:
                raise self._settings_restart_required(
                    "Previous settings could not be restored on disk."
                ) from error
            try:
                self._resume_runtime(was_running, telegram_was_running)
            except Exception as recovery_error:
                try:
                    self.stop()
                except Exception:
                    pass
                raise self._settings_restart_required(
                    "The previous runtime could not be restarted."
                ) from recovery_error
            raise RuntimeError(
                "Settings were not applied. Previous settings and runtime were restored. "
                f"{type(error).__name__}: {error}"
            ) from error

    def _resume_runtime(self, scheduler_running: bool, telegram_running: bool) -> None:
        if scheduler_running:
            self.start()
        elif telegram_running:
            self.telegram.start()

    def _settings_restart_required(self, reason: str) -> RuntimeError:
        self.settings_recovery_error = (
            f"Settings were not applied. {reason} "
            "Monitoring is stopped or still stopping; automatic recovery is disabled. "
            "Exit and restart Monitor."
        )
        return RuntimeError(self.settings_recovery_error)

    def save_theme_key(self, theme_key: str) -> MonitorSettings:
        settings = replace(self.settings, theme_key=theme_key).validate()
        self.settings_repository.save(settings)
        self.settings = settings
        return settings

    def save_window_geometry(
        self,
        x: int,
        y: int,
        width: int,
        height: int,
    ) -> None:
        settings = replace(
            self.settings,
            window_x=x,
            window_y=y,
            window_width=width,
            window_height=height,
        ).validate()
        self.settings_repository.save(settings)
        self.settings = settings

    def snapshots(self) -> tuple[ConnectionSnapshot, ...]:
        return self.scheduler.snapshots()

    def check_now(self) -> bool:
        if self.settings_recovery_error is not None:
            return False
        return self.scheduler.request_check_now()
