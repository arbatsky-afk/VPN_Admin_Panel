"""Ordered application shutdown protocol without Qt window responsibilities."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Protocol


class ApplicationShutdownBlocker(Enum):
    """A collaborator that could not confirm safe application shutdown."""

    DEPLOY_OPERATION_ACTIVE = "deploy_operation_active"
    TELEGRAM_STOP_FAILED = "telegram_stop_failed"
    SUBSCRIPTIONS_SHUTDOWN_FAILED = "subscriptions_shutdown_failed"
    USERS_CANCEL_FAILED = "users_cancel_failed"
    DIRECT_RUNNER_TIMEOUT = "direct_runner_timeout"
    BACKUP_RESTORE_SHUTDOWN_FAILED = "backup_restore_shutdown_failed"


class DirectRunnerKind(Enum):
    """Identity of a runner stopped directly by the application shell."""

    INVENTORY = "inventory"
    MANAGEMENT = "management"
    TELEGRAM_INVENTORY = "telegram_inventory"
    TELEGRAM_MANAGEMENT = "telegram_management"


@dataclass(frozen=True)
class ApplicationShutdownCompleted:
    """All shutdown phases confirmed completion."""


@dataclass(frozen=True)
class ApplicationShutdownBlocked:
    """Shutdown stopped at one fail-closed barrier."""

    blocker: ApplicationShutdownBlocker
    direct_runner: DirectRunnerKind | None = None

    def __post_init__(self) -> None:
        is_direct_runner_blocker = self.blocker is ApplicationShutdownBlocker.DIRECT_RUNNER_TIMEOUT
        if is_direct_runner_blocker != (self.direct_runner is not None):
            raise ValueError("direct_runner must be set exactly for a direct runner timeout")


type ApplicationShutdownOutcome = ApplicationShutdownCompleted | ApplicationShutdownBlocked


class _DeployController(Protocol):
    def can_close(self) -> bool: ...


class _TelegramController(Protocol):
    def start(self) -> None: ...

    def stop(self) -> bool: ...


class _SubscriptionsController(Protocol):
    def shutdown(self) -> bool: ...


class _UsersController(Protocol):
    def cancel(self) -> bool: ...


class _DirectRunner(Protocol):
    @property
    def is_running(self) -> bool: ...

    def requestInterruption(self) -> None: ...

    def wait(self, milliseconds: int) -> bool: ...


class _BackupRestoreController(Protocol):
    def shutdown(self) -> bool: ...


class ApplicationShutdownCoordinator:
    """Run the fixed fail-closed shutdown sequence for Admin Panel."""

    DIRECT_RUNNER_WAIT_TIMEOUT_MS = 5_000

    def __init__(
        self,
        *,
        deploy_controller: _DeployController,
        telegram_controller: _TelegramController,
        subscriptions_controller: _SubscriptionsController,
        users_controller: _UsersController,
        inventory_runner: _DirectRunner,
        management_runner: _DirectRunner,
        telegram_inventory_runner: _DirectRunner,
        telegram_management_runner: _DirectRunner,
        backup_restore_controller: _BackupRestoreController,
    ) -> None:
        self._deploy_controller = deploy_controller
        self._telegram_controller = telegram_controller
        self._subscriptions_controller = subscriptions_controller
        self._users_controller = users_controller
        self._direct_runners = (
            (DirectRunnerKind.INVENTORY, inventory_runner),
            (DirectRunnerKind.MANAGEMENT, management_runner),
            (DirectRunnerKind.TELEGRAM_INVENTORY, telegram_inventory_runner),
            (DirectRunnerKind.TELEGRAM_MANAGEMENT, telegram_management_runner),
        )
        self._backup_restore_controller = backup_restore_controller

    def shutdown(self) -> ApplicationShutdownOutcome:
        if not self._deploy_controller.can_close():
            return ApplicationShutdownBlocked(ApplicationShutdownBlocker.DEPLOY_OPERATION_ACTIVE)
        if not self._telegram_controller.stop():
            return ApplicationShutdownBlocked(ApplicationShutdownBlocker.TELEGRAM_STOP_FAILED)
        if not self._subscriptions_controller.shutdown():
            return self._blocked_after_telegram(
                ApplicationShutdownBlocker.SUBSCRIPTIONS_SHUTDOWN_FAILED
            )
        if not self._users_controller.cancel():
            return self._blocked_after_telegram(ApplicationShutdownBlocker.USERS_CANCEL_FAILED)

        for _kind, runner in self._direct_runners:
            if runner.is_running:
                runner.requestInterruption()
        for kind, runner in self._direct_runners:
            if runner.is_running and not runner.wait(self.DIRECT_RUNNER_WAIT_TIMEOUT_MS):
                return self._blocked_after_telegram(
                    ApplicationShutdownBlocker.DIRECT_RUNNER_TIMEOUT,
                    direct_runner=kind,
                )

        if not self._backup_restore_controller.shutdown():
            return self._blocked_after_telegram(
                ApplicationShutdownBlocker.BACKUP_RESTORE_SHUTDOWN_FAILED
            )
        return ApplicationShutdownCompleted()

    def _blocked_after_telegram(
        self,
        blocker: ApplicationShutdownBlocker,
        *,
        direct_runner: DirectRunnerKind | None = None,
    ) -> ApplicationShutdownBlocked:
        self._telegram_controller.start()
        return ApplicationShutdownBlocked(blocker, direct_runner)
