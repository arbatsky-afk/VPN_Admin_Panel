"""Authorized Telegram menu and operation orchestration for Admin Panel."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Literal

from PySide6.QtCore import QObject, QTimer, Signal

from app.services.inventory import InventorySnapshot
from app.services.management import (
    BaseSecurityManagementStatus,
    DockerManagementStatus,
    Hysteria2ManagementStatus,
    MieruManagementStatus,
    NetdataManagementStatus,
    NginxManagementStatus,
    ServiceManagementStatus,
    XrayManagementStatus,
)
from app.services.operational_telegram_pairing import (
    OperationalTelegramPairing,
    PairingDecisionKind,
)
from app.services.operational_telegram_settings import (
    OperationalTelegramSettings,
    load_operational_telegram_settings,
    save_operational_telegram_settings,
)
from app.services.settings_manager import SettingsManager
from app.services.telegram_audit_log import TelegramAuditLog

from . import operational_telegram_menu as menu
from .inventory_runner import InventoryRequestContext, InventoryRunner
from .management_runner import (
    ManagementOperationFailure,
    ManagementOperationRequest,
    ManagementRunner,
    management_failure_message,
)
from .operation_gate import OperationContext, OperationGate
from .operational_telegram_callback_store import (
    CallbackContext,
    CallbackResolutionKind,
    OperationalTelegramCallbackStore,
)
from .operational_telegram_menu import TelegramServiceTarget
from .operational_telegram_transport import (
    OperationalTelegramManager,
    OperationalTelegramStatus,
    OperationalTelegramUpdate,
    TelegramButton,
    TelegramKeyboard,
    TelegramOutbound,
)

COMMAND_MAX_AGE_SECONDS = 60
PendingPhase = Literal[
    "inventory",
    "action",
    "reboot",
    "reconciliation_inventory",
    "reconciliation_inspect",
]


@dataclass(frozen=True, slots=True)
class _PendingMessage:
    context: OperationContext
    chat_id: int
    user_id: int
    message_id: int | None
    server_ip: str
    target: TelegramServiceTarget | None = None
    action: str = ""
    phase: PendingPhase = "inventory"
    original_outcome: str = ""
    reason_code: str = ""
    safe_message: str = ""


class OperationalTelegramController(QObject):
    """Authorize Telegram input and reuse the panel's typed operation boundary."""

    transport_status_received = Signal(object)
    update_received = Signal(object)
    authorized_user_detected = Signal(int)
    management_status_confirmed = Signal(object, object)

    def __init__(
        self,
        project_directory: Path,
        settings_manager: SettingsManager,
        gate: OperationGate,
        inventory_runner: InventoryRunner,
        management_runner: ManagementRunner,
        *,
        recent_servers: Callable[[], Sequence[dict[str, str]]],
        cancel_users: Callable[[], bool],
        write_result: Callable[[str, str], None],
        set_status: Callable[[OperationalTelegramStatus], None],
        parent: QObject | None = None,
        manager_factory: Callable[..., OperationalTelegramManager] = OperationalTelegramManager,
    ) -> None:
        super().__init__(parent)
        self.project_directory = project_directory
        self.settings_manager = settings_manager
        self.gate = gate
        self.inventory_runner = inventory_runner
        self.management_runner = management_runner
        self.recent_servers = recent_servers
        self.cancel_users = cancel_users
        self.write_result = write_result
        self.set_status = set_status
        self.manager_factory = manager_factory
        self.settings, self.settings_error = load_operational_telegram_settings(settings_manager)
        self.audit_log = self._new_audit_log(self.settings.audit_log_retention_days)
        self.manager: OperationalTelegramManager | None = None
        self._callback_store = OperationalTelegramCallbackStore()
        self._pending: _PendingMessage | None = None
        self._pairing = OperationalTelegramPairing()
        self._detected_user_id: int | None = None
        self.transport_status_received.connect(self._transport_status_changed)
        self.update_received.connect(self.handle_update)
        self.inventory_runner.completed.connect(self.inventory_completed)
        self.inventory_runner.failed.connect(self.inventory_failed)
        self.management_runner.completed.connect(self.management_completed)
        self.management_runner.failed.connect(self.management_failed)

    @property
    def detected_user_id(self) -> int | None:
        return self._detected_user_id

    def start(self) -> None:
        if self.settings_error:
            self._write_audit("configuration_error", reason="invalid_schema")
            self.set_status(OperationalTelegramStatus.DISABLED)
            return
        if not self.settings.configured:
            self.set_status(OperationalTelegramStatus.DISABLED)
        self._create_manager()
        assert self.manager is not None
        self.manager.start()

    def stop(self, timeout: float = 5.0) -> bool:
        manager = self.manager
        if manager is None:
            return True
        return manager.stop(timeout)

    def apply_settings(self, settings: OperationalTelegramSettings) -> tuple[bool, str]:
        if (
            self.settings.bot_token != settings.bot_token
            or self.settings.chat_id != settings.chat_id
        ):
            settings = OperationalTelegramSettings(
                settings.bot_token,
                settings.chat_id,
                None,
                settings.audit_log_retention_days,
            )
        if not self.stop():
            return False, "Could not stop the current Telegram transport safely."
        previous_raw = self.settings_manager.get("telegram_operations")
        had_previous = previous_raw is not None
        try:
            save_operational_telegram_settings(self.settings_manager, settings)
        except OSError as error:
            if had_previous:
                self.settings_manager.set("telegram_operations", previous_raw)
            else:
                self.settings_manager.unset("telegram_operations")
            if self.manager is not None:
                self.manager.start()
            return False, f"Could not save Telegram settings: {error}"
        self.settings = settings
        self.settings_error = None
        self._invalidate_sessions()
        self.audit_log = self._new_audit_log(settings.audit_log_retention_days)
        self._create_manager()
        assert self.manager is not None
        self.manager.start()
        return True, ""

    def begin_identification(self) -> tuple[bool, str]:
        if not self.settings.configured:
            return False, "Save Bot token and Chat ID before detecting a user."
        if self.settings.authorized_user_id is not None:
            return False, "Authorized User ID is already configured."
        assert self.settings.chat_id is not None
        challenge = self._pairing.begin(self.settings.chat_id)
        QTimer.singleShot(
            challenge.ttl_seconds * 1000,
            lambda: self._expire_identification(challenge.generation),
        )
        self._detected_user_id = None
        self._write_audit("pairing_started", chat_id=self.settings.chat_id)
        return True, challenge.command

    def handle_update(self, update: object) -> None:
        if not isinstance(update, OperationalTelegramUpdate):
            return
        self._callback_store.purge_expired()
        if self._update_is_stale(update):
            self._audit_rejected(update, "stale_update")
            return
        if self._handle_pairing(update):
            return
        if not self._authorized(update):
            self._audit_rejected(update, "unauthorized")
            return
        self._write_audit(
            "command_accepted",
            chat_id=update.chat_id,
            user_id=update.user_id,
            update_id=update.update_id,
            route="callback" if update.callback_data is not None else "command",
        )
        command = update.text.split("@", 1)[0] if update.text and " " not in update.text else ""
        if command in {"/start", "/menu"}:
            self._show_home(update)
            return
        if update.callback_query_id is not None:
            self._handle_callback(update)

    def _handle_pairing(self, update: OperationalTelegramUpdate) -> bool:
        if self.settings.authorized_user_id is not None or not self.settings.configured:
            return False
        decision = self._pairing.evaluate(
            chat_id=update.chat_id,
            user_id=update.user_id,
            text=update.text,
        )
        if decision.kind is PairingDecisionKind.NOT_APPLICABLE:
            return False
        if decision.kind is PairingDecisionKind.EXPIRED:
            self._write_audit("pairing_expired", chat_id=self.settings.chat_id)
            return True
        if decision.kind is PairingDecisionKind.THROTTLED:
            return True
        if decision.kind is PairingDecisionKind.REJECTED:
            self._write_audit(
                "pairing_attempt_rejected",
                chat_id=update.chat_id,
                user_id=update.user_id,
                update_id=update.update_id,
                failed_attempts=decision.failed_attempts,
                reason="invalid_identify",
            )
            return True
        if decision.kind is PairingDecisionKind.INVALIDATED:
            self._write_audit(
                "pairing_invalidated",
                chat_id=update.chat_id,
                user_id=update.user_id,
                update_id=update.update_id,
                failed_attempts=decision.failed_attempts,
                reason="attempt_limit",
            )
            self._submit(
                update,
                "Pairing cancelled after too many attempts. "
                "Start Detect User ID again in Admin Panel.",
            )
            return True
        if decision.kind is not PairingDecisionKind.ACCEPTED:
            return True
        self._detected_user_id = update.user_id
        self._write_audit("pairing_completed", chat_id=update.chat_id, user_id=update.user_id)
        self.authorized_user_detected.emit(update.user_id)
        self._submit(update, "User detected. Return to Settings and click Save.")
        return True

    def _handle_callback(self, update: OperationalTelegramUpdate) -> None:
        token = update.callback_data or ""
        resolution = self._callback_store.resolve(
            token,
            chat_id=update.chat_id,
            user_id=update.user_id,
            server_catalog=self._server_catalog(),
        )
        if resolution.kind is CallbackResolutionKind.EXPIRED:
            self._reject(
                update,
                "This menu has expired. Use /menu to start again.",
                "expired_callback",
            )
            return
        if resolution.kind is CallbackResolutionKind.SERVER_REMOVED:
            self._reject(
                update,
                "This server is no longer available in Admin Panel.",
                "server_removed",
            )
            return
        if resolution.kind is CallbackResolutionKind.STALE_SERVICES:
            self._reject(
                update,
                "This Services menu has expired. Refresh Services.",
                "stale_services",
            )
            return
        callback = resolution.context
        if callback is None:
            return
        if callback.kind in {"home", "servers"}:
            if callback.kind == "home":
                self._show_home(update)
            else:
                self._show_servers(update)
        elif callback.kind == "server":
            self._show_server(update, callback.server_ip)
        elif callback.kind == "services":
            self._start_inventory(update, callback.server_ip)
        elif callback.kind == "service_group" and callback.targets:
            self._show_service_group(
                update,
                callback.server_ip,
                callback.targets,
                callback.generation,
            )
        elif callback.kind == "service" and callback.target is not None:
            self._show_service(update, callback.server_ip, callback.target, callback.generation)
        elif callback.kind == "action" and callback.target is not None:
            self._start_action(update, callback)
        elif callback.kind == "reboot":
            self._show_reboot_confirmation(update, callback.server_ip)
        elif callback.kind == "confirm_reboot":
            self._start_reboot(update, callback.server_ip)
        elif callback.kind == "cancel":
            self._show_server(update, callback.server_ip)

    def _show_home(self, update: OperationalTelegramUpdate) -> None:
        self._submit_menu(update, menu.home_menu())

    def _show_servers(self, update: OperationalTelegramUpdate) -> None:
        self._submit_menu(update, menu.servers_menu(self._catalog()))

    def _show_server(self, update: OperationalTelegramUpdate, server_ip: str) -> None:
        self._submit_menu(update, menu.server_menu(self._catalog(), server_ip))

    def _start_inventory(self, update: OperationalTelegramUpdate, server_ip: str) -> None:
        if not self._server_exists(server_ip):
            self._reject(update, "Server is no longer available.", "server_removed")
            return
        context = self.gate.begin("Telegram Inventory", scope="inventory", server_ip=server_ip)
        if context is None:
            self._reject(update, "Admin Panel is busy. Try again later.", "busy")
            return
        if not self.cancel_users():
            self.gate.finish(context)
            self._reject(
                update,
                "Could not stop the current Users operation safely.",
                "users_busy",
            )
            return
        self._callback_store.advance_services_generation(server_ip)
        self._callback_store.invalidate_server_callbacks(server_ip)
        request = InventoryRequestContext(
            context.token, "telegram", f"telegram:{update.user_id}", server_ip
        )
        self._pending = _PendingMessage(
            context, update.chat_id, update.user_id, update.message_id, server_ip
        )
        if not self.inventory_runner.start_collection(request):
            self._pending = None
            self.gate.finish(context)
            self._reject(update, "Inventory could not be started.", "runner_busy")
            return
        self._write_audit(
            "operation_started",
            request_token=context.token,
            server_ip=server_ip,
            action="inventory",
        )
        self._submit(update, f"Loading Services for {self._server_label(server_ip)}…")

    def inventory_completed(self, request: object, snapshot: object) -> None:
        reconciliation = self._matching_reconciliation_inventory(request)
        if reconciliation is not None:
            if (
                not isinstance(snapshot, InventorySnapshot)
                or snapshot.server_ip != reconciliation.server_ip
            ):
                self._finish_management_reconciliation(
                    reconciliation,
                    failure="Inventory reconciliation returned an invalid snapshot.",
                )
                return
            self._continue_management_reconciliation(reconciliation, snapshot)
            return
        pending = self._matching_inventory(request)
        if pending is None or not isinstance(snapshot, InventorySnapshot):
            return
        targets = menu.service_targets(snapshot)
        generation = self._callback_store.services_generation(pending.server_ip)
        update = self._pending_update(pending)
        self.write_result(f"=== Telegram Inventory {pending.server_ip}: successful ===", "success")
        projected = menu.services_menu(
            self._catalog(),
            pending.server_ip,
            targets,
            generation,
        )
        self._send_pending(
            pending,
            projected.text,
            self._materialize_keyboard(update, projected),
        )
        self.gate.finish(pending.context)
        self._pending = None
        self._write_audit(
            "operation_completed",
            request_token=pending.context.token,
            server_ip=pending.server_ip,
            action="inventory",
            outcome="success",
            service_count=len(targets),
        )

    def inventory_failed(self, request: object, message: str) -> None:
        reconciliation = self._matching_reconciliation_inventory(request)
        if reconciliation is not None:
            self._finish_management_reconciliation(
                reconciliation,
                failure="Inventory reconciliation could not be completed.",
            )
            return
        pending = self._matching_inventory(request)
        if pending is None:
            return
        safe = "Could not collect Inventory for the selected server."
        self.write_result(f"=== Telegram Inventory: failed — {message} ===", "error")
        self._send_pending(pending, f"❌ Failed — {safe}")
        self.gate.finish(pending.context)
        self._pending = None
        self._write_audit(
            "operation_completed",
            request_token=pending.context.token,
            server_ip=pending.server_ip,
            action="inventory",
            outcome="error",
            safe_message=safe,
        )

    def _show_service(
        self,
        update: OperationalTelegramUpdate,
        server_ip: str,
        target: TelegramServiceTarget,
        generation: int,
    ) -> None:
        self._submit_menu(
            update,
            menu.service_menu(self._catalog(), server_ip, target, generation),
        )

    def _show_service_group(
        self,
        update: OperationalTelegramUpdate,
        server_ip: str,
        targets: tuple[TelegramServiceTarget, ...],
        generation: int,
    ) -> None:
        self._submit_menu(
            update,
            menu.service_group_menu(
                self._catalog(),
                server_ip,
                targets,
                generation,
            ),
        )

    def _start_action(self, update: OperationalTelegramUpdate, callback: CallbackContext) -> None:
        target = callback.target
        action = callback.action
        if target is None or action not in menu.ALLOWED_ACTIONS or action not in target.actions:
            self._reject(update, "Action is not allowed.", "action_not_allowed")
            return
        if not self._server_exists(callback.server_ip):
            self._reject(update, "Server is no longer available.", "server_removed")
            return
        context = self.gate.begin(
            f"Telegram {target.display_name} {action}",
            scope="management",
            server_ip=callback.server_ip,
        )
        if context is None:
            self._reject(update, "Admin Panel is busy. Try again later.", "busy")
            return
        if not self.cancel_users():
            self.gate.finish(context)
            self._reject(
                update,
                "Could not stop the current Users operation safely.",
                "users_busy",
            )
            return
        request = ManagementOperationRequest(
            context.token,
            target.kind,  # type: ignore[arg-type]
            callback.server_ip,
            action=action,
            service=target.service,
        )
        self._pending = _PendingMessage(
            context,
            update.chat_id,
            update.user_id,
            update.message_id,
            callback.server_ip,
            target,
            action,
            "action",
        )
        if not self.management_runner.start_operation(request):
            self._pending = None
            self.gate.finish(context)
            self._reject(update, "Operation could not be started.", "runner_busy")
            return
        self._write_audit(
            "operation_started",
            request_token=context.token,
            server_ip=callback.server_ip,
            component=target.component_id,
            service=target.unit,
            action=action,
        )
        self._submit(update, f"Running {action} for {target.display_name}…")

    def _show_reboot_confirmation(self, update: OperationalTelegramUpdate, server_ip: str) -> None:
        self._submit_menu(
            update,
            menu.reboot_menu(self._catalog(), server_ip),
        )

    def _start_reboot(self, update: OperationalTelegramUpdate, server_ip: str) -> None:
        if not self._server_exists(server_ip):
            self._reject(update, "Server is no longer available.", "server_removed")
            return
        context = self.gate.begin("Telegram server reboot", scope="server", server_ip=server_ip)
        if context is None:
            self._reject(update, "Admin Panel is busy. Try again later.", "busy")
            return
        if not self.cancel_users():
            self.gate.finish(context)
            self._reject(
                update,
                "Could not stop the current Users operation safely.",
                "users_busy",
            )
            return
        request = ManagementOperationRequest(context.token, "server-reboot", server_ip)
        self._pending = _PendingMessage(
            context,
            update.chat_id,
            update.user_id,
            update.message_id,
            server_ip,
            action="reboot",
            phase="reboot",
        )
        if not self.management_runner.start_operation(request):
            self._pending = None
            self.gate.finish(context)
            self._reject(update, "Reboot could not be started.", "runner_busy")
            return
        self._write_audit(
            "operation_started",
            request_token=context.token,
            server_ip=server_ip,
            action="reboot",
        )
        self._submit(update, f"Scheduling reboot for {self._server_label(server_ip)}…")

    def management_completed(self, request: object, status: object) -> None:
        pending = self._matching_management(request)
        if pending is None or not isinstance(request, ManagementOperationRequest):
            return
        if pending.phase == "reconciliation_inspect":
            self._finish_management_reconciliation(pending, status=status, request=request)
            return
        if request.kind == "server-reboot":
            outcome = "success"
            safe_status = "reboot scheduled"
            user_text = "✅ Successful — reboot scheduled. SSH will be unavailable briefly."
        else:
            state = self._service_state(status, pending.target)
            expected = "inactive" if pending.action == "stop" else "active"
            outcome = "success" if state == expected else "warning"
            safe_status = f"service state: {state}"
            label = "✅ Successful" if outcome == "success" else "⚠️ Completed with warning"
            user_text = (
                f"{label} — {pending.action.capitalize()} "
                f"{pending.target.display_name}: {safe_status}."
            )
            self.management_status_confirmed.emit(request, status)
        self.write_result(
            f"=== Telegram {pending.action} {pending.server_ip}: {outcome}; {safe_status} ===",
            outcome,
        )
        self._send_pending(pending, f"{user_text}\n{self._server_label(pending.server_ip)}")
        self.gate.finish(pending.context)
        self._pending = None
        self._write_audit(
            "operation_completed",
            request_token=pending.context.token,
            server_ip=pending.server_ip,
            component=pending.target.component_id if pending.target else None,
            action=pending.action,
            outcome=outcome,
            safe_status=safe_status,
        )

    def management_failed(self, request: object, failure: object) -> None:
        pending = self._matching_management(request)
        if pending is None:
            return
        if pending.phase == "reconciliation_inspect":
            self._finish_management_reconciliation(
                pending,
                failure="Mandatory component inspect could not be completed.",
            )
            return
        typed = failure if isinstance(failure, ManagementOperationFailure) else None
        outcome = typed.outcome if typed is not None else "error"
        reason = typed.reason_code if typed is not None else "validation_failed"
        safe_message = management_failure_message(failure)
        if (
            typed is not None
            and typed.outcome == "unknown"
            and pending.phase == "action"
            and pending.target is not None
        ):
            self._start_management_reconciliation(
                pending,
                outcome=typed.outcome,
                reason_code=typed.reason_code,
                safe_message=typed.safe_message,
            )
            return
        label = "❓ Result unknown — check before retry" if outcome == "unknown" else "❌ Failed"
        gui_outcome = "warning" if outcome == "unknown" else "error"
        self.write_result(
            f"=== Telegram {pending.action}: {outcome} — {safe_message} ===",
            gui_outcome,
        )
        self._send_pending(
            pending,
            f"{label} — {safe_message}\n{self._server_label(pending.server_ip)}",
        )
        self.gate.finish(pending.context)
        self._pending = None
        self._write_audit(
            "operation_completed",
            request_token=pending.context.token,
            server_ip=pending.server_ip,
            component=pending.target.component_id if pending.target else None,
            action=pending.action,
            outcome=outcome,
            reason_code=reason,
            safe_message=safe_message,
        )

    def _start_management_reconciliation(
        self,
        pending: _PendingMessage,
        *,
        outcome: str,
        reason_code: str,
        safe_message: str,
    ) -> None:
        target = pending.target
        if target is None:
            return
        transitioned = self.gate.transition(
            pending.context,
            f"Telegram {target.display_name} reconciliation (Inventory)",
            scope="inventory",
            server_ip=pending.server_ip,
        )
        if transitioned is None:
            return
        reconciliation = replace(
            pending,
            context=transitioned,
            phase="reconciliation_inventory",
            original_outcome=outcome,
            reason_code=reason_code,
            safe_message=safe_message,
        )
        self._pending = reconciliation
        self.write_result(
            f"=== Telegram {pending.action}: unknown — {safe_message}; "
            "starting mandatory reconciliation ===",
            "warning",
        )
        self._send_pending(
            reconciliation,
            f"❓ Result unknown — checking the current state before another operation…\n"
            f"{self._server_label(pending.server_ip)}",
        )
        self._write_audit(
            "operation_reconciliation_started",
            request_token=transitioned.token,
            server_ip=pending.server_ip,
            component=target.component_id,
            action=pending.action,
            outcome=outcome,
            reason_code=reason_code,
        )
        inventory_request = InventoryRequestContext(
            transitioned.token,
            "telegram_reconciliation",
            target.component_id,
            pending.server_ip,
        )
        if (
            not self.inventory_runner.start_collection(inventory_request)
            and self._pending == reconciliation
        ):
            self._finish_management_reconciliation(
                reconciliation,
                failure="Mandatory Inventory reconciliation could not be started.",
            )

    def _continue_management_reconciliation(
        self,
        pending: _PendingMessage,
        snapshot: InventorySnapshot,
    ) -> None:
        original_target = pending.target
        target = next(
            (
                candidate
                for candidate in menu.service_targets(snapshot)
                if original_target is not None
                and candidate.component_id == original_target.component_id
                and candidate.kind == original_target.kind
                and candidate.service == original_target.service
            ),
            None,
        )
        if target is None:
            self._finish_management_reconciliation(
                pending,
                failure="The selected service is no longer available for reconciliation.",
            )
            return
        transitioned = self.gate.transition(
            pending.context,
            f"Telegram {target.display_name} reconciliation (inspect)",
            scope="management",
            server_ip=pending.server_ip,
        )
        if transitioned is None:
            return
        reconciliation = replace(
            pending,
            context=transitioned,
            target=target,
            phase="reconciliation_inspect",
        )
        self._pending = reconciliation
        inspect_request = ManagementOperationRequest(
            transitioned.token,
            target.kind,  # type: ignore[arg-type]
            pending.server_ip,
            action="inspect",
            service=target.service,
        )
        if (
            not self.management_runner.start_operation(inspect_request)
            and self._pending == reconciliation
        ):
            self._finish_management_reconciliation(
                reconciliation,
                failure="Mandatory component inspect could not be started.",
            )

    def _finish_management_reconciliation(
        self,
        pending: _PendingMessage,
        *,
        status: object | None = None,
        request: ManagementOperationRequest | None = None,
        failure: str | None = None,
    ) -> None:
        target = pending.target
        state = self._service_state(status, target)
        if failure is None and (target is None or not self._status_matches_target(status, target)):
            failure = "Mandatory component inspect returned an invalid status."
        if failure is None and state == "unknown":
            failure = "The resulting service state could not be confirmed."
        if failure is None and target is not None:
            safe_status = f"service state: {state}"
            text = (
                f"❓ Original {pending.action} result remains unknown. Reconciliation completed — "
                f"{safe_status}. Review this state before another operation.\n"
                f"{self._server_label(pending.server_ip)}"
            )
            self.write_result(
                f"=== Telegram {pending.action}: unknown; reconciliation completed; "
                f"{safe_status} ===",
                "warning",
            )
            if request is not None:
                self.management_status_confirmed.emit(request, status)
            reconciliation_state = "completed"
        else:
            safe_status = "service state requires manual verification"
            text = (
                f"❓ Original {pending.action} result remains unknown — "
                "reconciliation incomplete. "
                "Check the server manually before retrying.\n"
                f"{self._server_label(pending.server_ip)}"
            )
            self.write_result(
                f"=== Telegram {pending.action}: unknown; reconciliation incomplete — "
                f"{failure or 'the resulting server state could not be confirmed.'} "
                "The server state must be checked manually. ===",
                "error",
            )
            reconciliation_state = "incomplete"
        self._send_pending(pending, text)
        self.gate.finish(pending.context)
        self._pending = None
        self._write_audit(
            "operation_completed",
            request_token=pending.context.token,
            server_ip=pending.server_ip,
            component=target.component_id if target else None,
            action=pending.action,
            outcome=pending.original_outcome or "unknown",
            reason_code=pending.reason_code,
            safe_message=pending.safe_message,
            reconciliation=reconciliation_state,
            safe_status=safe_status,
        )

    @staticmethod
    def _status_matches_target(status: object, target: TelegramServiceTarget) -> bool:
        expected = {
            "docker": DockerManagementStatus,
            "base-security": BaseSecurityManagementStatus,
            "xray": XrayManagementStatus,
            "hysteria2": Hysteria2ManagementStatus,
            "mieru": MieruManagementStatus,
            "nginx": NginxManagementStatus,
            "netdata": NetdataManagementStatus,
        }.get(target.kind)
        return expected is not None and isinstance(status, expected)

    def _matching_inventory(self, request: object) -> _PendingMessage | None:
        pending = self._pending
        return (
            pending
            if isinstance(request, InventoryRequestContext)
            and request.purpose == "telegram"
            and pending is not None
            and pending.phase == "inventory"
            and request.operation_token == pending.context.token
            and request.server_ip == pending.server_ip
            and self.gate.matches(pending.context, scope="inventory", server_ip=pending.server_ip)
            else None
        )

    def _matching_reconciliation_inventory(
        self,
        request: object,
    ) -> _PendingMessage | None:
        pending = self._pending
        return (
            pending
            if isinstance(request, InventoryRequestContext)
            and request.purpose == "telegram_reconciliation"
            and pending is not None
            and pending.phase == "reconciliation_inventory"
            and request.operation_token == pending.context.token
            and request.server_ip == pending.server_ip
            and pending.target is not None
            and request.requester == pending.target.component_id
            and self.gate.matches(
                pending.context,
                scope="inventory",
                server_ip=pending.server_ip,
            )
            else None
        )

    def _matching_management(self, request: object) -> _PendingMessage | None:
        pending = self._pending
        return (
            pending
            if isinstance(request, ManagementOperationRequest)
            and pending is not None
            and pending.phase in {"action", "reboot", "reconciliation_inspect"}
            and request.token == pending.context.token
            and request.server_ip == pending.server_ip
            and self._management_request_matches_phase(request, pending)
            and self.gate.matches(pending.context, server_ip=pending.server_ip)
            else None
        )

    @staticmethod
    def _management_request_matches_phase(
        request: ManagementOperationRequest,
        pending: _PendingMessage,
    ) -> bool:
        if pending.phase == "reboot":
            return request.kind == "server-reboot"
        target = pending.target
        if target is None or request.kind != target.kind or request.service != target.service:
            return False
        if pending.phase == "action":
            return request.action == pending.action
        return pending.phase == "reconciliation_inspect" and request.action == "inspect"

    @staticmethod
    def _service_state(status: object, target: TelegramServiceTarget | None) -> str:
        if isinstance(status, DockerManagementStatus):
            return status.service_state
        if isinstance(status, (NginxManagementStatus, NetdataManagementStatus)):
            return status.service.service_state
        if isinstance(
            status,
            (XrayManagementStatus, Hysteria2ManagementStatus, MieruManagementStatus),
        ):
            return status.service.service_state
        if isinstance(status, BaseSecurityManagementStatus) and target is not None:
            selected: ServiceManagementStatus = (
                status.nftables if target.service == "nftables" else status.fail2ban
            )
            return selected.service_state
        return "unknown"

    def _materialize_keyboard(
        self,
        update: OperationalTelegramUpdate,
        projected: menu.TelegramMenu,
    ) -> TelegramKeyboard:
        catalog = self._server_catalog()
        return tuple(
            tuple(
                TelegramButton(
                    intent.text,
                    self._callback_store.issue(
                        intent.kind,
                        chat_id=update.chat_id,
                        user_id=update.user_id,
                        server_catalog=catalog,
                        server_ip=intent.server_ip,
                        target=intent.target,
                        targets=intent.targets,
                        action=intent.action,
                        generation=intent.generation,
                    ),
                )
                for intent in row
            )
            for row in projected.rows
        )

    def _submit_menu(
        self,
        update: OperationalTelegramUpdate,
        projected: menu.TelegramMenu,
    ) -> None:
        self._submit(
            update,
            projected.text,
            self._materialize_keyboard(update, projected),
        )

    def _submit(
        self,
        update: OperationalTelegramUpdate,
        text: str,
        keyboard: TelegramKeyboard = (),
    ) -> None:
        if self.manager is not None:
            self.manager.submit(
                TelegramOutbound(
                    update.chat_id,
                    text,
                    keyboard,
                    update.message_id if update.callback_query_id else None,
                    update.callback_query_id,
                )
            )

    def _send_pending(
        self, pending: _PendingMessage, text: str, keyboard: TelegramKeyboard = ()
    ) -> None:
        if self.manager is not None:
            self.manager.submit(
                TelegramOutbound(pending.chat_id, text, keyboard, pending.message_id)
            )

    @staticmethod
    def _pending_update(pending: _PendingMessage) -> OperationalTelegramUpdate:
        return OperationalTelegramUpdate(
            0,
            pending.chat_id,
            pending.user_id,
            datetime.now(UTC),
            message_id=pending.message_id,
            callback_query_id="pending",
        )

    def _reject(self, update: OperationalTelegramUpdate, text: str, reason: str) -> None:
        self._audit_rejected(update, reason)
        self._submit(update, text)

    def _audit_rejected(self, update: OperationalTelegramUpdate, reason: str) -> None:
        self._write_audit(
            "command_rejected",
            chat_id=update.chat_id,
            user_id=update.user_id,
            update_id=update.update_id,
            reason=reason,
        )

    def _authorized(self, update: OperationalTelegramUpdate) -> bool:
        return (
            self.settings.authorized
            and update.chat_id == self.settings.chat_id
            and update.user_id == self.settings.authorized_user_id
        )

    @staticmethod
    def _update_is_stale(update: OperationalTelegramUpdate) -> bool:
        created = update.created_at
        if created.tzinfo is None:
            created = created.replace(tzinfo=UTC)
        age = datetime.now(UTC) - created.astimezone(UTC)
        return age > timedelta(seconds=COMMAND_MAX_AGE_SECONDS) or age < timedelta(seconds=-5)

    def recent_servers_changed(self) -> None:
        """Expire menus immediately after the panel's Recent catalog changes."""
        valid_ips = {server.ip for server in self._catalog()}
        self._callback_store.recent_servers_changed(valid_ips)

    def _server_exists(self, server_ip: str) -> bool:
        return menu.server_exists(self._catalog(), server_ip)

    def _server_label(self, server_ip: str) -> str:
        return menu.server_label(self._catalog(), server_ip)

    def _invalidate_sessions(self) -> None:
        self._callback_store.clear()
        self._pairing.clear()
        self._detected_user_id = None

    def _catalog(self) -> menu.ServerCatalog:
        return menu.server_catalog(self.recent_servers())

    def _server_catalog(self) -> menu.ServerCatalogBinding:
        return menu.catalog_binding(self._catalog())

    def _expire_identification(self, generation: int) -> None:
        if not self._pairing.expire(generation):
            return
        self._write_audit("pairing_expired", chat_id=self.settings.chat_id)

    def _write_audit(self, event: str, **fields: object) -> None:
        try:
            self.audit_log.write(event, **fields)
        except OSError:
            pass

    def _create_manager(self) -> None:
        self.manager = self.manager_factory(
            self.settings,
            self.audit_log,
            self.transport_status_received.emit,
            self.update_received.emit,
        )

    def _transport_status_changed(self, status: object) -> None:
        if isinstance(status, OperationalTelegramStatus):
            self.set_status(status)

    def _new_audit_log(self, retention_days: int) -> TelegramAuditLog:
        return TelegramAuditLog(
            self.project_directory / "runtime" / "panel" / "logs", retention_days
        )
