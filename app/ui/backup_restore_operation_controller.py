"""Backup and Restore operation lifecycle for the desktop UI."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Literal

from app.services.backup import (
    BackupError,
    LocalBackupArchive,
    backup_plan_from_snapshot,
    configured_backups_directory,
    delete_local_backup_archive,
    list_local_backup_archives,
)
from app.services.inventory import ComponentInventory, InventorySnapshot
from app.services.restore import (
    EffectiveRestorePlan,
    RestoreError,
    RestorePlan,
    authorize_restore_plan,
    build_effective_restore_plan,
)

from .backup_runner import BackupOperationRequest, BackupRunner
from .inventory_runner import InventoryRequestContext
from .operation_gate import OperationContext, OperationGate
from .restore_preflight_runner import RestorePreflightRequest, RestorePreflightRunner
from .restore_runner import RestoreOperationRequest, RestoreOperationResult, RestoreRunner
from .tabs.backup_restore_tab import BackupRestoreTab

ArchiveInventoryPurpose = Literal["backup", "restore_compatibility", "restore_verification"]
OperationOutcome = Literal["success", "warning", "error"]


class BackupRestoreOperationController:
    """Own the local archive list and the multi-phase Backup/Restore lifecycle."""

    def __init__(
        self,
        project_directory: Path,
        gate: OperationGate,
        backup_runner: BackupRunner,
        preflight_runner: RestorePreflightRunner,
        restore_runner: RestoreRunner,
        tab: BackupRestoreTab,
        *,
        current_server_ip: Callable[[], str | None],
        recent_servers: Callable[[], list[dict[str, str]]],
        cancel_users: Callable[..., bool],
        resume_users: Callable[[], None],
        set_operation_controls_enabled: Callable[[bool], None],
        write_log: Callable[..., None],
        write_result: Callable[[str, OperationOutcome], None],
        write_inventory_component: Callable[[ComponentInventory], None],
        confirm: Callable[..., bool],
        request_inventory: Callable[[InventoryRequestContext], bool],
        consume_inventory: Callable[[], None],
    ) -> None:
        self.project_directory = project_directory
        self.gate = gate
        self.backup_runner = backup_runner
        self.preflight_runner = preflight_runner
        self.restore_runner = restore_runner
        self.tab = tab
        self.current_server_ip = current_server_ip
        self.recent_servers = recent_servers
        self.cancel_users = cancel_users
        self.resume_users = resume_users
        self.set_operation_controls_enabled = set_operation_controls_enabled
        self.write_log = write_log
        self.write_result = write_result
        self.write_inventory_component = write_inventory_component
        self.confirm = confirm
        self.request_inventory = request_inventory
        self.consume_inventory = consume_inventory
        self.restore_target_server_ip = ""
        self.verification_plan: EffectiveRestorePlan | None = None
        self.verification_server_ip = ""
        self.restore_apply_result: RestoreOperationResult | None = None

        backup_runner.line_received.connect(self.backup_process_line)
        backup_runner.completed.connect(self.backup_completed)
        backup_runner.failed.connect(self.backup_failed)
        preflight_runner.completed.connect(self.restore_preflight_completed)
        preflight_runner.failed.connect(self.restore_preflight_failed)
        restore_runner.line_received.connect(self.restore_process_line)
        restore_runner.completed.connect(self.restore_completed)
        restore_runner.failed.connect(self.restore_failed)

    def create_local_backup(self) -> None:
        if self.gate.busy:
            return
        server_ip = self.current_server_ip()
        if server_ip is None or self.gate.busy:
            return
        if not self.cancel_users():
            self.write_result("Could not close the current Users operation.", "error")
            return
        context = self.gate.begin("Inventory (Backup)", scope="inventory", server_ip=server_ip)
        if context is None:
            self.resume_users()
            return
        self.set_operation_controls_enabled(False)
        self.write_log(f"=== {context.title}: {server_ip} ===")
        request = InventoryRequestContext(
            context.token,
            "backup",
            "Backup",
            server_ip,
        )
        if not self.request_inventory(request):
            self.inventory_failed(
                request,
                "Inventory collection is already running.",
            )

    def inventory_completed(
        self,
        request: InventoryRequestContext,
        snapshot: InventorySnapshot,
    ) -> None:
        if self._matching_inventory_request(request) is None:
            return
        if request.purpose == "backup":
            self._start_backup_from_snapshot(snapshot)
        elif request.purpose == "restore_compatibility":
            self._finish_restore_compatibility_check(snapshot, request.restore_plan)
        else:
            self._finish_inventory_operation(
                self._write_restore_verification(snapshot, request.restore_plan)
            )

    def inventory_failed(
        self,
        request: InventoryRequestContext,
        message: str,
    ) -> None:
        if self._matching_inventory_request(request) is None:
            return
        missing_registry_message = (
            "Could not collect Inventory: Could not read remote file: "
            "/opt/vpn/state/components.json"
        )
        if request.purpose == "restore_compatibility" and message == missing_registry_message:
            message = (
                "Restore cannot start: Base + Security is not installed on the target server. "
                "Install Base + Security first."
            )
        self.write_log(f"Inventory requested by {request.requester}; server: {request.server_ip}.")
        self.write_result(message, "error")
        self._finish_inventory_operation("error")

    def _start_backup_from_snapshot(self, snapshot: InventorySnapshot) -> None:
        try:
            plan = backup_plan_from_snapshot(snapshot)
            backups_directory = configured_backups_directory(self.project_directory)
        except BackupError as error:
            request = self._current_inventory_request("backup")
            if request is not None:
                self.inventory_failed(request, str(error))
            return
        component_names = ", ".join(
            f"{component['id']} ({component['source_status']})" for component in plan.components
        )
        self.write_log(f"Backup Inventory selected: {component_names}.")
        self.write_log(f"Backup files: {len(plan.paths)}.")
        current = self.gate.current
        if current is None:
            return
        context = self.gate.transition(
            current,
            "Local backup",
            scope="backup",
            server_ip=snapshot.server_ip,
        )
        if context is None:
            return
        self.consume_inventory()
        self.set_operation_controls_enabled(False)
        self.write_log(f"=== {context.title}: {snapshot.server_ip} ===")
        request = BackupOperationRequest(context.token, snapshot.server_ip)
        if not self.backup_runner.start_backup(request, plan, backups_directory):
            self.backup_failed(request, "Backup is already running.")

    def backup_process_line(
        self,
        request: BackupOperationRequest,
        stream: str,
        line: str,
    ) -> None:
        if self._matching_backup_request(request) is None:
            return
        self.write_process_line(stream, line)

    def backup_completed(self, request: BackupOperationRequest, archive_path: str) -> None:
        context = self._matching_backup_request(request)
        if context is None:
            return
        self.write_log(f"Backup saved: {archive_path}")
        self.write_result("=== Local backup: successful ===", "success")
        self._release(context)
        self.refresh_archive_list()

    def backup_failed(self, request: BackupOperationRequest, message: str) -> None:
        context = self._matching_backup_request(request)
        if context is None:
            return
        self.write_result(f"=== Local backup: failed — {message} ===", "error")
        self._release(context)

    def refresh_archive_list(self) -> None:
        if self.gate.busy:
            return
        try:
            backups_directory = configured_backups_directory(self.project_directory)
            server_aliases = {
                server["ip"]: server["alias"]
                for server in self.recent_servers()
                if server["alias"].strip()
            }
            self.tab.set_archives(
                list_local_backup_archives(backups_directory),
                server_aliases,
            )
        except BackupError as error:
            self.tab.show_list_error(f"Could not list local backups: {error}")

    def delete_selected_backup(self, archive: LocalBackupArchive) -> None:
        try:
            backups_directory = configured_backups_directory(self.project_directory)
            delete_local_backup_archive(backups_directory, archive.path)
        except BackupError as error:
            self.write_result(f"Could not delete Backup archive: {error}", "error")
            return
        self.write_log(f"Backup archive deleted: {archive.path}")
        self.refresh_archive_list()

    def restore_selected_backup(self, archive: LocalBackupArchive) -> None:
        server_ip = self.current_server_ip()
        if server_ip is None:
            return
        self.restore_target_server_ip = server_ip
        context = self.gate.begin("Restore preflight", scope="restore", server_ip=server_ip)
        if context is None:
            self.restore_target_server_ip = ""
            return
        self.set_operation_controls_enabled(False)
        self.write_log(f"=== {context.title}: {server_ip} ===")
        request = RestorePreflightRequest(context.token, server_ip, archive.path)
        if not self.preflight_runner.start_preflight(request):
            self.restore_preflight_failed(request, "Restore preflight is already running.")

    def restore_preflight_completed(
        self,
        request: RestorePreflightRequest,
        plan: object,
    ) -> None:
        if self._matching_preflight_request(request) is None:
            return
        if not isinstance(plan, RestorePlan):
            self.restore_preflight_failed(request, "Restore preflight returned an invalid plan.")
            return
        try:
            effective_plan = build_effective_restore_plan(plan, request.server_ip)
        except RestoreError as error:
            self.restore_preflight_failed(request, str(error))
            return
        self._start_restore_compatibility_check(request, effective_plan)

    def _start_restore_compatibility_check(
        self,
        request: RestorePreflightRequest,
        plan: EffectiveRestorePlan,
    ) -> None:
        server_ip = self.restore_target_server_ip
        if not server_ip or server_ip != plan.target_server_ip:
            self.restore_preflight_failed(request, "Restore target server is no longer selected.")
            return
        if not self.cancel_users():
            self.restore_preflight_failed(request, "Could not close the current Users operation.")
            return
        current = self._matching_preflight_request(request)
        if current is None:
            return
        context = self.gate.transition(
            current,
            "Restore compatibility check",
            scope="inventory",
            server_ip=server_ip,
        )
        if context is None:
            self.restore_preflight_failed(
                request, "Restore operation context is no longer current."
            )
            return
        self.write_log(f"=== {context.title}: {server_ip} ===")
        request = InventoryRequestContext(
            context.token,
            "restore_compatibility",
            "Restore compatibility",
            server_ip,
            plan,
        )
        if not self.request_inventory(request):
            self.inventory_failed(
                request,
                "Inventory collection is already running.",
            )

    def _finish_restore_compatibility_check(
        self,
        snapshot: InventorySnapshot,
        plan: EffectiveRestorePlan | None,
    ) -> None:
        if plan is None:
            request = self._current_inventory_request("restore_compatibility")
            if request is not None:
                self.inventory_failed(
                    request,
                    "Restore compatibility check has no saved Restore plan.",
                )
            return
        self.write_log(
            "Restore compatibility requested for: "
            + ", ".join(component.component_id for component in plan.applied_components)
            + "."
        )
        try:
            authorized_plan = authorize_restore_plan(plan, snapshot)
        except RestoreError as error:
            self.write_result(str(error), "error")
            self._finish_inventory_operation("error")
            return

        components = {component.component_id: component for component in snapshot.components}
        target_statuses: list[str] = []
        for restored_component in authorized_plan.applied_components:
            component = components[restored_component.component_id]
            self.write_inventory_component(component)
            target_statuses.append(f"{restored_component.component_id}: {component.status}")

        current = self._matching_context("Restore compatibility check", "inventory")
        if current is None:
            return
        self.consume_inventory()
        self._confirm_restore_plan(current, authorized_plan, "; ".join(target_statuses))

    def _confirm_restore_plan(
        self,
        current: OperationContext,
        plan: EffectiveRestorePlan,
        target_statuses: str,
    ) -> None:
        target_server_ip = plan.target_server_ip
        if self.restore_target_server_ip != target_server_ip:
            self.write_result("Restore target server changed before confirmation.", "error")
            self._cancel_restore_confirmation(current)
            return
        applied_components = ", ".join(
            component.component_id for component in plan.applied_components
        )
        skipped_components = (
            ", ".join(exclusion.component_id for exclusion in plan.skipped_components) or "none"
        )
        if plan.has_policy_exclusions:
            mismatch_text = (
                "The selected Backup archive was created on a different server.\n\n"
                "Nginx will not be restored. The target server's Nginx configuration, "
                "TLS certificate, "
                "domain, and subscriptions will remain unchanged.\n\n"
                f"Components to restore: {applied_components}.\n"
                f"Components to skip: {skipped_components}."
            )
            mismatch_highlight = (
                f"Archive source: {plan.source_server_ip}\nRestore target: {target_server_ip}"
            )
            if not self.confirm(
                "Archive source and target differ",
                mismatch_text,
                "Continue",
                highlight_text=mismatch_highlight,
            ):
                self._cancel_restore_confirmation(current)
                return
        elif plan.source_server_ip != target_server_ip:
            mismatch_text = (
                "The selected Backup archive was created on a different server.\n\n"
                "Configuration files from the archive will be applied to the target "
                "server. Continue?"
            )
            mismatch_highlight = (
                f"Archive source: {plan.source_server_ip}\nRestore target: {target_server_ip}"
            )
            if not self.confirm(
                "Archive source and target differ",
                mismatch_text,
                "Continue",
                highlight_text=mismatch_highlight,
            ):
                self._cancel_restore_confirmation(current)
                return
        source_statuses = "; ".join(
            f"{component.component_id}: {component.source_status}"
            for component in plan.applied_components
        )
        service_actions = (
            ", ".join(f"{service.action} {service.unit}" for service in plan.service_actions)
            or "none"
        )
        text = (
            f"Archive: {plan.archive_path.name}\n"
            f"Source server: {plan.source_server_ip}\n"
            f"Target server: {target_server_ip}\n"
            f"Components to restore: {applied_components}\n"
            f"Components to skip: {skipped_components}\n"
            f"Archive component status: {source_statuses}\n"
            f"Target component status: {target_statuses}\n"
            f"Files to overwrite: {len(plan.paths)}\n"
            f"Systemd daemon-reload: {'yes' if plan.requires_daemon_reload else 'no'}\n"
            f"Service actions: {service_actions}\n\n"
            "The archive contains secrets and Restore will overwrite the listed files. Continue?"
        )
        if self.confirm("Restore local backup", text, "Restore"):
            self._start_restore(current, plan, target_server_ip)
        else:
            self._cancel_restore_confirmation(current)
        self.restore_target_server_ip = ""

    def _cancel_restore_confirmation(self, current: OperationContext) -> None:
        self.restore_target_server_ip = ""
        if not self.gate.finish(current):
            return
        self.set_operation_controls_enabled(True)
        self.resume_users()

    def restore_preflight_failed(
        self,
        request: RestorePreflightRequest,
        message: str,
    ) -> None:
        context = self._matching_preflight_request(request)
        if context is None:
            return
        self.write_result(f"=== Restore preflight: failed — {message} ===", "error")
        self.restore_target_server_ip = ""
        self._release(context)

    def _start_restore(
        self,
        current: OperationContext,
        plan: EffectiveRestorePlan,
        server_ip: str,
    ) -> None:
        context = self.gate.transition(
            current,
            "Local restore",
            scope="restore",
            server_ip=server_ip,
        )
        if context is None:
            return
        self.verification_plan = plan
        self.verification_server_ip = server_ip
        self.restore_apply_result = None
        self.set_operation_controls_enabled(False)
        self.write_log(f"=== {context.title}: {server_ip} ===")
        request = RestoreOperationRequest(context.token, server_ip)
        if not self.restore_runner.start_restore(request, plan.full_plan, plan):
            self.restore_failed(request, "Restore is already running.")

    def restore_process_line(
        self,
        request: RestoreOperationRequest,
        stream: str,
        line: str,
    ) -> None:
        if self._matching_restore_request(request) is None:
            return
        self.write_process_line(stream, line)

    def restore_completed(
        self,
        request: RestoreOperationRequest,
        result: RestoreOperationResult,
    ) -> None:
        current = self._matching_restore_request(request)
        if current is None:
            return
        if not isinstance(result, RestoreOperationResult):
            self.restore_failed(request, "Restore runner returned an invalid result.")
            return
        if result.outcome == "pre_apply_failed":
            self.write_result(
                f"=== Local restore: failed before applying files — {result.message} ===",
                "error",
            )
            self._clear_restore_context()
            self.consume_inventory()
            self._release(current)
            return
        self.restore_apply_result = result
        plan = self.verification_plan
        server_ip = self.verification_server_ip
        if plan is None or not server_ip:
            self.restore_failed(request, "Restore verification context is missing.")
            return
        context = self.gate.transition(
            current,
            "Restore verification",
            scope="inventory",
            server_ip=server_ip,
        )
        if context is None:
            self.restore_failed(request, "Restore operation context is no longer current.")
            return
        if result.outcome in {"partial", "unknown"}:
            self.write_result(
                f"=== Local restore: {result.outcome} after phase {result.last_phase} — "
                f"{result.message} "
                "The target server state must be verified. ===",
                "warning" if result.outcome == "partial" else "error",
            )
        self.write_log(f"=== {context.title}: {server_ip} ===")
        request = InventoryRequestContext(
            context.token,
            "restore_verification",
            "Restore verification",
            server_ip,
            plan,
        )
        if not self.request_inventory(request):
            self.inventory_failed(
                request,
                "Inventory collection is already running.",
            )

    def restore_failed(self, request: RestoreOperationRequest, message: str) -> None:
        context = self._matching_restore_request(request)
        if context is None:
            return
        self.write_result(f"=== Local restore: failed — {message} ===", "error")
        self._clear_restore_context()
        self.consume_inventory()
        self._release(context)

    def _write_restore_verification(
        self,
        snapshot: InventorySnapshot,
        plan: EffectiveRestorePlan | None,
    ) -> OperationOutcome:
        if plan is None:
            self.write_log("Restore verification has no saved Restore plan.")
            return "error"
        components = {component.component_id: component for component in snapshot.components}
        self.write_log(
            "Restore verification requested for: "
            + ", ".join(component.component_id for component in plan.applied_components)
            + "."
        )
        all_active = True
        for restored_component in plan.applied_components:
            component = components.get(restored_component.component_id)
            if component is None:
                self.write_log(
                    f"[ERROR] {restored_component.component_id} is not registered on "
                    "the target server."
                )
                all_active = False
                continue
            self.write_inventory_component(component)
            if component.status != "active":
                all_active = False
        for exclusion in plan.skipped_components:
            component = components.get(exclusion.component_id)
            if component is not None:
                self.write_log(
                    "Preserved target Component (not restored): "
                    f"{exclusion.component_id}: {component.status}."
                )
        apply_result = self.restore_apply_result
        if apply_result is not None and apply_result.outcome in {"partial", "unknown"}:
            if all_active:
                self.write_log(
                    f"Restore {apply_result.outcome} reconciliation reached all-active Inventory, "
                    "but file-level application cannot be proven automatically."
                )
                return "warning"
            return "error"
        if not all_active:
            return "error"
        return "warning" if plan.has_policy_exclusions else "success"

    def _finish_inventory_operation(self, outcome: OperationOutcome) -> None:
        context = self.gate.current
        if context is None or context.scope != "inventory":
            return
        status = (
            "successful"
            if outcome == "success"
            else "completed with warnings"
            if outcome == "warning"
            else "failed"
        )
        if (
            context.title == "Restore verification"
            and outcome == "warning"
            and self.verification_plan is not None
            and self.verification_plan.has_policy_exclusions
            and self.restore_apply_result is not None
            and self.restore_apply_result.outcome == "success"
        ):
            skipped = ", ".join(
                exclusion.component_id for exclusion in self.verification_plan.skipped_components
            )
            message = f"=== Restore completed with policy exclusions. Skipped: {skipped}. ==="
        else:
            message = f"=== {context.title}: {status} ==="
        self.write_result(message, outcome)
        if not self.gate.finish(context):
            return
        self.consume_inventory()
        self.restore_target_server_ip = ""
        self._clear_restore_context()
        self.set_operation_controls_enabled(True)
        self.resume_users()

    def _clear_restore_context(self) -> None:
        self.verification_plan = None
        self.verification_server_ip = ""
        self.restore_apply_result = None

    def write_process_line(self, stream: str, line: str) -> None:
        prefix = "[stderr] " if stream == "stderr" else ""
        self.write_log(f"{prefix}{line}")

    def shutdown(self) -> bool:
        stopped = True
        if self.backup_runner.is_running:
            self.backup_runner.stop()
            if not self.backup_runner.wait(20_000):
                stopped = False
        if self.preflight_runner.is_running:
            self.preflight_runner.requestInterruption()
            if not self.preflight_runner.wait(20_000):
                stopped = False
        if self.restore_runner.is_running:
            self.restore_runner.stop()
            if not self.restore_runner.wait(20_000):
                stopped = False
        return stopped

    def _matching_context(
        self,
        title: str,
        scope: str,
    ) -> OperationContext | None:
        context = self.gate.current
        if context is None:
            return None
        if context.title != title or context.scope != scope:
            return None
        return context

    def _matching_backup_request(
        self,
        request: BackupOperationRequest,
    ) -> OperationContext | None:
        if not isinstance(request, BackupOperationRequest) or request.kind != "local-backup":
            return None
        context = self._matching_context("Local backup", "backup")
        if context is None:
            return None
        if context.token != request.operation_token or context.server_ip != request.server_ip:
            return None
        return context

    def _matching_preflight_request(
        self,
        request: RestorePreflightRequest,
    ) -> OperationContext | None:
        if not isinstance(request, RestorePreflightRequest) or request.phase != "preflight":
            return None
        context = self._matching_context("Restore preflight", "restore")
        if context is None:
            return None
        if context.token != request.operation_token or context.server_ip != request.server_ip:
            return None
        return context

    def _matching_restore_request(
        self,
        request: RestoreOperationRequest,
    ) -> OperationContext | None:
        if not isinstance(request, RestoreOperationRequest) or request.phase != "apply":
            return None
        context = self._matching_context("Local restore", "restore")
        if context is None:
            return None
        if context.token != request.operation_token or context.server_ip != request.server_ip:
            return None
        return context

    def _matching_inventory_request(
        self,
        request: InventoryRequestContext,
    ) -> OperationContext | None:
        expected_route = {
            "backup": ("Backup", "Inventory (Backup)"),
            "restore_compatibility": (
                "Restore compatibility",
                "Restore compatibility check",
            ),
            "restore_verification": (
                "Restore verification",
                "Restore verification",
            ),
        }.get(request.purpose)
        if expected_route is None:
            return None
        expected_requester, expected_title = expected_route
        if request.requester != expected_requester:
            return None
        context = self.gate.current
        if context is None or context.token != request.operation_token:
            return None
        if (
            context.title != expected_title
            or context.scope != "inventory"
            or context.server_ip != request.server_ip
        ):
            return None
        return context

    def _current_inventory_request(
        self,
        purpose: ArchiveInventoryPurpose,
    ) -> InventoryRequestContext | None:
        context = self.gate.current
        if context is None or context.scope != "inventory":
            return None
        requester = {
            "backup": "Backup",
            "restore_compatibility": "Restore compatibility",
            "restore_verification": "Restore verification",
        }[purpose]
        return InventoryRequestContext(
            context.token,
            purpose,
            requester,
            context.server_ip,
        )

    def _release(self, context: OperationContext) -> None:
        if not self.gate.finish(context):
            return
        self.set_operation_controls_enabled(True)
        self.resume_users()
