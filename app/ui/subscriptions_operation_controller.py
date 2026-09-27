"""OperationGate ownership and stale-safe presentation for Subscriptions."""

from __future__ import annotations

import re
from collections.abc import Callable
from pathlib import Path
from urllib.parse import urlsplit

from app.services.inventory import InventorySnapshot
from app.services.ssh import validate_server_ip
from app.services.subscriptions import (
    FinalizedSubscription,
    SubscriptionDeleteRequest,
    SubscriptionError,
    SubscriptionInspectRequest,
    SubscriptionReconciliation,
    SubscriptionReconciliationItem,
    confirmed_subscription_url,
    list_subscription_source_files,
    validate_subscription_name,
)

from .operation_gate import OperationContext, OperationGate
from .subscriptions_runner import (
    SubscriptionDeleteCompletion,
    SubscriptionRunnerRequest,
    SubscriptionsRunner,
    SubscriptionsRunnerRequest,
)
from .tabs.subscriptions_tab import SubscriptionsTab


class SubscriptionsOperationController:
    """Own one publication request from confirmation through final gate release."""

    def __init__(
        self,
        project_directory: Path,
        operation_gate: OperationGate,
        runner: SubscriptionsRunner,
        tab: SubscriptionsTab,
        *,
        current_server_ip: Callable[[], str | None],
        current_server_text: Callable[[], str],
        editing_enabled: Callable[[], bool],
        cancel_users: Callable[[], bool],
        resume_users: Callable[[], None],
        set_operation_controls_enabled: Callable[[bool], None],
        write_log: Callable[..., None],
        write_result: Callable[[str, str], None],
        confirm: Callable[..., bool],
        copy_url: Callable[[str], None],
        subscriptions_is_visible: Callable[[], bool] | None = None,
        request_inventory: Callable[[], None] | None = None,
    ) -> None:
        self.project_directory = project_directory
        self.operation_gate = operation_gate
        self.runner = runner
        self.tab = tab
        self.current_server_ip = current_server_ip
        self.current_server_text = current_server_text
        self.editing_enabled = editing_enabled
        self.cancel_users = cancel_users
        self.resume_users = resume_users
        self.set_operation_controls_enabled = set_operation_controls_enabled
        self.write_log = write_log
        self.write_result = write_result
        self.confirm = confirm
        self.copy_url = copy_url
        self.subscriptions_is_visible = subscriptions_is_visible or (lambda: True)
        self.request_inventory = request_inventory
        self._next_request_id = 1
        self._active_request: SubscriptionsRunnerRequest | None = None
        self._active_operation: OperationContext | None = None
        self._url_pair: tuple[str, str] | None = None
        self._selected_server_name: str | None = None
        self._server_view: SubscriptionReconciliation | None = None
        runner.completed.connect(self.completed)
        runner.failed.connect(self.failed)

    def show(self) -> None:
        self._sync_server_title()
        try:
            sources = list_subscription_source_files(self.project_directory)
        except SubscriptionError as error:
            self.tab.clear_source_catalog()
            self.pair_changed()
            self.write_result(
                f"=== Subscription sources: failed — {error} ===",
                "error",
            )
        else:
            files_by_name: dict[str, list[str]] = {}
            for source in sources:
                files_by_name.setdefault(source.name, []).append(source.filename)
            self.tab.set_source_catalog(
                {name: tuple(filenames) for name, filenames in files_by_name.items()}
            )
            self.pair_changed()
        if self.request_inventory is not None:
            self.refresh_server()

    def hide(self) -> None:
        self.pair_changed()
        self._server_view = None
        self.tab.clear_server_subscriptions()

    def server_changed(self) -> None:
        self._sync_server_title()
        self.pair_changed()
        self._server_view = None
        self.tab.clear_server_subscriptions()
        if self.subscriptions_is_visible() and self.request_inventory is not None:
            self.refresh_server()

    def server_ip_edited(self) -> None:
        self._sync_server_title()
        self.pair_changed()
        self._server_view = None
        self.tab.clear_server_subscriptions()
        self.tab.set_server_status(
            "idle", "Server address changed. Press Enter or leave the field to inspect."
        )

    def refresh_server(self) -> None:
        if (
            self.request_inventory is None
            or not self.subscriptions_is_visible()
            or self.operation_gate.busy
            or self.runner.is_running
        ):
            return
        server_ip = self.current_server_ip()
        self._url_pair = None
        self.tab.clear_url()
        self._server_view = None
        self.tab.clear_server_subscriptions()
        if server_ip is None:
            self.tab.set_server_ip("")
            self.tab.set_server_status(
                "error", "Error · Enter a valid IPv4 address to inspect subscriptions."
            )
            return
        self.tab.set_server_ip(server_ip)
        self.tab.set_server_status("loading", "Checking managed Nginx…")
        self.request_inventory()

    def inventory_completed(self, snapshot: InventorySnapshot) -> None:
        operation = self.operation_gate.current
        if (
            operation is None
            or operation.scope != "inventory"
            or operation.server_ip != snapshot.server_ip
        ):
            return
        if not self.subscriptions_is_visible() or self.current_server_ip() != snapshot.server_ip:
            self._release_inventory(operation)
            return
        component = snapshot.component("nginx")
        if component is None:
            self._server_view = None
            self.tab.clear_server_subscriptions()
            self.tab.set_server_status(
                "unavailable", "Unavailable · Managed Nginx is not installed."
            )
            self._release_inventory(operation)
            return
        declaration = component.declaration
        if (
            declaration is None
            or declaration.contract_version != "5"
            or "/etc/nginx/vpn-admin-locations/subscriptions.conf"
            not in declaration.installation_files
        ):
            self._server_view = None
            self.tab.clear_server_subscriptions()
            self.tab.set_server_status(
                "unavailable",
                "Unavailable · Compatible managed Nginx must be deployed.",
            )
            self._release_inventory(operation)
            return
        transitioned = self.operation_gate.transition(
            operation,
            "Inspect subscriptions",
            scope="subscriptions",
            server_ip=snapshot.server_ip,
        )
        if transitioned is None:
            return
        request = SubscriptionInspectRequest(
            transitioned.token,
            self._next_request_id,
            snapshot.server_ip,
        )
        self._next_request_id += 1
        self._active_operation = transitioned
        self._active_request = request
        self.tab.set_server_status("loading", "Loading published subscriptions…")
        if not self.runner.start_operation(request):
            self.failed(request, "Another Subscriptions operation is already running.")

    def inventory_failed(self, message: str) -> None:
        operation = self.operation_gate.current
        if operation is None or operation.scope != "inventory":
            return
        self._server_view = None
        self.tab.clear_server_subscriptions()
        self.tab.set_server_status("error", f"Error · Inspection failed: {message}")
        self._release_inventory(operation)

    def delete_orphan(self, item: SubscriptionReconciliationItem) -> None:
        current = self._current_server_item(item)
        if current is None or not current.orphan_artifacts:
            return
        self._start_delete(
            "orphan",
            current,
            tuple(sorted(artifact.token for artifact in current.orphan_artifacts)),
        )

    def delete_active(self, item: SubscriptionReconciliationItem) -> None:
        current = self._current_server_item(item)
        if (
            current is None
            or current.registry_state is None
            or current.status not in {"active", "active_orphan", "deleting", "republish_required"}
        ):
            return
        self._start_delete("active", current, ())

    def make_subscription(self) -> None:
        if self.operation_gate.busy or self.runner.is_running:
            return
        if not self.editing_enabled():
            self.write_result("=== Make subscription: Editing mode is required ===", "error")
            return
        name = self.tab.name
        source_filenames = self.tab.selected_source_filenames
        if not source_filenames:
            return
        try:
            validate_subscription_name(name)
        except ValueError as error:
            self.write_result(f"=== Make subscription: failed — {error} ===", "error")
            return
        server_ip = self.current_server_ip()
        if server_ip is None:
            return
        if not self.confirm(
            "Make subscription",
            "Publish the combined subscription on the selected server? Existing "
            "content at its stable URL will be replaced.",
            "Make subscription",
            highlight_text=(f"Name: {name}\nServer: {server_ip}\nFiles: {len(source_filenames)}"),
        ):
            return
        if not self.cancel_users():
            self.write_result(
                "=== Make subscription: could not close the current Users operation ===", "error"
            )
            return
        operation = self.operation_gate.begin(
            "Make subscription",
            scope="subscriptions",
            server_ip=server_ip,
        )
        if operation is None:
            self.resume_users()
            return
        request = SubscriptionRunnerRequest(
            operation.token,
            self._next_request_id,
            server_ip,
            name,
            source_filenames,
        )
        self._next_request_id += 1
        self._active_operation = operation
        self._active_request = request
        self.set_operation_controls_enabled(False)
        self.write_log(f"=== Make subscription: {server_ip}; Name: {name} ===")
        if not self.runner.start_operation(request):
            self.failed(request, "Another subscription publication is already running.")

    def pair_changed(self) -> None:
        self._selected_server_name = None
        self._url_pair = None
        self.tab.clear_url()

    def server_subscription_selected(
        self,
        selected: SubscriptionReconciliationItem,
    ) -> None:
        self._url_pair = None
        self.tab.clear_url()
        view = self._server_view
        if (
            view is None
            or view.availability != "ready"
            or self.current_server_ip() != view.server_ip
            or selected not in view.items
        ):
            return
        self._selected_server_name = selected.name
        if (
            selected.registry_state not in {"active", "pending"}
            or selected.matching_artifact is None
            or selected.status not in {"active", "active_orphan"}
        ):
            return
        pair = (view.server_ip, selected.name)
        try:
            url = confirmed_subscription_url(self.project_directory, *pair)
        except SubscriptionError as error:
            self.write_result(
                f"=== Subscription URL lookup: failed — {error} ===",
                "error",
            )
            return
        if url and self._valid_url(url, view.server_name, pair[1]):
            self._url_pair = pair
            self.tab.set_url(url)

    def copy_current_url(self) -> None:
        pair = self._url_pair
        if pair is None or self.current_server_ip() != pair[0] or not self.tab.url:
            return
        self.copy_url(self.tab.url)

    def completed(self, request: object, finalized: object) -> None:
        if not isinstance(
            request,
            (SubscriptionRunnerRequest, SubscriptionInspectRequest, SubscriptionDeleteRequest),
        ) or not self._owns(request):
            return
        if isinstance(request, SubscriptionInspectRequest):
            self._inspection_completed(request, finalized)
            return
        if isinstance(request, SubscriptionDeleteRequest):
            self._delete_completed(request, finalized)
            return
        self._publication_completed(request, finalized)

    def _publication_completed(
        self,
        request: SubscriptionRunnerRequest,
        finalized: object,
    ) -> None:
        current_pair = self._current_pair()
        present = current_pair == (request.server_ip, request.name)
        if not isinstance(finalized, FinalizedSubscription):
            if present:
                self.write_result("=== Make subscription: invalid runner result ===", "error")
            self._finish(request)
            return
        result = finalized.result
        if result.outcome in {"success", "partial"} and not self._valid_url(
            finalized.url, result.server_name, request.name
        ):
            if present:
                self.write_result("=== Make subscription: invalid confirmed URL ===", "error")
            self._finish(request)
            return
        if present:
            if result.outcome in {"success", "partial"}:
                self._selected_server_name = request.name
                self.copy_url(finalized.url)
            if result.outcome == "success":
                self.write_result("=== Make subscription: successful ===", "success")
            elif result.outcome == "partial":
                self.write_result(
                    "=== Make subscription: published, but cleanup is incomplete — "
                    f"{result.error} ===",
                    "warning",
                )
            elif result.outcome == "failure":
                self.write_result(f"=== Make subscription: failed — {result.error} ===", "error")
            else:
                self.write_result(
                    f"=== Make subscription: result unknown — {result.error} ===",
                    "warning",
                )
        refresh_server = (
            present
            and result.outcome in {"success", "partial"}
            and self.request_inventory is not None
        )
        self._finish(request)
        if refresh_server:
            self.refresh_server()

    def failed(self, request: object, message: str) -> None:
        if not isinstance(
            request,
            (SubscriptionRunnerRequest, SubscriptionInspectRequest, SubscriptionDeleteRequest),
        ) or not self._owns(request):
            return
        if isinstance(request, SubscriptionInspectRequest):
            if self._server_request_is_present(request.server_ip):
                self._server_view = None
                self.tab.clear_server_subscriptions()
                self.tab.set_server_status("error", f"Error · Inspection failed: {message}")
                self.write_result(f"=== Subscription inspection: failed — {message} ===", "error")
        elif isinstance(request, SubscriptionDeleteRequest):
            if self._server_request_is_present(request.server_ip):
                self.tab.set_server_status("error", f"Error · Deletion failed: {message}")
                self.write_result(f"=== Delete subscription: failed — {message} ===", "error")
        elif self._current_pair() == (request.server_ip, request.name):
            self.write_result(f"=== Make subscription: failed — {message} ===", "error")
        self._finish(request)

    def shutdown(self) -> bool:
        if self.runner.is_running:
            self.runner.stop()
            if not self.runner.wait(5_000):
                return False
        request = self._active_request
        if request is not None:
            self._finish(request)
        return True

    def _owns(self, request: SubscriptionsRunnerRequest) -> bool:
        operation = self._active_operation
        return (
            request == self._active_request
            and operation is not None
            and operation.token == request.operation_token
            and self.operation_gate.matches(
                operation,
                scope="subscriptions",
                server_ip=request.server_ip,
            )
        )

    def _finish(self, request: SubscriptionsRunnerRequest) -> None:
        if request != self._active_request:
            return
        operation = self._active_operation
        self._active_request = None
        self._active_operation = None
        if operation is not None:
            self.operation_gate.finish(operation)
        self.set_operation_controls_enabled(True)
        self.resume_users()

    def _release_inventory(self, operation: OperationContext) -> None:
        if self.operation_gate.finish(operation):
            self.set_operation_controls_enabled(True)
            self.resume_users()

    def _inspection_completed(self, request: SubscriptionInspectRequest, value: object) -> None:
        present = self._server_request_is_present(request.server_ip)
        if (
            not isinstance(value, SubscriptionReconciliation)
            or value.server_ip != request.server_ip
        ):
            if present:
                self._server_view = None
                self.tab.clear_server_subscriptions()
                self.tab.set_server_status(
                    "error", "Error · Inspection returned an invalid result."
                )
            self._finish(request)
            return
        if present:
            self._apply_server_view(value)
            self.write_result("=== Subscription inspection: successful ===", "success")
        self._finish(request)

    def _delete_completed(self, request: SubscriptionDeleteRequest, value: object) -> None:
        present = self._server_request_is_present(request.server_ip)
        if not isinstance(value, SubscriptionDeleteCompletion):
            if present:
                self.tab.set_server_status("error", "Error · Deletion returned an invalid result.")
            self._finish(request)
            return
        result = value.finalized.result
        if present and value.reconciliation is not None:
            if value.reconciliation.server_ip != request.server_ip:
                self.tab.set_server_status("error", "Error · Deletion reconciliation is stale.")
                self._finish(request)
                return
            self._apply_server_view(value.reconciliation)
        elif present and result.outcome == "failure" and self._server_view is not None:
            self._apply_server_view(self._server_view)
        if present:
            label = "Delete orphan" if request.kind == "orphan" else "Delete active"
            if result.outcome == "success":
                self.write_result(f"=== {label}: successful ===", "success")
            elif result.outcome == "failure":
                self.write_result(f"=== {label}: failed — {result.error} ===", "error")
            else:
                detail = result.error
                if value.reconciliation_error:
                    detail = f"{detail} Reinspection failed: {value.reconciliation_error}"
                self.write_result(
                    f"=== {label}: result {result.outcome} — {detail} ===",
                    "warning",
                )
                if value.reconciliation is None:
                    self.tab.set_server_status(
                        "error",
                        "Error · Deletion result is uncertain; refresh is required.",
                    )
        self._finish(request)

    def _apply_server_view(self, view: SubscriptionReconciliation) -> None:
        self._server_view = view
        self.tab.set_server_ip(view.server_ip)
        self.tab.set_server_subscriptions(view)
        if view.availability == "ready":
            self.tab.set_server_status("ready", f"Ready · {view.server_name}")
        else:
            self.tab.set_server_status("unavailable", "Unavailable · Let's Encrypt is required.")
        selected = self.tab.select_server_subscription(self._selected_server_name)
        if selected is None:
            self._selected_server_name = None
            self._url_pair = None
            self.tab.clear_url()
        else:
            self.server_subscription_selected(selected)

    def _server_request_is_present(self, server_ip: str) -> bool:
        return self.subscriptions_is_visible() and self.current_server_ip() == server_ip

    def _current_server_item(
        self,
        item: SubscriptionReconciliationItem,
    ) -> SubscriptionReconciliationItem | None:
        view = self._server_view
        server_ip = self.current_server_ip()
        if (
            view is None
            or view.availability != "ready"
            or server_ip != view.server_ip
            or not self.subscriptions_is_visible()
        ):
            return None
        return next((value for value in view.items if value == item), None)

    def _start_delete(
        self,
        kind: str,
        item: SubscriptionReconciliationItem,
        tokens: tuple[str, ...],
    ) -> None:
        if self.operation_gate.busy or self.runner.is_running:
            return
        if not self.editing_enabled():
            self.write_result("=== Delete subscription: Editing mode is required ===", "error")
            return
        view = self._server_view
        server_ip = self.current_server_ip()
        if view is None or server_ip != view.server_ip:
            return
        label = "Delete orphan" if kind == "orphan" else "Delete active"
        description = (
            "Delete only the selected orphan server files? Registry will not be changed."
            if kind == "orphan"
            else "Delete all server files for this Name and remove its Registry entry?"
        )
        if not self.confirm(
            label,
            description,
            label,
            highlight_text=f"Server: {server_ip}\nName: {item.name}\nOperation: {label}",
        ):
            return
        if not self.cancel_users():
            self.write_result(
                f"=== {label}: could not close the current Users operation ===", "error"
            )
            return
        operation = self.operation_gate.begin(label, scope="subscriptions", server_ip=server_ip)
        if operation is None:
            self.resume_users()
            return
        request = SubscriptionDeleteRequest(
            operation.token,
            self._next_request_id,
            server_ip,
            kind,  # type: ignore[arg-type]
            item.name,
            tokens,
        )
        self._next_request_id += 1
        self._active_operation = operation
        self._active_request = request
        self.set_operation_controls_enabled(False)
        self.tab.set_server_status("loading", f"{label} in progress…")
        self.write_log(f"=== {label}: {server_ip}; Name: {item.name} ===")
        if not self.runner.start_operation(request):
            self.failed(request, "Another Subscriptions operation is already running.")

    def _current_pair(self) -> tuple[str, str] | None:
        server_ip, error = validate_server_ip(self.current_server_text())
        if error:
            return None
        name = self.tab.name
        try:
            validate_subscription_name(name)
        except ValueError:
            return None
        return server_ip, name

    def _sync_server_title(self) -> None:
        server_ip, error = validate_server_ip(self.current_server_text())
        self.tab.set_server_ip(server_ip if error is None else "")

    @staticmethod
    def _valid_url(url: str, server_name: str, name: str) -> bool:
        if not isinstance(url, str) or not url:
            return False
        parsed = urlsplit(url)
        return (
            parsed.scheme == "https"
            and parsed.netloc == server_name
            and re.fullmatch(
                r"/subscriptions/"
                + str(len(name))
                + "-"
                + re.escape(name)
                + r"-[A-Za-z0-9_-]{32,128}\.txt",
                parsed.path,
            )
            is not None
            and not parsed.query
            and not parsed.fragment
            and parsed.username is None
            and parsed.password is None
        )
