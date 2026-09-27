"""GUI state and one-shot runner lifecycle for the Users tab."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Literal

from app.services.inventory import InventorySnapshot
from app.services.ssh import validate_server_ip
from app.services.users import (
    UsersMutationResult,
    UsersOperationError,
    build_users_request,
    generated_connections_directory,
    inventory_users_protocols,
    save_connection_files,
)

from .tabs.users_tab import UsersTab
from .users_operation_runner import UsersOperationRunner

UsersViewState = Literal["idle", "connecting", "loading", "ready", "error"]
OperationOutcome = Literal["success", "warning", "error"]


class UsersOperationController:
    """Own Users request identity, presentation state, cancellation and refresh."""

    def __init__(
        self,
        project_directory: Path,
        runner: UsersOperationRunner,
        tab: UsersTab,
        *,
        current_server_ip: Callable[[], str | None],
        users_is_visible: Callable[[], bool],
        operation_is_busy: Callable[[], bool],
        request_inventory: Callable[[], None],
        write_log: Callable[..., None],
        write_result: Callable[[str, OperationOutcome], None],
        hide_content: Callable[[], None],
    ) -> None:
        self.project_directory = project_directory
        self.runner = runner
        self.tab = tab
        self.current_server_ip = current_server_ip
        self.users_is_visible = users_is_visible
        self.operation_is_busy = operation_is_busy
        self.request_inventory = request_inventory
        self.write_log = write_log
        self.write_result = write_result
        self.hide_content = hide_content
        self.request_id = 0
        self.active_request_id = 0
        self.active_server_ip = ""
        self.view_ip = ""
        self.pending_server_ip = ""
        self.authorization_server_ip = ""
        self.authorized_protocols: dict[str, tuple[str, ...]] = {}
        self.loaded_count = 0
        self.state: UsersViewState = "idle"
        runner.line_received.connect(self.write_process_line)
        runner.completed.connect(self.result_received)
        runner.failed.connect(self.failed)
        runner.finished.connect(self.runner_finished)
        self.clear_data()
        self.set_status("idle", "Open Users to load data from the selected server.")

    @property
    def has_session(self) -> bool:
        return bool(self.view_ip or self.runner.is_running)

    def selected_user(self) -> str | None:
        return self.tab.selected_user()

    def show(self) -> None:
        if self.operation_is_busy():
            self.cancel("Another server operation is running.")
            return
        if self.view_ip and self.state in {"ready", "error"} and not self.runner.is_running:
            self.tab.set_controls_enabled(True)
            self.tab.focus_table()
            return
        self.connect_selected_server()

    def hide(self) -> None:
        self.cancel("Open Users to reload data from the selected server.")
        self.hide_content()

    def switch_server(self, server_ip: str) -> None:
        if not self.users_is_visible():
            self.cancel("Open Users to load data from the selected server.")
            return
        if server_ip == self.view_ip and self.state in {"loading", "ready"}:
            return
        self.request_inventory_for_users("Checking Users authorization…")

    def server_ip_edited(self) -> None:
        if self.users_is_visible():
            self.cancel("Server address changed. Press Enter or leave the field to connect.")

    def server_ip_editing_finished(self, raw_server_ip: str) -> None:
        if not self.users_is_visible() or self.operation_is_busy():
            return
        server_ip, error = validate_server_ip(raw_server_ip)
        if error:
            self.cancel(f"Invalid server address: {error}", state="error")
            return
        if server_ip == self.view_ip and self.state in {"loading", "ready"}:
            return
        self.connect_selected_server()

    def connect_selected_server(self) -> None:
        server_ip = self.current_server_ip()
        if server_ip is None:
            self.cancel("Enter a valid IPv4 address to load users.", state="error")
            return
        if server_ip == self.view_ip and self.state in {"loading", "ready"}:
            return
        self.request_inventory_for_users("Checking Users authorization…")

    def request_inventory_for_users(self, message: str) -> None:
        self.authorization_server_ip = ""
        self.authorized_protocols.clear()
        self.clear_data()
        self.set_status("loading", message)
        self.request_inventory()

    def inventory_completed(self, snapshot: InventorySnapshot) -> None:
        if not self.users_is_visible():
            return
        self.authorization_server_ip = snapshot.server_ip
        self.authorized_protocols = {
            action: inventory_users_protocols(snapshot, action)
            for action in ("list", "get", "create", "extend", "delete")
        }
        self.start_list(snapshot.server_ip, "Loading users…")

    def inventory_failed(self, message: str) -> None:
        self.authorization_server_ip = ""
        self.authorized_protocols.clear()
        self.clear_data()
        self.set_status("error", f"Could not verify Users authorization: {message}")

    def run_action(self, action: str, name: str) -> None:
        if (
            not self.users_is_visible()
            or self.runner.is_running
            or self.view_ip != self.active_server_ip
        ):
            self.cancel(
                "Users data is no longer current. Reconnect before continuing.", state="error"
            )
            return
        if not self.authorized_protocols.get(action):
            self.write_result(
                f"=== Users {action}: failed — no registered component permits this action ===",
                "error",
            )
            self.set_status("error", "No registered component permits this Users action.")
            self.tab.set_controls_enabled(True)
            return
        self.tab.set_controls_enabled(False)
        status = {
            "create": f"Creating {name}…",
            "extend": f"Adding protocols for {name}…",
            "get": f"Loading connection files for {name}…",
            "delete": f"Deleting {name}…",
        }.get(action, "Running Users operation…")
        if action in {"create", "extend", "delete"}:
            self.clear_data()
        self.set_status("loading", status)
        self.start_request(action, self.active_server_ip, name)

    def clear_data(self) -> None:
        self.tab.clear()
        self.tab.set_available_create_protocols(())
        self.view_ip = ""
        self.loaded_count = 0
        self.tab.set_controls_enabled(False)

    def set_status(self, state: UsersViewState, message: str) -> None:
        self.state = state
        self.tab.set_status(state, message)

    def request_is_current(self, request_id: int, server_ip: str) -> bool:
        return (
            request_id == self.active_request_id
            and server_ip == self.active_server_ip
            and self.users_is_visible()
        )

    def write_process_line(self, request_id: int, server_ip: str, stream: str, line: str) -> None:
        if not self.request_is_current(request_id, server_ip):
            return
        prefix = "[stderr] " if stream == "stderr" else ""
        self.write_log(f"{prefix}{line}", reveal_log=False)

    def result_received(self, request_id: int, server_ip: str, action: str, data: object) -> None:
        if not self.request_is_current(request_id, server_ip):
            return
        if action == "list":
            if not self._valid_users_list(data):
                self.failed(
                    request_id, server_ip, action, "Invalid response from the Users helper."
                )
                return
            self.clear_data()
            self.tab.set_users(data)  # type: ignore[arg-type]
            self.tab.set_available_create_protocols(self.authorized_protocols.get("extend", ()))
            self.view_ip = server_ip
            self.loaded_count = len(data)  # type: ignore[arg-type]
            self.set_status("ready", "")
            self.tab.set_controls_enabled(True)
            self.write_result("=== Users list: successful ===", "success")
            return
        if action in {"create", "extend", "delete"}:
            if not isinstance(data, UsersMutationResult):
                self.failed(
                    request_id, server_ip, action, "Invalid response from the Users helper."
                )
                return
            self._mutation_result(server_ip, data)
            return
        if not isinstance(data, dict):
            self.failed(request_id, server_ip, action, "Invalid response from the Users helper.")
            return
        if action == "get":
            try:
                files = save_connection_files(
                    generated_connections_directory(self.project_directory),
                    server_ip,
                    data,
                )
            except (KeyError, OSError, TypeError, ValueError) as error:
                self.failed(
                    request_id, server_ip, action, f"Could not save connection files: {error}"
                )
                return
            self.write_log(
                f"Saved {len(files)} connection files for {data['name']}.", reveal_log=False
            )
            for path in files:
                self.write_log(f"Saved connection file: {path}", reveal_log=False)
            self.set_status("ready", "")
            self.tab.set_controls_enabled(True)
            self.write_result("=== Users get: successful ===", "success")
            return
        self.failed(request_id, server_ip, action, "Unknown response from the Users helper.")

    @staticmethod
    def _valid_users_list(data: object) -> bool:
        return isinstance(data, list) and not any(
            not isinstance(user, dict)
            or not isinstance(user.get("name"), str)
            or not isinstance(user.get("xray"), bool)
            or not isinstance(user.get("hysteria"), bool)
            or not isinstance(user.get("mieru"), bool)
            for user in data
        )

    def _mutation_result(self, server_ip: str, result: UsersMutationResult) -> None:
        states = "; ".join(
            f"{protocol.protocol}: config={protocol.config}, service={protocol.service}"
            for protocol in result.protocols
        )
        self.write_log(f"Users {result.action} protocol states — {states}.")
        restarted = (
            f" — restarted services: {', '.join(result.restarted)}" if result.restarted else ""
        )
        if result.outcome == "success":
            not_verified = [
                protocol.protocol
                for protocol in result.protocols
                if protocol.service == "not_verified"
            ]
            if not_verified:
                self.write_result(
                    f"=== Users {result.action}: configuration changed, but runtime "
                    "was not verified for "
                    f"{', '.join(not_verified)} because the service was inactive or "
                    f"failed{restarted} ===",
                    "warning",
                )
            else:
                success = (
                    "=== Users extend: successful — added protocols for "
                    f"{result.name}{restarted} ==="
                    if result.action == "extend"
                    else f"=== Users {result.action}: successful{restarted} ==="
                )
                self.write_result(success, "success")
            refresh_message = "Refreshing users…"
        elif result.outcome == "rolled_back":
            self.write_result(
                f"=== Users {result.action}: failed, previous state restored — {result.error} ===",
                "warning",
            )
            refresh_message = "Users operation was rolled back. Reloading users…"
        elif result.outcome == "partial":
            self.write_result(
                f"=== Users {result.action}: partial result — rollback incomplete — "
                f"{result.error} ===",
                "error",
            )
            refresh_message = "Users operation had a partial result. Reloading users…"
        else:
            self.write_result(
                f"=== Users {result.action}: result unknown — {result.error} ===",
                "warning",
            )
            refresh_message = "Users operation result is unknown. Reloading users…"
        self.start_list(server_ip, refresh_message, mutation_result_reported=True)

    def failed(self, request_id: int, server_ip: str, action: str, message: str) -> None:
        if not self.request_is_current(request_id, server_ip):
            return
        operation = action or "operation"
        self.write_result(f"=== Users {operation}: failed — {message} ===", "error")
        if action == "get" and self.view_ip == server_ip:
            self.set_status("error", f"Could not load connection files: {message}")
            self.tab.set_controls_enabled(True)
            return
        if action in {"create", "extend", "delete"}:
            self.start_list(
                server_ip,
                "Users operation failed. Reloading users…",
                mutation_result_reported=True,
            )
            return
        self.clear_data()
        prefix = "Could not load users" if action in {"", "list"} else "Users operation failed"
        self.set_status("error", f"{prefix}: {message}")

    def runner_finished(self) -> None:
        pending_server_ip = self.pending_server_ip
        self.pending_server_ip = ""
        if pending_server_ip and self.users_is_visible():
            self.start_list(pending_server_ip, "Loading users…")

    def start_list(
        self,
        server_ip: str,
        message: str,
        *,
        mutation_result_reported: bool = False,
    ) -> None:
        if self.runner.is_running:
            self.pending_server_ip = server_ip
            self.cancel(
                message,
                preserve_pending=True,
                preserve_authorization=True,
                mutation_result_reported=mutation_result_reported,
            )
            return
        self.clear_data()
        self.set_status("loading", message)
        self.start_request("list", server_ip)

    def start_request(self, action: str, server_ip: str, name: str = "") -> None:
        try:
            if server_ip != self.authorization_server_ip:
                raise UsersOperationError("Users authorization is not current for this server.")
            request = build_users_request(
                action,
                server_ip,
                name,
                allowed_protocols=self.authorized_protocols.get(action, ()),
            )
        except UsersOperationError as error:
            self.failed(self.active_request_id, server_ip, action, str(error))
            return
        self.request_id += 1
        self.active_request_id = self.request_id
        self.active_server_ip = request.server_ip
        if not self.runner.start_operation(self.active_request_id, request):
            self.failed(
                self.active_request_id,
                request.server_ip,
                action,
                "Another Users operation is already running.",
            )

    def cancel(
        self,
        message: str = "Users data is not loaded.",
        *,
        state: UsersViewState = "idle",
        preserve_pending: bool = False,
        preserve_authorization: bool = False,
        mutation_result_reported: bool = False,
    ) -> bool:
        request = self.runner.request
        if (
            self.runner.is_running
            and request is not None
            and request.action in {"create", "extend", "delete"}
            and not mutation_result_reported
        ):
            self.write_result(
                f"=== Users {request.action}: result unknown — local SSH operation was cancelled; "
                f"reload Users on {request.server_ip} to inspect the resulting configuration ===",
                "warning",
            )
        self.request_id += 1
        self.active_request_id = self.request_id
        self.active_server_ip = ""
        if not preserve_authorization:
            self.authorization_server_ip = ""
            self.authorized_protocols.clear()
        if not preserve_pending:
            self.pending_server_ip = ""
        self.clear_data()
        self.set_status(state, message)
        if not self.runner.is_running:
            return True
        self.runner.stop()
        return self.runner.wait(2_000)

    def resume_if_visible(self) -> None:
        if self.users_is_visible() and not self.operation_is_busy():
            self.show()
