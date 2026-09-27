"""One-shot SSH execution for Users requests."""

from __future__ import annotations

import threading
from pathlib import Path

from PySide6.QtCore import QThread, Signal

from app.services.ssh_settings import (
    SshConnectionSettings,
    SshSettingsError,
    primary_ssh_connection,
)
from app.services.ssh_transport import (
    SshCommand,
    SshTimeoutProfile,
    SshTransportError,
    run_buffered_ssh_bytes,
)
from app.services.users import (
    MUTATING_USERS_ACTIONS,
    REMOTE_USERS_COMMAND,
    UsersMutationResult,
    UsersOperationError,
    UsersOperationRequest,
    parse_users_response,
    render_remote_users_program,
    unknown_users_mutation_result,
)


class UsersOperationRunner(QThread):
    """Run one Users request and close its SSH connection before reporting it."""

    line_received = Signal(int, str, str, str)
    completed = Signal(int, str, str, object)
    failed = Signal(int, str, str, str)

    def __init__(self, project_directory: Path, parent=None) -> None:
        super().__init__(parent)
        self.project_directory = project_directory
        self.request_id = 0
        self.request: UsersOperationRequest | None = None
        self._stop_requested = threading.Event()

    @property
    def is_running(self) -> bool:
        return self.isRunning()

    def start_operation(self, request_id: int, request: UsersOperationRequest) -> bool:
        if self.isRunning():
            return False
        self.request_id = request_id
        self.request = request
        self._stop_requested.clear()
        self.start()
        return True

    def stop(self) -> None:
        self._stop_requested.set()

    def run(self) -> None:
        request = self.request
        if request is None:
            self.failed.emit(
                self.request_id, "", "", "Users runner was started without a request."
            )
            return
        try:
            connection = self._connection_settings()
            program = render_remote_users_program(self.project_directory, request)
            self.line_received.emit(
                self.request_id,
                request.server_ip,
                "stdout",
                f"Running Users {request.action} operation …",
            )
            result = run_buffered_ssh_bytes(
                SshCommand(
                    request.server_ip,
                    connection,
                    (REMOTE_USERS_COMMAND,),
                    SshTimeoutProfile.short_operation(),
                ),
                input_bytes=program,
                cancelled=self._stop_requested.is_set,
            )
            if result.stderr:
                for line in result.stderr.splitlines():
                    self.line_received.emit(self.request_id, request.server_ip, "stderr", line)
            if self._stop_requested.is_set():
                raise UsersOperationError("Users operation was cancelled.")
            response = parse_users_response(request.action, result.stdout)
            if result.returncode != 0:
                raise UsersOperationError(
                    f"Remote Users operation failed with exit code {result.returncode}."
                )
            if isinstance(response, UsersMutationResult) and response.name != request.name:
                raise UsersOperationError(
                    "Users mutation response name does not match the request."
                )
            self.completed.emit(self.request_id, request.server_ip, request.action, response)
        except (UsersOperationError, SshTransportError, OSError, TypeError, ValueError) as error:
            if request.action in MUTATING_USERS_ACTIONS:
                self.completed.emit(
                    self.request_id,
                    request.server_ip,
                    request.action,
                    unknown_users_mutation_result(request, str(error)),
                )
            else:
                self.failed.emit(self.request_id, request.server_ip, request.action, str(error))
        except Exception:  # noqa: BLE001 - terminal runner boundary must always publish.
            message = "An unexpected Users service failure occurred."
            if request.action in MUTATING_USERS_ACTIONS:
                self.completed.emit(
                    self.request_id,
                    request.server_ip,
                    request.action,
                    unknown_users_mutation_result(request, message),
                )
            else:
                self.failed.emit(self.request_id, request.server_ip, request.action, message)

    def _connection_settings(self) -> SshConnectionSettings:
        try:
            connection = primary_ssh_connection(self.project_directory)
        except SshSettingsError as error:
            raise UsersOperationError(
                f"Could not read local SSH configuration: {error}"
            ) from error
        return connection
