"""One-session SSH transport for a prevalidated local Restore archive."""

from __future__ import annotations

import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from PySide6.QtCore import QThread, Signal

from app.services.restore import (
    EffectiveRestorePlan,
    RestoreError,
    RestorePlan,
    render_streaming_restore_command,
    restore_plan_from_archive,
)
from app.services.ssh import validate_server_ip
from app.services.ssh_settings import (
    SshConnectionSettings,
    SshSettingsError,
    primary_ssh_connection,
)
from app.services.ssh_transport import (
    SshCommand,
    SshLaunchError,
    SshTimeoutProfile,
    SshTransportError,
    run_streaming_ssh,
)

RestoreOperationPhase = Literal["apply"]
RestoreOutcome = Literal["success", "pre_apply_failed", "partial", "unknown"]
RestoreRemotePhase = Literal[
    "pre_apply", "validated", "apply_started", "files_applied", "services_applied", "complete"
]
_RESTORE_PHASES = frozenset({"validated", "apply_started", "files_applied", "services_applied"})
_POST_APPLY_PHASES = frozenset({"apply_started", "files_applied", "services_applied"})


@dataclass(frozen=True, slots=True)
class RestoreOperationRequest:
    """Immutable input and signal identity for one remote Restore apply."""

    operation_token: int
    server_ip: str
    phase: RestoreOperationPhase = "apply"


@dataclass(frozen=True, slots=True)
class RestoreOperationResult:
    """Evidence-based outcome of one remote Restore process."""

    outcome: RestoreOutcome
    message: str
    last_phase: RestoreRemotePhase


class RestoreRunner(QThread):
    """Stream an archive to one fixed remote command outside the GUI thread."""

    line_received = Signal(object, str, str)
    completed = Signal(object, object)
    failed = Signal(object, str)

    def __init__(self, project_directory: Path, parent=None) -> None:
        super().__init__(parent)
        self.project_directory = project_directory
        self.request: RestoreOperationRequest | None = None
        self.full_plan: RestorePlan | None = None
        self.effective_plan: EffectiveRestorePlan | None = None
        self._stop_requested = threading.Event()

    @property
    def is_running(self) -> bool:
        return self.isRunning()

    def start_restore(
        self,
        request: RestoreOperationRequest,
        full_plan: RestorePlan,
        effective_plan: EffectiveRestorePlan,
    ) -> bool:
        if self.isRunning():
            return False
        try:
            request = self._validated_request(request)
            if not isinstance(full_plan, RestorePlan) or not isinstance(
                effective_plan, EffectiveRestorePlan
            ):
                raise TypeError("Invalid Restore plan.")
            if effective_plan.full_plan != full_plan:
                raise ValueError(
                    "Effective Restore plan does not belong to the validated archive plan."
                )
            if effective_plan.target_server_ip != request.server_ip:
                raise ValueError(
                    "Effective Restore plan target does not match the Restore request."
                )
        except (TypeError, ValueError) as error:
            self.failed.emit(request, str(error))
            return False
        if not full_plan.archive_path.is_file():
            self.failed.emit(request, "The selected Backup archive could not be found.")
            return False
        self.request = request
        self.full_plan = full_plan
        self.effective_plan = effective_plan
        self._stop_requested.clear()
        self.start()
        return True

    @staticmethod
    def _validated_request(request: RestoreOperationRequest) -> RestoreOperationRequest:
        if not isinstance(request, RestoreOperationRequest):
            raise TypeError("Invalid Restore operation request.")
        if (
            not isinstance(request.operation_token, int)
            or isinstance(request.operation_token, bool)
            or request.operation_token <= 0
        ):
            raise ValueError("Invalid Restore operation token.")
        if request.phase != "apply":
            raise ValueError("Unsupported Restore operation phase.")
        server_ip, error = validate_server_ip(request.server_ip)
        if error:
            raise ValueError(error)
        if server_ip != request.server_ip:
            raise ValueError("Restore target server IP must be normalized.")
        return request

    def stop(self) -> None:
        self._stop_requested.set()

    def run(self) -> None:
        phase_state: dict[str, str] = {"last_phase": "pre_apply"}
        ssh_started = False
        try:
            request = self.request
            full_plan = self.full_plan
            effective_plan = self.effective_plan
            if request is None or full_plan is None or effective_plan is None:
                raise RestoreError("Restore runner was started without a plan.")
            connection = self._connection_settings()
            with full_plan.archive_path.open("rb") as archive:
                validated_plan = restore_plan_from_archive(
                    full_plan.archive_path, archive_file=archive
                )
                if validated_plan != full_plan or effective_plan.full_plan != validated_plan:
                    raise RestoreError(
                        "The selected Backup archive changed after preflight validation."
                    )
                archive.seek(0)
                self.line_received.emit(
                    request,
                    "stdout",
                    "Streaming archive to the server through one SSH session …",
                )
                stderr_result: dict[str, object] = {}
                command = SshCommand(
                    request.server_ip,
                    connection,
                    (render_streaming_restore_command(effective_plan),),
                    SshTimeoutProfile.streaming_operation(),
                )
                ssh_started = True
                result = run_streaming_ssh(
                    command,
                    input_stream=archive,
                    stdout_line_received=lambda line: self._accept_output_line(
                        line, "stdout", {}, None
                    ),
                    stderr_line_received=lambda line: self._accept_output_line(
                        line, "stderr", stderr_result, phase_state
                    ),
                    cancelled=self._stop_requested.is_set,
                )
                if result.returncode != 0:
                    self.completed.emit(
                        request,
                        self._failed_process_result(result.returncode, stderr_result, phase_state),
                    )
                    return
                if stderr_result.get("remote_success_phase") != "complete":
                    self.completed.emit(
                        request,
                        RestoreOperationResult(
                            "unknown",
                            "Remote Restore exited without a confirmed completion marker.",
                            phase_state["last_phase"],  # type: ignore[arg-type]
                        ),
                    )
                    return
            self.completed.emit(
                request, RestoreOperationResult("success", "Restore completed.", "complete")
            )
        except (RestoreError, SshTransportError, OSError, TypeError, ValueError) as error:
            request = self.request
            if request is not None:
                if not ssh_started or isinstance(error, SshLaunchError):
                    self.failed.emit(request, str(error))
                else:
                    self.completed.emit(
                        request,
                        RestoreOperationResult(
                            "unknown",
                            str(error),
                            phase_state["last_phase"],  # type: ignore[arg-type]
                        ),
                    )
        except Exception:  # noqa: BLE001 - terminal runner boundary must always publish.
            request = self.request
            if request is not None:
                message = "An unexpected Restore service failure occurred."
                if not ssh_started:
                    self.failed.emit(request, message)
                else:
                    self.completed.emit(
                        request,
                        RestoreOperationResult(
                            "unknown",
                            message,
                            phase_state["last_phase"],  # type: ignore[arg-type]
                        ),
                    )

    def _connection_settings(self) -> SshConnectionSettings:
        try:
            connection = primary_ssh_connection(self.project_directory)
        except SshSettingsError as error:
            raise RestoreError(f"Could not read SSH settings: {error}") from error
        return connection

    def _accept_output_line(
        self,
        line: str,
        output_name: str,
        result: dict[str, object],
        phase_state: dict[str, str] | None = None,
    ) -> None:
        protocol_line = False
        if output_name == "stderr" and phase_state is not None:
            if line.startswith("VPN_RESTORE_PHASE "):
                protocol_line = True
                phase = line.removeprefix("VPN_RESTORE_PHASE ")
                if phase in _RESTORE_PHASES:
                    phase_state["last_phase"] = phase
            elif line.startswith("VPN_RESTORE_RESULT failure "):
                protocol_line = True
                parts = line.split()
                if (
                    len(parts) == 4
                    and parts[2] in {"pre_apply", *_RESTORE_PHASES}
                    and parts[3].isdigit()
                ):
                    result["remote_failure_phase"] = parts[2]
            elif line == "VPN_RESTORE_RESULT success complete 0":
                protocol_line = True
                result["remote_success_phase"] = "complete"
        request = self.request
        if request is not None and not protocol_line:
            self.line_received.emit(
                request,
                output_name,
                line,
            )

    @staticmethod
    def _failed_process_result(
        returncode: int,
        stderr_result: dict[str, object],
        phase_state: dict[str, str],
    ) -> RestoreOperationResult:
        failure_phase = stderr_result.get("remote_failure_phase")
        last_phase = phase_state["last_phase"]
        message = f"Remote Restore command failed with exit code {returncode}."
        if failure_phase in {"pre_apply", "validated"}:
            return RestoreOperationResult("pre_apply_failed", message, failure_phase)  # type: ignore[arg-type]
        if failure_phase in _POST_APPLY_PHASES:
            return RestoreOperationResult("partial", message, failure_phase)  # type: ignore[arg-type]
        return RestoreOperationResult("unknown", message, last_phase)  # type: ignore[arg-type]
