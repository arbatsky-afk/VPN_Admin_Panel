"""Asynchronous PowerShell execution with live output for the Qt UI."""

from __future__ import annotations

import codecs
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from PySide6.QtCore import QObject, QProcess, QTimer, Signal

from app.services.modular_deployment import ModularDeployRequest
from app.services.ssh import validate_server_ip

PowerShellOperationKind = Literal[
    "ssh-check",
    "deploy-base-security",
    "deploy-xray",
    "deploy-hysteria2",
    "deploy-mieru",
    "deploy-docker",
    "deploy-nginx",
    "deploy-netdata",
]
POWERSHELL_OPERATION_KINDS = frozenset(
    {
        "ssh-check",
        "deploy-base-security",
        "deploy-xray",
        "deploy-hysteria2",
        "deploy-mieru",
        "deploy-docker",
        "deploy-nginx",
        "deploy-netdata",
    }
)


@dataclass(frozen=True, slots=True)
class PowerShellOperationRequest:
    """Immutable input and signal identity for one PowerShell operation."""

    operation_token: int
    kind: PowerShellOperationKind
    server_ip: str
    script_path: Path
    timeout_ms: int | None = None
    script_arguments: tuple[str, ...] = ()
    deploy_request: ModularDeployRequest | None = None


class PowerShellRunner(QObject):
    """Run one non-interactive PowerShell script and expose its output line by line."""

    line_received = Signal(object, str, str)
    finished = Signal(object, int, bool)
    failed_to_start = Signal(object, str)

    def __init__(self, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self.process = QProcess(self)
        self.process.setProcessChannelMode(QProcess.ProcessChannelMode.SeparateChannels)
        self.process.readyReadStandardOutput.connect(self._read_standard_output)
        self.process.readyReadStandardError.connect(self._read_standard_error)
        self.process.finished.connect(self._finished)
        self.process.errorOccurred.connect(self._process_error)

        self._tree_killer = QProcess(self)
        self._tree_killer.finished.connect(self._tree_kill_finished)
        self._tree_killer.errorOccurred.connect(self._tree_kill_error)

        self.timeout_timer = QTimer(self)
        self.timeout_timer.setSingleShot(True)
        self.timeout_timer.timeout.connect(self._timeout)
        self.timed_out = False
        self._timeout_ms: int | None = None
        self._buffers = {"stdout": "", "stderr": ""}
        self._decoders = self._new_decoders()
        self.request: PowerShellOperationRequest | None = None
        self._tree_kill_in_progress = False
        self._pending_finish: tuple[int, QProcess.ExitStatus] | None = None

    def start(self, request: PowerShellOperationRequest) -> bool:
        if (
            self.process.state() != QProcess.ProcessState.NotRunning
            or self._tree_kill_in_progress
            or self._tree_killer.state() != QProcess.ProcessState.NotRunning
        ):
            self.failed_to_start.emit(request, "Another operation is already running.")
            return False
        try:
            request = self._validated_request(request)
        except (TypeError, ValueError) as error:
            self.failed_to_start.emit(request, str(error))
            return False
        if not request.script_path.is_file():
            self.failed_to_start.emit(
                request,
                f"PowerShell script not found: {request.script_path}",
            )
            return False

        self.request = request
        self.timed_out = False
        self._timeout_ms = request.timeout_ms
        self._buffers = {"stdout": "", "stderr": ""}
        self._decoders = self._new_decoders()
        self._tree_kill_in_progress = False
        self._pending_finish = None
        self.process.setProgram("powershell.exe")
        operation_arguments = (
            request.deploy_request.powershell_arguments()
            if request.deploy_request is not None
            else request.script_arguments
        )
        self.process.setArguments(
            [
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-File",
                str(request.script_path),
                request.server_ip,
                *operation_arguments,
            ]
        )
        self.process.start()
        if request.timeout_ms is not None:
            self.timeout_timer.start(request.timeout_ms)
        return True

    @staticmethod
    def _validated_request(request: PowerShellOperationRequest) -> PowerShellOperationRequest:
        if not isinstance(request, PowerShellOperationRequest):
            raise TypeError("Invalid PowerShell operation request.")
        if (
            not isinstance(request.operation_token, int)
            or isinstance(request.operation_token, bool)
            or request.operation_token <= 0
        ):
            raise ValueError("Invalid PowerShell operation token.")
        if request.kind not in POWERSHELL_OPERATION_KINDS:
            raise ValueError("Unsupported PowerShell operation kind.")
        server_ip, error = validate_server_ip(request.server_ip)
        if error:
            raise ValueError(error)
        if server_ip != request.server_ip:
            raise ValueError("PowerShell target server IP must be normalized.")
        if not isinstance(request.script_path, Path):
            raise TypeError("PowerShell script path must be a Path.")
        if request.timeout_ms is not None and (
            not isinstance(request.timeout_ms, int)
            or isinstance(request.timeout_ms, bool)
            or request.timeout_ms <= 0
        ):
            raise ValueError("PowerShell timeout must be a positive integer.")
        if not isinstance(request.script_arguments, tuple) or not all(
            isinstance(argument, str) for argument in request.script_arguments
        ):
            raise TypeError("PowerShell script arguments must be a tuple of strings.")
        is_deploy = request.kind.startswith("deploy-")
        if is_deploy:
            deploy = request.deploy_request
            if not isinstance(deploy, ModularDeployRequest):
                raise TypeError("Deploy operation is missing validated immutable inputs.")
            if request.script_arguments:
                raise ValueError("Deploy operation must not include untyped script arguments.")
            if request.kind.removeprefix("deploy-") != deploy.component:
                raise ValueError("Deploy operation kind does not match its Component inputs.")
            if not deploy.bundle_directory.is_absolute():
                raise ValueError("Deploy bundle directory must be an absolute validated path.")
        elif request.deploy_request is not None:
            raise ValueError("Non-Deploy operation must not include Deploy inputs.")
        return request

    @staticmethod
    def _new_decoders() -> dict[str, codecs.IncrementalDecoder]:
        return {
            "stdout": codecs.getincrementaldecoder("utf-8")(errors="replace"),
            "stderr": codecs.getincrementaldecoder("utf-8")(errors="replace"),
        }

    def _read_standard_output(self) -> None:
        self._append_bytes("stdout", bytes(self.process.readAllStandardOutput()))

    def _read_standard_error(self) -> None:
        self._append_bytes("stderr", bytes(self.process.readAllStandardError()))

    def _append_bytes(self, stream: str, data: bytes) -> None:
        self._buffers[stream] += self._decoders[stream].decode(data)
        lines = self._buffers[stream].splitlines(keepends=True)
        self._buffers[stream] = ""
        for line in lines:
            if line.endswith(("\n", "\r")):
                request = self.request
                if request is not None:
                    self.line_received.emit(request, stream, line.rstrip("\r\n"))
            else:
                self._buffers[stream] = line

    def _flush_streams(self) -> None:
        self._read_standard_output()
        self._read_standard_error()
        for stream in ("stdout", "stderr"):
            self._buffers[stream] += self._decoders[stream].decode(b"", final=True)
            if self._buffers[stream]:
                request = self.request
                if request is not None:
                    self.line_received.emit(request, stream, self._buffers[stream])
                self._buffers[stream] = ""

    def _timeout(self) -> None:
        if self.process.state() == QProcess.ProcessState.NotRunning:
            return
        self.timed_out = True
        if self._timeout_ms is None:
            message = "Operation timed out."
        else:
            message = f"Timed out after {self._timeout_ms / 1000:g} seconds."
        request = self.request
        if request is not None:
            self.line_received.emit(request, "stderr", message)
        process_id = self.process.processId()
        if process_id > 0:
            self._tree_kill_in_progress = True
            self._tree_killer.setProgram("taskkill.exe")
            self._tree_killer.setArguments(["/PID", str(process_id), "/T", "/F"])
            self._tree_killer.start()
        else:
            self.process.kill()

    def _tree_kill_finished(
        self,
        exit_code: int,
        _exit_status: QProcess.ExitStatus,
    ) -> None:
        self._tree_kill_in_progress = False
        if exit_code != 0 and not self._primary_process_exited_normally():
            self._report_tree_kill_failure()
            if self.process.state() != QProcess.ProcessState.NotRunning:
                self.process.kill()
        self._emit_pending_finish()

    def _tree_kill_error(self, error: QProcess.ProcessError) -> None:
        if error != QProcess.ProcessError.FailedToStart:
            return
        self._tree_kill_in_progress = False
        if not self._primary_process_exited_normally():
            self._report_tree_kill_failure()
            if self.process.state() != QProcess.ProcessState.NotRunning:
                self.process.kill()
        self._emit_pending_finish()

    def _primary_process_exited_normally(self) -> bool:
        pending = self._pending_finish
        if pending is not None:
            return pending[1] == QProcess.ExitStatus.NormalExit
        return (
            self.process.state() == QProcess.ProcessState.NotRunning
            and self.process.exitStatus() == QProcess.ExitStatus.NormalExit
        )

    def _report_tree_kill_failure(self) -> None:
        request = self.request
        if request is not None:
            self.line_received.emit(
                request,
                "stderr",
                "Could not terminate the complete PowerShell process tree.",
            )

    def _emit_pending_finish(self) -> None:
        pending = self._pending_finish
        if pending is None:
            return
        self._pending_finish = None
        self._emit_finished(*pending)

    def _process_error(self, error: QProcess.ProcessError) -> None:
        if error == QProcess.ProcessError.FailedToStart:
            self.timeout_timer.stop()
            request = self.request
            if request is not None:
                self.failed_to_start.emit(request, "PowerShell could not be started.")

    def _finished(self, exit_code: int, _exit_status: QProcess.ExitStatus) -> None:
        self.timeout_timer.stop()
        self._flush_streams()
        if self._tree_kill_in_progress:
            self._pending_finish = (exit_code, _exit_status)
            return
        self._emit_finished(exit_code, _exit_status)

    def _emit_finished(
        self,
        exit_code: int,
        _exit_status: QProcess.ExitStatus,
    ) -> None:
        request = self.request
        if request is not None:
            self.finished.emit(request, exit_code, self.timed_out)
