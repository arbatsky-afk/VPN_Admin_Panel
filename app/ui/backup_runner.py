"""One-session streaming Backup execution for the Qt UI."""

from __future__ import annotations

import hashlib
import re
import threading
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Literal
from uuid import uuid4

from PySide6.QtCore import QThread, Signal

from app.services.backup import BackupError, BackupPlan, render_streaming_backup_script
from app.services.restore import RestoreError, restore_plan_from_archive
from app.services.ssh import validate_server_ip
from app.services.ssh_settings import (
    SshConnectionSettings,
    SshSettingsError,
    primary_ssh_connection,
)
from app.services.ssh_transport import (
    SshCommand,
    SshTimeoutProfile,
    SshTransportError,
    run_streaming_ssh,
)

SHA256_LINE = re.compile(r"^SHA256=([0-9a-f]{64})$")
BackupOperationKind = Literal["local-backup"]


@dataclass(frozen=True, slots=True)
class BackupOperationRequest:
    """Immutable identity returned by every signal for one Backup run."""

    operation_token: int
    server_ip: str
    kind: BackupOperationKind = "local-backup"


class BackupRunner(QThread):
    """Stream one remote archive directly into a local temporary file."""

    line_received = Signal(object, str, str)
    completed = Signal(object, str)
    failed = Signal(object, str)

    def __init__(self, project_directory: Path, parent=None) -> None:
        super().__init__(parent)
        self.project_directory = project_directory
        self.request: BackupOperationRequest | None = None
        self.plan: BackupPlan | None = None
        self.backups_directory: Path | None = None
        self._stop_requested = threading.Event()

    @property
    def is_running(self) -> bool:
        return self.isRunning()

    def start_backup(
        self,
        request: BackupOperationRequest,
        plan: BackupPlan,
        backups_directory: Path,
    ) -> bool:
        if self.isRunning():
            return False
        try:
            request = self._validated_request(request)
        except (TypeError, ValueError) as error:
            self.failed.emit(request, str(error))
            return False
        self.request = request
        self.plan = plan
        self.backups_directory = backups_directory
        self._stop_requested.clear()
        self.start()
        return True

    @staticmethod
    def _validated_request(request: BackupOperationRequest) -> BackupOperationRequest:
        if not isinstance(request, BackupOperationRequest):
            raise TypeError("Invalid Backup operation request.")
        if (
            not isinstance(request.operation_token, int)
            or isinstance(request.operation_token, bool)
            or request.operation_token <= 0
        ):
            raise ValueError("Invalid Backup operation token.")
        if request.kind != "local-backup":
            raise ValueError("Unsupported Backup operation kind.")
        server_ip, error = validate_server_ip(request.server_ip)
        if error:
            raise ValueError(error)
        if server_ip != request.server_ip:
            raise ValueError("Backup server IP must be normalized.")
        return request

    def stop(self) -> None:
        self._stop_requested.set()

    def run(self) -> None:
        temporary_archive: Path | None = None
        try:
            request = self.request
            plan = self.plan
            backups_directory = self.backups_directory
            if request is None or plan is None or backups_directory is None:
                raise BackupError("Backup runner was started without a plan.")
            connection = self._connection_settings()
            backups_directory.mkdir(parents=True, exist_ok=True)
            final_archive = self._archive_destination(backups_directory)
            temporary_archive = backups_directory / f".{final_archive.name}.{uuid4().hex}.part"
            script = render_streaming_backup_script(plan).encode("utf-8")
            self.line_received.emit(
                request,
                "stdout",
                "Streaming server archive through one SSH session …",
            )
            stderr_result: dict[str, object] = {}
            digest = hashlib.sha256()
            with temporary_archive.open("xb") as archive:

                def write_archive_chunk(chunk: bytes) -> None:
                    archive.write(chunk)
                    digest.update(chunk)

                result = run_streaming_ssh(
                    SshCommand(
                        request.server_ip,
                        connection,
                        ("bash -s",),
                        SshTimeoutProfile.streaming_operation(),
                    ),
                    input_bytes=script,
                    stdout_chunk_received=write_archive_chunk,
                    stderr_line_received=lambda line: self._accept_stderr_line(
                        line, stderr_result
                    ),
                    cancelled=self._stop_requested.is_set,
                )
            if result.returncode != 0:
                raise BackupError(
                    f"Remote backup command failed with exit code {result.returncode}."
                )
            remote_hash = stderr_result.get("sha256")
            local_hash = digest.hexdigest()
            if not isinstance(remote_hash, str):
                raise BackupError("Remote backup did not provide an archive checksum.")
            if local_hash != remote_hash:
                raise BackupError("Downloaded archive checksum does not match the server archive.")
            try:
                restore_plan_from_archive(temporary_archive)
            except RestoreError as error:
                raise BackupError(
                    f"Generated Backup archive failed Restore preflight: {error}"
                ) from error
            temporary_archive.replace(final_archive)
            temporary_archive = None
            self.completed.emit(request, str(final_archive))
        except (BackupError, SshTransportError, OSError, TypeError, ValueError) as error:
            request = self.request
            if request is not None:
                self.failed.emit(request, str(error))
        except Exception:  # noqa: BLE001 - terminal runner boundary must always publish.
            request = self.request
            if request is not None:
                self.failed.emit(request, "An unexpected Backup service failure occurred.")
        finally:
            if temporary_archive is not None:
                try:
                    temporary_archive.unlink(missing_ok=True)
                except OSError:
                    pass

    def _connection_settings(self) -> SshConnectionSettings:
        try:
            connection = primary_ssh_connection(self.project_directory)
        except SshSettingsError as error:
            raise BackupError(f"Could not read SSH settings: {error}") from error
        return connection

    def _archive_destination(self, backups_directory: Path) -> Path:
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        request = self.request
        if request is None:
            raise BackupError("Backup runner was started without a request.")
        stem = f"vpn-backup-{request.server_ip}-{timestamp}"
        candidate = backups_directory / f"{stem}.tar.gz"
        suffix = 2
        while candidate.exists():
            candidate = backups_directory / f"{stem}-{suffix}.tar.gz"
            suffix += 1
        return candidate

    def _accept_stderr_line(self, line: str, result: dict[str, object]) -> None:
        match = SHA256_LINE.fullmatch(line)
        if match:
            result["sha256"] = match.group(1)
        request = self.request
        if request is not None:
            self.line_received.emit(request, "stderr", line)
