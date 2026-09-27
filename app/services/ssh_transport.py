"""Shared one-shot OpenSSH execution for VPN Admin Panel services."""

from __future__ import annotations

import re
import subprocess
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Literal

from .cancellable_process import (
    ProcessCancelledError,
    run_cancellable_binary_process,
    run_cancellable_process,
)
from .ssh import validate_server_ip
from .ssh_settings import SshConnectionSettings

DEFAULT_CONNECT_TIMEOUT_SECONDS = 20
DEFAULT_SERVER_ALIVE_INTERVAL_SECONDS = 15
DEFAULT_SERVER_ALIVE_COUNT_MAX = 4
DEFAULT_SHORT_OPERATION_GRACE_SECONDS = 45
DEFAULT_SUBSCRIPTION_OPERATION_GRACE_SECONDS = 60
DEFAULT_STREAM_INACTIVITY_TIMEOUT_SECONDS = 300

_ANSI_ESCAPE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
_OPENSSH_IDENTITY_PATH_MESSAGES = (
    re.compile(r"(?im)^warning: identity file .+? not accessible:(.*)$"),
    re.compile(r"(?im)^load key [\"'].+?[\"']:(.*)$"),
    re.compile(r"(?im)^no such identity: .+?:(.*)$"),
    re.compile(r"(?im)^permissions for [\"'].+?[\"'] are too open\.(.*)$"),
)


class SshTransportError(RuntimeError):
    """The local OpenSSH process could not produce a normal result."""


class SshLaunchError(SshTransportError):
    """The local OpenSSH process could not be started or used."""


class SshTimeoutError(SshTransportError):
    """The configured SSH execution deadline expired."""


class SshCancelledError(SshTransportError):
    """The caller cancelled the SSH operation."""


class SshStreamError(SshTransportError):
    """A local stdin/stdout/stderr streaming worker failed."""

    def __init__(self, stream: Literal["stdin", "stdout", "stderr"]) -> None:
        super().__init__(f"SSH {stream} stream failed.")
        self.stream = stream


@dataclass(frozen=True, slots=True)
class SshTimeoutProfile:
    """Timeout and keepalive policy for one kind of SSH operation."""

    connect_timeout_seconds: int
    total_timeout_seconds: float | None
    inactivity_timeout_seconds: float | None = None
    server_alive_interval_seconds: int = DEFAULT_SERVER_ALIVE_INTERVAL_SECONDS
    server_alive_count_max: int = DEFAULT_SERVER_ALIVE_COUNT_MAX

    @classmethod
    def short_operation(
        cls, connect_timeout_seconds: int = DEFAULT_CONNECT_TIMEOUT_SECONDS
    ) -> SshTimeoutProfile:
        return cls(
            connect_timeout_seconds=connect_timeout_seconds,
            total_timeout_seconds=connect_timeout_seconds + DEFAULT_SHORT_OPERATION_GRACE_SECONDS,
        )

    @classmethod
    def subscription_operation(
        cls,
        connect_timeout_seconds: int = DEFAULT_CONNECT_TIMEOUT_SECONDS,
    ) -> SshTimeoutProfile:
        return cls(
            connect_timeout_seconds=connect_timeout_seconds,
            total_timeout_seconds=connect_timeout_seconds
            + DEFAULT_SUBSCRIPTION_OPERATION_GRACE_SECONDS,
        )

    @classmethod
    def streaming_operation(
        cls,
        connect_timeout_seconds: int = DEFAULT_CONNECT_TIMEOUT_SECONDS,
        inactivity_timeout_seconds: float = DEFAULT_STREAM_INACTIVITY_TIMEOUT_SECONDS,
    ) -> SshTimeoutProfile:
        return cls(
            connect_timeout_seconds=connect_timeout_seconds,
            total_timeout_seconds=None,
            inactivity_timeout_seconds=inactivity_timeout_seconds,
        )


@dataclass(frozen=True, slots=True)
class SshCommand:
    """Validated local connection data and one fixed remote command."""

    server_ip: str
    connection: SshConnectionSettings
    remote_arguments: tuple[str, ...]
    timeout: SshTimeoutProfile

    def __post_init__(self) -> None:
        normalized_ip, error = validate_server_ip(self.server_ip)
        if error or normalized_ip != self.server_ip:
            raise ValueError(error or "SSH server IPv4 address must be normalized.")
        if not isinstance(self.connection, SshConnectionSettings):
            raise TypeError("SSH command requires validated connection settings.")
        if not isinstance(self.connection.private_key_path, Path):
            raise TypeError("SSH private key path must be a Path.")
        if (
            isinstance(self.connection.port, bool)
            or not isinstance(self.connection.port, int)
            or not 1 <= self.connection.port <= 65535
        ):
            raise ValueError("SSH port must be between 1 and 65535.")
        if (
            not isinstance(self.remote_arguments, tuple)
            or not self.remote_arguments
            or any(
                not isinstance(argument, str) or not argument for argument in self.remote_arguments
            )
        ):
            raise ValueError("SSH remote arguments must be a non-empty tuple of strings.")
        _validate_timeout_profile(self.timeout)


@dataclass(frozen=True, slots=True)
class SshCompletedProcess:
    """Sanitized result of one completed buffered SSH process."""

    returncode: int
    stdout: str
    stderr: str


@dataclass(frozen=True, slots=True)
class SshCompletedBinaryProcess:
    """Binary stdout and sanitized diagnostics from one SSH process."""

    returncode: int
    stdout: bytes
    stderr: str


@dataclass(frozen=True, slots=True)
class SshStreamingResult:
    """Exit status of one fully drained streaming SSH process."""

    returncode: int


def run_buffered_ssh(
    command: SshCommand,
    *,
    input_text: str | None = None,
    cancelled: Callable[[], bool] | None = None,
) -> SshCompletedProcess:
    """Run one bounded SSH command and return only sanitized diagnostics."""
    if not isinstance(command, SshCommand):
        raise TypeError("A validated SshCommand is required.")
    total_timeout = command.timeout.total_timeout_seconds
    if total_timeout is None:
        raise ValueError("Buffered SSH execution requires a total timeout.")
    arguments = _build_ssh_arguments(command)
    try:
        completed = run_cancellable_process(
            arguments,
            timeout=total_timeout,
            input_text=input_text,
            cancelled=cancelled,
        )
    except ProcessCancelledError as error:
        raise SshCancelledError("SSH operation was cancelled.") from error
    except subprocess.TimeoutExpired as error:
        raise SshTimeoutError("SSH operation timed out.") from error
    except OSError as error:
        raise SshLaunchError("SSH process could not run.") from error
    return SshCompletedProcess(
        returncode=completed.returncode,
        stdout=completed.stdout,
        stderr=redact_ssh_diagnostics(completed.stderr, command.connection.private_key_path),
    )


def run_buffered_ssh_bytes(
    command: SshCommand,
    *,
    input_bytes: bytes | None = None,
    cancelled: Callable[[], bool] | None = None,
) -> SshCompletedBinaryProcess:
    """Run one bounded SSH command without transcoding its stdin or stdout."""
    if not isinstance(command, SshCommand):
        raise TypeError("A validated SshCommand is required.")
    total_timeout = command.timeout.total_timeout_seconds
    if total_timeout is None:
        raise ValueError("Buffered SSH execution requires a total timeout.")
    arguments = _build_ssh_arguments(command)
    try:
        completed = run_cancellable_binary_process(
            arguments,
            timeout=total_timeout,
            input_bytes=input_bytes,
            cancelled=cancelled,
        )
    except ProcessCancelledError as error:
        raise SshCancelledError("SSH operation was cancelled.") from error
    except subprocess.TimeoutExpired as error:
        raise SshTimeoutError("SSH operation timed out.") from error
    except OSError as error:
        raise SshLaunchError("SSH process could not run.") from error
    return SshCompletedBinaryProcess(
        returncode=completed.returncode,
        stdout=completed.stdout,
        stderr=redact_ssh_diagnostics(
            completed.stderr.decode("utf-8", errors="replace"),
            command.connection.private_key_path,
        ),
    )


def run_streaming_ssh(
    command: SshCommand,
    *,
    input_bytes: bytes | None = None,
    input_stream: BinaryIO | None = None,
    stdout_chunk_received: Callable[[bytes], None] | None = None,
    stdout_line_received: Callable[[str], None] | None = None,
    stderr_line_received: Callable[[str], None] | None = None,
    cancelled: Callable[[], bool] | None = None,
    poll_seconds: float = 0.1,
    terminate_timeout: float = 5.0,
) -> SshStreamingResult:
    """Run one SSH process while owning all pipes, deadlines, and cleanup."""
    if not isinstance(command, SshCommand):
        raise TypeError("A validated SshCommand is required.")
    if input_bytes is not None and input_stream is not None:
        raise ValueError("Streaming SSH accepts one stdin source.")
    if stdout_chunk_received is not None and stdout_line_received is not None:
        raise ValueError("Streaming SSH stdout must use either chunk or line callbacks.")
    inactivity_timeout = command.timeout.inactivity_timeout_seconds
    if inactivity_timeout is None:
        raise ValueError("Streaming SSH execution requires an inactivity timeout.")
    if poll_seconds <= 0 or terminate_timeout <= 0:
        raise ValueError("Streaming SSH polling and termination timeouts must be positive.")

    has_input = input_bytes is not None or input_stream is not None
    try:
        process = subprocess.Popen(
            _build_ssh_arguments(command),
            stdin=subprocess.PIPE if has_input else None,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except OSError as error:
        raise SshLaunchError("SSH process could not run.") from error
    if process.stdout is None or process.stderr is None or (has_input and process.stdin is None):
        _stop_streaming_process(process, terminate_timeout)
        raise SshLaunchError("SSH process streams could not be opened.")

    progress_lock = threading.Lock()
    last_progress = [time.monotonic()]
    worker_errors: dict[str, Exception] = {}

    def record_progress() -> None:
        with progress_lock:
            last_progress[0] = time.monotonic()

    def read_stdout() -> None:
        try:
            if stdout_chunk_received is not None:
                while chunk := process.stdout.read(64 * 1024):
                    record_progress()
                    stdout_chunk_received(chunk)
            elif stdout_line_received is not None:
                for raw_line in iter(process.stdout.readline, b""):
                    record_progress()
                    stdout_line_received(
                        _safe_stream_line(raw_line, command.connection.private_key_path)
                    )
            else:
                while process.stdout.read(64 * 1024):
                    record_progress()
        except Exception as error:  # noqa: BLE001 - worker reports through shared state.
            worker_errors["stdout"] = error

    def read_stderr() -> None:
        try:
            for raw_line in iter(process.stderr.readline, b""):
                record_progress()
                if stderr_line_received is not None:
                    stderr_line_received(
                        _safe_stream_line(raw_line, command.connection.private_key_path)
                    )
        except Exception as error:  # noqa: BLE001 - worker reports through shared state.
            worker_errors["stderr"] = error

    def write_stdin() -> None:
        assert process.stdin is not None

        def write_chunk(chunk: bytes) -> bool:
            try:
                process.stdin.write(chunk)
                process.stdin.flush()
            except BrokenPipeError:
                return False
            except Exception as error:  # noqa: BLE001 - worker reports through shared state.
                worker_errors["stdin"] = error
                return False
            record_progress()
            return True

        try:
            if input_bytes is not None:
                chunks = (
                    input_bytes[index : index + 64 * 1024]
                    for index in range(0, len(input_bytes), 64 * 1024)
                )
                for chunk in chunks:
                    if not write_chunk(chunk):
                        return
            elif input_stream is not None:
                while True:
                    try:
                        chunk = input_stream.read(64 * 1024)
                    except Exception as error:  # noqa: BLE001 - worker reports through shared state.
                        worker_errors["stdin"] = error
                        return
                    if not chunk or not write_chunk(chunk):
                        return
        finally:
            try:
                process.stdin.close()
            except OSError:
                pass

    threads = [
        threading.Thread(target=read_stdout, daemon=True),
        threading.Thread(target=read_stderr, daemon=True),
    ]
    if has_input:
        threads.append(threading.Thread(target=write_stdin, daemon=True))
    for thread in threads:
        thread.start()

    started_at = time.monotonic()
    terminal_error: SshTransportError | None = None
    try:
        while process.poll() is None:
            if worker_errors:
                break
            if cancelled is not None and cancelled():
                terminal_error = SshCancelledError("SSH operation was cancelled.")
                break
            now = time.monotonic()
            total_timeout = command.timeout.total_timeout_seconds
            if total_timeout is not None and now - started_at >= total_timeout:
                terminal_error = SshTimeoutError("SSH operation timed out.")
                break
            with progress_lock:
                inactive_for = now - last_progress[0]
            if inactive_for >= inactivity_timeout:
                terminal_error = SshTimeoutError("SSH operation timed out after no data progress.")
                break
            time.sleep(poll_seconds)
    finally:
        if process.poll() is None:
            _stop_streaming_process(process, terminate_timeout)
        for thread in threads:
            thread.join(terminate_timeout)

    for stream_name, thread in zip(
        ("stdout", "stderr", "stdin"),
        threads,
        strict=False,
    ):
        if thread.is_alive():
            raise SshStreamError(stream_name)  # type: ignore[arg-type]

    if terminal_error is not None:
        raise terminal_error
    if worker_errors:
        stream_name, error = next(iter(worker_errors.items()))
        raise SshStreamError(stream_name) from error  # type: ignore[arg-type]
    return SshStreamingResult(process.returncode)


def _safe_stream_line(raw_line: bytes, private_key_path: Path) -> str:
    text = raw_line.decode("utf-8", errors="replace").rstrip("\r\n")
    return redact_ssh_diagnostics(text, private_key_path)


def _stop_streaming_process(process: subprocess.Popen[bytes], terminate_timeout: float) -> None:
    if process.poll() is not None:
        return
    try:
        process.terminate()
        try:
            process.wait(timeout=terminate_timeout)
            return
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
    except OSError:
        if process.poll() is None:
            try:
                process.kill()
                process.wait()
            except OSError:
                pass


def redact_ssh_diagnostics(text: str, private_key_path: Path) -> str:
    """Remove terminal escapes and every configured private-key path from SSH text."""
    if not isinstance(text, str):
        raise TypeError("SSH diagnostics must be text.")
    if not isinstance(private_key_path, Path):
        raise TypeError("SSH private key path must be a Path.")
    redacted = _ANSI_ESCAPE.sub("", text)
    variants = {
        str(private_key_path),
        str(private_key_path).replace("\\", "/"),
        str(private_key_path).replace("/", "\\"),
    }
    for variant in sorted(variants, key=len, reverse=True):
        if variant:
            redacted = re.sub(
                re.escape(variant), "<SSH private key>", redacted, flags=re.IGNORECASE
            )
    replacements = (
        "SSH identity file is not accessible.\\1",
        "Could not load SSH identity.\\1",
        "SSH identity is unavailable.\\1",
        "SSH identity permissions are too open.\\1",
    )
    for pattern, replacement in zip(_OPENSSH_IDENTITY_PATH_MESSAGES, replacements, strict=True):
        redacted = pattern.sub(replacement, redacted)
    return redacted


def format_ssh_error_detail(redacted_stderr: str, limit: int = 500) -> str:
    """Format already-redacted SSH diagnostics for one bounded error message."""
    if not isinstance(redacted_stderr, str):
        raise TypeError("SSH diagnostics must be text.")
    if isinstance(limit, bool) or not isinstance(limit, int) or limit <= 0:
        raise ValueError("SSH diagnostic limit must be a positive integer.")
    return " ".join(redacted_stderr.split())[:limit]


def _build_ssh_arguments(command: SshCommand) -> list[str]:
    timeout = command.timeout
    return [
        "ssh.exe",
        "-o",
        "BatchMode=yes",
        "-o",
        f"ConnectTimeout={timeout.connect_timeout_seconds}",
        "-o",
        "IdentitiesOnly=yes",
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        f"ServerAliveInterval={timeout.server_alive_interval_seconds}",
        "-o",
        f"ServerAliveCountMax={timeout.server_alive_count_max}",
        "-i",
        str(command.connection.private_key_path),
        "-p",
        str(command.connection.port),
        f"root@{command.server_ip}",
        *command.remote_arguments,
    ]


def _validate_timeout_profile(profile: SshTimeoutProfile) -> None:
    if not isinstance(profile, SshTimeoutProfile):
        raise TypeError("SSH command requires a timeout profile.")
    positive_integer_fields = (
        profile.connect_timeout_seconds,
        profile.server_alive_interval_seconds,
        profile.server_alive_count_max,
    )
    if any(
        isinstance(value, bool) or not isinstance(value, int) or value <= 0
        for value in positive_integer_fields
    ):
        raise ValueError("SSH timeout and keepalive values must be positive integers.")
    for value in (profile.total_timeout_seconds, profile.inactivity_timeout_seconds):
        if value is not None and (
            isinstance(value, bool) or not isinstance(value, (int, float)) or value <= 0
        ):
            raise ValueError("SSH execution deadlines must be positive numbers.")
