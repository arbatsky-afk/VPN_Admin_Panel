from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import socket
import subprocess
import threading
import time
import urllib.error
import urllib.request
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import BinaryIO

from monitor.domain import (
    Connection,
    FailureKind,
    MihomoStartDiagnostics,
    MihomoStartOutcome,
)
from monitor.path_security import ManagedPathGuard, UnsafeManagedPathError

LOG_FILE_NAME = "mihomo.log"
LOG_TAIL_BYTES = 16 * 1024
LOG_TAIL_LINES = 40
LOG_TAIL_CHARS = 6000
LOG_LEVEL_RE = re.compile(r"\blevel=(?:warning|error)\b")
CONTROLLER_QUERY_TIMEOUT = 2.0


class MihomoError(RuntimeError):
    def __init__(
        self,
        kind: FailureKind,
        message: str,
        diagnostics: MihomoStartDiagnostics | None = None,
    ) -> None:
        super().__init__(message)
        self.kind = kind
        self.diagnostics = diagnostics


class MihomoInstance:
    def __init__(
        self,
        process: subprocess.Popen[bytes],
        directory: Path,
        port: int,
        controller_port: int,
        controller_secret: str,
        stop_grace: int,
        runtime_guard: ManagedPathGuard | None = None,
    ) -> None:
        self.process = process
        self.directory = directory
        self.port = port
        self.controller_port = controller_port
        self.controller_secret = controller_secret
        self.stop_grace = stop_grace
        self._runtime_guard = runtime_guard or ManagedPathGuard(directory.parent)
        self.start_diagnostics: MihomoStartDiagnostics | None = None

    def log_tail(self) -> str | None:
        return _read_log_tail(self.directory / LOG_FILE_NAME, self._runtime_guard)

    def stop(self) -> None:
        try:
            if self.process.poll() is None:
                self.process.terminate()
                try:
                    self.process.wait(timeout=self.stop_grace)
                except subprocess.TimeoutExpired:
                    self.process.kill()
                    try:
                        self.process.wait(timeout=2)
                    except subprocess.TimeoutExpired as error:
                        raise MihomoError(
                            FailureKind.MIHOMO_EXITED, "Mihomo did not stop after kill."
                        ) from error
        finally:
            _remove_managed_directory(self.directory, self._runtime_guard)


class MihomoAdapter:
    DIRECTORY_PREFIX = "monitor-run-"
    OWNER = "vpn-admin-panel-monitor"

    def __init__(
        self,
        executable: Path,
        digest_file: Path,
        runtime_root: Path,
        start_timeout: int,
        stop_grace: int,
        runtime_guard: ManagedPathGuard | None = None,
        project_guard: ManagedPathGuard | None = None,
    ) -> None:
        self._executable = executable
        self._digest_file = digest_file
        self._runtime_root = runtime_root
        self._runtime_guard = runtime_guard or ManagedPathGuard(runtime_root)
        self._project_guard = project_guard or ManagedPathGuard(executable.parent)
        self._start_timeout = start_timeout
        self._stop_grace = stop_grace
        self._verification_lock = threading.Lock()
        self._verification_complete = False
        self._verification_error: tuple[FailureKind, str] | None = None
        self._port_lock = threading.Lock()
        self._reserved_ports: set[int] = set()

    def prepare(self) -> None:
        with self._verification_lock:
            if self._verification_complete:
                return
            try:
                self._verify_binary_once()
            except MihomoError as error:
                self._verification_error = (error.kind, str(error))
            self._verification_complete = True

    def verify_binary(self) -> None:
        self.prepare()
        if self._verification_error is not None:
            kind, message = self._verification_error
            raise MihomoError(kind, message)

    def _verify_binary_once(self) -> None:
        self._executable = self._project_guard.validate(self._executable, kind="file")
        self._digest_file = self._project_guard.validate(self._digest_file, kind="file")
        if not self._executable.is_file():
            raise MihomoError(FailureKind.MIHOMO_MISSING, "Bundled mihomo.exe was not found.")
        if not self._digest_file.is_file():
            raise MihomoError(FailureKind.MIHOMO_INTEGRITY, "Mihomo SHA-256 manifest is missing.")
        try:
            fields = self._digest_file.read_text(encoding="ascii").strip().split()
        except (OSError, UnicodeError) as error:
            raise MihomoError(
                FailureKind.MIHOMO_INTEGRITY, "Mihomo SHA-256 manifest could not be read."
            ) from error
        if not fields:
            raise MihomoError(FailureKind.MIHOMO_INTEGRITY, "Mihomo SHA-256 manifest is invalid.")
        expected = fields[0].lower()
        if len(expected) != 64 or any(
            character not in "0123456789abcdef" for character in expected
        ):
            raise MihomoError(FailureKind.MIHOMO_INTEGRITY, "Mihomo SHA-256 manifest is invalid.")
        try:
            digest = hashlib.sha256(self._executable.read_bytes()).hexdigest()
        except OSError as error:
            raise MihomoError(
                FailureKind.MIHOMO_INTEGRITY, "Mihomo executable could not be read."
            ) from error
        if digest != expected:
            raise MihomoError(
                FailureKind.MIHOMO_INTEGRITY, "Mihomo SHA-256 does not match the manifest."
            )

    def cleanup_stale_directories(self) -> None:
        self._runtime_root = self._runtime_guard.validate(self._runtime_root, kind="directory")
        if not self._runtime_root.exists():
            return
        for directory in self._runtime_root.glob(f"{self.DIRECTORY_PREFIX}*"):
            try:
                directory = self._runtime_guard.validate(
                    directory, kind="directory", allow_missing=False
                )
                marker = self._runtime_guard.validate(
                    directory / "owner.json", kind="file", allow_missing=False
                )
            except UnsafeManagedPathError:
                continue
            try:
                value = json.loads(marker.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError, UnicodeError):
                continue
            if value.get("owner") == self.OWNER and value.get("schema_version") == 1:
                _remove_managed_directory(directory, self._runtime_guard)

    @contextmanager
    def running(
        self, connection: Connection, request_id: str, cancelled: threading.Event
    ) -> Iterator[MihomoInstance]:
        startup_started = time.monotonic()
        self.verify_binary()
        self._runtime_root = self._runtime_guard.ensure_directory(self._runtime_root)
        directory = self._runtime_root / f"{self.DIRECTORY_PREFIX}{uuid.uuid4()}"
        directory = self._runtime_guard.create_directory(directory)
        port: int | None = None
        controller_port: int | None = None
        instance: MihomoInstance | None = None
        try:
            try:
                port = self._reserve_local_port(udp=True)
                controller_port = self._reserve_local_port()
            except MihomoError as error:
                os_error = error.__cause__ if isinstance(error.__cause__, OSError) else None
                diagnostics = _diagnostics(
                    MihomoStartOutcome.PORT_ALLOCATION_FAILED,
                    startup_started,
                    os_error=os_error,
                )
                raise MihomoError(error.kind, str(error), diagnostics) from error
            controller_secret = uuid.uuid4().hex
            _write_private_json(
                directory / "owner.json",
                {"schema_version": 1, "owner": self.OWNER, "request_id": request_id},
                self._runtime_guard,
            )
            proxy = dict(connection.proxy)
            proxy["name"] = "MONITOR_TARGET"
            _write_private_json(
                directory / "config.yaml",
                {
                    "mixed-port": port,
                    "allow-lan": False,
                    "bind-address": "127.0.0.1",
                    "mode": "rule",
                    "log-level": "warning",
                    "ipv6": False,
                    "external-controller": f"127.0.0.1:{controller_port}",
                    "secret": controller_secret,
                    "unified-delay": True,
                    "proxies": [proxy],
                    "proxy-groups": [
                        {"name": "MONITOR", "type": "select", "proxies": ["MONITOR_TARGET"]}
                    ],
                    "rules": ["MATCH,MONITOR"],
                },
                self._runtime_guard,
            )
            creationflags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
            spawn_started = time.monotonic()
            try:
                # The child keeps its own handle; the directory is removed after it stops.
                with _open_log_stream(directory / LOG_FILE_NAME, self._runtime_guard) as log:
                    process = subprocess.Popen(
                        [
                            str(self._executable),
                            "-d",
                            str(directory),
                            "-f",
                            str(directory / "config.yaml"),
                        ],
                        stdin=subprocess.DEVNULL,
                        stdout=log,
                        stderr=subprocess.STDOUT,
                        shell=False,
                        creationflags=creationflags,
                    )
            except OSError as error:
                diagnostics = _diagnostics(
                    MihomoStartOutcome.SPAWN_FAILED,
                    startup_started,
                    spawn_ms=_elapsed_ms(spawn_started),
                    os_error=error,
                )
                raise MihomoError(
                    FailureKind.MIHOMO_START,
                    "Mihomo could not be started.",
                    diagnostics,
                ) from error
            spawn_ms = _elapsed_ms(spawn_started)
            instance = MihomoInstance(
                process,
                directory,
                port,
                controller_port,
                controller_secret,
                self._stop_grace,
                self._runtime_guard,
            )
            instance.start_diagnostics = _wait_ready(
                instance,
                self._start_timeout,
                cancelled,
                startup_started=startup_started,
                spawn_ms=spawn_ms,
            )
            yield instance
        finally:
            try:
                if instance is not None:
                    instance.stop()
                else:
                    _remove_managed_directory(directory, self._runtime_guard)
            finally:
                if port is not None:
                    self._release_local_port(port)
                if controller_port is not None:
                    self._release_local_port(controller_port)

    def _reserve_local_port(self, *, udp: bool = False) -> int:
        for _attempt in range(64):
            try:
                port = _free_local_port()
            except OSError as error:
                raise MihomoError(
                    FailureKind.MIHOMO_START, "A local proxy port could not be allocated."
                ) from error
            if udp and not _udp_port_available(port):
                continue
            with self._port_lock:
                if port not in self._reserved_ports:
                    self._reserved_ports.add(port)
                    return port
        raise MihomoError(FailureKind.MIHOMO_START, "A unique local proxy port was not available.")

    def _release_local_port(self, port: int) -> None:
        with self._port_lock:
            self._reserved_ports.discard(port)


def _wait_ready(
    instance: MihomoInstance,
    timeout: int,
    cancelled: threading.Event,
    *,
    startup_started: float,
    spawn_ms: int,
) -> MihomoStartDiagnostics:
    deadline = time.monotonic() + timeout
    readiness_started = time.monotonic()
    proxy_ready_ms: int | None = None
    controller_ready_ms: int | None = None
    proxy_socket_error: int | None = None
    controller_socket_error: int | None = None
    proxy_probe_error_type: str | None = None
    while time.monotonic() < deadline:
        if cancelled.is_set():
            exit_code = instance.process.poll()
            diagnostics = _readiness_diagnostics(
                MihomoStartOutcome.CANCELLED,
                instance,
                startup_started,
                spawn_ms,
                readiness_started,
                proxy_ready_ms,
                controller_ready_ms,
                proxy_socket_error,
                controller_socket_error,
                exit_code=exit_code,
                proxy_probe_error_type=proxy_probe_error_type,
            )
            raise MihomoError(FailureKind.CANCELLED, "Check was cancelled.", diagnostics)
        exit_code = instance.process.poll()
        if exit_code is not None:
            diagnostics = _readiness_diagnostics(
                MihomoStartOutcome.EXITED_BEFORE_READY,
                instance,
                startup_started,
                spawn_ms,
                readiness_started,
                proxy_ready_ms,
                controller_ready_ms,
                proxy_socket_error,
                controller_socket_error,
                exit_code=exit_code,
                proxy_probe_error_type=proxy_probe_error_type,
            )
            raise MihomoError(
                FailureKind.MIHOMO_EXITED,
                "Mihomo exited before readiness.",
                diagnostics,
            )
        if proxy_ready_ms is None:
            proxy_ready, proxy_socket_error, proxy_probe_error_type = _local_port_ready(
                instance.port
            )
            if proxy_ready:
                proxy_ready_ms = _elapsed_ms(readiness_started)
        if controller_ready_ms is None:
            controller_ready, controller_socket_error, _ = _local_port_ready(
                instance.controller_port
            )
            if controller_ready:
                controller_ready_ms = _elapsed_ms(readiness_started)
        if proxy_ready_ms is not None and controller_ready_ms is not None:
            return _readiness_diagnostics(
                MihomoStartOutcome.READY,
                instance,
                startup_started,
                spawn_ms,
                readiness_started,
                proxy_ready_ms,
                controller_ready_ms,
                None,
                None,
            )
        cancelled.wait(0.05)
    exit_code = instance.process.poll()
    outcome = (
        MihomoStartOutcome.READINESS_TIMEOUT
        if exit_code is None
        else MihomoStartOutcome.EXITED_BEFORE_READY
    )
    diagnostics = _readiness_diagnostics(
        outcome,
        instance,
        startup_started,
        spawn_ms,
        readiness_started,
        proxy_ready_ms,
        controller_ready_ms,
        proxy_socket_error,
        controller_socket_error,
        exit_code=exit_code,
        proxy_probe_error_type=proxy_probe_error_type,
    )
    if exit_code is not None:
        raise MihomoError(
            FailureKind.MIHOMO_EXITED,
            "Mihomo exited before readiness.",
            diagnostics,
        )
    raise MihomoError(
        FailureKind.MIHOMO_START,
        "Mihomo readiness timed out.",
        diagnostics,
    )


def _local_port_ready(port: int) -> tuple[bool, int | None, str | None]:
    # A timeout carries no errno, so the exception type is what tells it apart from a refusal.
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=0.2):
            return True, None, None
    except OSError as error:
        return False, _socket_error_code(error), type(error).__name__


def _socket_error_code(error: OSError) -> int | None:
    winerror = getattr(error, "winerror", None)
    return winerror if isinstance(winerror, int) else error.errno


def _elapsed_ms(started: float) -> int:
    return max(0, round((time.monotonic() - started) * 1000))


def _diagnostics(
    outcome: MihomoStartOutcome,
    startup_started: float,
    *,
    spawn_ms: int | None = None,
    os_error: OSError | None = None,
) -> MihomoStartDiagnostics:
    return MihomoStartDiagnostics(
        outcome=outcome,
        start_ms=_elapsed_ms(startup_started),
        spawn_ms=spawn_ms,
        os_error_type=type(os_error).__name__ if os_error is not None else None,
        errno=os_error.errno if os_error is not None else None,
        winerror=getattr(os_error, "winerror", None) if os_error is not None else None,
    )


def _readiness_diagnostics(
    outcome: MihomoStartOutcome,
    instance: MihomoInstance,
    startup_started: float,
    spawn_ms: int,
    readiness_started: float,
    proxy_ready_ms: int | None,
    controller_ready_ms: int | None,
    proxy_socket_error: int | None,
    controller_socket_error: int | None,
    *,
    exit_code: int | None = None,
    proxy_probe_error_type: str | None = None,
) -> MihomoStartDiagnostics:
    readiness_ms = _elapsed_ms(readiness_started)
    if outcome == MihomoStartOutcome.READY:
        return MihomoStartDiagnostics(
            outcome=outcome,
            start_ms=_elapsed_ms(startup_started),
            spawn_ms=spawn_ms,
            readiness_ms=readiness_ms,
            pid=instance.process.pid,
            proxy_ready_ms=proxy_ready_ms,
            controller_ready_ms=controller_ready_ms,
            process_alive=True,
        )
    controller_version: str | None = None
    controller_mixed_port: int | None = None
    controller_query_error: str | None = None
    # A live controller reports which listeners Mihomo actually opened.
    if outcome == MihomoStartOutcome.READINESS_TIMEOUT and controller_ready_ms is not None:
        controller_version, controller_mixed_port, controller_query_error = _query_controller(
            instance
        )
    return MihomoStartDiagnostics(
        outcome=outcome,
        start_ms=_elapsed_ms(startup_started),
        spawn_ms=spawn_ms,
        readiness_ms=readiness_ms,
        pid=instance.process.pid,
        proxy_ready_ms=proxy_ready_ms,
        controller_ready_ms=controller_ready_ms,
        process_alive=exit_code is None,
        exit_code=exit_code,
        proxy_socket_error=proxy_socket_error,
        controller_socket_error=controller_socket_error,
        proxy_port=instance.port,
        controller_port=instance.controller_port,
        proxy_probe_error_type=proxy_probe_error_type,
        controller_version=controller_version,
        controller_mixed_port=controller_mixed_port,
        controller_query_error=controller_query_error,
        log_tail=instance.log_tail(),
    )


def _query_controller(instance: MihomoInstance) -> tuple[str | None, int | None, str | None]:
    version: str | None = None
    mixed_port: int | None = None
    errors: list[str] = []
    try:
        value = _controller_get(instance, "/version").get("version")
        if isinstance(value, str):
            version = value[:64]
    except _ControllerQueryError as error:
        errors.append(f"version:{error}")
    try:
        value = _controller_get(instance, "/configs").get("mixed-port")
        if isinstance(value, int) and not isinstance(value, bool):
            mixed_port = value
    except _ControllerQueryError as error:
        errors.append(f"configs:{error}")
    return version, mixed_port, ";".join(errors) or None


class _ControllerQueryError(Exception):
    pass


def _controller_get(instance: MihomoInstance, path: str) -> dict[str, object]:
    request = urllib.request.Request(
        f"http://127.0.0.1:{instance.controller_port}{path}",
        headers={"Authorization": f"Bearer {instance.controller_secret}"},
    )
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(request, timeout=CONTROLLER_QUERY_TIMEOUT) as response:
            payload = json.loads(response.read(64 * 1024).decode("utf-8", errors="strict"))
    except urllib.error.HTTPError as error:
        raise _ControllerQueryError(f"http_{error.code}") from error
    except urllib.error.URLError as error:
        reason = error.reason
        name = type(reason).__name__ if isinstance(reason, BaseException) else "URLError"
        raise _ControllerQueryError(name) from error
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise _ControllerQueryError(type(error).__name__) from error
    if not isinstance(payload, dict):
        raise _ControllerQueryError("unexpected_payload")
    return payload


def _open_log_stream(path: Path, guard: ManagedPathGuard) -> BinaryIO:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    return os.fdopen(guard.open_file(path, flags), "wb")


def _read_log_tail(path: Path, guard: ManagedPathGuard) -> str | None:
    try:
        descriptor = guard.open_file(path, os.O_RDONLY | getattr(os, "O_BINARY", 0))
        with os.fdopen(descriptor, "rb") as stream:
            size = stream.seek(0, os.SEEK_END)
            stream.seek(max(0, size - LOG_TAIL_BYTES))
            data = stream.read(LOG_TAIL_BYTES)
    except (OSError, UnsafeManagedPathError):
        return None
    lines = data.decode("utf-8", errors="replace").splitlines()
    if size > LOG_TAIL_BYTES and lines:
        lines = lines[1:]  # The first line may be cut mid-way.
    # Only Mihomo's own warning/error records reach the operation log, never raw output.
    lines = [line for line in lines if LOG_LEVEL_RE.search(line)]
    text = "\n".join(lines[-LOG_TAIL_LINES:]).strip()
    return text[-LOG_TAIL_CHARS:] or None


def _free_local_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def _udp_port_available(port: int) -> bool:
    # The mixed listener also binds UDP on the same number, and Windows can reserve
    # that UDP port (excluded port range) while the TCP one is free.
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            probe.bind(("127.0.0.1", port))
    except OSError:
        return False
    return True


def _write_private_json(
    path: Path,
    value: object,
    guard: ManagedPathGuard,
) -> None:
    encoded = (json.dumps(value, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")
    path = guard.validate(path, kind="file")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    descriptor = guard.open_file(path, flags)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(encoded)
        stream.flush()
        os.fsync(stream.fileno())


def _remove_managed_directory(directory: Path, guard: ManagedPathGuard) -> None:
    directory = guard.validate(directory, kind="directory")
    if not directory.exists():
        return
    directory = guard.validate(directory, kind="directory", allow_missing=False)
    shutil.rmtree(directory)
