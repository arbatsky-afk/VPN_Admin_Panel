"""Bounded local subprocess execution with cooperative cancellation."""

from __future__ import annotations

import subprocess
import threading
import time
from collections.abc import Callable, Sequence


class ProcessCancelledError(RuntimeError):
    """The caller requested cancellation while the process was running."""


def run_cancellable_process(
    arguments: Sequence[str],
    *,
    timeout: float,
    input_text: str | None = None,
    cancelled: Callable[[], bool] | None = None,
    poll_seconds: float = 0.1,
    terminate_timeout: float = 2.0,
) -> subprocess.CompletedProcess[str]:
    """Run one fixed command, polling for timeout or cooperative cancellation."""
    process = subprocess.Popen(
        list(arguments),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        stdin=subprocess.PIPE if input_text is not None else None,
        text=True,
        encoding="utf-8",
        errors="replace",
        shell=False,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    return _communicate_cancellable(
        process, arguments, input_text, timeout, cancelled, poll_seconds, terminate_timeout
    )


def run_cancellable_binary_process(
    arguments: Sequence[str],
    *,
    timeout: float,
    input_bytes: bytes | None = None,
    cancelled: Callable[[], bool] | None = None,
    poll_seconds: float = 0.1,
    terminate_timeout: float = 2.0,
) -> subprocess.CompletedProcess[bytes]:
    """Run one fixed binary command with the same bounded lifecycle."""
    process = subprocess.Popen(
        list(arguments),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        stdin=subprocess.PIPE if input_bytes is not None else None,
        shell=False,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    return _communicate_cancellable(
        process, arguments, input_bytes, timeout, cancelled, poll_seconds, terminate_timeout
    )


def _communicate_cancellable[T: (str, bytes)](
    process: subprocess.Popen[T],
    arguments: Sequence[str],
    input_data: T | None,
    timeout: float,
    cancelled: Callable[[], bool] | None,
    poll_seconds: float,
    terminate_timeout: float,
) -> subprocess.CompletedProcess[T]:
    # On Windows communicate(timeout=...) can block while writing stdin.
    # One worker owns all pipe I/O; this thread owns the deadline and process stop.
    deadline = time.monotonic() + timeout
    done = threading.Event()
    output: list[tuple[T, T]] = []
    errors: list[BaseException] = []

    def communicate() -> None:
        try:
            output.append(process.communicate(input=input_data))
        except BaseException as error:
            errors.append(error)
        finally:
            done.set()

    worker = threading.Thread(target=communicate, name="buffered-process-io")
    started = False
    try:
        while True:
            if cancelled is not None and cancelled():
                raise ProcessCancelledError("Operation was cancelled.")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired(list(arguments), timeout)
            if not started:
                worker.start()
                started = True
            if done.wait(min(poll_seconds, remaining)):
                if errors:
                    raise errors[0]
                stdout, stderr = output[0]
                return subprocess.CompletedProcess(
                    list(arguments), process.returncode, stdout, stderr
                )
    finally:
        # Stop before joining: terminating the child unblocks a stalled stdin
        # write. Never close a pipe concurrently with its owner's I/O.
        if process.poll() is None:
            _stop_process(process, terminate_timeout)
        if started:
            worker.join()
        for stream in (process.stdin, process.stdout, process.stderr):
            if stream is not None:
                stream.close()


def _stop_process(
    process: subprocess.Popen[str] | subprocess.Popen[bytes], terminate_timeout: float
) -> None:
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
