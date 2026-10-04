"""Safe Management error types and SSH-result classification."""

from __future__ import annotations

from typing import Protocol


class _CompletedTextProcess(Protocol):
    returncode: int


class ManagementError(RuntimeError):
    """A fixed Management operation could not be performed safely."""


class ManagementLaunchError(ManagementError):
    """The local process could not be launched, so no remote action was sent."""


class ManagementRemoteRejectedError(ManagementError):
    """The remote helper returned an explicit, authoritative rejection."""


class ManagementIndeterminateError(ManagementError):
    """A remote action may have run but no authoritative final result remains."""

    def __init__(self, reason_code: str, safe_message: str) -> None:
        super().__init__(safe_message)
        self.reason_code = reason_code


def _response_failure_reason(result: _CompletedTextProcess) -> str:
    """Classify SSH loss without parsing stderr or exception text."""
    return "connection_lost" if result.returncode == 255 else "invalid_response"


def _raise_remote_response_error(
    result: _CompletedTextProcess,
    action: str,
    remote_error: str,
) -> None:
    """Raise the typed outcome encoded by a fixed Management helper."""
    if action != "inspect" and result.returncode == 3:
        raise ManagementIndeterminateError(
            "invalid_response",
            f"{remote_error} The server state is unknown.",
        )
    raise ManagementRemoteRejectedError(remote_error)
