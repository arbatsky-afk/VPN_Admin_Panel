"""One-shot SSH publication and confirmed Registry finalization."""

from __future__ import annotations

import base64
import json
import re
from collections.abc import Callable
from pathlib import Path

from ..ssh import validate_server_ip
from ..ssh_settings import SshConnectionSettings, SshSettingsError, primary_ssh_connection
from ..ssh_transport import (
    SshCancelledError,
    SshCommand,
    SshLaunchError,
    SshTimeoutError,
    SshTimeoutProfile,
    run_buffered_ssh,
)
from .contracts import (
    FinalizedSubscription,
    PreparedSubscription,
    SubscriptionError,
    SubscriptionPublishResult,
)
from .registry import SubscriptionRegistry, _subscription_url
from .sources import collect_subscription_candidate

NGINX_SUBSCRIPTIONS_CONTRACT_VERSION = "5"
REMOTE_SUBSCRIPTION_COMMAND = (
    'python3 -c "import sys;exec(compile(sys.stdin.buffer.read(), '
    "'<subscription-publisher>', 'exec'))\""
)


_DOMAIN = re.compile(
    r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    r"(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$"
)


class SshSubscriptionTransport:
    """Execute one authoritative publisher helper through SSH stdin."""

    def __init__(
        self,
        server_ip: str,
        private_key: Path,
        ssh_port: int = 22,
        *,
        timeout_seconds: int = 20,
        cancelled: Callable[[], bool] | None = None,
    ) -> None:
        server_ip, error = validate_server_ip(server_ip)
        if error:
            raise SubscriptionError(error)
        if (
            isinstance(ssh_port, bool)
            or not isinstance(ssh_port, int)
            or not 1 <= ssh_port <= 65535
        ):
            raise SubscriptionError("SSH port must be between 1 and 65535.")
        if (
            isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, int)
            or not 1 <= timeout_seconds <= 300
        ):
            raise SubscriptionError("SSH timeout must be between 1 and 300 seconds.")
        self.server_ip = server_ip
        self.private_key = private_key
        self.ssh_port = ssh_port
        self.timeout_seconds = timeout_seconds
        self.cancelled = cancelled

    def execute(
        self, project_directory: Path, prepared: PreparedSubscription
    ) -> SubscriptionPublishResult:
        request = prepared.request
        if request.server_ip != self.server_ip:
            raise SubscriptionError("Subscription transport target does not match the request.")
        try:
            payload = render_remote_subscription_program(project_directory, prepared)
            completed = run_buffered_ssh(
                SshCommand(
                    self.server_ip,
                    SshConnectionSettings(self.private_key, self.ssh_port),
                    (REMOTE_SUBSCRIPTION_COMMAND,),
                    SshTimeoutProfile.subscription_operation(self.timeout_seconds),
                ),
                input_text=payload,
                cancelled=self.cancelled,
            )
        except SshCancelledError:
            return SubscriptionPublishResult(
                "unknown", error="Subscription publication was cancelled."
            )
        except SshTimeoutError:
            return SubscriptionPublishResult(
                "unknown", error="Subscription SSH operation timed out."
            )
        except SshLaunchError:
            return SubscriptionPublishResult(
                "unknown", error="Subscription SSH operation could not be started."
            )
        except SubscriptionError as error:
            return SubscriptionPublishResult("unknown", error=str(error))
        if completed.returncode != 0:
            return SubscriptionPublishResult(
                "unknown",
                error=(
                    "Subscription SSH operation ended without an authoritative result "
                    f"(exit {completed.returncode})."
                ),
            )
        try:
            result = parse_subscription_response(completed.stdout)
        except SubscriptionError as error:
            return SubscriptionPublishResult("unknown", error=str(error))
        if result.outcome in {"success", "partial"} and (
            result.content_sha256 != request.content_sha256
            or result.content_size != request.content_size
        ):
            return SubscriptionPublishResult(
                "unknown", error="Subscription confirmation does not match the immutable request."
            )
        return result


def render_remote_subscription_program(
    project_directory: Path, prepared: PreparedSubscription
) -> str:
    helper_path = (
        project_directory / "app" / "services" / "remote_sources" / "publish_subscription.py"
    )
    try:
        helper_source = helper_path.read_text(encoding="utf-8", errors="strict")
    except (OSError, UnicodeError) as error:
        raise SubscriptionError("Could not read the subscription remote source.") from error
    helper_source = helper_source.removeprefix("#!/usr/bin/env python3\n").replace(
        "from __future__ import annotations\n", ""
    )
    request = prepared.request
    request_json = json.dumps(
        {
            "schema_version": 1,
            "server_ip": request.server_ip,
            "name": request.name,
            "token": request.token,
            "content_sha256": request.content_sha256,
            "content_size": request.content_size,
            "nginx_contract_version": NGINX_SUBSCRIPTIONS_CONTRACT_VERSION,
        },
        separators=(",", ":"),
    ).encode("utf-8")
    encoded_request = base64.b64encode(request_json).decode("ascii")
    encoded_content = base64.b64encode(prepared.content).decode("ascii")
    return "\n".join(
        (
            "import base64",
            helper_source,
            "",
            f"_request = json.loads(base64.b64decode('{encoded_request}'))",
            f"_content = base64.b64decode('{encoded_content}')",
            "print(json.dumps(execute(_request, _content), separators=(',', ':')))",
            "",
        )
    )


def parse_subscription_response(output: str) -> SubscriptionPublishResult:
    try:
        value = json.loads(output)
    except (TypeError, json.JSONDecodeError) as error:
        raise SubscriptionError("Subscription helper returned invalid JSON.") from error
    expected = {
        "schema_version",
        "outcome",
        "server_name",
        "content_sha256",
        "content_size",
        "cleanup_failed_count",
        "error",
    }
    if not isinstance(value, dict) or set(value) != expected or value["schema_version"] != 1:
        raise SubscriptionError("Subscription helper returned an invalid response schema.")
    outcome = value["outcome"]
    if outcome not in {"success", "failure", "partial"}:
        raise SubscriptionError("Subscription helper returned an invalid outcome.")
    server_name = value["server_name"]
    digest = value["content_sha256"]
    content_size = value["content_size"]
    cleanup_failed_count = value["cleanup_failed_count"]
    error = value["error"]
    if (
        not isinstance(server_name, str)
        or not isinstance(digest, str)
        or not isinstance(error, str)
    ):
        raise SubscriptionError("Subscription helper returned invalid result fields.")
    if isinstance(content_size, bool) or not isinstance(content_size, int) or content_size < 0:
        raise SubscriptionError("Subscription helper returned an invalid content size.")
    if (
        isinstance(cleanup_failed_count, bool)
        or not isinstance(cleanup_failed_count, int)
        or cleanup_failed_count < 0
    ):
        raise SubscriptionError("Subscription helper returned an invalid cleanup count.")
    if outcome in {"success", "partial"}:
        if (
            not _valid_domain(server_name)
            or re.fullmatch(r"[0-9a-f]{64}", digest) is None
            or content_size < 1
        ):
            raise SubscriptionError(
                "Subscription helper returned incomplete publication confirmation."
            )
        if outcome == "success" and (error or cleanup_failed_count != 0):
            raise SubscriptionError("Subscription helper success contains error details.")
        if outcome == "partial" and (not error or cleanup_failed_count < 1):
            raise SubscriptionError("Subscription helper partial result lacks cleanup details.")
    elif server_name or digest or content_size or cleanup_failed_count or not error:
        raise SubscriptionError(
            "Subscription helper failure contains invalid confirmation fields."
        )
    return SubscriptionPublishResult(
        outcome, server_name, digest, content_size, cleanup_failed_count, error
    )


def prepare_subscription(
    project_directory: Path,
    operation_token: int,
    request_id: int,
    server_ip: str,
    name: str,
    source_filenames: tuple[str, ...],
) -> PreparedSubscription:
    candidate = collect_subscription_candidate(project_directory, name, source_filenames)
    return SubscriptionRegistry(project_directory).prepare(
        operation_token, request_id, server_ip, candidate
    )


def confirmed_subscription_url(project_directory: Path, server_ip: str, name: str) -> str:
    return SubscriptionRegistry(project_directory).confirmed_url(server_ip, name)


def publish_prepared_subscription(
    project_directory: Path,
    prepared: PreparedSubscription,
    *,
    cancelled: Callable[[], bool] | None = None,
) -> FinalizedSubscription:
    try:
        connection = primary_ssh_connection(project_directory)
    except SshSettingsError as error:
        result = SubscriptionPublishResult(
            "failure", error=f"Could not read local SSH configuration: {error}"
        )
        return FinalizedSubscription(result)
    result = SshSubscriptionTransport(
        prepared.request.server_ip,
        connection.private_key_path,
        connection.port,
        cancelled=cancelled,
    ).execute(project_directory, prepared)
    if result.outcome not in {"success", "partial"}:
        return FinalizedSubscription(result)
    entry = SubscriptionRegistry(project_directory).confirm(prepared.request, result)
    return FinalizedSubscription(result, _subscription_url(entry))


def _valid_domain(value: str) -> bool:
    return (
        isinstance(value, str)
        and len(value) <= 253
        and any(character.isalpha() for character in value)
        and _DOMAIN.fullmatch(value) is not None
    )
