"""One-shot SSH inspection of managed subscription artifacts."""

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
    FinalizedSubscriptionDelete,
    SubscriptionDeleteRequest,
    SubscriptionDeleteResult,
    SubscriptionError,
    SubscriptionInspectRequest,
    SubscriptionServerArtifact,
    SubscriptionServerSnapshot,
)
from .publication import NGINX_SUBSCRIPTIONS_CONTRACT_VERSION
from .registry import SubscriptionRegistry
from .sources import validate_subscription_name

REMOTE_SUBSCRIPTION_MANAGEMENT_COMMAND = (
    'python3 -c "import sys;exec(compile(sys.stdin.buffer.read(), '
    "'<subscription-management>', 'exec'))\""
)
_TOKEN = re.compile(r"^[A-Za-z0-9_-]{32,128}$")
_DOMAIN = re.compile(
    r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    r"(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$"
)


class SshSubscriptionManagementTransport:
    """Execute one fixed subscription-management helper through SSH stdin."""

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

    def inspect(
        self,
        project_directory: Path,
        request: SubscriptionInspectRequest,
    ) -> SubscriptionServerSnapshot:
        if request.server_ip != self.server_ip:
            raise SubscriptionError("Subscription inspection target does not match its request.")
        try:
            completed = run_buffered_ssh(
                SshCommand(
                    self.server_ip,
                    SshConnectionSettings(self.private_key, self.ssh_port),
                    (REMOTE_SUBSCRIPTION_MANAGEMENT_COMMAND,),
                    SshTimeoutProfile.short_operation(self.timeout_seconds),
                ),
                input_text=render_remote_inspection_program(project_directory, request),
                cancelled=self.cancelled,
            )
        except SshCancelledError as error:
            raise SubscriptionError("Subscription inspection was cancelled.") from error
        except SshTimeoutError as error:
            raise SubscriptionError("Subscription inspection timed out.") from error
        except SshLaunchError as error:
            raise SubscriptionError("Subscription inspection could not be started.") from error
        if completed.returncode != 0:
            raise SubscriptionError(
                "Subscription inspection ended without an authoritative result "
                f"(exit {completed.returncode})."
            )
        return parse_subscription_inspection_response(completed.stdout, request.server_ip)

    def delete(
        self,
        project_directory: Path,
        request: SubscriptionDeleteRequest,
    ) -> FinalizedSubscriptionDelete:
        if request.server_ip != self.server_ip:
            raise SubscriptionError("Subscription deletion target does not match its request.")
        try:
            completed = run_buffered_ssh(
                SshCommand(
                    self.server_ip,
                    SshConnectionSettings(self.private_key, self.ssh_port),
                    (REMOTE_SUBSCRIPTION_MANAGEMENT_COMMAND,),
                    SshTimeoutProfile.short_operation(self.timeout_seconds),
                ),
                input_text=render_remote_delete_program(project_directory, request),
                cancelled=self.cancelled,
            )
        except SshCancelledError:
            return FinalizedSubscriptionDelete(
                SubscriptionDeleteResult("unknown", error="Subscription deletion was cancelled.")
            )
        except SshTimeoutError:
            return FinalizedSubscriptionDelete(
                SubscriptionDeleteResult("unknown", error="Subscription deletion timed out.")
            )
        except SshLaunchError:
            return FinalizedSubscriptionDelete(
                SubscriptionDeleteResult(
                    "unknown", error="Subscription deletion could not be started."
                )
            )
        if completed.returncode != 0:
            return FinalizedSubscriptionDelete(
                SubscriptionDeleteResult(
                    "unknown",
                    error=(
                        "Subscription deletion ended without an authoritative result "
                        f"(exit {completed.returncode})."
                    ),
                )
            )
        try:
            return parse_subscription_delete_response(completed.stdout, request.server_ip)
        except SubscriptionError as error:
            return FinalizedSubscriptionDelete(
                SubscriptionDeleteResult("unknown", error=str(error))
            )


def render_remote_inspection_program(
    project_directory: Path,
    request: SubscriptionInspectRequest,
) -> str:
    helper_path = (
        project_directory / "app" / "services" / "remote_sources" / "manage_subscriptions.py"
    )
    try:
        helper_source = helper_path.read_text(encoding="utf-8", errors="strict")
    except (OSError, UnicodeError) as error:
        raise SubscriptionError(
            "Could not read the subscription management remote source."
        ) from error
    helper_source = helper_source.removeprefix("#!/usr/bin/env python3\n").replace(
        "from __future__ import annotations\n", ""
    )
    request_json = json.dumps(
        {
            "schema_version": 1,
            "action": "inspect",
            "server_ip": request.server_ip,
            "nginx_contract_version": NGINX_SUBSCRIPTIONS_CONTRACT_VERSION,
        },
        separators=(",", ":"),
    ).encode("utf-8")
    encoded_request = base64.b64encode(request_json).decode("ascii")
    return "\n".join(
        (
            "import base64",
            helper_source,
            "",
            f"_request = json.loads(base64.b64decode('{encoded_request}'))",
            "print(json.dumps(execute_inspect(_request), separators=(',', ':')))",
            "",
        )
    )


def render_remote_delete_program(
    project_directory: Path,
    request: SubscriptionDeleteRequest,
) -> str:
    helper_path = (
        project_directory / "app" / "services" / "remote_sources" / "manage_subscriptions.py"
    )
    try:
        helper_source = helper_path.read_text(encoding="utf-8", errors="strict")
    except (OSError, UnicodeError) as error:
        raise SubscriptionError(
            "Could not read the subscription management remote source."
        ) from error
    helper_source = helper_source.removeprefix("#!/usr/bin/env python3\n").replace(
        "from __future__ import annotations\n", ""
    )
    request_json = json.dumps(
        {
            "schema_version": 1,
            "action": "delete",
            "server_ip": request.server_ip,
            "nginx_contract_version": NGINX_SUBSCRIPTIONS_CONTRACT_VERSION,
            "kind": request.kind,
            "name": request.name,
            "tokens": list(request.tokens),
        },
        separators=(",", ":"),
    ).encode("utf-8")
    encoded_request = base64.b64encode(request_json).decode("ascii")
    return "\n".join(
        (
            "import base64",
            helper_source,
            "",
            f"_request = json.loads(base64.b64decode('{encoded_request}'))",
            "print(json.dumps(execute_delete(_request), separators=(',', ':')))",
            "",
        )
    )


def parse_subscription_inspection_response(
    output: str,
    expected_server_ip: str,
) -> SubscriptionServerSnapshot:
    try:
        value = json.loads(output)
    except (TypeError, json.JSONDecodeError) as error:
        raise SubscriptionError("Subscription inspection returned invalid JSON.") from error
    expected = {
        "schema_version",
        "action",
        "outcome",
        "availability",
        "server_name",
        "tls_mode",
        "artifacts",
        "error",
    }
    if (
        not isinstance(value, dict)
        or set(value) != expected
        or value["schema_version"] != 1
        or value["action"] != "inspect"
    ):
        raise SubscriptionError("Subscription inspection returned an invalid response schema.")
    if value["outcome"] == "failure":
        if (
            value["availability"]
            or value["server_name"]
            or value["tls_mode"]
            or value["artifacts"] != []
            or not isinstance(value["error"], str)
            or not value["error"]
        ):
            raise SubscriptionError("Subscription inspection failure is malformed.")
        raise SubscriptionError(value["error"])
    if value["outcome"] != "success" or value["error"] != "":
        raise SubscriptionError("Subscription inspection returned an invalid outcome.")
    availability = value["availability"]
    server_name = value["server_name"]
    tls_mode = value["tls_mode"]
    artifacts_value = value["artifacts"]
    if availability not in {"ready", "letsencrypt_required"}:
        raise SubscriptionError("Subscription inspection returned invalid availability.")
    if (
        not isinstance(server_name, str)
        or not isinstance(tls_mode, str)
        or not isinstance(artifacts_value, list)
    ):
        raise SubscriptionError("Subscription inspection returned invalid fields.")
    if availability == "ready":
        if (
            tls_mode != "letsencrypt"
            or len(server_name) > 253
            or not any(character.isalpha() for character in server_name)
            or _DOMAIN.fullmatch(server_name) is None
        ):
            raise SubscriptionError("Subscription inspection returned invalid managed TLS state.")
    elif tls_mode != "self_signed" or server_name != expected_server_ip or artifacts_value:
        raise SubscriptionError("Subscription inspection returned invalid self-signed state.")
    artifacts: list[SubscriptionServerArtifact] = []
    for item in artifacts_value:
        if not isinstance(item, dict) or set(item) != {"name", "token"}:
            raise SubscriptionError("Subscription inspection returned an invalid artifact.")
        name = validate_subscription_name(item["name"] if isinstance(item["name"], str) else "")
        token = item["token"]
        if not isinstance(token, str) or _TOKEN.fullmatch(token) is None:
            raise SubscriptionError("Subscription inspection returned an invalid artifact token.")
        artifacts.append(SubscriptionServerArtifact(name, token))
    if len(artifacts) != len(set(artifacts)):
        raise SubscriptionError("Subscription inspection returned duplicate artifacts.")
    expected_order = sorted(
        artifacts,
        key=lambda item: (item.name.casefold(), item.name, item.token),
    )
    if artifacts != expected_order:
        raise SubscriptionError("Subscription inspection artifacts are not canonically ordered.")
    return SubscriptionServerSnapshot(
        expected_server_ip,
        availability,
        server_name,
        tls_mode,
        tuple(artifacts),
    )


def parse_subscription_delete_response(
    output: str,
    expected_server_ip: str,
) -> FinalizedSubscriptionDelete:
    try:
        value = json.loads(output)
    except (TypeError, json.JSONDecodeError) as error:
        raise SubscriptionError("Subscription deletion returned invalid JSON.") from error
    expected = {
        "schema_version",
        "action",
        "outcome",
        "availability",
        "server_name",
        "tls_mode",
        "artifacts",
        "deleted_count",
        "remaining_count",
        "error",
    }
    if (
        not isinstance(value, dict)
        or set(value) != expected
        or value["schema_version"] != 1
        or value["action"] != "delete"
        or value["outcome"] not in {"success", "failure", "partial"}
    ):
        raise SubscriptionError("Subscription deletion returned an invalid response schema.")
    deleted_count = value["deleted_count"]
    remaining_count = value["remaining_count"]
    error = value["error"]
    if (
        isinstance(deleted_count, bool)
        or not isinstance(deleted_count, int)
        or deleted_count < 0
        or isinstance(remaining_count, bool)
        or not isinstance(remaining_count, int)
        or remaining_count < 0
        or not isinstance(error, str)
    ):
        raise SubscriptionError("Subscription deletion returned invalid result fields.")
    outcome = value["outcome"]
    if outcome == "failure":
        if (
            value["availability"]
            or value["server_name"]
            or value["tls_mode"]
            or value["artifacts"] != []
            or deleted_count != 0
            or remaining_count != 0
            or not error
        ):
            raise SubscriptionError("Subscription deletion failure is malformed.")
        return FinalizedSubscriptionDelete(SubscriptionDeleteResult("failure", error=error))
    if outcome == "success" and (error or remaining_count != 0):
        raise SubscriptionError("Subscription deletion success is malformed.")
    if outcome == "partial" and not error:
        raise SubscriptionError("Subscription deletion partial result lacks an error.")
    if outcome == "partial" and not value["availability"]:
        if (
            value["server_name"]
            or value["tls_mode"]
            or value["artifacts"] != []
            or remaining_count != 0
        ):
            raise SubscriptionError("Subscription deletion partial result is malformed.")
        return FinalizedSubscriptionDelete(
            SubscriptionDeleteResult(
                "partial",
                deleted_count=deleted_count,
                error=error,
            )
        )
    inspect_shape = {
        "schema_version": 1,
        "action": "inspect",
        "outcome": "success",
        "availability": value["availability"],
        "server_name": value["server_name"],
        "tls_mode": value["tls_mode"],
        "artifacts": value["artifacts"],
        "error": "",
    }
    snapshot = parse_subscription_inspection_response(
        json.dumps(inspect_shape, separators=(",", ":")),
        expected_server_ip,
    )
    return FinalizedSubscriptionDelete(
        SubscriptionDeleteResult(
            outcome,
            deleted_count=deleted_count,
            remaining_count=remaining_count,
            error=error,
        ),
        snapshot,
    )


def inspect_subscription_server(
    project_directory: Path,
    request: SubscriptionInspectRequest,
    *,
    cancelled: Callable[[], bool] | None = None,
) -> SubscriptionServerSnapshot:
    server_ip, error = validate_server_ip(request.server_ip)
    if error or server_ip != request.server_ip:
        raise SubscriptionError(error or "Subscription server IP is not canonical.")
    if request.operation_token < 1 or request.request_id < 1:
        raise SubscriptionError("Subscription inspection identity is invalid.")
    try:
        connection = primary_ssh_connection(project_directory)
    except SshSettingsError as error:
        raise SubscriptionError(f"Could not read local SSH configuration: {error}") from error
    return SshSubscriptionManagementTransport(
        request.server_ip,
        connection.private_key_path,
        connection.port,
        cancelled=cancelled,
    ).inspect(project_directory, request)


def delete_subscription(
    project_directory: Path,
    request: SubscriptionDeleteRequest,
    *,
    cancelled: Callable[[], bool] | None = None,
) -> FinalizedSubscriptionDelete:
    server_ip, error = validate_server_ip(request.server_ip)
    if error or server_ip != request.server_ip:
        raise SubscriptionError(error or "Subscription server IP is not canonical.")
    if request.operation_token < 1 or request.request_id < 1:
        raise SubscriptionError("Subscription deletion identity is invalid.")
    name = validate_subscription_name(request.name)
    if request.kind not in {"orphan", "active"}:
        raise SubscriptionError("Subscription deletion kind is invalid.")
    if (
        not isinstance(request.tokens, tuple)
        or any(
            not isinstance(token, str) or _TOKEN.fullmatch(token) is None
            for token in request.tokens
        )
        or len(request.tokens) != len(set(request.tokens))
        or request.tokens != tuple(sorted(request.tokens))
    ):
        raise SubscriptionError("Subscription deletion tokens are invalid.")
    registry = SubscriptionRegistry(project_directory)
    previous = None
    if request.kind == "active":
        if request.tokens:
            raise SubscriptionError("Delete active does not accept individual server tokens.")
        previous = registry.begin_deletion(request.server_ip, name)
    else:
        if not request.tokens:
            raise SubscriptionError("Delete orphan requires exact server tokens.")
        desired = next(
            (entry for entry in registry.entries(request.server_ip) if entry.name == name),
            None,
        )
        if desired is not None and desired.token in request.tokens:
            raise SubscriptionError("Delete orphan cannot remove the desired Registry token.")
    try:
        connection = primary_ssh_connection(project_directory)
    except SshSettingsError as error:
        if previous is not None:
            registry.restore_deletion(previous)
        raise SubscriptionError(f"Could not read local SSH configuration: {error}") from error
    finalized = SshSubscriptionManagementTransport(
        request.server_ip,
        connection.private_key_path,
        connection.port,
        cancelled=cancelled,
    ).delete(project_directory, request)
    if request.kind != "active" or previous is None:
        return finalized
    if finalized.result.outcome == "failure":
        registry.restore_deletion(previous)
        return finalized
    if finalized.result.outcome != "success":
        return finalized
    try:
        registry.complete_deletion(request.server_ip, name, previous.token)
    except SubscriptionError as error:
        return FinalizedSubscriptionDelete(
            SubscriptionDeleteResult(
                "partial",
                finalized.result.deleted_count,
                finalized.result.remaining_count,
                f"Server deletion succeeded, but Registry finalization failed: {error}",
            ),
            finalized.snapshot,
        )
    return finalized
