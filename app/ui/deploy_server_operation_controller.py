"""Deploy and selected-server operation lifecycle for the desktop UI."""

from __future__ import annotations

import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import Literal

from PySide6.QtCore import QTimer

from app.services.app_defaults import AppDefaultsError
from app.services.inventory import InventorySnapshot
from app.services.management import NginxManagementStatus
from app.services.modular_deployment import (
    ModularComponent,
    ModularDeployRequest,
    NginxTlsSettings,
    base_security_component,
    build_modular_deploy_request,
    docker_component,
    hysteria2_component,
    mieru_component,
    modular_deployment_script,
    netdata_component,
    nginx_component,
    validate_nginx_tls_settings,
    xray_component,
)
from app.services.restore_ssh import launch_ssh_restore
from app.services.ssh import ssh_check_script

from .inventory_runner import InventoryRequestContext
from .management_runner import (
    ManagementOperationRequest,
    ManagementRunner,
    management_failure_message,
)
from .operation_gate import OperationContext, OperationGate
from .process_runner import (
    PowerShellOperationKind,
    PowerShellOperationRequest,
    PowerShellRunner,
)

OperationOutcome = Literal["success", "warning", "error"]


class DeployServerOperationController:
    """Own fixed PowerShell deploy actions, SSH Fix and selected-server reboot."""

    def __init__(
        self,
        gate: OperationGate,
        process_runner: PowerShellRunner,
        management_runner: ManagementRunner,
        *,
        current_server_ip: Callable[[], str | None],
        current_server_alias: Callable[[], str],
        cancel_users: Callable[[], bool],
        resume_users: Callable[[], None],
        set_operation_controls_enabled: Callable[[bool], None],
        write_log: Callable[..., None],
        write_result: Callable[[str, OperationOutcome], None],
        confirm: Callable[..., bool],
        request_nginx_tls: Callable[[NginxTlsSettings | None], NginxTlsSettings | None],
        request_inventory: Callable[[InventoryRequestContext], bool],
    ) -> None:
        self.gate = gate
        self.process_runner = process_runner
        self.management_runner = management_runner
        self.current_server_ip = current_server_ip
        self.current_server_alias = current_server_alias
        self.cancel_users = cancel_users
        self.resume_users = resume_users
        self.set_operation_controls_enabled = set_operation_controls_enabled
        self.write_log = write_log
        self.write_result = write_result
        self.confirm = confirm
        self.request_nginx_tls = request_nginx_tls
        self.request_inventory = request_inventory
        self.process_context: OperationContext | None = None
        self.nginx_inventory_request: InventoryRequestContext | None = None
        self.nginx_management_request: ManagementOperationRequest | None = None
        self.nginx_current_tls: NginxTlsSettings | None = None
        self.ssh_fix_context: OperationContext | None = None
        self.ssh_fix_process: subprocess.Popen[bytes] | None = None
        self.ssh_fix_exit_code: int | None = None
        self.ssh_fix_timer = QTimer()
        self.ssh_fix_timer.setInterval(250)
        self.ssh_fix_timer.timeout.connect(self._poll_ssh_fix)

        process_runner.line_received.connect(self.write_process_line)
        process_runner.finished.connect(self.operation_finished)
        process_runner.failed_to_start.connect(self.operation_failed_to_start)
        management_runner.completed.connect(self.management_operation_completed)
        management_runner.failed.connect(self.management_operation_failed)

    def check_ssh(self) -> None:
        self._start_process("SSH check", "ssh-check", ssh_check_script, timeout_ms=25_000)

    def deploy_base_security(self) -> None:
        if self.confirm(
            "Base + Security",
            "This operation installs the base packages, configures Fail2Ban, and applies "
            "a firewall that allows only SSH. Continue?",
            "Install Base + Security",
        ):
            self._start_deploy(
                "Base + Security",
                base_security_component,
            )

    def deploy_xray(self) -> None:
        if self.confirm(
            "Install Xray",
            "This operation installs Xray and opens its configured TCP port in the firewall. "
            "Base + Security must already be active on the selected server. Continue?",
            "Install Xray",
        ):
            self._start_deploy(
                "Install Xray",
                xray_component,
            )

    def deploy_hysteria2(self) -> None:
        if self.confirm(
            "Install Hysteria2",
            "This operation installs Hysteria2 and opens its configured UDP port in the firewall. "
            "Base + Security must already be active on the selected server. Continue?",
            "Install Hysteria2",
        ):
            self._start_deploy(
                "Install Hysteria2",
                hysteria2_component,
            )

    def deploy_docker(self) -> None:
        if self.confirm(
            "Install Docker",
            "This operation installs Docker Engine and its Compose plugin from Docker's official "
            "repository. Base + Security must already be active on the selected server. Continue?",
            "Install Docker",
        ):
            self._start_deploy(
                "Install Docker",
                docker_component,
            )

    def deploy_mieru(self) -> None:
        if self.confirm(
            "Install Mieru",
            "This operation installs the Mita server, creates the initial Mieru user, and opens "
            "the configured TCP or UDP port in the firewall. Base + Security must already be "
            "active on the selected server. Continue?",
            "Install Mieru",
        ):
            self._start_deploy(
                "Install Mieru",
                mieru_component,
            )

    def deploy_nginx(self) -> None:
        if self.gate.busy:
            return
        if not self.cancel_users():
            self.write_result("Could not close the current Users operation.", "error")
            return
        server_ip = self.current_server_ip()
        if server_ip is None:
            self.resume_users()
            return
        context = self.gate.begin(
            "Nginx Deploy preflight",
            scope="inventory",
            server_ip=server_ip,
        )
        if context is None:
            self.resume_users()
            return
        self.set_operation_controls_enabled(False)
        self.write_log(f"=== {context.title}: {server_ip} ===")
        request = InventoryRequestContext(
            context.token,
            "nginx_deploy",
            "Nginx Deploy",
            server_ip,
        )
        self.nginx_inventory_request = request
        if not self.request_inventory(request) and self.gate.matches(context):
            self.write_result("Could not start Nginx Inventory preflight.", "error")
            self._release(context)

    def inventory_completed(
        self,
        request: InventoryRequestContext,
        snapshot: InventorySnapshot,
    ) -> None:
        context = self._matching_nginx_inventory_context(request)
        if context is None:
            return
        if not isinstance(snapshot, InventorySnapshot) or snapshot.server_ip != context.server_ip:
            self.write_result("Nginx Inventory preflight returned an invalid snapshot.", "error")
            self._release(context)
            return
        self.nginx_inventory_request = None
        if snapshot.component("nginx") is None:
            self._request_nginx_deploy(context, None)
            return
        management_context = self.gate.transition(
            context,
            "Nginx TLS inspect",
            scope="management",
            server_ip=context.server_ip,
        )
        if management_context is None:
            return
        management_request = ManagementOperationRequest(
            management_context.token,
            "nginx",
            management_context.server_ip,
            action="inspect",
        )
        self.nginx_management_request = management_request
        self.write_log(f"Inspecting current Nginx TLS state on {management_context.server_ip}.")
        if not self.management_runner.start_operation(management_request) and self.gate.matches(
            management_context
        ):
            self.write_result("Could not start Nginx TLS inspection.", "error")
            self._release(management_context)

    def inventory_failed(self, request: InventoryRequestContext, message: str) -> None:
        context = self._matching_nginx_inventory_context(request)
        if context is None:
            return
        self.write_result(f"Nginx Deploy preflight failed: {message}", "error")
        self._release(context)

    def _request_nginx_deploy(
        self,
        context: OperationContext,
        current_tls: NginxTlsSettings | None,
    ) -> None:
        if not self.gate.matches(context):
            return
        self.nginx_current_tls = current_tls
        nginx_tls = self.request_nginx_tls(current_tls)
        if nginx_tls is None:
            self._release(context)
            return
        current_description = self._nginx_tls_description(current_tls)
        requested_description = self._nginx_tls_description(nginx_tls)
        if self.confirm(
            "Install Nginx",
            "This operation installs Nginx, opens TCP ports 80 and 443, and serves a static "
            "placeholder. The requested TLS state becomes the managed final state.\n\n"
            f"Current: {current_description}\n"
            f"Requested: {requested_description}\n\n"
            "Base + Security must already be active on the selected server. Continue?",
            "Install Nginx",
            highlight_text=f"Server: {context.server_ip}",
        ):
            self._start_nginx_deploy(context, nginx_tls)
            return
        self._release(context)

    def _start_nginx_deploy(
        self,
        context: OperationContext,
        nginx_tls: NginxTlsSettings,
    ) -> None:
        try:
            deploy_request = build_modular_deploy_request(
                Path(__file__).resolve().parents[2],
                nginx_component,
                nginx_tls=nginx_tls,
            )
        except (AppDefaultsError, OSError, TypeError, ValueError) as error:
            self.write_result(f"Deploy preflight failed before launch: {error}", "error")
            self._release(context)
            return
        process_context = self.gate.transition(
            context,
            "Install Nginx",
            scope="process",
            server_ip=context.server_ip,
        )
        if process_context is None:
            return
        self.process_context = process_context
        self.write_log(f"=== Install Nginx: {process_context.server_ip} ===")
        request = PowerShellOperationRequest(
            process_context.token,
            "deploy-nginx",
            process_context.server_ip,
            modular_deployment_script,
            deploy_request=deploy_request,
        )
        if not self.process_runner.start(request) and self.gate.matches(process_context):
            self._release_process(process_context)

    def deploy_netdata(self) -> None:
        if self.confirm(
            "Install Netdata",
            "Before continuing, open Settings > Netdata and fill or verify Claim token and "
            "Claim rooms. This operation installs "
            "the stable Netdata Agent on fixed localhost port 19999, claims it to Netdata "
            "Cloud, enables automatic stable updates and publishes a Cloud SSO-protected HTTPS "
            "dashboard through managed Nginx. No firewall port is opened. Continue?",
            "Install Netdata",
        ):
            self._start_deploy(
                "Install Netdata",
                netdata_component,
            )

    def _start_deploy(
        self,
        title: str,
        component: ModularComponent,
        *,
        nginx_tls: NginxTlsSettings | None = None,
    ) -> None:
        try:
            deploy_request = build_modular_deploy_request(
                Path(__file__).resolve().parents[2],
                component,
                nginx_tls=nginx_tls,
            )
        except (AppDefaultsError, OSError, TypeError, ValueError) as error:
            self.write_result(f"Deploy preflight failed before launch: {error}", "error")
            return
        self._start_process(
            title,
            f"deploy-{component}",  # type: ignore[arg-type]
            modular_deployment_script,
            deploy_request=deploy_request,
        )

    def ssh_fix(self) -> None:
        if self.gate.busy:
            return
        if not self.confirm(
            "Fix SSH access",
            "SSH access will be changed, a key will be added, and password login "
            "will be disabled. "
            "Continue?",
            "SSH Fix",
        ):
            return
        server_ip = self.current_server_ip()
        if server_ip is None or self.gate.busy:
            return
        if not self.cancel_users():
            self.write_result("Could not close the current Users operation.", "error")
            return
        context = self.gate.begin("SSH Fix", scope="process", server_ip=server_ip)
        if context is None:
            self.resume_users()
            return
        self.ssh_fix_context = context
        self.set_operation_controls_enabled(False)
        self.write_log(f"=== SSH Fix: {server_ip} ===")
        launch = launch_ssh_restore(server_ip)
        if launch.error is not None or launch.process is None:
            self.write_result(
                launch.error or "The SSH recovery window could not be opened.",
                "error",
            )
            self._release_ssh_fix(context)
            return
        self.ssh_fix_process = launch.process
        self.ssh_fix_exit_code = None
        self.write_log(
            "SSH Fix console opened. Complete the prompts; SSH access will be checked "
            "automatically after the console closes."
        )
        self.ssh_fix_timer.start()

    def can_close(self) -> bool:
        """Keep the panel alive while it owns any PowerShell operation."""
        return (
            self.process_context is None
            and self.ssh_fix_context is None
            and self.ssh_fix_exit_code is None
        )

    def _poll_ssh_fix(self) -> None:
        context = self.ssh_fix_context
        process = self.ssh_fix_process
        if context is None or process is None or not self.gate.matches(context):
            self.ssh_fix_timer.stop()
            return
        exit_code = process.poll()
        if exit_code is None:
            return
        self.ssh_fix_timer.stop()
        self.ssh_fix_process = None
        self.ssh_fix_context = None
        self.ssh_fix_exit_code = exit_code
        self.write_log(f"SSH Fix console closed (exit code {exit_code}). Running Check SSH...")
        verification_context = self.gate.transition(
            context,
            "SSH Fix verification",
            scope="process",
            server_ip=context.server_ip,
        )
        if verification_context is None:
            self.ssh_fix_exit_code = None
            return
        self.process_context = verification_context
        request = PowerShellOperationRequest(
            verification_context.token,
            "ssh-check",
            verification_context.server_ip,
            ssh_check_script,
            25_000,
        )
        if not self.process_runner.start(request) and self.gate.matches(verification_context):
            self.write_result(
                "SSH Fix console closed, but Check SSH could not be started.",
                "error",
            )
            self._release_process(verification_context)

    def reboot_server(self) -> None:
        if self.gate.busy:
            return
        server_ip = self.current_server_ip()
        if server_ip is None:
            return
        server_alias = self.current_server_alias().strip()
        target = f"{server_ip} — {server_alias}" if server_alias else server_ip
        if not self.confirm(
            "Reboot server",
            "The selected server will restart. Active VPN connections will be interrupted.",
            "Reboot server",
            highlight_text=f"Server: {target}",
        ):
            return
        if self.gate.busy:
            return
        if not self.cancel_users():
            self.write_result("Could not close the current Users operation.", "error")
            return
        context = self.gate.begin("Server reboot", scope="server", server_ip=server_ip)
        if context is None:
            self.resume_users()
            return
        self.set_operation_controls_enabled(False)
        self.write_log(f"=== {context.title}: {server_ip} ===")
        request = ManagementOperationRequest(context.token, "server-reboot", server_ip)
        if not self.management_runner.start_operation(request) and self.gate.matches(context):
            self._release(context)

    def _start_process(
        self,
        title: str,
        kind: PowerShellOperationKind,
        script_path: Path,
        *,
        timeout_ms: int | None = None,
        script_arguments: list[str] | None = None,
        deploy_request: ModularDeployRequest | None = None,
    ) -> None:
        if self.gate.busy:
            return
        server_ip = self.current_server_ip()
        if server_ip is None or self.gate.busy:
            return
        if not self.cancel_users():
            self.write_result("Could not close the current Users operation.", "error")
            return
        context = self.gate.begin(title, scope="process", server_ip=server_ip)
        if context is None:
            self.resume_users()
            return
        self.process_context = context
        self.set_operation_controls_enabled(False)
        self.write_log(f"=== {title}: {server_ip} ===")
        request = PowerShellOperationRequest(
            context.token,
            kind,
            server_ip,
            script_path,
            timeout_ms,
            tuple(script_arguments or ()),
            deploy_request,
        )
        if not self.process_runner.start(request) and self.gate.matches(context):
            self._release_process(context)

    def write_process_line(
        self,
        request: PowerShellOperationRequest,
        stream: str,
        line: str,
    ) -> None:
        if self._matching_process_request(request) is None:
            return
        prefix = "[stderr] " if stream == "stderr" else ""
        self.write_log(f"{prefix}{line}")

    def operation_finished(
        self,
        request: PowerShellOperationRequest,
        exit_code: int,
        timed_out: bool,
    ) -> None:
        context = self._matching_process_request(request)
        if context is None:
            return
        if timed_out:
            status = "timed out"
            outcome: OperationOutcome = "error"
        elif exit_code == 0:
            status = "successful"
            outcome = "success"
        else:
            status = f"failed (exit code {exit_code})"
            outcome = "error"
        if context.title == "SSH Fix verification":
            self._write_ssh_fix_result(exit_code, timed_out)
        else:
            self.write_result(f"=== {context.title}: {status} ===", outcome)
        self._release_process(context)

    def operation_failed_to_start(
        self,
        request: PowerShellOperationRequest,
        error: str,
    ) -> None:
        context = self._matching_process_request(request)
        if context is None:
            return
        if context.title == "SSH Fix verification":
            self.write_result(
                f"SSH Fix console closed, but Check SSH could not start: {error}",
                "error",
            )
        else:
            self.write_result(f"Launch error: {error}", "error")
        self._release_process(context)

    def management_operation_completed(self, request: object, status: object) -> None:
        nginx_context = self._matching_nginx_management_context(request)
        if nginx_context is not None:
            if not isinstance(status, NginxManagementStatus):
                self.write_result("Nginx TLS inspection returned an invalid status.", "error")
                self._release(nginx_context)
                return
            if status.tls_mode == "self_signed" and status.server_name not in {
                nginx_context.server_ip,
                "default",
            }:
                self.write_result("Nginx TLS inspection returned an unsupported state.", "error")
                self._release(nginx_context)
                return
            try:
                current_tls = validate_nginx_tls_settings(
                    status.tls_mode,
                    status.server_name if status.tls_mode == "letsencrypt" else "",
                )
            except ValueError:
                self.write_result("Nginx TLS inspection returned an unsupported state.", "error")
                self._release(nginx_context)
                return
            self.nginx_management_request = None
            self._request_nginx_deploy(nginx_context, current_tls)
            return
        context = self._matching_reboot_context(request)
        if context is None:
            return
        self.write_result(
            "=== Server reboot: scheduled — SSH will be unavailable briefly ===",
            "success",
        )
        self._release(context)

    def management_operation_failed(self, request: object, failure: object) -> None:
        nginx_context = self._matching_nginx_management_context(request)
        if nginx_context is not None:
            message = management_failure_message(failure)
            self.write_result(f"Nginx TLS inspection failed: {message}", "error")
            self._release(nginx_context)
            return
        context = self._matching_reboot_context(request)
        if context is None:
            return
        message = management_failure_message(failure)
        self.write_result(f"=== Server reboot: failed — {message} ===", "error")
        self._release(context)

    def _matching_process_context(self) -> OperationContext | None:
        context = self.process_context
        if context is None or not self.gate.matches(context, scope="process"):
            return None
        return context

    def _matching_process_request(
        self,
        request: PowerShellOperationRequest,
    ) -> OperationContext | None:
        if not isinstance(request, PowerShellOperationRequest):
            return None
        context = self._matching_process_context()
        if context is None:
            return None
        if context.token != request.operation_token or context.server_ip != request.server_ip:
            return None
        expected_kind = {
            "SSH check": "ssh-check",
            "SSH Fix verification": "ssh-check",
            "Base + Security": "deploy-base-security",
            "Install Xray": "deploy-xray",
            "Install Hysteria2": "deploy-hysteria2",
            "Install Mieru": "deploy-mieru",
            "Install Docker": "deploy-docker",
            "Install Nginx": "deploy-nginx",
            "Install Netdata": "deploy-netdata",
        }.get(context.title)
        if request.kind != expected_kind:
            return None
        return context

    def _matching_reboot_context(self, request: object) -> OperationContext | None:
        if not isinstance(request, ManagementOperationRequest) or request.kind != "server-reboot":
            return None
        context = self.gate.current
        if context is None or context.token != request.token:
            return None
        if not self.gate.matches(
            context,
            title="Server reboot",
            scope="server",
            server_ip=request.server_ip,
        ):
            return None
        return context

    @staticmethod
    def _nginx_tls_description(settings: NginxTlsSettings | None) -> str:
        if settings is None:
            return "Nginx not installed"
        if settings.mode == "self_signed":
            return "Self-signed (domain unbound)"
        return f"Let's Encrypt — {settings.domain}"

    def _matching_nginx_inventory_context(
        self,
        request: object,
    ) -> OperationContext | None:
        if not isinstance(request, InventoryRequestContext):
            return None
        if request != self.nginx_inventory_request or request.purpose != "nginx_deploy":
            return None
        context = self.gate.current
        if context is None or context.token != request.operation_token:
            return None
        if not self.gate.matches(
            context,
            title="Nginx Deploy preflight",
            scope="inventory",
            server_ip=request.server_ip,
        ):
            return None
        return context

    def _matching_nginx_management_context(
        self,
        request: object,
    ) -> OperationContext | None:
        if not isinstance(request, ManagementOperationRequest):
            return None
        if request != self.nginx_management_request:
            return None
        if request.kind != "nginx" or request.action != "inspect":
            return None
        context = self.gate.current
        if context is None or context.token != request.token:
            return None
        if not self.gate.matches(
            context,
            title="Nginx TLS inspect",
            scope="management",
            server_ip=request.server_ip,
        ):
            return None
        return context

    def _release_process(self, context: OperationContext) -> None:
        if not self.gate.finish(context):
            return
        self.process_context = None
        self.nginx_current_tls = None
        self.ssh_fix_exit_code = None
        self.set_operation_controls_enabled(True)
        self.resume_users()

    def _write_ssh_fix_result(self, check_exit_code: int, timed_out: bool) -> None:
        fix_exit_code = self.ssh_fix_exit_code
        if timed_out:
            self.write_result("=== SSH Fix: Check SSH timed out ===", "error")
        elif check_exit_code != 0:
            self.write_result(
                f"=== SSH Fix: Check SSH failed (exit code {check_exit_code}) ===",
                "error",
            )
        elif fix_exit_code == 0:
            self.write_result(
                "=== SSH Fix: successful — SSH access confirmed ===",
                "success",
            )
        else:
            self.write_result(
                f"=== SSH Fix: console exited with code {fix_exit_code}, but SSH "
                "access is available ===",
                "warning",
            )

    def _release_ssh_fix(self, context: OperationContext) -> None:
        self.ssh_fix_timer.stop()
        self.ssh_fix_process = None
        self.ssh_fix_context = None
        self.ssh_fix_exit_code = None
        self._release(context)

    def _release(self, context: OperationContext) -> None:
        if not self.gate.finish(context):
            return
        self.nginx_inventory_request = None
        self.nginx_management_request = None
        self.nginx_current_tls = None
        self.set_operation_controls_enabled(True)
        self.resume_users()
