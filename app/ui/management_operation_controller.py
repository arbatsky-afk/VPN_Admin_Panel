"""GUI orchestration for fixed component Management operations."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, replace

from app.services.management import (
    BASE_SECURITY_ACTIONS,
    BASE_SECURITY_SERVICES,
    DOCKER_ACTIONS,
    HYSTERIA2_ACTIONS,
    MIERU_ACTIONS,
    NETDATA_ACTIONS,
    NGINX_ACTIONS,
    XRAY_ACTIONS,
    BaseSecurityManagementStatus,
    DockerManagementStatus,
    Hysteria2ManagementStatus,
    ManagementMutationResult,
    MieruManagementStatus,
    NetdataManagementStatus,
    NginxManagementStatus,
    ServiceManagementStatus,
    XrayManagementStatus,
)

from .inventory_runner import InventoryRequestContext
from .management_runner import (
    COMPONENT_MANAGEMENT_OPERATION_KINDS,
    ManagementOperationFailure,
    ManagementOperationRequest,
    ManagementRunner,
    management_failure_message,
)
from .operation_gate import OperationContext, OperationGate
from .tabs.management_tab import ManagementTab


@dataclass(frozen=True, slots=True)
class ManagementReconciliation:
    """Original uncertain mutation retained across Inventory and inspect."""

    token: int
    server_ip: str
    component_id: str
    outcome: str
    message: str
    title: str
    service: str = ""
    connection_update: bool = False


class ManagementOperationController:
    """Own the common start/success/failure lifecycle of component actions."""

    def __init__(
        self,
        gate: OperationGate,
        runner: ManagementRunner,
        tab: ManagementTab,
        *,
        cancel_users: Callable[[], bool],
        current_server_ip: Callable[[], str | None],
        set_operation_controls_enabled: Callable[[bool], None],
        write_log: Callable[[str], None],
        write_result: Callable[[str, str], None],
        resume_users: Callable[[], None],
        refresh_snapshot: Callable[..., None],
        management_is_visible: Callable[[], bool],
        request_reconciliation_inventory: Callable[[InventoryRequestContext], bool] | None = None,
        editing_enabled: Callable[[], bool],
        confirm: Callable[..., bool],
    ) -> None:
        self.gate = gate
        self.runner = runner
        self.tab = tab
        self.cancel_users = cancel_users
        self.current_server_ip = current_server_ip
        self.set_operation_controls_enabled = set_operation_controls_enabled
        self.write_log = write_log
        self.write_result = write_result
        self.resume_users = resume_users
        self.refresh_snapshot = refresh_snapshot
        self.request_reconciliation_inventory = request_reconciliation_inventory
        self.editing_enabled = editing_enabled
        self.confirm = confirm
        self.management_is_visible = management_is_visible
        self.reconciliation: ManagementReconciliation | None = None
        self.active_request: ManagementOperationRequest | None = None
        runner.completed.connect(self.operation_completed)
        runner.failed.connect(self.operation_failed)

    def inspect_docker(self) -> None:
        if not self.gate.busy and self.management_is_visible():
            self._start(
                "Docker inspect", ManagementOperationRequest(0, "docker", "", action="inspect")
            )

    def docker_action_requested(self, action: str) -> None:
        if action not in DOCKER_ACTIONS - {"inspect"}:
            self.write_result("Unsupported Docker action.", "error")
            return
        self._start(f"Docker {action}", ManagementOperationRequest(0, "docker", "", action=action))

    def inspect_base_security(self) -> None:
        if not self.gate.busy and self.management_is_visible():
            self._start(
                "Base + Security nftables inspect",
                ManagementOperationRequest(
                    0, "base-security", "", action="inspect", service="nftables"
                ),
            )

    def base_security_action_requested(self, service: str, action: str) -> None:
        if service not in BASE_SECURITY_SERVICES or action not in BASE_SECURITY_ACTIONS - {
            "inspect"
        }:
            self.write_result("Unsupported Base + Security action.", "error")
            return
        self._start(
            f"Base + Security {service} {action}",
            ManagementOperationRequest(0, "base-security", "", action=action, service=service),
        )

    def inspect_xray(self) -> None:
        if not self.gate.busy and self.management_is_visible():
            self._start(
                "Xray inspect", ManagementOperationRequest(0, "xray", "", action="inspect")
            )

    def xray_action_requested(self, action: str) -> None:
        if action not in XRAY_ACTIONS - {"inspect"}:
            self.write_result("Unsupported Xray action.", "error")
            return
        self._start(f"Xray {action}", ManagementOperationRequest(0, "xray", "", action=action))

    def xray_connection_update_requested(self, port_text: str, sni: str) -> None:
        try:
            port = int(port_text)
        except ValueError:
            self.write_result("The Xray TCP port must be a number.", "error")
            return
        if not self._confirm_settings_update(
            "Change Xray connection settings",
            f"Change Xray to TCP port {port} and SNI {sni.strip()}? Active Xray "
            "connections will be interrupted.",
            "Apply Xray settings",
        ):
            return
        self._start(
            "Xray update connection settings",
            ManagementOperationRequest(
                0, "xray-connection-update", "", port=port, sni=sni.strip()
            ),
        )

    def inspect_hysteria2(self) -> None:
        if not self.gate.busy and self.management_is_visible():
            self._start(
                "Hysteria2 inspect",
                ManagementOperationRequest(0, "hysteria2", "", action="inspect"),
            )

    def hysteria2_action_requested(self, action: str) -> None:
        if action not in HYSTERIA2_ACTIONS - {"inspect"}:
            self.write_result("Unsupported Hysteria2 action.", "error")
            return
        self._start(
            f"Hysteria2 {action}", ManagementOperationRequest(0, "hysteria2", "", action=action)
        )

    def hysteria2_connection_update_requested(self, port_text: str, sni: str) -> None:
        try:
            port = int(port_text)
        except ValueError:
            self.write_result("The Hysteria2 UDP port must be a number.", "error")
            return
        if not self._confirm_settings_update(
            "Change Hysteria2 connection settings",
            f"Change Hysteria2 to UDP port {port} and SNI {sni.strip()}? Active "
            "Hysteria2 connections will be interrupted.",
            "Apply Hysteria2 settings",
        ):
            return
        self._start(
            "Hysteria2 update connection settings",
            ManagementOperationRequest(
                0, "hysteria2-connection-update", "", port=port, sni=sni.strip()
            ),
        )

    def inspect_mieru(self) -> None:
        if not self.gate.busy and self.management_is_visible():
            self._start(
                "Mieru inspect", ManagementOperationRequest(0, "mieru", "", action="inspect")
            )

    def mieru_action_requested(self, action: str) -> None:
        if action not in MIERU_ACTIONS - {"inspect"}:
            self.write_result("Unsupported Mieru action.", "error")
            return
        self._start(f"Mieru {action}", ManagementOperationRequest(0, "mieru", "", action=action))

    def mieru_port_update_requested(self, port_text: str) -> None:
        try:
            port = int(port_text)
        except ValueError:
            self.write_result("The Mieru port must be a number.", "error")
            return
        if not 1025 <= port <= 65535:
            self.write_result("The Mieru port must be between 1025 and 65535.", "error")
            return
        if not self._confirm_settings_update(
            "Change Mieru port",
            f"Change Mieru to port {port}? Active Mieru connections will be interrupted.",
            "Apply Mieru port",
        ):
            return
        self._start(
            "Mieru update port",
            ManagementOperationRequest(0, "mieru-port-update", "", port=port),
        )

    def inspect_nginx(self) -> None:
        if not self.gate.busy and self.management_is_visible():
            self._start(
                "Nginx inspect", ManagementOperationRequest(0, "nginx", "", action="inspect")
            )

    def nginx_action_requested(self, action: str) -> None:
        if action not in NGINX_ACTIONS - {"inspect"}:
            self.write_result("Unsupported Nginx action.", "error")
            return
        self._start(f"Nginx {action}", ManagementOperationRequest(0, "nginx", "", action=action))

    def inspect_netdata(self) -> None:
        if not self.gate.busy and self.management_is_visible():
            self._start(
                "Netdata inspect", ManagementOperationRequest(0, "netdata", "", action="inspect")
            )

    def netdata_action_requested(self, action: str) -> None:
        if action not in NETDATA_ACTIONS - {"inspect"}:
            self.write_result("Unsupported Netdata action.", "error")
            return
        self._start(
            f"Netdata {action}", ManagementOperationRequest(0, "netdata", "", action=action)
        )

    def _confirm_settings_update(self, title: str, text: str, action_label: str) -> bool:
        if not self.editing_enabled():
            self.write_result(
                "Enable Editing before changing Management connection settings.", "error"
            )
            return False
        server_ip = self.current_server_ip()
        if server_ip is None:
            return False
        return self.confirm(
            title,
            text,
            action_label,
            highlight_text=f"Server: {server_ip}",
        )

    def _start(self, title: str, request: ManagementOperationRequest) -> None:
        if self.gate.busy:
            return
        server_ip = self.current_server_ip()
        if server_ip is None or self.gate.busy:
            return
        if not self.cancel_users():
            self.write_result("Could not close the current Users operation.", "error")
            return
        context = self.gate.begin(title, scope="management", server_ip=server_ip)
        if context is None:
            self.resume_users()
            return
        request = replace(request, token=context.token, server_ip=server_ip)
        self.active_request = request
        self.set_operation_controls_enabled(False)
        self.write_log(f"=== {title}: {server_ip} ===")
        if not self.runner.start_operation(request) and self.gate.matches(context):
            self._release(context)

    def operation_completed(self, request: object, status: object) -> None:
        if (
            not isinstance(request, ManagementOperationRequest)
            or request.kind not in COMPONENT_MANAGEMENT_OPERATION_KINDS
        ):
            return
        context = self._matching_context(request)
        if context is None:
            return
        expected_type = {
            "docker": DockerManagementStatus,
            "base-security": BaseSecurityManagementStatus,
            "xray": XrayManagementStatus,
            "xray-connection-update": ManagementMutationResult,
            "hysteria2": Hysteria2ManagementStatus,
            "hysteria2-connection-update": ManagementMutationResult,
            "mieru": MieruManagementStatus,
            "mieru-port-update": ManagementMutationResult,
            "nginx": NginxManagementStatus,
            "netdata": NetdataManagementStatus,
        }.get(request.kind)
        if expected_type is None:
            return
        if not isinstance(status, expected_type):
            self._fail_current(context, request, "Management runner returned an invalid status.")
            return
        if self._is_reconciliation_inspect(request):
            self._set_status(request, status)
            self._finish_reconciliation(context, status=status)
            return
        if request.kind in {
            "xray-connection-update",
            "hysteria2-connection-update",
            "mieru-port-update",
        }:
            self._complete_connection_update(context, request, status)
            return
        self._set_status(request, status)
        self.write_result(f"=== {self._result_title(request)}: successful ===", "success")
        self._release(context)
        if request.action != "inspect" and self.management_is_visible():
            self.refresh_snapshot(**self._refresh_options(request))

    def apply_external_status(self, request: object, status: object) -> bool:
        """Apply an authoritative status produced by another trusted UI controller."""
        if (
            not isinstance(request, ManagementOperationRequest)
            or request.kind not in COMPONENT_MANAGEMENT_OPERATION_KINDS
            or request.server_ip != self.current_server_ip()
        ):
            return False
        expected_type = {
            "docker": DockerManagementStatus,
            "base-security": BaseSecurityManagementStatus,
            "xray": XrayManagementStatus,
            "hysteria2": Hysteria2ManagementStatus,
            "mieru": MieruManagementStatus,
            "nginx": NginxManagementStatus,
            "netdata": NetdataManagementStatus,
        }.get(request.kind)
        if expected_type is None or not isinstance(status, expected_type):
            return False
        self._set_status(request, status)
        return True

    def _complete_connection_update(
        self,
        context: OperationContext,
        request: ManagementOperationRequest,
        result: ManagementMutationResult,
    ) -> None:
        component_id = self._component_id(request)
        if result.outcome == "success":
            expected_status = {
                "xray": XrayManagementStatus,
                "hysteria2": Hysteria2ManagementStatus,
                "mieru": MieruManagementStatus,
            }[component_id]
            if not isinstance(result.status, expected_status):
                self._fail_current(
                    context, request, "Management runner returned an invalid transaction status."
                )
                return
            self._set_status(request, result.status)
            self.write_result(
                f"=== {self._mutation_title(component_id)}: successful — existing "
                "client profiles need updated links ===",
                "success",
            )
        elif result.outcome == "rolled_back":
            self.write_result(
                f"=== {self._mutation_title(component_id)}: rolled back — {result.message} ===",
                "warning",
            )
        else:
            self._start_reconciliation(
                context,
                request,
                outcome=result.outcome,
                message=result.message,
                connection_update=True,
            )
            return
        self._release(context)
        if result.outcome == "success" and self.management_is_visible():
            self.refresh_snapshot(**self._refresh_options(request))

    def _start_reconciliation(
        self,
        context: OperationContext,
        request: ManagementOperationRequest,
        *,
        outcome: str,
        message: str,
        connection_update: bool,
    ) -> None:
        component_id = self._component_id(request)
        component_name = self._component_name(component_id)
        self.write_log(
            f"{self._result_title(request)} returned {outcome}: {message} "
            "Starting mandatory Inventory and inspect reconciliation."
        )
        transitioned = self.gate.transition(
            context,
            f"{component_name} reconciliation (Inventory)",
            scope="inventory",
            server_ip=request.server_ip,
        )
        if transitioned is None:
            return
        reconciliation = ManagementReconciliation(
            request.token,
            request.server_ip,
            component_id,
            outcome,
            message,
            self._result_title(request),
            request.service,
            connection_update,
        )
        self.reconciliation = reconciliation
        inventory_request = InventoryRequestContext(
            request.token,
            "management_reconciliation",
            component_id,
            request.server_ip,
        )
        if (
            self.request_reconciliation_inventory is None
            or not self.request_reconciliation_inventory(inventory_request)
        ):
            self.reconciliation_failed(
                inventory_request,
                "Could not start mandatory Inventory reconciliation.",
            )

    def reconciliation_inventory_completed(
        self,
        request: InventoryRequestContext,
    ) -> bool:
        reconciliation = self._matching_reconciliation(request)
        if reconciliation is None:
            return False
        context = self.gate.current
        if context is None:
            return False
        component_name = self._component_name(reconciliation.component_id)
        transitioned = self.gate.transition(
            context,
            f"{component_name} reconciliation (inspect)",
            scope="management",
            server_ip=reconciliation.server_ip,
        )
        if transitioned is None:
            return False
        inspect_request = ManagementOperationRequest(
            reconciliation.token,
            reconciliation.component_id,  # type: ignore[arg-type]
            reconciliation.server_ip,
            action="inspect",
            service=reconciliation.service,
        )
        self.active_request = inspect_request
        self.write_log(f"Inventory reconciliation completed; inspecting {component_name}.")
        if not self.runner.start_operation(inspect_request):
            self._finish_reconciliation(
                transitioned,
                f"Could not start mandatory {component_name} inspect.",
            )
        return True

    def reconciliation_failed(self, request: InventoryRequestContext, message: str) -> bool:
        reconciliation = self._matching_reconciliation(request)
        if reconciliation is None:
            return False
        context = self.gate.current
        if context is None:
            return False
        self._finish_reconciliation(context, f"Inventory reconciliation failed: {message}")
        return True

    def _matching_reconciliation(
        self,
        request: InventoryRequestContext,
    ) -> ManagementReconciliation | None:
        reconciliation = self.reconciliation
        context = self.gate.current
        if (
            reconciliation is None
            or request.purpose != "management_reconciliation"
            or request.operation_token != reconciliation.token
            or request.server_ip != reconciliation.server_ip
            or request.requester != reconciliation.component_id
            or context is None
            or context.token != reconciliation.token
            or context.scope != "inventory"
            or context.server_ip != reconciliation.server_ip
        ):
            return None
        return reconciliation

    def operation_failed(self, request: object, failure: object) -> None:
        if (
            not isinstance(request, ManagementOperationRequest)
            or request.kind not in COMPONENT_MANAGEMENT_OPERATION_KINDS
        ):
            return
        context = self._matching_context(request)
        if context is None:
            return
        message = management_failure_message(failure)
        if self._is_reconciliation_inspect(request):
            self.tab.finish_selected_component_refresh(self._component_id(request))
            self._finish_reconciliation(context, f"Mandatory component inspect failed: {message}")
            return
        typed_failure = failure if isinstance(failure, ManagementOperationFailure) else None
        if typed_failure is not None and typed_failure.outcome == "unknown":
            if request.action != "inspect":
                self._start_reconciliation(
                    context,
                    request,
                    outcome=typed_failure.outcome,
                    message=typed_failure.safe_message,
                    connection_update=request.kind
                    in {
                        "xray-connection-update",
                        "hysteria2-connection-update",
                        "mieru-port-update",
                    },
                )
                return
            self.tab.finish_selected_component_refresh(self._component_id(request))
            self.write_result(
                f"=== {self._result_title(request)}: unknown — {message} ===",
                "warning",
            )
            self._release(context)
            return
        self._fail_current(context, request, message)

    def _is_reconciliation_inspect(self, request: ManagementOperationRequest) -> bool:
        reconciliation = self.reconciliation
        return (
            reconciliation is not None
            and request.token == reconciliation.token
            and request.server_ip == reconciliation.server_ip
            and request.kind == reconciliation.component_id
            and request.action == "inspect"
            and request.service == reconciliation.service
        )

    def _finish_reconciliation(
        self,
        context: OperationContext,
        failure: str | None = None,
        *,
        status: object | None = None,
    ) -> None:
        reconciliation = self.reconciliation
        if reconciliation is None or context.token != reconciliation.token:
            return
        valid_status = isinstance(
            status,
            (
                DockerManagementStatus,
                BaseSecurityManagementStatus,
                XrayManagementStatus,
                Hysteria2ManagementStatus,
                MieruManagementStatus,
                NginxManagementStatus,
                NetdataManagementStatus,
            ),
        )
        if (
            reconciliation.connection_update
            and failure is None
            and isinstance(status, MieruManagementStatus)
            and (status.service.service_state != "active" or status.runtime_state != "RUNNING")
        ):
            failure = (
                "Mieru service/runtime is not active/RUNNING, so the listener state "
                "is not confirmed."
            )
        if (
            reconciliation.connection_update
            and failure is None
            and isinstance(status, (XrayManagementStatus, Hysteria2ManagementStatus))
        ):
            self.write_result(
                f"=== {self._mutation_title(reconciliation.component_id)}: "
                f"{reconciliation.outcome}; reconciliation completed. "
                f"Observed server state: port {status.port}, SNI {status.sni}, service "
                f"{status.service.service_state}/{status.service.startup_state}. "
                "Review the observed state before further changes. ===",
                "warning",
            )
        elif (
            reconciliation.connection_update
            and failure is None
            and isinstance(status, MieruManagementStatus)
        ):
            self.write_result(
                f"=== Mieru port: {reconciliation.outcome}; reconciliation completed. "
                f"Observed server state: {status.transport} port {status.port}, service "
                f"{status.service.service_state}/{status.service.startup_state}, "
                f"runtime {status.runtime_state}. "
                "Review the observed state before further changes. ===",
                "warning",
            )
        elif failure is None and valid_status:
            observed = self._service_status(
                reconciliation.component_id,
                reconciliation.service,
                status,
            )
            if observed is None:
                failure = "the component inspect did not return the selected service state."
            else:
                self.write_result(
                    f"=== {reconciliation.title}: {reconciliation.outcome}; "
                    "reconciliation completed. "
                    f"Observed service state: {observed.service_state}/{observed.startup_state}. "
                    "Review the observed state before further changes. ===",
                    "warning",
                )
        if failure is not None or not valid_status:
            self.write_result(
                f"=== {reconciliation.title}: {reconciliation.outcome}; "
                "reconciliation incomplete — "
                f"{failure or 'the resulting server state could not be confirmed.'} "
                "The server state must be checked manually. ===",
                "error",
            )
        self.reconciliation = None
        self._release(context)

    @staticmethod
    def _service_status(
        component_id: str,
        service: str,
        status: object,
    ) -> ServiceManagementStatus | None:
        if component_id == "docker" and isinstance(status, DockerManagementStatus):
            return ServiceManagementStatus(status.service_state, status.startup_state)
        if component_id == "base-security" and isinstance(status, BaseSecurityManagementStatus):
            if service == "nftables":
                return status.nftables
            if service == "fail2ban":
                return status.fail2ban
            return None
        if isinstance(
            status, (XrayManagementStatus, Hysteria2ManagementStatus, MieruManagementStatus)
        ):
            return status.service
        if isinstance(status, (NginxManagementStatus, NetdataManagementStatus)):
            return status.service
        return None

    def _matching_context(self, request: ManagementOperationRequest) -> OperationContext | None:
        if request != self.active_request:
            return None
        context = self.gate.current
        if context is None or context.token != request.token:
            return None
        if not self.gate.matches(context, scope="management", server_ip=request.server_ip):
            return None
        if self.reconciliation is not None and not self._is_reconciliation_inspect(request):
            return None
        return context

    def _fail_current(
        self,
        context: OperationContext,
        request: ManagementOperationRequest,
        message: str,
    ) -> None:
        if request.action == "inspect":
            self.tab.finish_selected_component_refresh(self._component_id(request))
        self.write_result(f"=== {self._result_title(request)}: failed — {message} ===", "error")
        self._release(context)

    def _release(self, context: OperationContext) -> None:
        if not self.gate.finish(context):
            return
        self.active_request = None
        self.set_operation_controls_enabled(True)
        self.resume_users()

    def _set_status(self, request: ManagementOperationRequest, status: object) -> None:
        if request.kind == "docker":
            self.tab.set_docker_status(status)  # type: ignore[arg-type]
        elif request.kind == "base-security":
            self.tab.set_base_security_status(status)  # type: ignore[arg-type]
        elif request.kind.startswith("xray"):
            self.tab.set_xray_status(status)  # type: ignore[arg-type]
        elif request.kind.startswith("hysteria2"):
            self.tab.set_hysteria2_status(status)  # type: ignore[arg-type]
        elif request.kind.startswith("mieru"):
            self.tab.set_mieru_status(status)  # type: ignore[arg-type]
        elif request.kind == "nginx":
            self.tab.set_nginx_status(status)  # type: ignore[arg-type]
        else:
            self.tab.set_netdata_status(status)  # type: ignore[arg-type]

    @staticmethod
    def _component_id(request: ManagementOperationRequest) -> str:
        if request.kind == "docker":
            return "docker"
        if request.kind == "base-security":
            return "base-security"
        if request.kind.startswith("xray"):
            return "xray"
        if request.kind.startswith("hysteria2"):
            return "hysteria2"
        if request.kind.startswith("mieru"):
            return "mieru"
        return request.kind

    @staticmethod
    def _result_title(request: ManagementOperationRequest) -> str:
        if request.kind == "docker":
            return f"Docker {request.action}"
        if request.kind == "base-security":
            return f"Base + Security {request.service} {request.action}"
        if request.kind == "xray":
            return f"Xray {request.action}"
        if request.kind == "hysteria2":
            return f"Hysteria2 {request.action}"
        if request.kind == "mieru":
            return f"Mieru {request.action}"
        if request.kind == "mieru-port-update":
            return "Mieru port"
        if request.kind == "nginx":
            return f"Nginx {request.action}"
        if request.kind == "netdata":
            return f"Netdata {request.action}"
        return (
            "Xray connection settings"
            if request.kind.startswith("xray")
            else "Hysteria2 connection settings"
        )

    @staticmethod
    def _component_name(component_id: str) -> str:
        return {
            "xray": "Xray",
            "hysteria2": "Hysteria2",
            "mieru": "Mieru",
            "nginx": "Nginx",
            "netdata": "Netdata",
        }.get(component_id, component_id)

    @staticmethod
    def _mutation_title(component_id: str) -> str:
        return (
            "Mieru port"
            if component_id == "mieru"
            else (
                f"{ManagementOperationController._component_name(component_id)} "
                "connection settings"
            )
        )

    def _refresh_options(self, request: ManagementOperationRequest) -> dict[str, bool]:
        return {
            "preserve_selection": True,
            f"preserve_{self._component_id(request).replace('-', '_')}_status": True,
        }
