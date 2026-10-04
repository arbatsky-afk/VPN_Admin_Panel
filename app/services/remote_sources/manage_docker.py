import json
import subprocess
import sys

ALLOWED_ACTIONS = __MANAGEMENT_ACTIONS__
SERVICE_STATES = {"active", "inactive", "failed", "activating", "deactivating"}
STARTUP_STATES = {"enabled", "disabled", "static", "indirect", "masked"}


def run(arguments):
    try:
        return subprocess.run(arguments, capture_output=True, text=True, check=False)
    except OSError:
        return subprocess.CompletedProcess(arguments, 127, "", "")


def first_line(result):
    return result.stdout.strip().splitlines()[0] if result.stdout.strip() else ""


def service_state():
    state = first_line(run(["systemctl", "is-active", "docker.service"]))
    return state if state in SERVICE_STATES else "unknown"


def startup_state():
    state = first_line(run(["systemctl", "is-enabled", "docker.service"]))
    return state if state in STARTUP_STATES else "unknown"


def amnezia_status(current_service_state):
    if current_service_state != "active":
        return {"state": "unknown", "container_state": None, "udp_ports": []}
    state_result = run(
        [
            "docker",
            "container",
            "inspect",
            "--format",
            "{{json .State.Status}}",
            "amnezia-awg2",
        ]
    )
    if state_result.returncode != 0:
        return {"state": "not_detected", "container_state": None, "udp_ports": []}
    try:
        container_state = json.loads(first_line(state_result))
    except json.JSONDecodeError:
        return {"state": "unknown", "container_state": None, "udp_ports": []}
    if not isinstance(container_state, str):
        return {"state": "unknown", "container_state": None, "udp_ports": []}
    ports_result = run(
        [
            "docker",
            "container",
            "inspect",
            "--format",
            "{{json .NetworkSettings.Ports}}",
            "amnezia-awg2",
        ]
    )
    try:
        port_bindings = json.loads(first_line(ports_result))
    except json.JSONDecodeError:
        return {"state": "unknown", "container_state": None, "udp_ports": []}
    if not isinstance(port_bindings, dict):
        return {"state": "unknown", "container_state": None, "udp_ports": []}
    udp_ports = []
    for container_port, bindings in port_bindings.items():
        if (
            not isinstance(container_port, str)
            or not container_port.endswith("/udp")
            or not isinstance(bindings, list)
        ):
            continue
        for binding in bindings:
            if not isinstance(binding, dict):
                continue
            host_address = binding.get("HostIp")
            host_port = binding.get("HostPort")
            if (
                isinstance(host_address, str)
                and isinstance(host_port, str)
                and host_port.isdigit()
            ):
                udp_ports.append({"host_address": host_address, "port": int(host_port)})
    return {"state": "detected", "container_state": container_state, "udp_ports": udp_ports}


action = sys.argv[1] if len(sys.argv) == 2 else ""
if action not in ALLOWED_ACTIONS:
    print(json.dumps({"error": "Unsupported Docker action."}))
    raise SystemExit(2)
if action != "inspect":
    result = run(["systemctl", action, "--", "docker.service"])
    if result.returncode != 0:
        print(json.dumps({"error": "Docker service action failed."}))
        raise SystemExit(3)
current_service_state = service_state()
print(
    json.dumps(
        {
            "service_state": current_service_state,
            "startup_state": startup_state(),
            "amnezia": amnezia_status(current_service_state),
        },
        separators=(",", ":"),
    )
)
