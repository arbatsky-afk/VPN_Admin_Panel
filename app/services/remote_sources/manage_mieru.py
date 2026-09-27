import subprocess

CONFIG_PREFLIGHT_ACTIONS = {"start", "restart", "enable"}
SERVICE_STATES = {"active", "inactive", "failed", "activating", "deactivating"}
STARTUP_STATES = {"enabled", "disabled", "static", "indirect", "masked"}
RECOVERY_PATH = Path("/opt/vpn/recovery/mieru-secrets.json")
FRAGMENT_PATH = Path("/etc/nftables.d/40-mieru.nft")


def management_run(arguments):
    try:
        return subprocess.run(arguments, capture_output=True, text=True, check=False)
    except OSError:
        return subprocess.CompletedProcess(arguments, 127, "", "")


def management_first_line(result):
    return result.stdout.strip().splitlines()[0] if result.stdout.strip() else ""


def management_service_status():
    service_state = management_first_line(
        management_run(["systemctl", "is-active", "mita.service"])
    )
    startup_state = management_first_line(
        management_run(["systemctl", "is-enabled", "mita.service"])
    )
    return {
        "service_state": service_state if service_state in SERVICE_STATES else "unknown",
        "startup_state": startup_state if startup_state in STARTUP_STATES else "unknown",
    }


def management_runtime_state():
    state = management_first_line(management_run(["mita", "status"]))
    return {
        "RUNNING": "RUNNING",
        "IDLE": "IDLE",
        'mita server status is "RUNNING"': "RUNNING",
        'mita server status is "IDLE"': "IDLE",
    }.get(state, "unknown")


def management_described_binding():
    result = management_run(["mita", "describe", "config"])
    if result.returncode != 0:
        raise RuntimeError("Could not describe the active Mita configuration.")
    try:
        data = json.loads(result.stdout)
        bindings = data["portBindings"]
        if (
            not isinstance(bindings, list)
            or len(bindings) != 1
            or not isinstance(bindings[0], dict)
        ):
            raise ValueError
        port = bindings[0].get("port")
        protocol = bindings[0].get("protocol")
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
        raise RuntimeError("The active Mita configuration has an invalid port binding.") from error
    if type(port) is not int or not 1025 <= port <= 65535 or protocol not in MIERU_PROTOCOLS:
        raise RuntimeError("The active Mita configuration has an invalid port binding.")
    return port, protocol


def management_verify_active_port(recovery):
    server = recovery["server"]
    described_port, described_protocol = management_described_binding()
    if described_protocol != server["protocol"]:
        raise RuntimeError("Mita config and recovery protocols do not match.")
    protocol = str(server["protocol"]).lower()
    verify_port_contract(
        protocol,
        int(server["port"]),
        described_port,
        int(server["port"]),
        FRAGMENT_PATH.read_text(encoding="utf-8"),
        collect_active_nft_ports(),
        collect_listeners(protocol),
    )


action = sys.argv[1] if len(sys.argv) == 2 else ""
if action not in ALLOWED_MIERU_ACTIONS:
    print(json.dumps({"error": "Unsupported Mieru action."}))
    raise SystemExit(2)
recovery = None
try:
    recovery = load_recovery(RECOVERY_PATH)
except (MieruConfigError, OSError):
    pass
if action in CONFIG_PREFLIGHT_ACTIONS and recovery is None:
    print(json.dumps({"error": "Mieru recovery configuration is invalid."}))
    raise SystemExit(4)
if action != "inspect":
    action_result = management_run(["systemctl", action, "--", "mita.service"])
    if action_result.returncode != 0:
        print(json.dumps({"error": "Mieru service action failed."}))
        raise SystemExit(3)
if recovery is None:
    print(json.dumps({"error": "Mieru recovery configuration is invalid."}))
    raise SystemExit(3 if action != "inspect" else 4)
server = recovery["server"]
users = recovery["users"]
service = management_service_status()
runtime = management_runtime_state()
if service["service_state"] == "active" and runtime == "RUNNING":
    try:
        management_verify_active_port(recovery)
    except (OSError, RuntimeError, ValueError, PortContractError):
        print(
            json.dumps({"error": "Mieru config, recovery, firewall, and listener do not agree."})
        )
        raise SystemExit(3 if action != "inspect" else 5)
print(
    json.dumps(
        {
            "service": service,
            "runtime_state": runtime,
            "transport": server["protocol"],
            "port": server["port"],
            "mtu": server["mtu"],
            "user_count": len(users),
        },
        separators=(",", ":"),
    )
)
