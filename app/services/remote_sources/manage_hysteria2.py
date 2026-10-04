import json
import subprocess
import sys

ALLOWED_ACTIONS = __MANAGEMENT_ACTIONS__
CONFIG_PREFLIGHT_ACTIONS = {"start", "restart", "enable"}
SERVICE_STATES = {"active", "inactive", "failed", "activating", "deactivating"}
STARTUP_STATES = {"enabled", "disabled", "static", "indirect", "masked"}
CONFIG_PATH = "/etc/hysteria/config.yaml"


def run(arguments):
    try:
        return subprocess.run(arguments, capture_output=True, text=True, check=False)
    except OSError:
        return subprocess.CompletedProcess(arguments, 127, "", "")


def first_line(result):
    return result.stdout.strip().splitlines()[0] if result.stdout.strip() else ""


def service_status():
    service_state = first_line(run(["systemctl", "is-active", "hysteria-server.service"]))
    startup_state = first_line(run(["systemctl", "is-enabled", "hysteria-server.service"]))
    return {
        "service_state": service_state if service_state in SERVICE_STATES else "unknown",
        "startup_state": startup_state if startup_state in STARTUP_STATES else "unknown",
    }


def connection_details():
    try:
        with open(CONFIG_PATH, encoding="utf-8") as source:
            port, sni, _users, _obfs = hysteria2_connection_details(source.read())
    except (Hysteria2ConfigError, OSError, UnicodeError, ValueError):
        return None
    return {"protocol": "Hysteria2 · QUIC · TLS · Salamander", "port": port, "sni": sni}


action = sys.argv[1] if len(sys.argv) == 2 else ""
if action not in ALLOWED_ACTIONS:
    print(json.dumps({"error": "Unsupported Hysteria2 action."}))
    raise SystemExit(2)
details = connection_details()
if action in CONFIG_PREFLIGHT_ACTIONS and details is None:
    print(json.dumps({"error": "Hysteria2 configuration is invalid."}))
    raise SystemExit(4)
if action != "inspect":
    result = run(["systemctl", action, "--", "hysteria-server.service"])
    if result.returncode != 0:
        print(json.dumps({"error": "Hysteria2 service action failed."}))
        raise SystemExit(3)
if details is None:
    print(json.dumps({"error": "Hysteria2 configuration is invalid."}))
    raise SystemExit(3 if action != "inspect" else 4)
print(json.dumps({"service": service_status(), **details}, separators=(",", ":")))
