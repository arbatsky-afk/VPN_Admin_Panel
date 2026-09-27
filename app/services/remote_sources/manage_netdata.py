import json
import subprocess
import sys
import time
from pathlib import Path

ALLOWED_ACTIONS = __MANAGEMENT_ACTIONS__
CONFIG_PREFLIGHT_ACTIONS = {"start", "restart", "enable"}
SERVICE_STATES = {"active", "inactive", "failed", "activating", "deactivating"}
STARTUP_STATES = {"enabled", "disabled", "static", "indirect", "masked"}
UNIT = "netdata.service"
CONFIG = "/etc/netdata/netdata.conf"
LOCATION = "/etc/nginx/vpn-admin-locations/netdata.conf"
AUTH_FILE = "/etc/nginx/vpn-admin-auth/netdata.htpasswd"
CLAIM_FILE = "/etc/netdata/claim.conf"
EXPECTED_CONFIG = """[web]
    default port = 19999
    bind to = 127.0.0.1=dashboard
    bearer token protection = yes
"""
EXPECTED_LOCATION = """location = /netdata {
    if ($scheme != https) { return 404; }
    return 308 /netdata/;
}

location /netdata/ {
    if ($scheme != https) { return 404; }

    proxy_redirect off;
    proxy_http_version 1.1;
    proxy_pass_request_headers on;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-Host $host;
    proxy_set_header X-Forwarded-Server $host;
    proxy_set_header X-Forwarded-Proto https;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Netdata-Auth $http_x_netdata_auth;
    proxy_set_header Authorization $http_authorization;
    proxy_set_header Connection "keep-alive";
    proxy_store off;
    proxy_pass http://127.0.0.1:19999/;
}
"""


def run(arguments):
    try:
        return subprocess.run(arguments, capture_output=True, text=True, check=False, timeout=15)
    except (OSError, subprocess.TimeoutExpired):
        return subprocess.CompletedProcess(arguments, 127, "", "")


def first_line(result):
    return result.stdout.strip().splitlines()[0] if result.stdout.strip() else ""


def service_status():
    service_state = first_line(run(["systemctl", "is-active", "--", UNIT]))
    startup_state = first_line(run(["systemctl", "is-enabled", "--", UNIT]))
    return {
        "service_state": service_state if service_state in SERVICE_STATES else "unknown",
        "startup_state": startup_state if startup_state in STARTUP_STATES else "unknown",
    }


def owned_config_valid():
    try:
        config_valid = Path(CONFIG).read_text(encoding="utf-8") == EXPECTED_CONFIG
        location_valid = Path(LOCATION).read_text(encoding="utf-8") == EXPECTED_LOCATION
        auth_path = Path(AUTH_FILE)
        claim_path = Path(CLAIM_FILE)
    except (OSError, UnicodeError):
        return False
    return (
        config_valid
        and location_valid
        and not auth_path.exists()
        and not auth_path.is_symlink()
        and not claim_path.exists()
        and not claim_path.is_symlink()
        and run(["nginx", "-t"]).returncode == 0
    )


def agent_info(wait_for_ready=False):
    attempts = 30 if wait_for_ready else 1
    for attempt in range(attempts):
        result = run(
            [
                "curl",
                "--fail",
                "--silent",
                "--show-error",
                "--max-time",
                "2",
                "http://127.0.0.1:19999/api/v3/info",
            ]
        )
        if result.returncode == 0:
            try:
                payload = json.loads(result.stdout)
            except json.JSONDecodeError:
                payload = None
            if isinstance(payload, dict):
                return payload
        if attempt + 1 < attempts:
            time.sleep(1)
    return None


def cloud_online(wait_for_ready=False):
    attempts = 30 if wait_for_ready else 1
    for attempt in range(attempts):
        result = run(["netdatacli", "aclk-state"])
        lines = result.stdout.splitlines()
        if (
            result.returncode == 0
            and lines.count("Claimed: Yes") == 1
            and lines.count("Online: Yes") == 1
        ):
            return True
        if attempt + 1 < attempts:
            time.sleep(1)
    return False


def proxy_bearer_protected():
    result = run(
        [
            "curl",
            "--silent",
            "--show-error",
            "--insecure",
            "--output",
            "/dev/null",
            "--write-out",
            "%{http_code}",
            "--max-time",
            "5",
            "https://127.0.0.1/netdata/api/v3/nodes",
        ]
    )
    return result.returncode == 0 and result.stdout == "412"


action = sys.argv[1] if len(sys.argv) == 2 else ""
if action not in ALLOWED_ACTIONS:
    print(json.dumps({"error": "Unsupported Netdata action."}))
    raise SystemExit(2)
config_valid = owned_config_valid()
if action in CONFIG_PREFLIGHT_ACTIONS and not config_valid:
    print(json.dumps({"error": "Netdata managed configuration is invalid."}))
    raise SystemExit(4)
if action != "inspect":
    result = run(["systemctl", action, "--", UNIT])
    if result.returncode != 0:
        print(json.dumps({"error": "Netdata service action failed."}))
        raise SystemExit(3)
if not config_valid:
    print(json.dumps({"error": "Netdata managed configuration is invalid."}))
    raise SystemExit(3 if action != "inspect" else 4)
info = agent_info(action in {"start", "restart"})
print(
    json.dumps(
        {
            "service": service_status(),
            "listen_port": 19999,
            "bind_mode": "localhost",
            "dashboard_healthy": info is not None,
            "cloud_online": cloud_online(action in {"start", "restart"}),
            "proxy_bearer_protected": proxy_bearer_protected(),
        },
        separators=(",", ":"),
    )
)
