import ipaddress
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ALLOWED_ACTIONS = __MANAGEMENT_ACTIONS__
CONFIG_PREFLIGHT_ACTIONS = {"start", "restart", "enable"}
SERVICE_STATES = {"active", "inactive", "failed", "activating", "deactivating"}
STARTUP_STATES = {"enabled", "disabled", "static", "indirect", "masked"}
UNIT = "nginx.service"
VHOST = "/etc/nginx/conf.d/vpn-admin-site.conf"
CERTIFICATE = "/etc/nginx/vpn-admin-tls/server.crt"
CONTRACT = "/usr/local/lib/vpn-admin/nginx_contract.py"
LEGACY_EXPECTED_VHOST = """server {
    listen 80 default_server;
    listen 443 ssl default_server;
    server_name _;

    root /var/www/vpn-admin-site;
    index index.html;
    autoindex off;
    server_tokens off;
    add_header X-VPN-Admin-Component "nginx/1" always;

    ssl_certificate /etc/nginx/vpn-admin-tls/server.crt;
    ssl_certificate_key /etc/nginx/vpn-admin-tls/server.key;
    ssl_protocols TLSv1.2 TLSv1.3;

    location / {
        try_files $uri $uri/ =404;
    }

    include /etc/nginx/vpn-admin-locations/*.conf;
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


def owned_vhost_state():
    verified = run(["python3", CONTRACT, "verify-owned"])
    if verified.returncode == 0:
        inspected = run(["python3", CONTRACT, "inspect"])
        if inspected.returncode != 0:
            return None
        try:
            state = json.loads(inspected.stdout)
        except (TypeError, ValueError):
            return None
        if set(state) != {"tls_mode", "server_name", "server_address"}:
            return None
        if state["tls_mode"] not in {"self_signed", "letsencrypt"}:
            return None
        if not all(isinstance(state[field], str) for field in state):
            return None
        try:
            if str(ipaddress.IPv4Address(state["server_address"])) != state["server_address"]:
                return None
        except ipaddress.AddressValueError:
            return None
        if run(["nginx", "-t"]).returncode != 0:
            return None
        return state
    try:
        if Path(VHOST).read_text(encoding="utf-8") != LEGACY_EXPECTED_VHOST:
            return None
    except (OSError, UnicodeError):
        return None
    if run(["nginx", "-t"]).returncode != 0:
        return None
    return {"tls_mode": "self_signed", "server_name": "default", "server_address": ""}


def endpoint_healthy(url, insecure=False, resolve=None):
    arguments = ["curl", "--fail", "--silent", "--show-error"]
    if insecure:
        arguments.append("--insecure")
    if resolve:
        arguments.extend(["--resolve", resolve])
    arguments.extend(["--output", "/dev/null", "--max-time", "5", url])
    return run(arguments).returncode == 0


def certificate_expiry():
    result = run(["openssl", "x509", "-in", CERTIFICATE, "-noout", "-enddate"])
    if result.returncode != 0 or not result.stdout.startswith("notAfter="):
        return None
    try:
        value = datetime.strptime(result.stdout.strip()[9:], "%b %d %H:%M:%S %Y GMT")
    except ValueError:
        return None
    return value.replace(tzinfo=timezone.utc).isoformat().replace("+00:00", "Z")


action = sys.argv[1] if len(sys.argv) == 2 else ""
if action not in ALLOWED_ACTIONS:
    print(json.dumps({"error": "Unsupported Nginx action."}))
    raise SystemExit(2)
tls_state = owned_vhost_state()
if action in CONFIG_PREFLIGHT_ACTIONS and tls_state is None:
    print(json.dumps({"error": "Nginx owned site configuration is invalid."}))
    raise SystemExit(4)
if action != "inspect":
    result = run(["systemctl", action, "--", UNIT])
    if result.returncode != 0:
        print(json.dumps({"error": "Nginx service action failed."}))
        raise SystemExit(3)
if tls_state is None:
    print(json.dumps({"error": "Nginx owned site configuration is invalid."}))
    raise SystemExit(3 if action != "inspect" else 4)
trusted = tls_state["tls_mode"] == "letsencrypt"
https_url = "https://" + tls_state["server_name"] + "/" if trusted else "https://127.0.0.1/"
print(
    json.dumps(
        {
            "service": service_status(),
            "http_port": 80,
            "https_port": 443,
            "server_name": tls_state["server_name"],
            "tls_mode": tls_state["tls_mode"],
            "certificate_expires_at": certificate_expiry(),
            "http_healthy": endpoint_healthy("http://127.0.0.1/"),
            "https_healthy": endpoint_healthy(
                https_url,
                insecure=not trusted,
                resolve=(tls_state["server_name"] + ":443:127.0.0.1") if trusted else None,
            ),
        },
        separators=(",", ":"),
    )
)
