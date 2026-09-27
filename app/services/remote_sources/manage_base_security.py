import json
import re
import subprocess
import sys
from pathlib import Path

ALLOWED_ACTIONS = __MANAGEMENT_ACTIONS__
SERVICES = {"nftables": "nftables.service", "fail2ban": "fail2ban.service"}
SERVICE_STATES = {"active", "inactive", "failed", "activating", "deactivating"}
STARTUP_STATES = {"enabled", "disabled", "static", "indirect", "masked"}
PORT_OWNERS = (
    (Path("/etc/nftables.d/10-base.nft"), "SSH"),
    (Path("/etc/nftables.d/20-xray.nft"), "Xray"),
    (Path("/etc/nftables.d/30-hysteria2.nft"), "Hysteria2"),
    (Path("/etc/nftables.d/40-mieru.nft"), "Mieru"),
)
LISTENER_OWNERS = {
    "sshd": "SSH",
    "xray": "Xray",
    "hysteria": "Hysteria2",
    "hysteria-server": "Hysteria2",
    "mita": "Mieru",
    "docker-proxy": "Docker",
}


def run(arguments):
    try:
        return subprocess.run(arguments, capture_output=True, text=True, check=False)
    except OSError:
        return subprocess.CompletedProcess(arguments, 127, "", "")


def first_line(result):
    return result.stdout.strip().splitlines()[0] if result.stdout.strip() else ""


def service_status(unit):
    service_state = first_line(run(["systemctl", "is-active", "--", unit]))
    startup_state = first_line(run(["systemctl", "is-enabled", "--", unit]))
    return {
        "service_state": service_state if service_state in SERVICE_STATES else "unknown",
        "startup_state": startup_state if startup_state in STARTUP_STATES else "unknown",
    }


def active_nftables_ports():
    result = run(["nft", "-j", "list", "table", "inet", "vpn_filter"])
    if result.returncode != 0:
        return set()
    try:
        records = json.loads(result.stdout).get("nftables", [])
    except (AttributeError, json.JSONDecodeError):
        return set()
    ports = set()
    for record in records:
        rule = record.get("rule") if isinstance(record, dict) else None
        if (
            not isinstance(rule, dict)
            or rule.get("table") != "vpn_filter"
            or rule.get("chain") != "input"
        ):
            continue
        expressions = rule.get("expr")
        if not isinstance(expressions, list) or not any(
            isinstance(expr, dict) and "accept" in expr for expr in expressions
        ):
            continue
        for expression in expressions:
            match = expression.get("match") if isinstance(expression, dict) else None
            if not isinstance(match, dict):
                continue
            left = match.get("left")
            payload = left.get("payload") if isinstance(left, dict) else None
            protocol = payload.get("protocol") if isinstance(payload, dict) else None
            field = payload.get("field") if isinstance(payload, dict) else None
            port = match.get("right")
            if (
                protocol in {"tcp", "udp"}
                and field == "dport"
                and isinstance(port, int)
                and 1 <= port <= 65535
            ):
                ports.add((protocol, port))
    return ports


def configured_port_owners():
    owners = {}
    pattern = re.compile(
        r"^\\s*add rule inet vpn_filter input (tcp|udp) dport ([0-9]+) accept\\s*$", re.MULTILINE
    )
    for path, owner in PORT_OWNERS:
        try:
            contents = path.read_text(encoding="utf-8")
        except OSError:
            continue
        for protocol, port in pattern.findall(contents):
            owners[(protocol, int(port))] = owner
    return owners


def listening_port_owners():
    result = run(["ss", "-H", "-l", "-n", "-t", "-u", "-p"])
    if result.returncode != 0:
        return {}
    owners = {}
    process_pattern = re.compile(r'users:\(\("([^"\\]+)"')
    for line in result.stdout.splitlines():
        fields = line.split()
        if not fields or fields[0] not in {"tcp", "udp"}:
            continue
        process_match = process_pattern.search(line)
        owner = LISTENER_OWNERS.get(process_match.group(1)) if process_match else None
        if owner is None:
            continue
        for field in fields[1:]:
            separator = field.rfind(":")
            port = field[separator + 1 :] if separator >= 0 else ""
            if port.isdigit() and 1 <= int(port) <= 65535:
                owners[(fields[0], int(port))] = owner
                break
    return owners


def docker_amnezia_ports():
    result = run(
        [
            "docker",
            "container",
            "inspect",
            "--format",
            "{{json .NetworkSettings.Ports}}",
            "amnezia-awg2",
        ]
    )
    if result.returncode != 0:
        return set()
    try:
        bindings = json.loads(first_line(result))
    except json.JSONDecodeError:
        return set()
    if not isinstance(bindings, dict):
        return set()
    ports = set()
    for container_port, entries in bindings.items():
        if (
            not isinstance(container_port, str)
            or not container_port.endswith("/udp")
            or not isinstance(entries, list)
        ):
            continue
        for entry in entries:
            host_port = entry.get("HostPort") if isinstance(entry, dict) else None
            if isinstance(host_port, str) and host_port.isdigit() and 1 <= int(host_port) <= 65535:
                ports.add(("udp", int(host_port)))
    return ports


def allowed_ports():
    active_ports = active_nftables_ports()
    configured_owners = configured_port_owners()
    listening_owners = listening_port_owners()
    rendered = [
        {
            "protocol": protocol,
            "port": port,
            "owner": listening_owners.get((protocol, port))
            or configured_owners.get((protocol, port)),
            "source": "nftables",
        }
        for protocol, port in active_ports
    ]
    rendered.extend(
        {"protocol": protocol, "port": port, "owner": "Docker / AmneziaWG", "source": "docker"}
        for protocol, port in docker_amnezia_ports()
    )
    return sorted(
        rendered, key=lambda item: (item["port"], item["protocol"], item["source"], item["owner"])
    )


action = sys.argv[1] if len(sys.argv) == 3 else ""
service = sys.argv[2] if len(sys.argv) == 3 else ""
if action not in ALLOWED_ACTIONS or service not in SERVICES:
    print(json.dumps({"error": "Unsupported Base + Security action."}))
    raise SystemExit(2)
if action != "inspect":
    result = run(["systemctl", action, "--", SERVICES[service]])
    if result.returncode != 0:
        print(json.dumps({"error": "Base + Security service action failed."}))
        raise SystemExit(3)
print(
    json.dumps(
        {
            "nftables": service_status(SERVICES["nftables"]),
            "fail2ban": service_status(SERVICES["fail2ban"]),
            "allowed_ports": allowed_ports(),
        },
        separators=(",", ":"),
    )
)
