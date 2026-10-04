# Local source for one-shot remote Hysteria2 connection updates; never copied to the server.

import ipaddress
import json
import os
import re
import subprocess
import sys
import tempfile

try:
    validate_hysteria2_config_text
except NameError:
    _validator_path = os.path.abspath(
        os.path.join(
            os.path.dirname(__file__),
            "..",
            "..",
            "..",
            "scripts",
            "ubuntu",
            "modular-deployment",
            "lib",
            "hysteria2_config.py",
        )
    )
    _validator_namespace = {"__name__": "hysteria2_config"}
    with open(_validator_path, encoding="utf-8") as _validator_source:
        exec(compile(_validator_source.read(), _validator_path, "exec"), _validator_namespace)
    hysteria2_connection_details = _validator_namespace["hysteria2_connection_details"]
    validate_hysteria2_config_text = _validator_namespace["validate_hysteria2_config_text"]

CONFIG = "/etc/hysteria/config.yaml"
FRAGMENT = "/etc/nftables.d/30-hysteria2.nft"
SECRETS = "/opt/vpn/recovery/hysteria2-secrets.env"
MAIN_NFT = "/etc/nftables.conf"
SERVICE = "hysteria-server.service"
SERVICE_STATES = {"active", "inactive", "failed", "activating", "deactivating"}
STARTUP_STATES = {"enabled", "disabled", "static", "indirect", "masked"}
HOSTNAME = re.compile(
    r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(?:\.(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?))*$"
)


def run(arguments):
    try:
        return subprocess.run(arguments, capture_output=True, text=True, check=False)
    except OSError:
        return subprocess.CompletedProcess(arguments, 127, "", "")


def is_fqdn(value):
    if not isinstance(value, str) or "." not in value or not HOSTNAME.fullmatch(value):
        return False
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return True
    return False


def require_success(arguments, message):
    if run(arguments).returncode != 0:
        raise RuntimeError(message)


def first_line(result):
    return result.stdout.strip().splitlines()[0] if result.stdout.strip() else ""


def service_status():
    service_state = first_line(run(["systemctl", "is-active", SERVICE]))
    startup_state = first_line(run(["systemctl", "is-enabled", SERVICE]))
    return {
        "service_state": service_state if service_state in SERVICE_STATES else "unknown",
        "startup_state": startup_state if startup_state in STARTUP_STATES else "unknown",
    }


def connection_details(config):
    port, host, _users, _obfs = hysteria2_connection_details(config)
    if not 1 <= port <= 65535 or not is_fqdn(host):
        raise ValueError("Hysteria2 configuration is invalid.")
    return port, host


def read(path):
    with open(path, "rb") as source:
        return source.read()


def write_atomic(path, contents, mode):
    descriptor, candidate = tempfile.mkstemp(prefix=".management-", dir=os.path.dirname(path))
    try:
        with os.fdopen(descriptor, "wb") as destination:
            destination.write(contents)
        os.chmod(candidate, mode)
        os.replace(candidate, path)
    finally:
        if os.path.exists(candidate):
            os.unlink(candidate)


def write_hysteria_config(contents):
    write_atomic(CONFIG, contents, 0o640)
    require_success(
        ["chown", "hysteria:hysteria", CONFIG], "Could not set Hysteria2 configuration ownership."
    )


def port_is_available(port, current_port):
    result = run(["ss", "-H", "-l", "-n", "-u", "-p"])
    if result.returncode != 0:
        raise RuntimeError("Could not inspect UDP listeners.")
    pattern = re.compile(r"(?:\[[^\]]+\]|[^\s]+):" + str(port) + r"(?:\s|$)")
    for line in result.stdout.splitlines():
        if not pattern.search(line):
            continue
        if port == current_port and 'users:(("hysteria"' in line:
            continue
        raise ValueError("The requested UDP port is already in use.")


def update_secrets(text, port, host):
    for name, value in {
        "DEPLOYED_HYSTERIA_PORT": str(port),
        "DEPLOYED_HYSTERIA_MASQUERADE_HOST": host,
    }.items():
        pattern = re.compile(r"^" + name + r"='[^\n]*'$", re.MULTILINE)
        if len(pattern.findall(text)) != 1:
            raise ValueError("Hysteria2 recovery metadata is invalid.")
        text = pattern.sub(name + "='" + value + "'", text)
    return text.encode("utf-8")


def apply_firewall():
    require_success(
        ["nft", "-c", "-f", MAIN_NFT], "The updated firewall configuration is invalid."
    )
    if run(["systemctl", "is-active", "--quiet", "nftables.service"]).returncode == 0:
        require_success(["systemctl", "reload", "nftables.service"], "Could not reload nftables.")
    else:
        require_success(["systemctl", "start", "nftables.service"], "Could not start nftables.")


def rollback(previous):
    states = {"config": "restored", "firewall": "restored", "service": "restored"}
    messages = []
    for path, contents, mode in previous:
        try:
            if path == CONFIG:
                write_hysteria_config(contents)
            else:
                write_atomic(path, contents, mode)
        except (OSError, RuntimeError) as error:
            states["firewall" if path == FRAGMENT else "config"] = "unknown"
            messages.append("Could not restore " + path + ": " + str(error))
    try:
        apply_firewall()
    except (OSError, RuntimeError) as error:
        states["firewall"] = "unknown"
        messages.append("Could not restore the firewall: " + str(error))
    try:
        require_success(
            ["systemctl", "restart", SERVICE], "Could not restart Hysteria2 after rollback."
        )
        require_success(
            ["systemctl", "is-active", "--quiet", SERVICE],
            "Hysteria2 is not active after rollback.",
        )
    except (OSError, RuntimeError) as error:
        states["service"] = "unknown"
        messages.append(str(error))
    if states["config"] != "restored":
        states["service"] = "unknown"
    return states, messages


def update(port, host):
    config_bytes, fragment_bytes, secrets_bytes = read(CONFIG), read(FRAGMENT), read(SECRETS)
    config = config_bytes.decode("utf-8")
    current_port, _current_host = connection_details(config)
    if (
        re.fullmatch(
            r"add rule inet vpn_filter input udp dport \d+ accept\s*",
            fragment_bytes.decode("utf-8"),
        )
        is None
    ):
        raise ValueError("The Hysteria2 firewall fragment is invalid.")
    port_is_available(port, current_port)
    candidate_config = re.sub(
        r"^listen:\s*:\d+\s*$", "listen: :" + str(port), config, count=1, flags=re.MULTILINE
    )
    candidate_config = re.sub(
        r"^\s{4}url:\s*https://[^/\s]+/\s*$",
        "    url: https://" + host + "/",
        candidate_config,
        count=1,
        flags=re.MULTILINE,
    )
    validate_hysteria2_config_text(candidate_config)
    connection_details(candidate_config)
    candidate_fragment = (
        "add rule inet vpn_filter input udp dport " + str(port) + " accept\n"
    ).encode("utf-8")
    candidate_secrets = update_secrets(secrets_bytes.decode("utf-8"), port, host)
    previous = (
        (CONFIG, config_bytes, 0o640),
        (FRAGMENT, fragment_bytes, 0o644),
        (SECRETS, secrets_bytes, 0o600),
    )
    try:
        write_hysteria_config(candidate_config.encode("utf-8"))
        write_atomic(FRAGMENT, candidate_fragment, 0o644)
        write_atomic(SECRETS, candidate_secrets, 0o600)
        apply_firewall()
        require_success(["systemctl", "restart", SERVICE], "Could not restart Hysteria2.")
        require_success(
            ["systemctl", "is-active", "--quiet", SERVICE], "Hysteria2 did not become active."
        )
    except (OSError, RuntimeError) as error:
        states, rollback_messages = rollback(previous)
        if all(value == "restored" for value in states.values()):
            return {"outcome": "rolled_back", "message": str(error), "states": states}
        details = "; ".join(rollback_messages)
        message = str(error) + (" Rollback problems: " + details if details else "")
        return {"outcome": "partial", "message": message, "states": states}
    return {
        "outcome": "success",
        "message": "Hysteria2 connection settings were updated.",
        "states": {"config": "applied", "firewall": "applied", "service": "applied"},
        "status": {
            "service": service_status(),
            "protocol": "Hysteria2 · QUIC · TLS · Salamander",
            "port": port,
            "sni": host,
        },
    }


if len(sys.argv) != 3 or not sys.argv[1].isdigit() or not is_fqdn(sys.argv[2]):
    print(json.dumps({"error": "Invalid Hysteria2 connection settings."}))
    raise SystemExit(2)
port = int(sys.argv[1])
if not 1 <= port <= 65535:
    print(json.dumps({"error": "Invalid Hysteria2 connection settings."}))
    raise SystemExit(2)
try:
    result = update(port, sys.argv[2])
except (OSError, RuntimeError, ValueError) as error:
    print(json.dumps({"error": str(error)}))
    raise SystemExit(3)
print(json.dumps(result, separators=(",", ":")))
