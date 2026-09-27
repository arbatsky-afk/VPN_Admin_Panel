# Local source for one-shot remote Xray connection updates; never copied to the server.

import ipaddress
import json
import os
import re
import subprocess
import sys
import tempfile

CONFIG = "/usr/local/etc/xray/config.json"
FRAGMENT = "/etc/nftables.d/20-xray.nft"
SECRETS = "/opt/vpn/recovery/xray-secrets.env"
MAIN_NFT = "/etc/nftables.conf"
BASE_FRAGMENT = "/etc/nftables.d/10-base.nft"
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
    result = run(arguments)
    if result.returncode != 0:
        raise RuntimeError(message)


def first_line(result):
    return result.stdout.strip().splitlines()[0] if result.stdout.strip() else ""


def service_status():
    service_state = first_line(run(["systemctl", "is-active", "xray.service"]))
    startup_state = first_line(run(["systemctl", "is-enabled", "xray.service"]))
    return {
        "service_state": service_state if service_state in SERVICE_STATES else "unknown",
        "startup_state": startup_state if startup_state in STARTUP_STATES else "unknown",
    }


def connection_details(config):
    inbound = config["inbounds"][0]
    stream = inbound["streamSettings"]
    reality = stream["realitySettings"]
    flow = inbound["settings"]["clients"][0].get("flow", "")
    sni = reality["serverNames"][0]
    port = inbound["port"]
    if (
        inbound.get("protocol") != "vless"
        or stream.get("network") != "tcp"
        or stream.get("security") != "reality"
        or flow != "xtls-rprx-vision"
        or isinstance(port, bool)
        or not isinstance(port, int)
        or not 1 <= port <= 65535
        or not is_fqdn(sni)
    ):
        raise ValueError("Xray configuration is invalid.")
    return inbound, reality, port, sni


def read(path):
    with open(path, "rb") as source:
        return source.read()


def write_atomic(path, contents, mode):
    directory = os.path.dirname(path)
    descriptor, candidate = tempfile.mkstemp(prefix=".management-", dir=directory)
    try:
        with os.fdopen(descriptor, "wb") as destination:
            destination.write(contents)
        os.chmod(candidate, mode)
        os.replace(candidate, path)
    finally:
        if os.path.exists(candidate):
            os.unlink(candidate)


def ssh_port():
    match = re.search(
        r"^\s*add rule inet vpn_filter input tcp dport (\d+) accept\s*$",
        open(BASE_FRAGMENT, encoding="utf-8").read(),
        re.MULTILINE,
    )
    if match is None:
        raise ValueError("The Base + Security SSH rule is invalid.")
    return int(match.group(1))


def port_is_available(port, current_port):
    result = run(["ss", "-H", "-l", "-n", "-t", "-p"])
    if result.returncode != 0:
        raise RuntimeError("Could not inspect TCP listeners.")
    pattern = re.compile(r"(?:\[[^\]]+\]|[^\s]+):" + str(port) + r"(?:\s|$)")
    for line in result.stdout.splitlines():
        if not pattern.search(line):
            continue
        if port == current_port and 'users:(("xray"' in line:
            continue
        raise ValueError("The requested TCP port is already in use.")


def update_secrets(text, port, host):
    replacements = {"DEPLOYED_XRAY_PORT": str(port), "DEPLOYED_MASQUERADE_HOST": host}
    for name, value in replacements.items():
        pattern = re.compile(r"^" + name + r"='[^\n]*'$", re.MULTILINE)
        if len(pattern.findall(text)) != 1:
            raise ValueError("Xray recovery metadata is invalid.")
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
            write_atomic(path, contents, mode)
        except OSError as error:
            states["firewall" if path == FRAGMENT else "config"] = "unknown"
            messages.append("Could not restore " + path + ": " + str(error))
    try:
        apply_firewall()
    except (OSError, RuntimeError) as error:
        states["firewall"] = "unknown"
        messages.append("Could not restore the firewall: " + str(error))
    try:
        require_success(
            ["systemctl", "restart", "xray.service"], "Could not restart Xray after rollback."
        )
        require_success(
            ["systemctl", "is-active", "--quiet", "xray.service"],
            "Xray is not active after rollback.",
        )
    except (OSError, RuntimeError) as error:
        states["service"] = "unknown"
        messages.append(str(error))
    if states["config"] != "restored":
        states["service"] = "unknown"
    return states, messages


def update(port, host):
    if port == ssh_port():
        raise ValueError("The Xray TCP port must differ from the SSH port.")
    config_bytes, fragment_bytes, secrets_bytes = read(CONFIG), read(FRAGMENT), read(SECRETS)
    try:
        config = json.loads(config_bytes)
        inbound, reality, current_port, _current_host = connection_details(config)
    except (AttributeError, IndexError, KeyError, TypeError, ValueError, json.JSONDecodeError):
        raise ValueError("Xray configuration is invalid.")
    if (
        re.fullmatch(
            r"add rule inet vpn_filter input tcp dport \d+ accept\s*",
            fragment_bytes.decode("utf-8"),
        )
        is None
    ):
        raise ValueError("The Xray firewall fragment is invalid.")
    port_is_available(port, current_port)
    inbound["port"] = port
    reality["serverNames"] = [host]
    reality["dest"] = host + ":443"
    candidate_config = json.dumps(config, indent=2, ensure_ascii=False).encode("utf-8") + b"\n"
    descriptor, candidate_path = tempfile.mkstemp(
        prefix=".management-xray-", suffix=".json", dir=os.path.dirname(CONFIG)
    )
    try:
        with os.fdopen(descriptor, "wb") as candidate:
            candidate.write(candidate_config)
        require_success(
            ["xray", "run", "-test", "-config", candidate_path],
            "The updated Xray configuration is invalid.",
        )
    finally:
        if os.path.exists(candidate_path):
            os.unlink(candidate_path)
    candidate_fragment = (
        "add rule inet vpn_filter input tcp dport " + str(port) + " accept\n"
    ).encode("utf-8")
    candidate_secrets = update_secrets(secrets_bytes.decode("utf-8"), port, host)
    previous = (
        (CONFIG, config_bytes, 0o600),
        (FRAGMENT, fragment_bytes, 0o644),
        (SECRETS, secrets_bytes, 0o600),
    )
    try:
        write_atomic(CONFIG, candidate_config, 0o600)
        write_atomic(FRAGMENT, candidate_fragment, 0o644)
        write_atomic(SECRETS, candidate_secrets, 0o600)
        apply_firewall()
        require_success(["systemctl", "restart", "xray.service"], "Could not restart Xray.")
        require_success(
            ["systemctl", "is-active", "--quiet", "xray.service"], "Xray did not become active."
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
        "message": "Xray connection settings were updated.",
        "states": {"config": "applied", "firewall": "applied", "service": "applied"},
        "status": {
            "service": service_status(),
            "protocol": "VLESS · TCP · Reality · Vision",
            "port": port,
            "sni": host,
        },
    }


if len(sys.argv) != 3 or not sys.argv[1].isdigit() or not is_fqdn(sys.argv[2]):
    print(json.dumps({"error": "Invalid Xray connection settings."}))
    raise SystemExit(2)
port = int(sys.argv[1])
if not 1 <= port <= 65535:
    print(json.dumps({"error": "Invalid Xray connection settings."}))
    raise SystemExit(2)
try:
    result = update(port, sys.argv[2])
except (OSError, RuntimeError, ValueError) as error:
    print(json.dumps({"error": str(error)}))
    raise SystemExit(3)
print(json.dumps(result, separators=(",", ":")))
