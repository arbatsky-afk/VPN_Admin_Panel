# Local source for one-shot remote Mieru Port updates; never copied to the server.

import copy
import json
import os
import re
import subprocess
import sys
import tempfile

RECOVERY = "/opt/vpn/recovery/mieru-secrets.json"
FRAGMENT = "/etc/nftables.d/40-mieru.nft"
FRAGMENT_DIRECTORY = Path("/etc/nftables.d")
MAIN_NFT = "/etc/nftables.conf"
BASE_FRAGMENT = "/etc/nftables.d/10-base.nft"
SERVICE = "mita.service"
SERVICE_STATES = {"active", "inactive", "failed", "activating", "deactivating"}
STARTUP_STATES = {"enabled", "disabled", "static", "indirect", "masked"}


def management_run(arguments):
    try:
        return subprocess.run(arguments, capture_output=True, text=True, check=False)
    except OSError:
        return subprocess.CompletedProcess(arguments, 127, "", "")


def require_success(arguments, message):
    result = management_run(arguments)
    if result.returncode != 0:
        raise RuntimeError(message)
    return result


def first_line(result):
    return result.stdout.strip().splitlines()[0] if result.stdout.strip() else ""


def service_status():
    service_state = first_line(management_run(["systemctl", "is-active", SERVICE]))
    startup_state = first_line(management_run(["systemctl", "is-enabled", SERVICE]))
    return {
        "service_state": service_state if service_state in SERVICE_STATES else "unknown",
        "startup_state": startup_state if startup_state in STARTUP_STATES else "unknown",
    }


def runtime_state():
    state = first_line(management_run(["mita", "status"]))
    return {
        "RUNNING": "RUNNING",
        "IDLE": "IDLE",
        'mita server status is "RUNNING"': "RUNNING",
        'mita server status is "IDLE"': "IDLE",
    }.get(state, "unknown")


def read_bytes(path):
    with open(path, "rb") as source:
        return source.read()


def write_atomic(path, contents, mode):
    descriptor, candidate = tempfile.mkstemp(
        prefix=".management-mieru-", dir=os.path.dirname(path)
    )
    try:
        with os.fdopen(descriptor, "wb") as destination:
            destination.write(contents)
            destination.flush()
            os.fsync(destination.fileno())
        os.chmod(candidate, mode)
        os.replace(candidate, path)
    finally:
        if os.path.exists(candidate):
            os.unlink(candidate)


def ssh_port():
    text = Path(BASE_FRAGMENT).read_text(encoding="utf-8")
    match = re.search(
        r"^\s*add rule inet vpn_filter input tcp dport (\d+) accept\s*$", text, re.MULTILINE
    )
    if match is None:
        raise ValueError("The Base + Security SSH rule is invalid.")
    port = int(match.group(1))
    if not 1 <= port <= 65535:
        raise ValueError("The Base + Security SSH rule is invalid.")
    return port


def described_binding():
    result = require_success(
        ["mita", "describe", "config"], "Could not describe the active Mita configuration."
    )
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
        raise ValueError("The active Mita configuration has an invalid port binding.") from error
    if type(port) is not int or not 1025 <= port <= 65535 or protocol not in MIERU_PROTOCOLS:
        raise ValueError("The active Mita configuration has an invalid port binding.")
    return port, protocol


def apply_recovery(recovery):
    recovery = validate_recovery_data(recovery)
    descriptor, candidate = tempfile.mkstemp(
        prefix=".management-mieru-config-", suffix=".json", dir="/etc/mita"
    )
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as destination:
            json.dump(server_config(recovery), destination)
            destination.flush()
            os.fsync(destination.fileno())
        require_success(["mita", "apply", "config", candidate], "Could not apply the Mita configuration.")  # fmt: skip  # noqa: E501 -- source shape is contract-tested
    finally:
        if os.path.exists(candidate):
            os.unlink(candidate)


def apply_firewall():
    require_success(
        ["nft", "-c", "-f", MAIN_NFT], "The updated firewall configuration is invalid."
    )
    require_success(["systemctl", "reload", "nftables.service"], "Could not reload nftables.")
    require_success(
        ["systemctl", "is-active", "--quiet", "nftables.service"], "nftables is not active."
    )


def reload_mita():
    require_success(["mita", "reload"], "Could not reload the Mita proxy.")
    if runtime_state() != "RUNNING":
        raise RuntimeError("Mita proxy runtime is not RUNNING after reload.")


def strict_status(recovery):
    recovery = validate_recovery_data(recovery)
    service = service_status()
    if service["service_state"] != "active":
        raise RuntimeError("Mita daemon must be active.")
    if runtime_state() != "RUNNING":
        raise RuntimeError("Mita proxy runtime must be RUNNING.")
    server = recovery["server"]
    users = recovery["users"]
    described_port, described_protocol = described_binding()
    protocol = str(server["protocol"]).lower()
    expected_port = int(server["port"])
    if described_protocol != server["protocol"]:
        raise ValueError("Mita config and recovery protocols do not match.")
    verify_port_contract(
        protocol,
        expected_port,
        described_port,
        expected_port,
        Path(FRAGMENT).read_text(encoding="utf-8"),
        collect_active_nft_ports(),
        collect_listeners(protocol),
    )
    return {
        "service": service,
        "runtime_state": "RUNNING",
        "transport": server["protocol"],
        "port": expected_port,
        "mtu": server["mtu"],
        "user_count": len(users),
    }


def require_port_available(port, current_port, protocol):
    if port == ssh_port():
        raise ValueError("The Mieru port must differ from the SSH port.")
    if port == current_port:
        return
    normalized_protocol = protocol.lower()
    if (normalized_protocol, port) in collect_listeners(normalized_protocol):
        raise ValueError("The requested Mieru port already has a listener.")
    nft_ports = collect_active_nft_ports() | collect_fragment_ports(FRAGMENT_DIRECTORY)
    if any(used_port == port for _used_protocol, used_port in nft_ports):
        raise ValueError("The requested Mieru port is already present in nftables.")
    if port in collect_docker_ports():
        raise ValueError("The requested Mieru port is published by Docker.")


def rollback(original, original_bytes, fragment_bytes):
    states = {"config": "restored", "firewall": "restored", "service": "restored"}
    messages = []
    try:
        apply_recovery(original)
        write_atomic(RECOVERY, original_bytes, 0o600)
    except (OSError, RuntimeError, ValueError, MieruConfigError) as error:
        states["config"] = "unknown"
        messages.append("Could not restore Mieru config: " + str(error))
    try:
        write_atomic(FRAGMENT, fragment_bytes, 0o644)
        apply_firewall()
    except (OSError, RuntimeError, ValueError) as error:
        states["firewall"] = "unknown"
        messages.append("Could not restore Mieru firewall: " + str(error))
    try:
        reload_mita()
        strict_status(original)
    except (OSError, RuntimeError, ValueError, MieruConfigError, PortContractError) as error:
        states["service"] = "unknown"
        messages.append("Could not verify restored Mieru runtime: " + str(error))
    if states["config"] != "restored" or states["firewall"] != "restored":
        states["service"] = "unknown"
    return states, messages


def update(port):
    original_bytes = read_bytes(RECOVERY)
    fragment_bytes = read_bytes(FRAGMENT)
    try:
        original = validate_recovery_data(json.loads(original_bytes))
    except (TypeError, ValueError, json.JSONDecodeError, MieruConfigError) as error:
        raise ValueError("Mieru recovery configuration is invalid.") from error
    strict_status(original)
    server = original["server"]
    current_port = int(server["port"])
    protocol = str(server["protocol"])
    if (
        re.fullmatch(
            r"add rule inet vpn_filter input (tcp|udp) dport \d+ accept\s*",
            fragment_bytes.decode("utf-8"),
        )
        is None
    ):
        raise ValueError("The Mieru firewall fragment is invalid.")
    require_port_available(port, current_port, protocol)
    candidate = copy.deepcopy(original)
    candidate["server"]["port"] = port
    candidate = validate_recovery_data(candidate)
    candidate_bytes = (json.dumps(candidate, indent=2) + "\n").encode("utf-8")
    candidate_fragment = (
        "add rule inet vpn_filter input " + protocol.lower() + " dport " + str(port) + " accept\n"
    ).encode("utf-8")
    try:
        apply_recovery(candidate)
        write_atomic(RECOVERY, candidate_bytes, 0o600)
        write_atomic(FRAGMENT, candidate_fragment, 0o644)
        apply_firewall()
        reload_mita()
        status = strict_status(candidate)
    except (OSError, RuntimeError, ValueError, MieruConfigError, PortContractError) as error:
        states, rollback_messages = rollback(original, original_bytes, fragment_bytes)
        if all(value == "restored" for value in states.values()):
            return {"outcome": "rolled_back", "message": str(error), "states": states}
        details = "; ".join(rollback_messages)
        message = str(error) + (" Rollback problems: " + details if details else "")
        return {"outcome": "partial", "message": message, "states": states}
    return {
        "outcome": "success",
        "message": "Mieru port was updated.",
        "states": {"config": "applied", "firewall": "applied", "service": "applied"},
        "status": status,
    }


if len(sys.argv) != 2 or not sys.argv[1].isdigit():
    print(json.dumps({"error": "Invalid Mieru port."}))
    raise SystemExit(2)
requested_port = int(sys.argv[1])
if not 1025 <= requested_port <= 65535:
    print(json.dumps({"error": "Invalid Mieru port."}))
    raise SystemExit(2)
try:
    result = update(requested_port)
except (OSError, RuntimeError, ValueError, MieruConfigError, PortContractError) as error:
    print(json.dumps({"error": str(error)}))
    raise SystemExit(3)
print(json.dumps(result, separators=(",", ":")))
