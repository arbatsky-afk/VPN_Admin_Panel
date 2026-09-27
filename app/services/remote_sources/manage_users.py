#!/usr/bin/env python3
# Local source for one-shot remote Users operations; never copied to the server.

import grp
import json
import os
import pwd
import re
import secrets
import shutil
import stat
import subprocess
import tempfile
import time
from pathlib import Path

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

try:
    validate_recovery_data
except NameError:
    _mieru_validator_path = os.path.abspath(
        os.path.join(
            os.path.dirname(__file__),
            "..",
            "..",
            "..",
            "scripts",
            "ubuntu",
            "modular-deployment",
            "lib",
            "mieru_config.py",
        )
    )
    _mieru_namespace = {"__name__": "mieru_config"}
    with open(_mieru_validator_path, encoding="utf-8") as _mieru_validator_source:
        exec(
            compile(_mieru_validator_source.read(), _mieru_validator_path, "exec"),
            _mieru_namespace,
        )
    client_config = _mieru_namespace["client_config"]
    server_config = _mieru_namespace["server_config"]
    simple_share_link = _mieru_namespace["simple_share_link"]
    user_record = _mieru_namespace["user_record"]
    validate_recovery_data = _mieru_namespace["validate_recovery_data"]

XRAY = "/usr/local/etc/xray/config.json"
HY2 = "/etc/hysteria/config.yaml"
MODULAR_XRAY_STATE = "/opt/vpn/recovery/xray-secrets.env"
LEGACY_STATE = "/opt/vpn/recovery/server-secrets.env"
MIERU_RECOVERY = "/opt/vpn/recovery/mieru-secrets.json"
MITA_CONFIG = "/etc/mita/server.conf.pb"
NAME = re.compile(r"^[A-Za-z0-9-]+$")
PROTOCOLS = {
    "xray": {"path": XRAY, "service": "xray"},
    "hysteria2": {"path": HY2, "service": "hysteria-server"},
    "mieru": {"path": MIERU_RECOVERY, "service": "mita"},
}
REGISTRY = Path("/opt/vpn/state/components.json")
COMPONENT_ROOT = Path("/opt/vpn/components")
DECLARED_USERS_ACTIONS = ("list", "get", "create", "delete")
USERS_ACTIONS = ("list", "get", "create", "extend", "delete")
AUTHORIZED_PROTOCOLS = frozenset()
SUPPORTED_RUNTIME_STATES = {"active", "inactive", "failed"}
MAX_MANAGE_BACKUPS = 3


def run(*cmd):
    subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL)


def regular_file(path):
    try:
        metadata = path.lstat()
    except OSError:
        return False
    return stat.S_ISREG(metadata.st_mode) and not path.is_symlink()


def load_json_object(path, label):
    if not regular_file(path):
        raise ValueError(label + " is missing or unsafe")
    try:
        value = json.loads(path.read_text(encoding="utf-8", errors="strict"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError(label + " is invalid") from error
    if not isinstance(value, dict):
        raise ValueError(label + " is invalid")
    return value


def authorize_protocols(action, requested_protocols):
    if not isinstance(requested_protocols, list):
        raise ValueError("Users allowed protocols must be an array")
    if (
        any(not isinstance(protocol, str) for protocol in requested_protocols)
        or len(set(requested_protocols)) != len(requested_protocols)
        or requested_protocols
        != [protocol for protocol in PROTOCOLS if protocol in requested_protocols]
    ):
        raise ValueError("Users allowed protocols are invalid or not in canonical order")
    if not requested_protocols:
        return frozenset()
    registry = load_json_object(REGISTRY, "The component registry")
    components = registry.get("components")
    if registry.get("schema_version") != 2 or not isinstance(components, dict):
        raise ValueError("The component registry has an unsupported schema")
    declaration_action = "create" if action == "extend" else action
    authorized = []
    for protocol in requested_protocols:
        record = components.get(protocol)
        declaration_path = COMPONENT_ROOT / protocol / "declaration.json"
        if not isinstance(record, dict) or record.get("installed") is not True:
            raise ValueError(f"{protocol} is not registered as an installed component")
        contract_version = record.get("contract_version")
        if not isinstance(contract_version, str) or not contract_version:
            raise ValueError(f"{protocol} has an invalid registered contract")
        if record.get("declaration_path") != str(declaration_path):
            raise ValueError(f"{protocol} has an invalid registered declaration path")
        declaration = load_json_object(declaration_path, f"The {protocol} declaration")
        if (
            declaration.get("schema_version") != 2
            or declaration.get("component") != protocol
            or declaration.get("contract_version") != contract_version
        ):
            raise ValueError(f"The {protocol} declaration does not match its registry record")
        users = declaration.get("users")
        actions = users.get("actions") if isinstance(users, dict) else None
        if (
            not isinstance(users, dict)
            or users.get("supported") is not True
            or not isinstance(actions, list)
            or any(candidate not in DECLARED_USERS_ACTIONS for candidate in actions)
            or len(set(actions)) != len(actions)
            or declaration_action not in actions
        ):
            raise ValueError(
                f"The {protocol} declaration does not permit Users {declaration_action}"
            )
        authorized.append(protocol)
    return frozenset(authorized)


def xray_state():
    state_path = MODULAR_XRAY_STATE if os.path.isfile(MODULAR_XRAY_STATE) else LEGACY_STATE
    data = {}
    with open(state_path) as source:
        for line in source:
            match = re.match(r"(\w+)='(.*)'", line.rstrip())
            if match:
                data[match.group(1)] = match.group(2)
    return data


def loadx():
    if "xray" not in AUTHORIZED_PROTOCOLS or not os.path.isfile(XRAY):
        return None
    with open(XRAY) as source:
        return json.load(source)


def usersx(x):
    if x is None:
        return {}
    return {
        client.get("email"): client
        for client in x["inbounds"][0]["settings"]["clients"]
        if client.get("email")
    }


def loadh():
    if "hysteria2" not in AUTHORIZED_PROTOCOLS or not os.path.isfile(HY2):
        return ""
    with open(HY2) as source:
        return source.read()


def usersh(text):
    if not text:
        return {}
    return hysteria2_connection_details(text)[2]


def loadm():
    if "mieru" not in AUTHORIZED_PROTOCOLS or not os.path.isfile(MIERU_RECOVERY):
        return None
    with open(MIERU_RECOVERY, encoding="utf-8") as source:
        return validate_recovery_data(json.load(source))


def usersm(data):
    if data is None:
        return {}
    return {user["name"]: user for user in data["users"]}


def write(path, data):
    fd, temporary = tempfile.mkstemp(dir=os.path.dirname(path))
    with os.fdopen(fd, "w") as stream:
        stream.write(data)
    os.replace(temporary, path)
    if path == HY2:
        os.chown(path, pwd.getpwnam("hysteria").pw_uid, grp.getgrnam("hysteria").gr_gid)
        os.chmod(path, 0o640)
    elif path == MIERU_RECOVERY:
        os.chown(path, 0, 0)
        os.chmod(path, 0o600)


def manage_backups(path):
    directory = os.path.dirname(path)
    prefix = os.path.basename(path) + ".manage-"
    backups = []
    with os.scandir(directory) as entries:
        for entry in entries:
            if (
                entry.name.startswith(prefix)
                and entry.name.endswith(".bak")
                and entry.is_file(follow_symlinks=False)
            ):
                backups.append((entry.path, entry.stat(follow_symlinks=False).st_mtime_ns))
    return backups


def prune_manage_backups(path, preserve=(), limit=MAX_MANAGE_BACKUPS):
    preserved = set(preserve)
    backups = manage_backups(path)
    for backup_path, _modified in backups:
        os.chmod(backup_path, 0o600)
    backups.sort(
        key=lambda item: (item[0] in preserved, item[1], item[0]),
        reverse=True,
    )
    for backup_path, _modified in backups[limit:]:
        os.unlink(backup_path)


def backup(path):
    prune_manage_backups(path, limit=MAX_MANAGE_BACKUPS - 1)
    descriptor, backup_path = tempfile.mkstemp(
        prefix=os.path.basename(path) + ".manage-" + time.strftime("%Y%m%d-%H%M%S") + "-",
        suffix=".bak",
        dir=os.path.dirname(path),
    )
    os.close(descriptor)
    try:
        shutil.copyfile(path, backup_path)
        os.chmod(backup_path, 0o600)
        prune_manage_backups(path, preserve=(backup_path,))
        return backup_path
    except Exception:
        if os.path.exists(backup_path):
            os.unlink(backup_path)
        raise


def cleanup_transaction_backups(backups):
    for backup_path in backups.values():
        try:
            os.unlink(backup_path)
        except FileNotFoundError:
            pass
        except OSError:
            # The backup was already pruned to the bounded recovery set.
            pass


def service_runtime_state(service):
    result = subprocess.run(
        ["systemctl", "is-active", service],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    state = result.stdout.strip()
    if state not in SUPPORTED_RUNTIME_STATES:
        raise RuntimeError(f"Unsupported runtime state for {service}: {state or 'unknown'}")
    return state


def restart_and_check(service):
    run("systemctl", "restart", service)
    run("systemctl", "is-active", "--quiet", service)


def mita_runtime_state():
    result = subprocess.run(
        ["mita", "status"],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    return {
        'mita server status is "RUNNING"': "RUNNING",
        'mita server status is "IDLE"': "IDLE",
    }.get(result.stdout.strip(), "unknown")


def mita_apply_recovery(recovery_text):
    recovery = validate_recovery_data(json.loads(recovery_text))
    descriptor, candidate_path = tempfile.mkstemp(
        prefix=".manage-users-mita-", suffix=".json", dir="/etc/mita"
    )
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w") as stream:
            json.dump(server_config(recovery), stream)
            stream.flush()
            os.fsync(stream.fileno())
        run("mita", "apply", "config", candidate_path)
        write(MIERU_RECOVERY, json.dumps(recovery, indent=2) + "\n")
    finally:
        if os.path.exists(candidate_path):
            os.unlink(candidate_path)


def mita_reload_and_check():
    run("mita", "reload")
    if mita_runtime_state() != "RUNNING":
        raise RuntimeError("Mita proxy runtime is not RUNNING after reload")


def validate_xray_candidate(config):
    descriptor, candidate = tempfile.mkstemp(prefix=".manage-users-", suffix=".json")
    try:
        with os.fdopen(descriptor, "w") as stream:
            json.dump(config, stream, indent=2)
        run("xray", "run", "-test", "-config", candidate)
    finally:
        if os.path.exists(candidate):
            os.unlink(candidate)


def mutation_result(action, name, outcome, states, restarted, error=""):
    return {
        "action": action,
        "name": name,
        "outcome": outcome,
        "protocols": states,
        "restarted": restarted,
        "error": error,
    }


def initial_protocol_states():
    return {protocol: {"config": "unchanged", "service": "unchanged"} for protocol in PROTOCOLS}


def rollback_mutation(action, name, originals, runtime_states, backups, touched, states, error):
    rollback_failed = False
    for protocol in reversed(touched):
        settings = PROTOCOLS[protocol]
        try:
            if protocol == "mieru":
                mita_apply_recovery(originals[protocol])
            else:
                write(settings["path"], originals[protocol])
            states[protocol]["config"] = "rolled_back"
        except Exception:
            states[protocol]["config"] = "rollback_failed"
            rollback_failed = True
        if protocol == "mieru" and runtime_states[protocol] == "RUNNING":
            try:
                mita_reload_and_check()
                states[protocol]["service"] = "rollback_reloaded"
            except Exception:
                states[protocol]["service"] = "rollback_restart_failed"
                rollback_failed = True
        elif protocol != "mieru" and runtime_states[protocol] == "active":
            try:
                restart_and_check(settings["service"])
                states[protocol]["service"] = "rollback_restarted"
            except Exception:
                states[protocol]["service"] = "rollback_restart_failed"
                rollback_failed = True
        else:
            states[protocol]["service"] = "unchanged"
    outcome = "partial" if rollback_failed else "rolled_back"
    if not rollback_failed:
        cleanup_transaction_backups(backups)
    return mutation_result(action, name, outcome, states, [], str(error))


def apply_mutation(action, name, originals, candidates):
    states = initial_protocol_states()
    runtime_states = {}
    backups = {}
    touched = []
    restarted = []
    try:
        for protocol in candidates:
            if protocol == "mieru":
                if service_runtime_state("mita") != "active":
                    raise RuntimeError("Mita daemon must be active before changing Users")
                runtime_states[protocol] = mita_runtime_state()
                if runtime_states[protocol] not in {"RUNNING", "IDLE"}:
                    raise RuntimeError("Mita proxy runtime state is unknown")
            else:
                runtime_states[protocol] = service_runtime_state(PROTOCOLS[protocol]["service"])
        for protocol in ("xray", "hysteria2", "mieru"):
            if protocol not in candidates:
                continue
            settings = PROTOCOLS[protocol]
            backups[protocol] = backup(settings["path"])
            if protocol == "mieru":
                backups["mieru-protobuf"] = backup(MITA_CONFIG)
            touched.append(protocol)
            if protocol == "mieru":
                mita_apply_recovery(candidates[protocol])
            else:
                write(settings["path"], candidates[protocol])
            states[protocol]["config"] = "applied"
            if protocol == "mieru" and runtime_states[protocol] == "RUNNING":
                try:
                    mita_reload_and_check()
                except Exception:
                    states[protocol]["service"] = "restart_failed"
                    raise
                states[protocol]["service"] = "reloaded"
            elif protocol == "mieru":
                states[protocol]["service"] = "not_verified"
            elif runtime_states[protocol] == "active":
                try:
                    restart_and_check(settings["service"])
                except Exception:
                    states[protocol]["service"] = "restart_failed"
                    raise
                states[protocol]["service"] = "restarted"
                restarted.append(settings["service"])
            else:
                states[protocol]["service"] = "not_verified"
        cleanup_transaction_backups(backups)
        return mutation_result(action, name, "success", states, restarted)
    except Exception as error:
        return rollback_mutation(
            action,
            name,
            originals,
            runtime_states,
            backups,
            touched,
            states,
            error,
        )


def info(name):
    x = loadx()
    h = loadh()
    ux = usersx(x)
    uh = usersh(h)
    m = loadm()
    um = usersm(m)
    output = {"name": name, "xray": name in ux, "hysteria": name in uh, "mieru": name in um}
    if name in ux:
        sx = xray_state()
        reality = x["inbounds"][0]["streamSettings"]["realitySettings"]
        output["xray_link"] = (
            f"vless://{ux[name]['id']}@{os.environ['SERVER_IP']}:{x['inbounds'][0]['port']}"
            f"?security=reality&encryption=none&type=tcp&flow=xtls-rprx-vision"
            f"&pbk={sx['XRAY_PUBLIC_KEY']}&fp=chrome&sni={reality['serverNames'][0]}"
            f"&sid={reality['shortIds'][0]}#{name}"
        )
        output["xray_yaml"] = {
            "name": name,
            "type": "vless",
            "server": os.environ["SERVER_IP"],
            "port": x["inbounds"][0]["port"],
            "uuid": ux[name]["id"],
            "flow": "xtls-rprx-vision",
            "encryption": "none",
            "tls": True,
            "skip-cert-verify": True,
            "servername": reality["serverNames"][0],
            "client-fingerprint": "chrome",
            "reality-opts": {
                "public-key": sx["XRAY_PUBLIC_KEY"],
                "short-id": reality["shortIds"][0],
            },
        }
    if name in uh:
        port, sni, _users, obfs = hysteria2_connection_details(h)
        output["hysteria_link"] = (
            f"hysteria2://{name}:{uh[name]}@{os.environ['SERVER_IP']}:{port}"
            f"?obfs=salamander&obfs-password={obfs}&sni={sni}&insecure=1#{name}"
        )
        output["hysteria_yaml"] = {
            "name": name,
            "type": "hysteria2",
            "server": os.environ["SERVER_IP"],
            "port": port,
            "password": f"{name}:{uh[name]}",
            "sni": sni,
            "skip-cert-verify": True,
            "obfs": "salamander",
            "obfs-password": obfs,
        }
    if name in um:
        server = m["server"]
        user = user_record(m, name)
        output["mieru_link"] = simple_share_link(m, os.environ["SERVER_IP"], name)
        output["mieru_json"] = client_config(m, os.environ["SERVER_IP"], name)
        output["mieru_yaml"] = {
            "name": name,
            "server": os.environ["SERVER_IP"],
            "port": server["port"],
            "transport": server["protocol"],
            "username": user["name"],
            "password": user["password"],
        }
    return output


def create(name):
    states = initial_protocol_states()
    try:
        if not NAME.fullmatch(name):
            raise ValueError("Invalid name")
        original_xray = None
        if "xray" in AUTHORIZED_PROTOCOLS and os.path.isfile(XRAY):
            with open(XRAY) as source:
                original_xray = source.read()
        x = json.loads(original_xray) if original_xray is not None else None
        h = loadh()
        m = loadm()
        if name in usersx(x) or name in usersh(h) or name in usersm(m):
            raise ValueError("User already exists in at least one protocol")
        originals = {}
        candidates = {}
        if x is not None:
            originals["xray"] = original_xray
            uid = subprocess.check_output(["xray", "uuid"], text=True).strip()
            x["inbounds"][0]["settings"]["clients"].append(
                {"id": uid, "flow": "xtls-rprx-vision", "email": name}
            )
            validate_xray_candidate(x)
            candidates["xray"] = json.dumps(x, indent=2) + "\n"
        if h:
            originals["hysteria2"] = h
            password = secrets.token_hex(24)
            marker = "  userpass:\n"
            position = h.index(marker) + len(marker)
            candidate = h[:position] + f"    {name}: {password}\n" + h[position:]
            validate_hysteria2_config_text(candidate)
            if name not in usersh(candidate):
                raise ValueError("The updated Hysteria2 configuration is invalid")
            candidates["hysteria2"] = candidate
        if m is not None:
            originals["mieru"] = json.dumps(m, indent=2) + "\n"
            candidate = json.loads(json.dumps(m))
            candidate["users"].append({"name": name, "password": secrets.token_hex(32)})
            validate_recovery_data(candidate)
            server_config(candidate)
            candidates["mieru"] = json.dumps(candidate, indent=2) + "\n"
        if not candidates:
            raise ValueError("No supported Users protocol is available")
        return apply_mutation("create", name, originals, candidates)
    except Exception as error:
        return mutation_result("create", name, "rolled_back", states, [], str(error))


def extend(name):
    states = initial_protocol_states()
    try:
        if not NAME.fullmatch(name):
            raise ValueError("Invalid name")
        original_xray = None
        if "xray" in AUTHORIZED_PROTOCOLS and os.path.isfile(XRAY):
            with open(XRAY) as source:
                original_xray = source.read()
        x = json.loads(original_xray) if original_xray is not None else None
        h = loadh()
        m = loadm()
        xray_users = usersx(x)
        hysteria_users = usersh(h)
        mieru_users = usersm(m)
        if name not in xray_users and name not in hysteria_users and name not in mieru_users:
            raise ValueError("User does not exist in any available protocol")
        originals = {}
        candidates = {}
        if x is not None and name not in xray_users:
            originals["xray"] = original_xray
            uid = subprocess.check_output(["xray", "uuid"], text=True).strip()
            x["inbounds"][0]["settings"]["clients"].append(
                {"id": uid, "flow": "xtls-rprx-vision", "email": name}
            )
            validate_xray_candidate(x)
            candidates["xray"] = json.dumps(x, indent=2) + "\n"
        if h and name not in hysteria_users:
            originals["hysteria2"] = h
            password = secrets.token_hex(24)
            marker = "  userpass:\n"
            position = h.index(marker) + len(marker)
            candidate = h[:position] + f"    {name}: {password}\n" + h[position:]
            validate_hysteria2_config_text(candidate)
            if name not in usersh(candidate):
                raise ValueError("The updated Hysteria2 configuration is invalid")
            candidates["hysteria2"] = candidate
        if m is not None and name not in mieru_users:
            originals["mieru"] = json.dumps(m, indent=2) + "\n"
            candidate = json.loads(json.dumps(m))
            candidate["users"].append({"name": name, "password": secrets.token_hex(32)})
            validate_recovery_data(candidate)
            server_config(candidate)
            candidates["mieru"] = json.dumps(candidate, indent=2) + "\n"
        if not candidates:
            raise ValueError("User already exists in all available protocols")
        return apply_mutation("extend", name, originals, candidates)
    except Exception as error:
        return mutation_result("extend", name, "rolled_back", states, [], str(error))


def delete(name):
    states = initial_protocol_states()
    try:
        original_xray = None
        if "xray" in AUTHORIZED_PROTOCOLS and os.path.isfile(XRAY):
            with open(XRAY) as source:
                original_xray = source.read()
        x = json.loads(original_xray) if original_xray is not None else None
        h = loadh()
        m = loadm()
        originals = {}
        candidates = {}
        if name in usersx(x):
            originals["xray"] = original_xray
            x["inbounds"][0]["settings"]["clients"] = [
                client
                for client in x["inbounds"][0]["settings"]["clients"]
                if client.get("email") != name
            ]
            validate_xray_candidate(x)
            candidates["xray"] = json.dumps(x, indent=2) + "\n"
        if name in usersh(h):
            originals["hysteria2"] = h
            candidate = re.sub(rf"^    {re.escape(name)}:\s*\S+\n", "", h, flags=re.M)
            validate_hysteria2_config_text(candidate)
            if name in usersh(candidate):
                raise ValueError("The updated Hysteria2 configuration is invalid")
            candidates["hysteria2"] = candidate
        if name in usersm(m):
            originals["mieru"] = json.dumps(m, indent=2) + "\n"
            candidate = json.loads(json.dumps(m))
            candidate["users"] = [user for user in candidate["users"] if user.get("name") != name]
            validate_recovery_data(candidate)
            server_config(candidate)
            candidates["mieru"] = json.dumps(candidate, indent=2) + "\n"
        return apply_mutation("delete", name, originals, candidates)
    except Exception as error:
        return mutation_result("delete", name, "rolled_back", states, [], str(error))


def execute(request):
    global AUTHORIZED_PROTOCOLS
    if not isinstance(request, dict):
        raise ValueError("Invalid Users request")
    if set(request) != {"action", "name", "server_ip", "allowed_protocols"}:
        raise ValueError("Invalid Users request schema")
    action = request.get("action")
    name = request.get("name", "")
    server_ip = request.get("server_ip")
    if action not in USERS_ACTIONS:
        raise ValueError("Invalid Users action")
    if not isinstance(server_ip, str) or not re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", server_ip):
        raise ValueError("Invalid server IP")
    if not isinstance(name, str):
        raise ValueError("Invalid user name")
    AUTHORIZED_PROTOCOLS = frozenset()
    AUTHORIZED_PROTOCOLS = authorize_protocols(action, request.get("allowed_protocols"))
    if action == "list":
        if name:
            raise ValueError("List Users request must not contain a name")
        xray_users = usersx(loadx())
        hysteria_users = usersh(loadh())
        mieru_users = usersm(loadm())
        return [
            {
                "name": name,
                "xray": name in xray_users,
                "hysteria": name in hysteria_users,
                "mieru": name in mieru_users,
            }
            for name in sorted(set(xray_users) | set(hysteria_users) | set(mieru_users))
        ]
    if not NAME.fullmatch(name):
        raise ValueError("Name required")
    os.environ["SERVER_IP"] = server_ip
    return (
        create(name)
        if action == "create"
        else extend(name)
        if action == "extend"
        else delete(name)
        if action == "delete"
        else info(name)
    )
