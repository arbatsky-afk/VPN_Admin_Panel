import json
import os
import re
import subprocess
from pathlib import Path

REGISTRY_PATH = "/opt/vpn/state/components.json"
COMPONENTS_DIRECTORY = "/opt/vpn/components"
component_pattern = re.compile(r"^[a-z0-9][a-z0-9-]*$")
path_pattern = re.compile(r"^/[A-Za-z0-9._/@+-]+$")
unit_pattern = re.compile(r"^[a-zA-Z0-9@_.-]+\.service$")
if inventory_profile not in {"full", "users", "subscriptions"}:
    raise ValueError("Unsupported Inventory profile.")


def read_text(path):
    try:
        return {"content": Path(path).read_text(encoding="utf-8")}
    except OSError as error:
        return {"error": str(error)}


def valid_path(path):
    return (
        isinstance(path, str)
        and path_pattern.fullmatch(path)
        and "/../" not in path
        and not path.endswith("/..")
    )


result = {
    "texts": {REGISTRY_PATH: read_text(REGISTRY_PATH)},
    "files": {},
    "directories": {},
    "systemd": {},
    "health": {},
    "versions": {},
}
registry_text = result["texts"][REGISTRY_PATH]
if "content" in registry_text:
    try:
        registry = json.loads(registry_text["content"])
    except json.JSONDecodeError:
        registry = None
    components = registry.get("components") if isinstance(registry, dict) else None
    if isinstance(components, dict):
        for component_id, record in components.items():
            if (
                not isinstance(component_id, str)
                or not component_pattern.fullmatch(component_id)
                or not isinstance(record, dict)
                or record.get("installed") is not True
            ):
                continue
            declaration_path = f"{COMPONENTS_DIRECTORY}/{component_id}/declaration.json"
            if record.get("declaration_path") != declaration_path:
                continue
            declaration_text = read_text(declaration_path)
            result["texts"][declaration_path] = declaration_text
            if "content" not in declaration_text:
                continue
            try:
                declaration = validate_declaration_text(declaration_text["content"], component_id)
            except DeclarationError:
                continue
            if record.get("contract_version") != declaration["contract_version"]:
                continue
            if inventory_profile != "full":
                continue
            if component_id == "base-security":
                result["versions"][component_id] = {"version": None}
            elif component_id in software_version_commands:
                try:
                    completed = subprocess.run(
                        software_version_commands[component_id],
                        capture_output=True,
                        encoding="utf-8",
                        errors="replace",
                        check=False,
                        timeout=15,
                    )
                    if component_id == "nginx":
                        output = (completed.stdout + "\n" + completed.stderr).strip()
                        match = re.fullmatch(
                            r"nginx version: nginx/([0-9]+(?:\.[0-9]+)+"
                            r"(?:[-+._A-Za-z0-9]*)?)(?: \([^()\r\n]+\))?",
                            output,
                        )
                    else:
                        output = completed.stdout.strip()
                        match = re.search(
                            r"(?<![0-9])v?([0-9]+(?:\.[0-9]+)+(?:[-+._A-Za-z0-9]*)?)", output
                        )
                    if completed.returncode == 0 and match is not None:
                        result["versions"][component_id] = {"version": match.group(1)}
                    else:
                        result["versions"][component_id] = {"error": "version command failed"}
                except (OSError, subprocess.TimeoutExpired):
                    result["versions"][component_id] = {"error": "version command failed"}
            installation_checks = declaration.get("installation_checks")
            if not isinstance(installation_checks, dict):
                continue
            backup = declaration.get("backup")
            if not isinstance(backup, dict):
                continue
            installation_files = installation_checks.get("files", [])
            backup_files = backup.get("paths", [])
            backup_directories = backup.get("optional_directories", [])
            files = [
                *(installation_files if isinstance(installation_files, list) else []),
                *(backup_files if isinstance(backup_files, list) else []),
            ]
            for path in dict.fromkeys(files):
                if valid_path(path):
                    result["files"][path] = {
                        "exists": os.path.isfile(path) and not os.path.islink(path)
                    }
            for path in backup_directories if isinstance(backup_directories, list) else []:
                if valid_path(path):
                    result["directories"][path] = {
                        "exists": os.path.isdir(path) and not os.path.islink(path)
                    }
            units = installation_checks.get("systemd_units", [])
            for unit in units if isinstance(units, list) else []:
                if isinstance(unit, str) and unit_pattern.fullmatch(unit):
                    try:
                        command = subprocess.run(
                            ("systemctl", "is-active", "--", unit),
                            capture_output=True,
                            encoding="utf-8",
                            errors="replace",
                            check=False,
                            timeout=15,
                        )
                        state = (
                            command.stdout.strip().splitlines()[-1]
                            if command.stdout.strip()
                            else "unknown"
                        )
                        result["systemd"][unit] = {
                            "state": state
                            if state in {"active", "inactive", "failed"}
                            else "unknown"
                        }
                    except (OSError, subprocess.TimeoutExpired) as error:
                        result["systemd"][unit] = {"error": str(error)}
            health_checks = installation_checks.get("health_checks", [])
            for check_id in health_checks if isinstance(health_checks, list) else []:
                if not isinstance(check_id, str):
                    continue
                command = health_commands.get((component_id, check_id))
                if (component_id, check_id) not in health_commands:
                    continue
                try:
                    if (component_id, check_id) == ("hysteria2", "hysteria2_config"):
                        validate_hysteria2_config_file("/etc/hysteria/config.yaml")
                        passed = True
                    elif (component_id, check_id) == ("mieru", "mieru_config"):
                        load_recovery(Path("/opt/vpn/recovery/mieru-secrets.json"))
                        completed = subprocess.run(
                            ("mita", "describe", "config"),
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL,
                            check=False,
                            timeout=15,
                        )
                        passed = completed.returncode == 0
                    elif (component_id, check_id) == ("mieru", "mieru_runtime"):
                        completed = subprocess.run(
                            command,
                            capture_output=True,
                            encoding="utf-8",
                            errors="replace",
                            check=False,
                            timeout=15,
                        )
                        passed = completed.returncode == 0 and '"RUNNING"' in (completed.stdout + completed.stderr)  # fmt: skip  # noqa: E501 -- source shape is contract-tested
                    elif (component_id, check_id) == ("nginx", "nginx_certificate"):
                        completed = subprocess.run(
                            (
                                "python3",
                                "/usr/local/lib/vpn-admin/nginx_contract.py",
                                "verify-owned",
                            ),
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL,
                            check=False,
                            timeout=15,
                        )
                        passed = completed.returncode == 0
                    elif (component_id, check_id) == ("nginx", "nginx_listeners"):
                        completed = subprocess.run(
                            ("ss", "-H", "-lntp"),
                            capture_output=True,
                            encoding="utf-8",
                            errors="replace",
                            check=False,
                            timeout=15,
                        )
                        owned_ports = {"80": False, "443": False}
                        if completed.returncode == 0:
                            for line in completed.stdout.splitlines():
                                fields = line.split()
                                if len(fields) < 4:
                                    continue
                                port = fields[3].rsplit(":", 1)[-1]
                                if port in owned_ports:
                                    owned_ports[port] = owned_ports[port] or '"nginx"' in line
                        passed = completed.returncode == 0 and all(owned_ports.values())
                    elif (component_id, check_id) == ("nginx", "nginx_renewal"):
                        enabled = subprocess.run(
                            ("systemctl", "is-enabled", "--quiet", "vpn-admin-nginx-renew.timer"),
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL,
                            check=False,
                            timeout=15,
                        )
                        active = subprocess.run(
                            ("systemctl", "is-active", "--quiet", "vpn-admin-nginx-renew.timer"),
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL,
                            check=False,
                            timeout=15,
                        )
                        passed = enabled.returncode == 0 and active.returncode == 0
                    elif (component_id, check_id) == ("netdata", "netdata_config"):
                        content = Path("/etc/netdata/netdata.conf").read_text(encoding="utf-8")
                        lines = [line.strip() for line in content.splitlines() if line.strip()]
                        passed = lines == [
                            "[web]",
                            "default port = 19999",
                            "bind to = 127.0.0.1=dashboard",
                            "bearer token protection = yes",
                        ]
                    elif (component_id, check_id) == ("netdata", "netdata_listener"):
                        completed = subprocess.run(
                            ("ss", "-H", "-lntp"),
                            capture_output=True,
                            encoding="utf-8",
                            errors="replace",
                            check=False,
                            timeout=15,
                        )
                        matching = []
                        if completed.returncode == 0:
                            for line in completed.stdout.splitlines():
                                fields = line.split()
                                if len(fields) >= 4 and fields[3].rsplit(":", 1)[-1] == "19999":
                                    matching.append(line)
                        passed = (
                            completed.returncode == 0
                            and bool(matching)
                            and all(
                                "127.0.0.1:19999" in line and '"netdata"' in line
                                for line in matching
                            )
                        )
                    elif (component_id, check_id) == ("netdata", "netdata_proxy_bearer"):
                        completed = subprocess.run(
                            (
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
                            ),
                            capture_output=True,
                            encoding="utf-8",
                            errors="replace",
                            check=False,
                            timeout=15,
                        )
                        passed = completed.returncode == 0 and completed.stdout == "412"
                    else:
                        completed = subprocess.run(
                            command,
                            capture_output=True,
                            encoding="utf-8",
                            errors="replace",
                            check=False,
                            timeout=15,
                        )
                        passed = completed.returncode == 0
                    result["health"].setdefault(component_id, {})[check_id] = {
                        "passed": passed,
                        "detail": "passed" if passed else "failed",
                    }
                except (
                    Hysteria2ConfigError,
                    MieruConfigError,
                    OSError,
                    UnicodeError,
                    ValueError,
                    subprocess.TimeoutExpired,
                ):
                    result["health"].setdefault(component_id, {})[check_id] = {
                        "passed": False,
                        "detail": "invalid Hysteria2 configuration"
                        if component_id == "hysteria2"
                        else "invalid Mieru configuration"
                        if component_id == "mieru" and check_id == "mieru_config"
                        else "failed",
                    }

print(json.dumps(result, ensure_ascii=False))
