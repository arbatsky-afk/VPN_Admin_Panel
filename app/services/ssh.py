from ipaddress import AddressValueError, IPv4Address
from pathlib import Path

project_directory = Path(__file__).resolve().parents[2]
ssh_check_script = project_directory / "scripts" / "windows" / "test-ssh.ps1"


def validate_server_ip(server_ip: str) -> tuple[str, str | None]:
    server_ip = server_ip.strip()

    if not server_ip:
        return server_ip, "Enter a server IPv4 address."

    try:
        IPv4Address(server_ip)
    except AddressValueError:
        return server_ip, "The supplied IPv4 address is invalid."

    return server_ip, None
