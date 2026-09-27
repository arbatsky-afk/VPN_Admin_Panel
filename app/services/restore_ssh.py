import subprocess
from dataclasses import dataclass
from pathlib import Path

from .ssh import validate_server_ip

project_directory = Path(__file__).resolve().parents[2]
ssh_restore_script = project_directory / "scripts" / "windows" / "restore-ssh.ps1"


@dataclass(frozen=True, slots=True)
class SshRestoreLaunch:
    """Result of opening the interactive SSH Fix console."""

    server_ip: str
    process: subprocess.Popen[bytes] | None
    error: str | None = None


def launch_ssh_restore(server_ip: str) -> SshRestoreLaunch:
    server_ip, validation_error = validate_server_ip(server_ip)
    if validation_error:
        return SshRestoreLaunch(server_ip, None, validation_error)

    if not ssh_restore_script.is_file():
        return SshRestoreLaunch(
            server_ip,
            None,
            "The local SSH recovery tool could not be found.",
        )

    try:
        process = subprocess.Popen(
            [
                "powershell.exe",
                "-NoLogo",
                "-NoProfile",
                "-File",
                str(ssh_restore_script),
                server_ip,
            ],
            creationflags=subprocess.CREATE_NEW_CONSOLE,
            close_fds=True,
            shell=False,
        )
    except OSError:
        return SshRestoreLaunch(
            server_ip,
            None,
            "The SSH recovery window could not be opened.",
        )

    return SshRestoreLaunch(server_ip, process)
