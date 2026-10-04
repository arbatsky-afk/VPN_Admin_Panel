"""Persistent settings for VPN Admin Panel."""

from __future__ import annotations

import json
import os
import re
from ipaddress import AddressValueError, IPv4Address
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Any

from .project_paths import panel_settings_path

_NETDATA_CLAIM_TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{20,1024}$")
_NETDATA_ROOM_ID = r"[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}"
_NETDATA_CLAIM_ROOMS_RE = re.compile(rf"^{_NETDATA_ROOM_ID}(?:,{_NETDATA_ROOM_ID})*$")


class NetdataCloudSettingsError(ValueError):
    """The local Netdata Cloud settings are incomplete or malformed."""


class SettingsFileProtectedError(OSError):
    """An existing settings file is protected after an unsafe load."""


class SettingsManager:
    """Read and write panel state in ``runtime/panel/settings.json``."""

    _RECENT_SERVERS_KEY = "recent_servers"
    _MAX_RECENT_SERVERS = 10
    _NETDATA_CLOUD_KEY = "netdata_cloud"
    _NETDATA_CLOUD_FIELDS = ("claim_token", "claim_rooms")
    _START_MINIMIZED_TO_TRAY_KEY = "ui.start_minimized_to_tray"

    def __init__(self, settings_file: Path | None = None) -> None:
        if settings_file is None:
            project_directory = Path(__file__).resolve().parents[2]
            settings_file = panel_settings_path(project_directory)
        self._settings_file = settings_file
        self._settings: dict[str, Any] = {}
        self._persistence_available = True
        self._persistence_error: str | None = None
        self._recovery_notice: str | None = None
        self.load()

    def load(self) -> None:
        """Load settings and atomically reset a malformed document."""
        self._recovery_notice = None
        if not self._settings_file.exists():
            self._settings = {}
            self._persistence_available = True
            self._persistence_error = None
            return

        try:
            with self._settings_file.open("r", encoding="utf-8") as file:
                settings = json.load(file)
        except (json.JSONDecodeError, UnicodeDecodeError):
            self._reset_malformed_settings(
                "The panel settings file contains invalid JSON or text encoding."
            )
            return
        except OSError as error:
            self._settings = {}
            self._persistence_available = False
            self._persistence_error = f"The panel settings file could not be read: {error}"
            return

        if not isinstance(settings, dict):
            self._reset_malformed_settings("The panel settings file root is not a JSON object.")
            return

        self._settings = settings
        self._persistence_available = True
        self._persistence_error = None

    def _reset_malformed_settings(self, reason: str) -> None:
        """Replace malformed settings with defaults or protect the original on failure."""
        self._settings = {}
        self._persistence_available = True
        self._persistence_error = None
        try:
            self.save()
        except OSError:
            self._persistence_available = False
            self._persistence_error = f"{reason} The file could not be reset safely."
            return
        self._recovery_notice = f"{reason} It was reset to default settings."

    @property
    def persistence_available(self) -> bool:
        """Return whether this instance may persist settings safely."""
        return self._persistence_available

    @property
    def persistence_error(self) -> str | None:
        """Return the load failure that disabled persistence, if any."""
        return self._persistence_error

    @property
    def recovery_notice(self) -> str | None:
        """Return the successful automatic-recovery notice, if any."""
        return self._recovery_notice

    def save(self) -> None:
        """Atomically save settings, creating the parent directory when needed."""
        if not self._persistence_available:
            reason = (
                self._persistence_error or "The existing settings file could not be loaded safely."
            )
            raise SettingsFileProtectedError(
                f"{reason} It was left unchanged. Fix or restore it, then restart Admin Panel."
            )
        self._settings_file.parent.mkdir(parents=True, exist_ok=True)
        temporary_path: Path | None = None
        try:
            with NamedTemporaryFile(
                "w",
                encoding="utf-8",
                newline="\n",
                dir=self._settings_file.parent,
                prefix=f".{self._settings_file.name}-",
                suffix=".tmp",
                delete=False,
            ) as temporary_file:
                temporary_path = Path(temporary_file.name)
                json.dump(self._settings, temporary_file, indent=4, ensure_ascii=False)
                temporary_file.write("\n")
                temporary_file.flush()
                os.fsync(temporary_file.fileno())
            os.replace(temporary_path, self._settings_file)
        finally:
            if temporary_path is not None:
                temporary_path.unlink(missing_ok=True)

    def get(self, key: str, default: Any = None) -> Any:
        """Return a setting by a dot-separated key."""
        data: Any = self._settings
        for part in key.split("."):
            if not isinstance(data, dict) or part not in data:
                return default
            data = data[part]
        return data

    def set(self, key: str, value: Any) -> None:
        """Set a setting by a dot-separated key without saving it yet."""
        parts = key.split(".")
        data = self._settings
        for part in parts[:-1]:
            current = data.get(part)
            if not isinstance(current, dict):
                current = {}
                data[part] = current
            data = current
        data[parts[-1]] = value

    def unset(self, key: str) -> None:
        """Remove a dot-separated setting without saving it yet."""
        parts = key.split(".")
        data: Any = self._settings
        parents: list[tuple[dict[str, Any], str]] = []
        for part in parts[:-1]:
            if not isinstance(data, dict) or not isinstance(data.get(part), dict):
                return
            parents.append((data, part))
            data = data[part]
        if not isinstance(data, dict):
            return
        data.pop(parts[-1], None)
        for parent, part in reversed(parents):
            child = parent.get(part)
            if isinstance(child, dict) and not child:
                parent.pop(part, None)
            else:
                break

    def start_minimized_to_tray(self) -> bool:
        """Return true only for an explicit valid startup preference."""
        return self.get(self._START_MINIMIZED_TO_TRAY_KEY) is True

    def recent_servers(self) -> list[dict[str, str]]:
        """Return the remembered servers, newest first."""
        servers = self.get(self._RECENT_SERVERS_KEY, [])
        if not isinstance(servers, list):
            servers = []

        result: list[dict[str, str]] = []
        seen: set[str] = set()
        for server in servers:
            if not isinstance(server, dict):
                continue
            alias = server.get("alias")
            ip = server.get("ip")
            if not isinstance(alias, str) or not isinstance(ip, str):
                continue
            try:
                canonical_ip = _canonical_ipv4(ip)
            except ValueError:
                continue
            if canonical_ip in seen:
                continue
            seen.add(canonical_ip)
            result.append({"alias": alias, "ip": canonical_ip})

        return result[: self._MAX_RECENT_SERVERS]

    def remember_server(self, alias: str, ip: str) -> None:
        """Place a server at the top of the recent-server list and save it."""
        if not isinstance(alias, str):
            raise TypeError("Recent server alias must be text.")
        canonical_ip = _canonical_ipv4(ip)
        servers = [server for server in self.recent_servers() if server["ip"] != canonical_ip]
        servers.insert(0, {"alias": alias, "ip": canonical_ip})
        self.set(self._RECENT_SERVERS_KEY, servers[: self._MAX_RECENT_SERVERS])
        self.save()

    def update_recent_server_alias(self, alias: str, ip: str) -> bool:
        """Update an existing Recent alias without changing MRU order."""
        if not isinstance(alias, str):
            raise TypeError("Recent server alias must be text.")
        canonical_ip = _canonical_ipv4(ip)
        servers = self.recent_servers()
        for server in servers:
            if server["ip"] != canonical_ip:
                continue
            if server["alias"] == alias:
                return False
            server["alias"] = alias
            self.set(self._RECENT_SERVERS_KEY, servers)
            self.save()
            return True
        return False

    def remove_recent_server(self, ip: str) -> bool:
        """Atomically remove one canonical IPv4 while preserving all other settings."""
        canonical_ip = _canonical_ipv4(ip)
        servers = self.recent_servers()
        remaining = [server for server in servers if server["ip"] != canonical_ip]
        if len(remaining) == len(servers):
            return False
        self.set(self._RECENT_SERVERS_KEY, remaining)
        self.save()
        return True

    def ensure_netdata_cloud_defaults(self) -> bool:
        """Create the local Netdata Cloud fields without replacing invalid data."""
        if not self._persistence_available:
            return False
        section = self._settings.get(self._NETDATA_CLOUD_KEY)
        if section is None:
            self._settings[self._NETDATA_CLOUD_KEY] = {
                field: "" for field in self._NETDATA_CLOUD_FIELDS
            }
            self.save()
            return True
        if not isinstance(section, dict):
            return False
        if any(
            field in section and not isinstance(section[field], str)
            for field in self._NETDATA_CLOUD_FIELDS
        ):
            return False
        changed = False
        for field in self._NETDATA_CLOUD_FIELDS:
            if field not in section:
                section[field] = ""
                changed = True
        if changed:
            self.save()
        return True

    def editable_netdata_cloud_settings(self) -> tuple[str, str, str | None]:
        """Return editable Claim values and a safe error for an invalid section."""
        section = self._settings.get(self._NETDATA_CLOUD_KEY)
        if section is None:
            return "", "", None
        if not isinstance(section, dict):
            return "", "", "The saved Netdata section is invalid."
        claim_token = section.get("claim_token", "")
        claim_rooms = section.get("claim_rooms", "")
        if not isinstance(claim_token, str) or not isinstance(claim_rooms, str):
            return (
                claim_token if isinstance(claim_token, str) else "",
                claim_rooms if isinstance(claim_rooms, str) else "",
                "The saved Netdata fields must be text.",
            )
        try:
            self.validate_netdata_cloud_settings(claim_token, claim_rooms)
        except NetdataCloudSettingsError as error:
            return claim_token, claim_rooms, str(error)
        return claim_token, claim_rooms, None

    @staticmethod
    def validate_netdata_cloud_settings(
        claim_token: object,
        claim_rooms: object,
    ) -> tuple[str, str]:
        """Normalize and validate the local Netdata Cloud Claim values."""
        if not isinstance(claim_token, str) or not isinstance(claim_rooms, str):
            raise NetdataCloudSettingsError("Netdata Claim fields must be text.")
        token = claim_token.strip()
        rooms = claim_rooms.strip()
        if rooms and not token:
            raise NetdataCloudSettingsError("Claim token is required when Claim rooms is filled.")
        if token and not _NETDATA_CLAIM_TOKEN_RE.fullmatch(token):
            raise NetdataCloudSettingsError("Claim token has an invalid format.")
        if rooms and not _NETDATA_CLAIM_ROOMS_RE.fullmatch(rooms):
            raise NetdataCloudSettingsError(
                "Claim rooms must be a comma-separated list of Room IDs."
            )
        return token, rooms

    def set_netdata_cloud_settings(
        self,
        claim_token: object,
        claim_rooms: object,
        *,
        save: bool = True,
    ) -> tuple[str, str]:
        """Set validated Netdata Cloud Claim values, optionally deferring save."""
        token, rooms = self.validate_netdata_cloud_settings(claim_token, claim_rooms)
        self.set(f"{self._NETDATA_CLOUD_KEY}.claim_token", token)
        self.set(f"{self._NETDATA_CLOUD_KEY}.claim_rooms", rooms)
        if save:
            self.save()
        return token, rooms


def _canonical_ipv4(value: object) -> str:
    if not isinstance(value, str):
        raise TypeError("Recent server IPv4 must be text.")
    try:
        return str(IPv4Address(value.strip()))
    except AddressValueError as error:
        raise ValueError("Recent server IPv4 is invalid.") from error
