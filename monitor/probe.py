from __future__ import annotations

import ipaddress
import json
import ssl
import threading
import urllib.error
import urllib.parse
import urllib.request
import uuid

from monitor.domain import Connection, ConnectionStatus, FailureKind, ProbeResult
from monitor.mihomo import MihomoAdapter, MihomoError, MihomoInstance
from monitor.settings import MonitorSettings


class _MihomoProxyHandler(urllib.request.ProxyHandler):
    """Route probe traffic through Mihomo even when system settings bypass proxies."""

    def __init__(self, port: int) -> None:
        proxy_host = f"127.0.0.1:{port}"
        super().__init__({"http": proxy_host, "https": proxy_host})

    def proxy_open(self, req, proxy, type):  # type: ignore[no-untyped-def]
        # ProxyHandler.proxy_open consults system bypass rules even for an
        # explicit proxy. Set it directly, including the CONNECT target for HTTPS.
        req.set_proxy(proxy, "http")
        return None


class _LimitedRedirectHandler(urllib.request.HTTPRedirectHandler):
    def __init__(self, maximum: int) -> None:
        super().__init__()
        self._maximum = maximum
        self._count = 0

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        if self._count >= self._maximum:
            raise urllib.error.HTTPError(
                req.full_url, code, "Redirect limit exceeded", headers, fp
            )
        resolved_url = urllib.parse.urljoin(req.full_url, newurl)
        source_origin = _https_origin(req.full_url)
        if source_origin is None or _https_origin(resolved_url) != source_origin:
            raise urllib.error.HTTPError(
                req.full_url,
                code,
                "Redirect must preserve the HTTPS origin and contain no credentials",
                headers,
                fp,
            )
        self._count += 1
        return super().redirect_request(req, fp, code, msg, headers, resolved_url)


def _https_origin(url: str) -> tuple[str, int] | None:
    try:
        parsed = urllib.parse.urlsplit(url)
        port = parsed.port
    except (TypeError, ValueError):
        return None
    if (
        parsed.scheme.casefold() != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
    ):
        return None
    return parsed.hostname.rstrip(".").casefold(), 443 if port is None else port


class ProbeService:
    def __init__(self, mihomo: MihomoAdapter, settings: MonitorSettings) -> None:
        self._mihomo = mihomo
        self._settings = settings

    def check(self, connection: Connection, cancelled: threading.Event) -> ProbeResult:
        request_id = str(uuid.uuid4())
        mihomo_start = None
        try:
            with self._mihomo.running(connection, request_id, cancelled) as instance:
                mihomo_start = instance.start_diagnostics
                observed = self._external_ipv4(instance.port, cancelled)
                latency = self._unified_delay(instance, cancelled)
                if observed is not None:
                    if observed == connection.expected_ipv4:
                        return ProbeResult(
                            ConnectionStatus.OK,
                            latency,
                            observed,
                            message="IPv4 matched.",
                            mihomo_start=mihomo_start,
                        )
                    return ProbeResult(
                        ConnectionStatus.FAIL,
                        latency,
                        observed,
                        FailureKind.IP_MISMATCH,
                        "External IPv4 does not match the connection server.",
                        mihomo_start,
                    )
                if self._connectivity_proof(instance.port, cancelled):
                    return ProbeResult(
                        ConnectionStatus.OK_NO_IP,
                        latency,
                        message="VPN works, but external IPv4 was not determined.",
                        mihomo_start=mihomo_start,
                    )
                return ProbeResult.failure(
                    FailureKind.IP_INVALID,
                    "No valid external IPv4 or connectivity proof.",
                    mihomo_start,
                )
        except MihomoError as error:
            return ProbeResult.failure(error.kind, str(error), error.diagnostics or mihomo_start)
        except TimeoutError:
            return ProbeResult.failure(
                FailureKind.PROBE_TIMEOUT,
                "Proxy probe timed out.",
                mihomo_start,
            )
        except (OSError, urllib.error.URLError, ssl.SSLError):
            return ProbeResult.failure(
                FailureKind.PROBE_NETWORK,
                "Proxy probe failed.",
                mihomo_start,
            )

    def _unified_delay(self, instance: MihomoInstance, cancelled: threading.Event) -> int | None:
        if cancelled.is_set():
            raise MihomoError(FailureKind.CANCELLED, "Check was cancelled.")
        timeout_ms = min(self._settings.probe_timeout_seconds * 1000, 32767)
        query = urllib.parse.urlencode(
            {
                "url": self._settings.connectivity_check_url,
                "timeout": timeout_ms,
                "expected": "200-399",
            }
        )
        proxy_name = urllib.parse.quote("MONITOR_TARGET", safe="")
        endpoint = (
            f"http://127.0.0.1:{instance.controller_port}/proxies/{proxy_name}/delay?{query}"
        )
        request = urllib.request.Request(
            endpoint,
            headers={
                "Authorization": f"Bearer {instance.controller_secret}",
                "User-Agent": "VPN-Admin-Panel-Monitor/0.1",
            },
        )
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        try:
            with opener.open(request, timeout=self._settings.probe_timeout_seconds) as response:
                if int(response.status) != 200:
                    return None
                payload = json.loads(response.read(4096).decode("utf-8", errors="strict"))
        except (
            TimeoutError,
            OSError,
            urllib.error.URLError,
            ssl.SSLError,
            UnicodeError,
            json.JSONDecodeError,
        ):
            return None
        if not isinstance(payload, dict):
            return None
        delay = payload.get("delay")
        if isinstance(delay, bool) or not isinstance(delay, int) or not 1 <= delay <= 65535:
            return None
        return delay

    def _external_ipv4(self, port: int, cancelled: threading.Event) -> str | None:
        for url in (self._settings.primary_ip_url, self._settings.secondary_ip_url):
            if cancelled.is_set():
                raise MihomoError(FailureKind.CANCELLED, "Check was cancelled.")
            try:
                body, status = self._request(url, port)
            except (TimeoutError, OSError, urllib.error.URLError, ssl.SSLError):
                continue
            if not 200 <= status <= 399:
                continue
            try:
                value = ipaddress.ip_address(body.decode("utf-8", errors="strict").strip())
            except (ValueError, UnicodeError):
                continue
            if isinstance(value, ipaddress.IPv4Address):
                return str(value)
        return None

    def _connectivity_proof(self, port: int, cancelled: threading.Event) -> bool:
        if cancelled.is_set():
            raise MihomoError(FailureKind.CANCELLED, "Check was cancelled.")
        try:
            _body, status = self._request(self._settings.connectivity_check_url, port)
        except (TimeoutError, OSError, urllib.error.URLError, ssl.SSLError):
            return False
        return 200 <= status <= 399

    def _request(self, url: str, port: int) -> tuple[bytes, int]:
        opener = urllib.request.build_opener(
            _MihomoProxyHandler(port),
            urllib.request.HTTPSHandler(context=ssl.create_default_context()),
            _LimitedRedirectHandler(self._settings.max_redirects),
        )
        request = urllib.request.Request(
            url, headers={"User-Agent": "VPN-Admin-Panel-Monitor/0.1"}
        )
        with opener.open(request, timeout=self._settings.probe_timeout_seconds) as response:
            return response.read(4096), int(response.status)
