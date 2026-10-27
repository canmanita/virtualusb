"""Auto-Find support: announce the server as a DNS-SD service `_vhusb._tcp` exactly like the stock server does.

Observed stock announcement: instance "<friendly name>", SRV -> <host>.local:<port>, TXT = one string holding
the server serial (no key=value), plus the same under `_ssl_vhusb._tcp` when an SSL port is served.
"""
from __future__ import annotations

import asyncio
import contextlib
import functools
import importlib
import inspect
import ipaddress
import logging
import socket
from typing import Callable

import ifaddr
from zeroconf import IPVersion, ServiceInfo
from zeroconf.asyncio import AsyncZeroconf

log = logging.getLogger("vhserver.discovery")

SERVICE_TYPE = "_vhusb._tcp.local."
SSL_SERVICE_TYPE = "_ssl_vhusb._tcp.local."
DEFAULT_FRIENDLY_NAME = "VH Clone"
WATCH_INTERVAL_S = 5.0


TAILSCALE_NET = ipaddress.ip_network("100.64.0.0/10")  # overlay adapters carry no multicast, mDNS cannot work there


_NAME_CHECKERS = ("zeroconf._core", "zeroconf._services.info")  # modules that validate the service type name


def _accepts_strict(azc) -> bool:
    try:
        return "strict" in inspect.signature(azc.async_register_service).parameters
    except (TypeError, ValueError):
        return True  # cannot tell: assume a recent zeroconf and let the call itself decide


@contextlib.contextmanager
def _lenient_service_names():
    """zeroconf before ~0.6x validates the service type strictly and has no switch for it, but the stock type
    ``_ssl_vhusb`` contains an underscore (Debian 12 ships 0.47). Relax the check only while registering."""
    patched = []
    for module_name in _NAME_CHECKERS:
        try:
            module = importlib.import_module(module_name)
        except ImportError:
            continue
        original = getattr(module, "service_type_name", None)
        if original is not None:
            module.service_type_name = functools.partial(original, strict=False)
            patched.append((module, original))
    try:
        yield
    finally:
        for module, original in patched:
            module.service_type_name = original


def _multicast_capable(address: str) -> bool:
    ip = ipaddress.ip_address(address)
    return not (ip.is_loopback or ip.is_link_local or ip in TAILSCALE_NET)


def primary_ipv4() -> str | None:
    """Address of the interface holding the default route (a UDP connect sends no packet)."""
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.connect(("192.0.2.1", 9))  # TEST-NET-1, never routed off-link
        address = probe.getsockname()[0]
    except OSError:
        return None
    finally:
        probe.close()
    return address if _multicast_capable(address) else None


def local_ipv4_strings() -> list[str]:
    """Addresses to announce. Virtual adapters (WSL, Hyper-V) are unreachable for LAN clients, so the
    default-route interface wins; without a default route fall back to every multicast-capable address."""
    primary = primary_ipv4()
    if primary:
        return [primary]
    return [str(ip.ip) for adapter in ifaddr.get_adapters() for ip in adapter.ips
            if ip.is_IPv4 and _multicast_capable(str(ip.ip))]


def local_ipv4_addresses() -> list[bytes]:
    return [socket.inet_aton(addr) for addr in local_ipv4_strings()]


class Discovery:
    """Announces the service and keeps the announcement right when the network changes (cable, Wi-Fi, late DHCP)."""

    def __init__(self, serial: str, port: int, friendly_name: str = DEFAULT_FRIENDLY_NAME, *,
                 ssl_port: int | None = None, plain: bool = True,
                 address_provider: Callable[[], list[str]] = local_ipv4_strings,
                 zeroconf_factory: Callable[..., AsyncZeroconf] = AsyncZeroconf,
                 interval: float = WATCH_INTERVAL_S) -> None:
        self._serial, self._friendly_name = serial, friendly_name
        self._services = ([(SERVICE_TYPE, port)] if plain else []) + ([(SSL_SERVICE_TYPE, ssl_port)] if ssl_port else [])
        self._address_provider, self._factory, self._interval = address_provider, zeroconf_factory, interval
        self._azc: AsyncZeroconf | None = None
        self._infos: list[ServiceInfo] = []
        self._addresses: list[str] | None = []  # what is announced now; None forces the next check to try again
        self._watcher: asyncio.Task | None = None

    def _make_infos(self, addresses: list[str]) -> list[ServiceInfo]:
        host = socket.gethostname().split(".")[0]
        return [ServiceInfo(
            service_type,
            f"{self._friendly_name}{' (SSL)' if service_type == SSL_SERVICE_TYPE else ''}.{service_type}",  # as the stock server
            port=port,
            properties={self._serial.encode(): None},
            server=f"{host}.local.",
            addresses=[socket.inet_aton(address) for address in addresses],
        ) for service_type, port in self._services]

    async def start(self) -> None:
        try:
            await self._sync(sorted(self._address_provider()))
        except Exception:  # noqa: BLE001 - a failed first announcement must not stop the server; the watcher retries
            log.exception("cannot announce the server on mDNS yet, will retry")
        self._watcher = asyncio.create_task(self._watch(), name="mdns-watch")

    async def stop(self) -> None:
        if self._watcher is not None:
            self._watcher.cancel()
            await asyncio.gather(self._watcher, return_exceptions=True)
            self._watcher = None
        await self._withdraw()

    async def _sync(self, addresses: list[str]) -> None:
        await self._withdraw()
        if not addresses:
            log.info("no multicast-capable network: announcement paused until one appears")
            self._addresses = []  # nothing announced, nothing to retry until an address shows up
            return
        azc = self._factory(ip_version=IPVersion.V4Only, interfaces=addresses)
        registered: list[ServiceInfo] = []
        failure: Exception | None = None
        for info in self._make_infos(addresses):
            try:
                await self._register(azc, info)
            except Exception as exc:  # noqa: BLE001 - one service failing must not take the others down
                failure = exc
                log.warning("cannot announce %s on mDNS: %s%s", info.type, exc,
                            " (an older zeroconf cannot register this type: upgrade python3-zeroconf)"
                            if info.type == SSL_SERVICE_TYPE else "")
                continue
            registered.append(info)
        if not registered:
            await azc.async_close()
            raise failure if failure is not None else OSError("nothing to announce")
        self._azc, self._infos, self._addresses = azc, registered, addresses
        for info in registered:
            log.info("announced %s on mDNS at %s (port %d)", info.name, ", ".join(addresses), info.port)

    @staticmethod
    async def _register(azc, info: ServiceInfo) -> None:
        """'_ssl_vhusb' has an underscore: newer zeroconf accepts it with strict=False, older ones (Debian 12 ships
        0.47) have no such argument, so the name check is relaxed for the duration of the call."""
        if _accepts_strict(azc):
            await azc.async_register_service(info, allow_name_change=True, strict=False)
            return
        with _lenient_service_names():
            await azc.async_register_service(info, allow_name_change=True)

    async def _withdraw(self) -> None:
        azc, infos = self._azc, self._infos
        self._azc, self._infos = None, []
        self._addresses = None
        if azc is None:
            return
        try:
            for info in infos:
                await azc.async_unregister_service(info)
        except Exception:  # noqa: BLE001 - the interface may already be gone
            log.debug("withdrawing the announcement failed", exc_info=True)
        finally:
            await azc.async_close()

    async def _watch(self) -> None:
        while True:
            await asyncio.sleep(self._interval)
            try:
                current = sorted(self._address_provider())
                if current == self._addresses:
                    continue
                log.info("network changed (%s): announcing again", ", ".join(current) or "none")
                await self._sync(current)
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001 - keep watching; the next check retries
                log.exception("cannot update the mDNS announcement")
