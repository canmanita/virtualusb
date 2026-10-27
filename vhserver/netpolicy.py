"""Who may connect. The wire protocol has no authentication, so access is restricted by source address.

By default only loopback, link-local and private networks are accepted (including the 100.64.0.0/10 range used by
Tailscale), which keeps a server that is reachable from the internet from being driven by strangers.
"""
from __future__ import annotations

import ipaddress
from typing import Iterable

DEFAULT_ALLOWED = (
    "127.0.0.0/8",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "169.254.0.0/16",
    "100.64.0.0/10",
    "::1/128",
    "fc00::/7",
    "fe80::/10",
)


class AccessPolicy:
    def __init__(self, allowed: Iterable[str] = DEFAULT_ALLOWED) -> None:
        self._networks = tuple(ipaddress.ip_network(n, strict=False) for n in allowed)

    def permits(self, address: str) -> bool:
        try:
            ip = ipaddress.ip_address(address.split("%", 1)[0])
        except ValueError:
            return False
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
            ip = ip.ipv4_mapped
        return any(ip in net for net in self._networks)
