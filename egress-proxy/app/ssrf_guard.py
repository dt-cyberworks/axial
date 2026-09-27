"""SSRF containment for the egress-proxy (REQ-HARDEN-002).

The proxy authorizes a request against engagement scope by HOST NAME (or an
audited materialized IP), then connects to that host. Upstream it connected by
name, so DNS resolution happened at connect time with no address vetting. A
scoped name that resolves - now or via DNS rebinding - to a loopback,
link-local, or the cloud-metadata address (169.254.169.254) would let a scan
reach the proxy's own host, the container's neighbours, or the instance
metadata service, entirely inside "allowed" scope.

This module resolves the target once, refuses the never-legitimate address
classes, and returns a vetted IP to connect to (pinning it also closes the
resolve-then-connect rebinding window). Private ranges (RFC1918, ULA) are
deliberately NOT blocked: lab targets and internal own-domain engagements
legitimately live there, and scope enforcement already gates them. Only
addresses that can never be a legitimate scan target are refused.
"""

from __future__ import annotations

import ipaddress
import socket
from typing import Callable

# getaddrinfo-compatible resolver signature, injectable for tests.
Resolver = Callable[[str, int], list]


class BlockedAddressError(RuntimeError):
    """Raised when a target resolves to a never-legitimate address class."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def _classify(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str | None:
    """Return a block reason if this address may never be a scan target, else None."""
    # IPv4-mapped IPv6 (::ffff:a.b.c.d) - evaluate the embedded v4 address too.
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return _classify(ip.ipv4_mapped)
    if ip.is_loopback:
        return "blocked_loopback_address"
    if ip.is_link_local:
        # Covers 169.254.0.0/16 (incl. 169.254.169.254 cloud metadata) and fe80::/10.
        return "blocked_link_local_address"
    if ip.is_unspecified:
        return "blocked_unspecified_address"
    if ip.is_multicast:
        return "blocked_multicast_address"
    if ip.is_reserved:
        return "blocked_reserved_address"
    return None


def vet_target_host(host: str, port: int, *, resolver: Resolver | None = None) -> str:
    """Resolve ``host`` and return a single vetted IP literal to connect to.

    Raises BlockedAddressError if the host is, or resolves to, any
    never-legitimate address class. If ANY resolved address is blocked the whole
    target is refused (fail-closed against split-horizon / rebinding tricks that
    mix a public and a metadata address).
    """
    resolve = resolver or socket.getaddrinfo

    # A literal IP target skips DNS entirely.
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        literal = None
    if literal is not None:
        reason = _classify(literal)
        if reason is not None:
            raise BlockedAddressError(reason)
        return str(literal)

    try:
        infos = resolve(host, port)
    except OSError as exc:
        raise BlockedAddressError("dns_resolution_failed") from exc

    vetted: list[str] = []
    for info in infos:
        sockaddr = info[4]
        try:
            ip = ipaddress.ip_address(sockaddr[0])
        except ValueError:
            continue
        reason = _classify(ip)
        if reason is not None:
            # One bad answer poisons the whole name - never connect to any of them.
            raise BlockedAddressError(reason)
        vetted.append(str(ip))

    if not vetted:
        raise BlockedAddressError("dns_resolution_failed")
    return vetted[0]
