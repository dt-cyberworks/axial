"""Addresses that can never be a legitimate scan target (REQ-HARDEN-002, REQ-SCAN-016; GitHub #77).

The egress proxy refuses a name that resolves to such an address before it connects (egress-proxy/app/ssrf_guard.py).
The raw path (nmap through the raw-egress gateway) did not look at the class of an address at all: it only compared
the address with the audited materialization, and the materialization accepted whatever a scoped name resolved to.
A name an attacker controls could therefore be made to resolve to the loopback of the scanner's own network namespace,
the cloud metadata address or a link-local address, and be port-scanned from inside. This module is the shared rule,
applied where the materialization is built and again where a raw-egress lease is issued.

Private ranges (RFC 1918, unique-local fc00::/7) are deliberately NOT refused: lab targets and internal own-domain
engagements live there, and scope already gates them. The rule is a copy of the proxy's across the process boundary on
purpose; scripts/tests/test_address_vetting_parity.py fails when the two disagree.
"""

from __future__ import annotations

import ipaddress

_NAT64 = ipaddress.ip_network("64:ff9b::/96")
_SIXTO4 = ipaddress.ip_network("2002::/16")


def _embedded_v4(ip: ipaddress.IPv6Address) -> ipaddress.IPv4Address | None:
    """The IPv4 address an IPv6 address carries, so that `::ffff:127.0.0.1`, the NAT64 form `64:ff9b::7f00:1` and the
    6to4 form `2002:7f00:1::` are judged as the IPv4 address they reach."""
    if ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    if ip in _NAT64:
        return ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
    if ip in _SIXTO4:
        return ipaddress.IPv4Address((int(ip) >> 80) & 0xFFFFFFFF)
    return None


def classify(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str | None:
    """A reason when this address may never be a scan target, else None."""
    if isinstance(ip, ipaddress.IPv6Address):
        embedded = _embedded_v4(ip)
        if embedded is not None:
            return classify(embedded)
    if ip.is_loopback:
        return "blocked_loopback_address"
    if ip.is_link_local:
        return "blocked_link_local_address"  # 169.254.0.0/16 (cloud metadata) and fe80::/10
    if ip.is_unspecified:
        return "blocked_unspecified_address"
    if ip.is_multicast:
        return "blocked_multicast_address"
    if ip.is_reserved:
        return "blocked_reserved_address"
    return None


def never_legitimate_reason(address: str) -> str | None:
    """`classify` for a string, which may carry an IPv6 zone id (`fe80::1%eth0`, which `ipaddress` parses and judges by
    its address). An address that cannot be parsed is refused too: the question is only asked about an address that
    is about to be used."""
    try:
        ip = ipaddress.ip_address(str(address).strip())
    except ValueError:
        return "blocked_unparseable_address"
    return classify(ip)
