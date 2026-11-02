"""REQ-SCAN-016: the control plane's address vetting and the egress proxy's must agree.

The rule that says which addresses can never be a scan target exists twice, once for the raw path (the control plane,
control-plane/app/gateway/address_vetting.py) and once for the proxy path (egress-proxy/app/ssrf_guard.py), because the
two are separate processes with separate packages that are both called `app`. If one learns a new form and the other
does not, a name is refused on one path and port-scanned on the other. Both modules are loaded by path.
"""

from __future__ import annotations

import importlib.util
import ipaddress
import itertools
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def _load(name: str, relative: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


control_plane = _load("cp_address_vetting", "control-plane/app/gateway/address_vetting.py")
proxy = _load("proxy_ssrf_guard", "egress-proxy/app/ssrf_guard.py")

# Boundaries of every class the rule names, in both families, and the embedded-IPv4 forms around them.
V4_EDGES = [
    "0.0.0.0", "0.255.255.255", "1.0.0.0", "9.255.255.255", "10.0.0.1", "100.64.0.1", "126.255.255.255", "127.0.0.1",
    "127.255.255.255", "128.0.0.1", "169.253.255.255", "169.254.0.1", "169.254.169.254", "169.255.0.0", "172.15.0.1",
    "172.16.0.1", "172.31.255.255", "192.0.2.1", "192.168.0.1", "198.51.100.1", "203.0.113.9", "223.255.255.255",
    "224.0.0.1", "239.255.255.255", "240.0.0.1", "255.255.255.254", "255.255.255.255",
]
V6_BASES = [
    "::", "::1", "::2", "fe7f::1", "fe80::1", "febf::1", "fec0::1", "fc00::1", "fd12:3456::1", "ff00::1", "ff02::1",
    "2001:db8::1", "2606:4700::1111", "2a00:1450::1", "100::1", "64:ff9b::1", "2002::1",
]
EMBEDDING = ["::ffff:{v4}", "64:ff9b::{hex}", "2002:{hex}::1"]


def _hex(v4: str) -> str:
    packed = ipaddress.IPv4Address(v4).packed
    return f"{packed[0]:02x}{packed[1]:02x}:{packed[2]:02x}{packed[3]:02x}"


def _addresses() -> list[str]:
    out = list(V4_EDGES) + list(V6_BASES)
    for v4, form in itertools.product(V4_EDGES, EMBEDDING):
        out.append(form.format(v4=v4, hex=_hex(v4)))
    return out


def test_both_rules_judge_every_boundary_address_and_embedded_form_alike():
    disagreements = []
    for text in _addresses():
        ip = ipaddress.ip_address(text)
        if control_plane.classify(ip) != proxy._classify(ip):
            disagreements.append((text, control_plane.classify(ip), proxy._classify(ip)))
    assert not disagreements, disagreements


def test_the_corpus_is_not_trivially_one_sided():
    reasons = {control_plane.classify(ipaddress.ip_address(t)) for t in _addresses()}
    assert None in reasons and {
        "blocked_loopback_address", "blocked_link_local_address", "blocked_unspecified_address",
        "blocked_multicast_address", "blocked_reserved_address",
    } <= reasons
