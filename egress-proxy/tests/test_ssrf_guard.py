"""REQ-HARDEN-002: the egress-proxy refuses to connect to never-legitimate
address classes (loopback, link-local/cloud-metadata, unspecified, multicast,
reserved) even when engagement scope allows the host name, and pins the vetted
IP to close the resolve-then-connect DNS-rebinding window. Private ranges stay
allowed (lab + internal own-domain targets legitimately use them)."""

from __future__ import annotations

import socket

import pytest

from app.ssrf_guard import BlockedAddressError, vet_target_host


def _resolver(*addresses):
    """Build a getaddrinfo-compatible stub returning the given IPs."""
    def resolve(host, port):
        infos = []
        for addr in addresses:
            family = socket.AF_INET6 if ":" in addr else socket.AF_INET
            sockaddr = (addr, port, 0, 0) if family == socket.AF_INET6 else (addr, port)
            infos.append((family, socket.SOCK_STREAM, 6, "", sockaddr))
        return infos
    return resolve


# --- literal IP targets (testssl --ip / materialized IP path) ---------------

def test_literal_public_ip_is_allowed():
    assert vet_target_host("203.0.113.10", 443) == "203.0.113.10"


def test_literal_private_ip_is_allowed_for_lab_and_internal_targets():
    # metasploitable2 / own-domain internal hosts legitimately live here.
    assert vet_target_host("172.20.0.5", 443) == "172.20.0.5"
    assert vet_target_host("10.1.2.3", 80) == "10.1.2.3"
    assert vet_target_host("192.168.1.4", 8443) == "192.168.1.4"


@pytest.mark.parametrize("addr,reason", [
    ("127.0.0.1", "blocked_loopback_address"),
    ("169.254.169.254", "blocked_link_local_address"),  # cloud metadata
    ("0.0.0.0", "blocked_unspecified_address"),
    ("::1", "blocked_loopback_address"),
    ("fe80::1", "blocked_link_local_address"),
    ("::ffff:127.0.0.1", "blocked_loopback_address"),   # v4-mapped loopback
    ("::ffff:169.254.169.254", "blocked_link_local_address"),
])
def test_literal_forbidden_addresses_are_blocked(addr, reason):
    with pytest.raises(BlockedAddressError) as exc:
        vet_target_host(addr, 443)
    assert exc.value.reason == reason


# --- name resolution + DNS rebinding ---------------------------------------

def test_name_resolving_to_public_ip_is_allowed():
    out = vet_target_host("scan-me.example.com", 443, resolver=_resolver("203.0.113.7"))
    assert out == "203.0.113.7"


def test_name_resolving_to_metadata_is_blocked():
    with pytest.raises(BlockedAddressError) as exc:
        vet_target_host("rebind.evil.test", 80, resolver=_resolver("169.254.169.254"))
    assert exc.value.reason == "blocked_link_local_address"


def test_split_horizon_answer_with_one_bad_ip_blocks_the_whole_name():
    # A public + a metadata answer must NOT be salvaged into the public one.
    with pytest.raises(BlockedAddressError):
        vet_target_host("dual.evil.test", 443, resolver=_resolver("203.0.113.9", "169.254.169.254"))


def test_unresolvable_name_fails_closed():
    def boom(host, port):
        raise OSError("NXDOMAIN")
    with pytest.raises(BlockedAddressError) as exc:
        vet_target_host("nope.example.com", 443, resolver=boom)
    assert exc.value.reason == "dns_resolution_failed"


def test_name_resolving_to_private_ip_is_allowed():
    out = vet_target_host("internal.corp.test", 443, resolver=_resolver("10.0.0.5"))
    assert out == "10.0.0.5"


# --- GitHub #77: the IPv6 literal forms and the IPv4 addresses they carry ------------------------

@pytest.mark.parametrize("literal, reason", [
    ("::1", "blocked_loopback_address"),
    ("fe80::1", "blocked_link_local_address"),
    ("fe80::1%eth0", "blocked_link_local_address"),             # a zone id does not hide a link-local address
    ("::", "blocked_unspecified_address"),
    ("ff02::1", "blocked_multicast_address"),
    ("::ffff:127.0.0.1", "blocked_loopback_address"),          # IPv4-mapped loopback
    ("::ffff:169.254.169.254", "blocked_link_local_address"),  # IPv4-mapped cloud metadata
    ("64:ff9b::7f00:1", "blocked_loopback_address"),           # NAT64 form of 127.0.0.1
    ("64:ff9b::a9fe:a9fe", "blocked_link_local_address"),      # NAT64 form of the metadata address
    ("2002:7f00:1::", "blocked_loopback_address"),             # 6to4 form of 127.0.0.1
    ("2002:a9fe:a9fe::1", "blocked_link_local_address"),       # 6to4 form of the metadata address
])
def test_negative_ipv6_literal_forms_that_reach_a_never_legitimate_address_are_refused(literal, reason):
    with pytest.raises(BlockedAddressError) as caught:
        vet_target_host(literal, 443)
    assert caught.value.reason == reason


@pytest.mark.parametrize("literal", ["2606:4700::1111", "fc00::5", "fd12:3456::7", "::ffff:203.0.113.9", "64:ff9b::cb00:7109"])
def test_ipv6_public_unique_local_and_embedded_public_addresses_stay_allowed(literal):
    import ipaddress

    assert vet_target_host(literal, 443) == str(ipaddress.ip_address(literal))


@pytest.mark.parametrize("bad", ["::1", "fe80::5", "::ffff:127.0.0.1", "64:ff9b::7f00:1", "2002:7f00:1::"])
def test_negative_a_name_with_one_bad_aaaa_answer_is_refused_whole_even_next_to_a_public_one(bad):
    with pytest.raises(BlockedAddressError):
        vet_target_host("scoped.example", 443, resolver=_resolver("2606:4700::1111", "203.0.113.10", bad))
