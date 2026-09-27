"""Pure unit tests for the shared engagement-port -> target-URL helper used by
both the deterministic fingerprint phase (REQ-FIDELITY-003) and agent dispatch
(REQ-FIDELITY-007)."""

from __future__ import annotations

from app import target_envelope as te


def test_single_custom_port_is_detected():
    assert te.single_port_from_envelope({"tcp_port_from": 4280, "tcp_port_to": 4280}) == 4280


def test_full_range_envelope_yields_no_single_port():
    assert te.single_port_from_envelope({"tcp_port_from": 1, "tcp_port_to": 65535}) is None


def test_explicit_default_ports_yield_no_single_port():
    assert te.single_port_from_envelope({"tcp_port_from": 443, "tcp_port_to": 443}) is None
    assert te.single_port_from_envelope({"tcp_port_from": 80, "tcp_port_to": 80}) is None


def test_target_url_appends_custom_port():
    assert te.target_url("host.example.com", 4280) == "https://host.example.com:4280"


def test_target_url_defaults_to_443_without_single_port():
    assert te.target_url("host.example.com", None) == "https://host.example.com"


def test_target_url_leaves_an_existing_scheme_untouched():
    assert te.target_url("https://host.example.com:8443", 4280) == "https://host.example.com:8443"


def test_target_url_does_not_double_port_an_already_ported_host():
    # REQ-FIDELITY-007: an agent that already guessed "host:port" itself (the
    # exact workaround observed in a live run before this fix) must not get a
    # second port appended - that would build an invalid "host:4280:4280" URL.
    assert te.target_url("host.example.com:4280", 4280) == "https://host.example.com:4280"


# --- httpx_target: fixed twice.
#
# 2026-08-03: target_url() above always forces https://, which httpx respects
# rather than probing the other scheme - so a plain-HTTP service on a
# non-standard port (internal tools, dev/staging servers, admin panels on odd
# ports) got ZERO httpx results. First fix made this schemeless, reasoning
# "httpx auto-probes https-then-http for a bare host[:port]".
#
# CORRECTED 2026-08-04 (REQ-FIDELITY-010), found live deploying OWASP
# Benchmark (TLS-only, self-signed cert, non-standard port): that reasoning
# was wrong for a non-standard port - schemeless httpx does NOT probe https at
# all there, it assumes http and silently accepts whatever answers (here,
# Tomcat's "requires TLS" 400, misreported as a confirmed plain-HTTP service).
# Verified empirically which direction actually self-corrects: explicit
# http:// correctly upgraded itself to https against the OWASP Benchmark
# target; explicit https:// did NOT fall back to http against DVWA (a real
# plain-HTTP-only target) - no result at all, silently. So httpx_target() now
# always starts from an explicit http://, the one direction proven to
# self-correct both ways, never schemeless. ---

def test_httpx_target_uses_explicit_http_for_a_bare_host_and_port():
    assert te.httpx_target("host.example.com", 4280) == "http://host.example.com:4280"


def test_httpx_target_uses_explicit_http_without_a_single_port():
    assert te.httpx_target("host.example.com", None) == "http://host.example.com"


def test_httpx_target_leaves_an_existing_scheme_untouched():
    # some caller already built a full URL (e.g. an agent that guessed one
    # itself, or a confirmed-https re-scan) - httpx_target must not override
    # an explicit caller choice.
    assert te.httpx_target("https://host.example.com:8443", 4280) == "https://host.example.com:8443"


def test_httpx_target_does_not_double_port_an_already_ported_host():
    assert te.httpx_target("host.example.com:4280", 4280) == "http://host.example.com:4280"


# --- protocol_from_httpx_url: read the scheme httpx actually used, not a
# hardcoded assumption (same fix). ---

def test_protocol_from_httpx_url_reads_http():
    assert te.protocol_from_httpx_url("http://host.example.com:4280/") == "http"


def test_protocol_from_httpx_url_reads_https():
    assert te.protocol_from_httpx_url("https://host.example.com/") == "https"


def test_protocol_from_httpx_url_falls_back_when_url_is_missing_or_malformed():
    assert te.protocol_from_httpx_url("") == "https"
    assert te.protocol_from_httpx_url("not-a-url") == "https"


# --- REQ-FIDELITY-009: target_url's optional confirmed-protocol parameter ---

def test_target_url_uses_confirmed_http_scheme():
    assert te.target_url("host.example", 8080, "http") == "http://host.example:8080"


def test_target_url_keeps_https_for_confirmed_https():
    assert te.target_url("host.example", 8443, "https") == "https://host.example:8443"


def test_target_url_without_protocol_is_unchanged_https_default():
    """The pre-existing behaviour must survive: an unknown protocol is still
    https, which is the right guess for the public web and keeps every
    existing caller/test valid."""
    assert te.target_url("host.example", 8443) == "https://host.example:8443"
    assert te.target_url("host.example", None) == "https://host.example"


def test_target_url_ignores_unrecognised_protocol_values():
    """NEGATIVE: only a literal 'http' downgrades the scheme. Anything else
    (None, empty, a transport name, junk) must fall back to https rather than
    producing a bogus scheme like 'tcp://'."""
    for bogus in (None, "", "   ", "tcp", "udp", "ftp", "HTTPS", "nonsense"):
        assert te.target_url("host.example", 8443, bogus).startswith("https://"), bogus


def test_target_url_confirmed_protocol_is_case_insensitive():
    assert te.target_url("host.example", 80, "HTTP") == "http://host.example:80"


def test_target_url_never_double_prefixes_an_existing_scheme():
    assert te.target_url("http://host.example:8080", 8080, "https") == "http://host.example:8080"


def test_httpx_target_never_returns_bare_schemeless_host():
    """REQ-FIDELITY-010 regression guard: the specific defect was httpx_target
    ever producing a schemeless string. Assert the invariant directly, not
    just the specific examples above, so a future edit cannot silently
    reintroduce it for some other input shape."""
    for host, port in [("h.example", 4280), ("h.example", None), ("h.example:9000", 9000)]:
        result = te.httpx_target(host, port)
        assert result.startswith("http://") or result.startswith("https://"), result
