"""REQ-DISCO-001..004: a discovery hit must be a distinct response, and the
platform's own denial is never evidence about a target.

Modelled on real measurements from int run 019fec2a-a66c-762b-a68d-571a854c4b44,
where three hosts produced 1677/1677/1800 "discovered paths" that were in fact
one response each:

    scan-int.example.org   1677 hits, 100%  (200, 396)  <- SPA catch-all
    scan.example.org       1677 hits, 99.9% (200, 396)  <- SPA catch-all
    synapp-int.example.org 1800 hits, 100%  (403,  21)  <- our own proxy denial

Two of those hosts resolve and serve real content, so this is not confined to
broken targets - which is what makes the fabricated findings dangerous.
"""

from __future__ import annotations

import json

import pytest

from app.ffuf_parse import is_catch_all, parse_ffuf_json
from app.tasks import fingerprint

EID = "11111111-1111-1111-1111-111111111111"
RUN = "22222222-2222-2222-2222-222222222222"


def _hits(n: int, status: int, length: int, *, distinct_tail: int = 0) -> list[dict]:
    out = [{"word": f"p{i}", "url": f"https://x/{i}", "status": status, "length": length}
           for i in range(n - distinct_tail)]
    out += [{"word": f"q{i}", "url": f"https://x/q{i}", "status": 200, "length": 1000 + i}
            for i in range(distinct_tail)]
    return out


# --- REQ-DISCO-001: the three observed cases must yield nothing -------------

@pytest.mark.parametrize("n,status,length,label", [
    (1677, 200, 396, "scan-int SPA catch-all"),
    (1800, 403, 21, "our own proxy denial (dns_resolution_failed is 21 bytes)"),
])
def test_negative_the_observed_catch_all_cases_are_rejected(n, status, length, label):
    assert is_catch_all(_hits(n, status, length)) is True, label


def test_negative_a_catch_all_with_one_genuine_outlier_is_still_rejected():
    """Observed on scan.example.org: 1676 of 1677 identical, one 0-length
    straggler. A single outlier must not rescue the whole set."""
    assert is_catch_all(_hits(1677, 200, 396, distinct_tail=1)) is True


# --- REQ-DISCO-001: real discovery must survive ----------------------------

def test_a_genuinely_varied_result_set_is_kept():
    """The fix must not suppress real content discovery - that is the tool's
    entire purpose."""
    hits = [
        {"word": "admin", "url": "https://x/admin", "status": 200, "length": 5120},
        {"word": ".git/config", "url": "https://x/.git/config", "status": 200, "length": 92},
        {"word": "backup.zip", "url": "https://x/backup.zip", "status": 200, "length": 998877},
        {"word": "login", "url": "https://x/login", "status": 302, "length": 0},
        {"word": "api", "url": "https://x/api", "status": 401, "length": 33},
    ] * 4
    assert is_catch_all(hits) is False


def test_a_small_uniform_result_set_is_not_discarded():
    """Two or three same-sized 200s are a plausible real result, not evidence
    of a catch-all - the guard targets wildcard behaviour, not coincidence."""
    assert is_catch_all(_hits(3, 200, 512)) is False
    assert is_catch_all([]) is False


def test_a_mixed_set_just_under_the_threshold_is_kept():
    """80% uniform is suspicious but not conclusive; the guard only fires at
    the overwhelming-majority mark, erring toward keeping findings."""
    assert is_catch_all(_hits(100, 200, 396, distinct_tail=20)) is False


# --- REQ-DISCO-001: wired into the fingerprint path ------------------------

def _discovery_harness(monkeypatch, hits):
    recorded: list[dict] = []
    findings: list[dict] = []
    monkeypatch.setattr(fingerprint, "_propose", lambda *a, **k: {"allowed": True})
    monkeypatch.setattr(fingerprint.tool_runner, "run",
                        lambda *a, **k: {"success": True, "stdout": json.dumps({"results": []})})
    monkeypatch.setattr(fingerprint, "parse_ffuf_json", lambda _s: hits)
    monkeypatch.setattr(fingerprint.tool_execution, "record", lambda *a, **k: recorded.append(k))
    monkeypatch.setattr(fingerprint.client, "add_finding", lambda *a, **k: findings.append(k))
    fingerprint._content_discovery(EID, "asset-1", "host.example.com", RUN, None, "https")
    return recorded, findings


def test_negative_a_catch_all_produces_no_finding_but_is_still_recorded(monkeypatch):
    recorded, findings = _discovery_harness(monkeypatch, _hits(1800, 403, 21))

    assert findings == [], "a catch-all must never become a content-discovery finding"
    # Recorded, not silently dropped: an operator must see that discovery ran
    # and why it produced nothing (REQ-SCAN-014 depends on honest outcomes).
    assert len(recorded) == 1
    assert recorded[0]["result"]["error_reason"] == "content_discovery_catch_all"
    assert recorded[0]["result"]["success"] is False


def test_a_real_result_set_still_produces_its_finding(monkeypatch):
    hits = [
        {"word": "admin", "url": "https://x/admin", "status": 200, "length": 5120},
        {"word": ".git/config", "url": "https://x/.git/config", "status": 200, "length": 92},
        {"word": "backup.zip", "url": "https://x/backup.zip", "status": 200, "length": 998877},
    ] * 5
    recorded, findings = _discovery_harness(monkeypatch, hits)

    assert len(findings) == 1
    assert "Content discovery" in findings[0]["title"]
    assert recorded[0]["result"]["success"] is True


# --- REQ-DISCO-001: ffuf's own calibration is enabled ----------------------

def test_ffuf_runs_with_auto_calibration():
    """-ac is ffuf's purpose-built remedy: it probes known-nonexistent paths
    first and filters responses matching the catch-all signature."""
    from app import tool_runner_client as trc
    cmd = trc._ffuf_command("https://host.example.com", {"wordlist": "quickhits"})
    assert " -ac " in cmd or cmd.endswith(" -ac") or "'-ac'" in cmd


# --- REQ-DISCO-004: no web tooling against an unresolvable host ------------

def test_negative_an_unresolved_host_runs_no_web_tools_at_all(monkeypatch):
    """The NXDOMAIN case: nmap already refused it (materialized_ip_missing);
    the web tools used to proceed anyway and generated ~33,000 denied
    requests plus fabricated findings."""
    called: list[str] = []
    recorded: list[dict] = []
    for tool in ("_http_probe", "_web_enum", "_waf_detect", "_tls_scan", "_nuclei_scan", "_content_discovery"):
        monkeypatch.setattr(fingerprint, tool, lambda *a, _t=tool, **k: called.append(_t))
    monkeypatch.setattr(fingerprint.tool_execution, "record", lambda *a, **k: recorded.append(k))

    out = fingerprint._web_suite(
        fingerprint._RunContext(), EID, "asset-1", "nxdomain.example.com", None, RUN, None,
    )

    assert out == []
    assert called == [], "no web tool may run without a materialized IP"
    # Every skipped tool is recorded, so the audit trail explains the absence.
    assert {r["tool"] for r in recorded} == {"httpx", "nikto", "wafw00f", "testssl", "ffuf", "nuclei"}
    assert all(r["result"]["error_reason"] == "materialized_ip_missing" for r in recorded)


def test_a_resolved_host_is_unaffected_and_runs_the_suite(monkeypatch):
    called: list[str] = []
    monkeypatch.setattr(fingerprint, "_http_probe",
                        lambda *a, **k: {"url": "https://h", "status_code": 200, "webserver": "nginx",
                                         "title": "t", "content_length": 10})
    for tool in ("_web_enum", "_waf_detect", "_tls_scan", "_nuclei_scan", "_content_discovery"):
        monkeypatch.setattr(fingerprint, tool, lambda *a, _t=tool, **k: called.append(_t))
    monkeypatch.setattr(fingerprint.tool_execution, "record", lambda *a, **k: None)

    fingerprint._web_suite(
        fingerprint._RunContext(), EID, "asset-1", "real.example.com", "192.0.2.10", RUN, None,
    )

    assert called == ["_waf_detect", "_tls_scan", "_web_enum", "_content_discovery", "_nuclei_scan"]


# --- REQ-DISCO-003: a denial-marked response is never target evidence ------

def _httpx_line(**over) -> str:
    rec = {"url": "https://h.example.com", "input": "h.example.com", "port": 443,
           "status_code": 403, "title": "", "webserver": "", "tech": []}
    rec.update(over)
    return json.dumps(rec)


def test_negative_a_proxy_denial_is_not_parsed_as_a_live_service():
    """The exact observed case: an NXDOMAIN host whose only 'response' was our
    own proxy's `403 Blocked` + `dns_resolution_failed` was recorded as a live
    service, which then let the whole web suite loose on it."""
    from app.httpx_parse import parse_httpx_json

    line = _httpx_line(header={"X-ASM-Egress-Denied": "dns_resolution_failed",
                              "Content-Length": "21"})
    assert parse_httpx_json(line) == []


def test_negative_the_marker_is_matched_case_insensitively():
    from app.httpx_parse import parse_httpx_json

    for name in ("X-ASM-Egress-Denied", "x-asm-egress-denied", "X-Asm-Egress-Denied"):
        assert parse_httpx_json(_httpx_line(header={name: "out_of_scope_port"})) == [], name


def test_negative_the_marker_is_also_detected_in_a_raw_response_blob():
    from app.httpx_parse import parse_httpx_json

    raw = "HTTP/1.1 403 Blocked\r\nX-ASM-Egress-Denied: not_in_scope\r\n\r\nnot_in_scope"
    assert parse_httpx_json(_httpx_line(response=raw)) == []


def test_a_genuine_403_from_a_real_target_is_still_recorded():
    """Critical counterpart: hosts that legitimately answer 403 (observed:
    events-test.example.org) must keep producing findings. The fix must
    suppress OUR denials, never the target's own responses."""
    from app.httpx_parse import parse_httpx_json

    rows = parse_httpx_json(_httpx_line(
        status_code=403, title="403 Forbidden", webserver="nginx",
        header={"Server": "nginx", "Content-Type": "text/html"},
    ))
    assert len(rows) == 1
    assert rows[0]["status_code"] == 403
    assert rows[0]["webserver"] == "nginx"


def test_httpx_requests_the_response_headers_it_needs_for_this():
    """Without -include-response-header the marker never reaches the parser."""
    from app import tool_runner_client as trc
    assert "-include-response-header" in trc._httpx_command("http://h.example.com", {})
