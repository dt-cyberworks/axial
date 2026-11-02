"""REQ-SCORE-002/005 (GitHub #87): the worker hands the control plane what the rating needs.

* the CVE testssl names for a vulnerability check, so Heartbleed-class findings are rated as vulnerabilities and a certificate note is not;
  it goes into the evidence and NOT into `cve_ids`, because `cve_ids` is part of a finding's fingerprint and adding it would turn every
  existing finding into a "new" one (a flood of alerts on every monitor);
* the name the certificate check was run against, so a mismatch on a mail port can be read for what it is."""

from __future__ import annotations

import json

from app.tasks import fingerprint
from app.testssl_parse import parse_testssl_json

RECORDS = [
    {"id": "cert_trust", "severity": "HIGH", "finding": "certificate does not match supplied URI (same w/o SNI)"},
    {"id": "heartbleed", "severity": "CRITICAL", "finding": "VULNERABLE", "cve": "CVE-2014-0160", "cwe": "CWE-119"},
    {"id": "SWEET32", "severity": "LOW", "finding": "uses 64 bit block ciphers", "cve": "CVE-2016-2183 CVE-2016-6329"},
    {"id": "cert_trust", "severity": "HIGH", "finding": "certificate does not match supplied URI (same w/o SNI)"},  # duplicate
    {"id": "TLS1_3", "severity": "OK", "finding": "offered"},
]


def test_the_parser_keeps_the_cves_testssl_names_and_drops_duplicates_and_ok_records():
    findings = parse_testssl_json(json.dumps(RECORDS))
    by_id = {f["id"]: f for f in findings}
    assert set(by_id) == {"cert_trust", "heartbleed", "SWEET32"} and len(findings) == 3
    assert by_id["cert_trust"]["cve"] == []
    assert by_id["heartbleed"]["cve"] == ["CVE-2014-0160"]
    assert by_id["SWEET32"]["cve"] == ["CVE-2016-2183", "CVE-2016-6329"]
    assert by_id["cert_trust"]["severity"] == "high", "the tool's label is still parsed, it is evidence"


def test_negative_free_text_in_the_cve_field_is_not_taken_for_a_cve():
    findings = parse_testssl_json(json.dumps([{"id": "x", "severity": "HIGH", "finding": "f", "cve": "see RFC 7525, not CVE"}]))
    assert findings[0]["cve"] == []


def _scan(monkeypatch, parsed, *, service=False):
    written = []
    monkeypatch.setattr(fingerprint.tool_runner, "run", lambda *a, **k: {"success": True, "stdout": "[]"})
    monkeypatch.setattr(fingerprint, "parse_testssl_json", lambda stdout: parsed)
    monkeypatch.setattr(fingerprint.tool_execution, "record", lambda *a, **k: None)
    monkeypatch.setattr(fingerprint, "_propose", lambda *a, **k: {"allowed": True})
    monkeypatch.setattr(fingerprint, "_add_finding", lambda eng, **k: written.append(k))
    if service:
        fingerprint._tls_service_scan("11111111-1111-1111-1111-111111111111", "a1", "mail.example.com", "1.2.3.4", "run-1", 993,
                                      service_name="imaps", starttls=None)
    else:
        fingerprint._tls_scan("11111111-1111-1111-1111-111111111111", "a1", "host.example.com", "1.2.3.4", "run-1",
                              single_port=443, confirmed_protocol="https")
    return written


def test_a_web_tls_finding_carries_the_tested_name_and_the_cve(monkeypatch):
    parsed = [{"id": "heartbleed", "severity": "critical", "title": "TLS: heartbleed - VULNERABLE", "cve": ["CVE-2014-0160"]},
              {"id": "cert_trust", "severity": "high", "title": "TLS: cert_trust - x", "cve": []}]
    written = _scan(monkeypatch, parsed)
    heartbleed, trust = (w["evidence"] for w in written)
    assert heartbleed["tested_name"] == "host.example.com" and heartbleed["cve"] == ["CVE-2014-0160"]
    assert trust["tested_name"] == "host.example.com" and "cve" not in trust, "no empty key when testssl names no CVE"
    assert all("cve_ids" not in w for w in written), "cve_ids would change the fingerprint of every existing finding"


def test_a_mail_port_finding_says_which_name_it_tested(monkeypatch):
    written = _scan(monkeypatch, [{"id": "cert_trust", "severity": "high", "title": "TLS: cert_trust - x", "cve": []}], service=True)
    ev = written[0]["evidence"]
    assert (ev["tested_name"], ev["port"], ev["service"]) == ("mail.example.com", 993, "imaps")
    assert written[0]["severity_override"] == "high", "the label is sent unchanged; the control plane rates it"
