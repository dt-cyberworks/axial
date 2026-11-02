"""REQ-HANDOVER-005 (GitHub #84): the assessment's agent is told what monitoring found, as context and nothing more."""

from __future__ import annotations

from app.tasks import agent

ENG = "11111111-1111-1111-1111-111111111111"
KNOWN = {
    "source": {"id": "m-1", "title": "Sirkos Application"},
    "as_of": "2026-10-29T08:10:00+00:00",
    "note": "This is what an earlier unattended run of the monitoring engagement reported. It is not verified in this engagement.",
    "hosts": [
        {"host": "www.example.test",
         "services": [{"port": 443, "protocol": "tcp", "product": "nginx", "version": "1.25.3"}],
         "findings": [{"title": "Missing HSTS", "severity": "low", "category": "misconfig", "cve_ids": ["CVE-2024-0001"], "port": 443}]},
    ],
}


def _context(monkeypatch, ctx):
    monkeypatch.setattr(agent.client, "get_agent_context", lambda eid: ctx)
    return agent._initial_context(ENG, {"www.example.test": "asset-1"})


def test_the_block_names_the_source_the_date_the_services_and_the_open_findings(monkeypatch):
    text = _context(monkeypatch, {"hosts": [], "known_from_monitor": KNOWN})
    assert "KNOWN FROM MONITORING" in text and 'monitoring engagement "Sirkos Application"' in text
    assert "2026-10-29T08:10:00+00:00" in text
    assert "www.example.test: services: 443/tcp nginx 1.25.3" in text
    assert "[low] Missing HSTS (port 443) CVE-2024-0001" in text


def test_the_block_says_it_is_context_only_and_not_verified(monkeypatch):
    text = _context(monkeypatch, {"hosts": [], "known_from_monitor": KNOWN})
    assert "does NOT change what is in scope" in text
    assert "not verified" in text.lower()


def test_without_the_section_or_without_hosts_the_prompt_is_unchanged(monkeypatch):
    plain = _context(monkeypatch, {"hosts": []})
    assert "KNOWN FROM MONITORING" not in plain
    assert "KNOWN FROM MONITORING" not in _context(monkeypatch, {"hosts": [], "known_from_monitor": {**KNOWN, "hosts": []}})
    assert "KNOWN FROM MONITORING" not in _context(monkeypatch, {"hosts": [], "known_from_monitor": "not a dict"})


def test_the_block_sits_between_the_evidence_and_the_instruction_to_work(monkeypatch):
    text = _context(monkeypatch, {"hosts": [], "known_from_monitor": KNOWN})
    assert text.index("starting intelligence") < text.index("KNOWN FROM MONITORING") < text.index("Now work the surface")


def test_negative_what_is_rendered_is_capped_and_never_a_scope_list(monkeypatch):
    many = {**KNOWN, "hosts": [{"host": f"h{i}.example.test", "services": [], "findings": []} for i in range(200)]}
    rendered = agent._render_known_from_monitor(many)
    assert rendered.count("\n- ") <= 40, "no more than 40 hosts reach the model"
    huge = {**KNOWN, "hosts": [{"host": "www.example.test", "services": [],
                                "findings": [{"title": "T" * 500, "severity": "low"}] * 50}]}
    line = [l for l in agent._render_known_from_monitor(huge).splitlines() if l.startswith("- www")][0]
    assert line.count("[low]") <= 15 and "T" * 101 not in line


def test_negative_an_evidence_field_that_should_not_be_there_is_not_rendered(monkeypatch):
    sneaky = {**KNOWN, "hosts": [{"host": "www.example.test", "services": [],
                                  "findings": [{"title": "x", "severity": "low", "evidence": {"cookie": "SESSION=abc"}}]}]}
    assert "SESSION=abc" not in agent._render_known_from_monitor(sneaky)
