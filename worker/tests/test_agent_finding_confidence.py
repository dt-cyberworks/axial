"""REQ-AGENT-021 / TC-AGENT-021: an agent-reported finding's confidence and
severity must reflect what its evidence actually supports.

R3 requirement - the negative cases below are mandatory, not optional. The
defect these lock down was measured live (2026-08-03): 47 of 47 vector_agent
findings in the dev database were persisted as confidence="validated",
because `_handle_report_finding` hardcoded it and the tool schema gave the
model no way to express doubt. Findings whose own rationale conceded they
were derived from the engagement title - not from any observation - were
stored as validated/critical/risk_score 85.0, indistinguishable from a
demonstrated exploit.

Two things are load-bearing here and must not be relaxed to make a future
change pass:
  1. only `direct_technical_proof` may yield confidence="validated";
  2. anything else must ALSO forfeit severity_override, because
     severity_override bypasses compute_severity entirely and floors the
     risk score up to match the agent's own claim (REQ-AGENT-010).
"""

from __future__ import annotations

import pytest

from app.tasks import agent


class _Ctx(agent.SimpleContext):
    pass


@pytest.fixture
def recorded(monkeypatch):
    """Captures the kwargs actually handed to client.add_finding - asserting on
    the persisted call, not on the handler's return string."""
    calls: list[dict] = []
    monkeypatch.setattr(agent.client, "add_finding",
                        lambda eid, **f: (calls.append(f), {"id": "f1"})[1])
    monkeypatch.setattr(agent.client, "agent_event", lambda *a, **k: None)
    return calls


def _report(basis, recorded, *, severity="critical", include_key=True):
    tool_input = {"target": "host.example", "title": "Some weakness",
                  "severity": severity, "category": "exposure",
                  "rationale": "because reasons"}
    if include_key:
        tool_input["evidence_basis"] = basis
    result = agent._handle_report_finding(
        "11111111-1111-1111-1111-111111111111", tool_input,
        {"host.example": "asset-1"}, _Ctx(scan_run_id="22222222-2222-2222-2222-222222222222"),
    )
    return result, (recorded[0] if recorded else None)


def test_direct_technical_proof_is_validated_and_keeps_its_severity(recorded):
    _, f = _report("direct_technical_proof", recorded)
    assert f["confidence"] == "validated"
    assert f["severity_override"] == "critical"
    assert f["evidence"]["evidence_basis"] == "direct_technical_proof"


def test_tool_signal_is_inferred_and_forfeits_severity_override(recorded):
    _, f = _report("tool_signal", recorded)
    assert f["confidence"] == "inferred"
    assert f["severity_override"] is None
    assert f["evidence"]["evidence_basis"] == "tool_signal"


def test_contextual_inference_is_inferred_and_forfeits_severity_override(recorded):
    _, f = _report("contextual_inference", recorded)
    assert f["confidence"] == "inferred"
    assert f["severity_override"] is None
    assert f["evidence"]["evidence_basis"] == "contextual_inference"


# --- Negative / fail-closed cases (mandatory for R3) ------------------------

@pytest.mark.parametrize("bogus", ["", "   ", "proven", "DIRECT_TECHNICAL_PROOF_OF_SOMETHING",
                                   "validated", "high", "unknown-value"])
def test_unrecognised_basis_never_yields_validated(recorded, bogus):
    """An unknown string must fail CLOSED to inference - never to validated,
    and never keeping the agent's severity claim."""
    _, f = _report(bogus, recorded)
    assert f["confidence"] == "inferred"
    assert f["severity_override"] is None
    assert f["evidence"]["evidence_basis"] == "contextual_inference"


def test_missing_basis_key_never_yields_validated(recorded):
    """An older/misbehaving model that omits the field entirely must not be
    silently upgraded to validated - this is exactly the pre-fix behaviour."""
    _, f = _report(None, recorded, include_key=False)
    assert f["confidence"] == "inferred"
    assert f["severity_override"] is None


@pytest.mark.parametrize("bogus", [None, 123, 4.5, True, ["direct_technical_proof"],
                                   {"basis": "direct_technical_proof"}])
def test_non_string_basis_never_yields_validated(recorded, bogus):
    """Type confusion must not bypass the check (e.g. a list whose repr
    contains the magic word)."""
    _, f = _report(bogus, recorded)
    assert f["confidence"] == "inferred"
    assert f["severity_override"] is None


def test_case_and_whitespace_are_normalised_not_rejected(recorded):
    """Genuine intent expressed with sloppy formatting should still be honoured -
    the fail-closed default must not be so brittle it punishes valid claims."""
    _, f = _report("  Direct_Technical_Proof  ", recorded)
    assert f["confidence"] == "validated"
    assert f["severity_override"] == "critical"


# --- Surrounding behaviour that must not regress ---------------------------

def test_agent_assessed_severity_is_preserved_even_when_not_honoured(recorded):
    """Not honouring the claim is not the same as discarding it - triage needs
    to see what the agent thought, to spot a model that over-rates itself."""
    _, f = _report("contextual_inference", recorded, severity="critical")
    assert f["severity_override"] is None
    assert f["evidence"]["agent_assessed_severity"] == "critical"


def test_evidence_tool_attribution_still_set(recorded):
    """REQ-AGENT-013 must keep holding through this change."""
    _, f = _report("tool_signal", recorded)
    assert f["evidence"]["tool"] == "vector_agent"
    assert f["evidence"]["reported_by"] == "vector_agent"


def test_inferred_result_message_tells_the_agent_it_was_downgraded(recorded):
    """The model can only correct course if the observation says so."""
    msg, _ = _report("contextual_inference", recorded)
    assert "INFERRED" in msg
    assert "direct_technical_proof" in msg


def test_out_of_scope_target_still_rejected_before_any_write(recorded):
    """Scope enforcement must not have been disturbed by the new branch."""
    result = agent._handle_report_finding(
        "11111111-1111-1111-1111-111111111111",
        {"target": "not-in-scope.example", "title": "x", "severity": "high",
         "category": "exposure", "evidence_basis": "direct_technical_proof"},
        {"host.example": "asset-1"}, _Ctx(),
    )
    assert result.startswith("REJECTED")
    assert recorded == []


def test_schema_requires_evidence_basis():
    """The model must be *forced* to state a basis; an optional field would
    silently re-create the old behaviour for any model that omits it."""
    spec = next(t for t in agent._TOOLS if t["function"]["name"] == "report_finding")
    params = spec["function"]["parameters"]
    assert "evidence_basis" in params["required"]
    assert set(params["properties"]["evidence_basis"]["enum"]) == set(agent._EVIDENCE_BASES)


# --- REQ-AGENT-024 / TC-AGENT-024: optional cve_id, fail-closed to proven ---
# Found live 2026-08-04 (full benchmark sweep): the agent correctly identified
# and proved CVE-2022-22965 (Spring4Shell) - critical, direct_technical_proof
# - but report_finding had no field to carry the CVE ID, so it could never
# structurally satisfy a CVE-keyed benchmark case (or, in a real engagement,
# feed the live correlation/EPSS/KEV pipeline). Mirrors severity_override's
# existing fail-closed shape: only honoured when evidence_basis is
# direct_technical_proof.

def _report_with_cve(basis, recorded, *, cve_id="CVE-2022-22965"):
    tool_input = {"target": "host.example", "title": "Some weakness", "severity": "critical",
                  "category": "cve", "rationale": "because reasons", "evidence_basis": basis, "cve_id": cve_id}
    result = agent._handle_report_finding(
        "11111111-1111-1111-1111-111111111111", tool_input,
        {"host.example": "asset-1"}, _Ctx(scan_run_id="22222222-2222-2222-2222-222222222222"),
    )
    return result, (recorded[0] if recorded else None)


def test_proven_cve_id_is_attached_and_normalised_to_uppercase(recorded):
    _, f = _report_with_cve("direct_technical_proof", recorded, cve_id="cve-2022-22965")
    assert f["cve_ids"] == ["CVE-2022-22965"]


def test_unproven_cve_id_is_silently_dropped_not_attached(recorded):
    """A hedge/inference must never buy a structured CVE attribution - that
    would let contextual_inference masquerade as a confirmed CVE downstream
    (correlation, KEV, benchmark scoring) even though severity_override is
    already correctly withheld for the same call."""
    _, f = _report_with_cve("contextual_inference", recorded)
    assert f["cve_ids"] is None


def test_malformed_cve_id_is_rejected_not_passed_through(recorded):
    """Fail closed on shape too - a hallucinated or garbled ID must not reach
    add_finding (and from there, correlation lookups) at all."""
    _, f = _report_with_cve("direct_technical_proof", recorded, cve_id="Spring4Shell")
    assert f["cve_ids"] is None


def test_missing_cve_id_is_simply_none_no_error(recorded):
    """cve_id is optional - most findings legitimately have none."""
    _, f = _report("direct_technical_proof", recorded)
    assert f["cve_ids"] is None


def test_schema_documents_cve_id_as_optional():
    spec = next(t for t in agent._TOOLS if t["function"]["name"] == "report_finding")
    params = spec["function"]["parameters"]
    assert "cve_id" in params["properties"]
    assert "cve_id" not in params["required"]
