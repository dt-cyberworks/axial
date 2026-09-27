---
title: Agent quality and scoring fixes verification
status: ready
risk: R2
owner: security-engineering
---

# Agent Quality and Scoring Fixes Verification

Verifies [`../requirements/agent-quality-and-scoring.md`](../requirements/agent-quality-and-scoring.md).

## TC-AGENT-010: Risk score stays consistent with an explicit severity assessment

Requirements:

- REQ-AGENT-010

Automated tests:

- `control-plane/tests/test_risk_score.py`
- `control-plane/tests/integration/test_finding_severity_override.py`

Objective:

Verify the severity-floor function keeps a `severity_override`'d finding's
numeric score inside its own severity band, that two different overridden
severities produce genuinely different scores, that a higher real
EPSS/CVSS-driven score is never clamped down, and that rescoring preserves
this consistency using the finding's current effective override.

Expected results:

- `risk_score_floor_for_severity(sev)` maps back to `sev` via
  `compute_severity`, for every severity band.
- A `critical`-overridden finding scores ≥85; a `low`-overridden finding
  scores in [15, 40); they differ.
- A finding whose real computed score already exceeds its band's floor keeps
  the higher value.
- `rescore_open_findings` keeps a finding's score inside its (retained)
  severity's band even on a later, override-less re-observation.
- A finding without any `severity_override` scores and rescoring exactly as
  before (no regression for CVE-backed findings).

## TC-AGENT-011: Default agent prompt is always visible and editable

Requirements:

- REQ-AGENT-011

Automated tests:

- `control-plane/tests/integration/test_config_layers.py`
- `control-plane/tests/integration/test_agent_config_engagement_params.py`

Objective:

Verify the effective global prompt is never an empty string (falls back to
the built-in default), that the internal agent-config endpoint always
returns a non-empty prompt, and that the existing campaign-override-beats
-global-beats-default resolution order still holds.

Expected results:

- With no global override stored, `effective_agent_prompt` returns the
  built-in `DEFAULT_AGENT_PROMPT`, not `""`.
- Setting a global override makes it the effective prompt; a campaign
  override on top of that still wins, unchanged from before.
- `internal_agent_config`'s `prompt` field is never blank for any engagement.

## TC-AGENT-012: Engagement parameters and structured checklist reach the agent

Requirements:

- REQ-AGENT-012

Automated tests:

- `worker/tests/test_agent.py`

Objective:

Verify the per-run initial context includes a concrete ENGAGEMENT PARAMETERS
block (sourced from the internal config endpoint's new `engagement` field)
when available, omits it cleanly when not, and correctly reports a
single-port restriction versus the standard/unrestricted case.

Expected results:

- Given engagement parameters with `tcp_port_from == tcp_port_to == 4280`,
  the initial context contains `ENGAGEMENT PARAMETERS`, the engagement title,
  and `Authorized port: 4280 ONLY`.
- Given no engagement parameters, the initial context contains no
  `ENGAGEMENT PARAMETERS` section (unchanged behavior for callers that don't
  supply it).
- `agent.run()` fetches `engagement` from `client.get_agent_config()` and
  threads it into the initial context automatically; a standard/full-range
  engagement renders `Authorized ports: standard`.

## TC-AGENT-013: Findings are attributed to their actual detecting tool

Requirements:

- REQ-AGENT-013

Automated tests:

- `worker/tests/test_agent.py`
- `worker/tests/test_scan_integrity.py`

Objective:

Verify a Vector-Agent-reported finding's evidence carries
`tool: "vector_agent"`, and a known-vulnerable-version finding derived from
nmap's product/version banner carries `tool: "nmap"`, so the Findings UI
never shows "unknown tool" for either.

Expected results:

- `_handle_report_finding` calls `client.add_finding` with
  `evidence["tool"] == "vector_agent"`.
- The nmap known-vulnerability lookup path calls `client.add_finding` with
  `evidence["tool"] == "nmap"`.

## TC-AGENT-021: Agent-reported confidence and severity reflect actual evidence

Requirements:

- REQ-AGENT-021

Automated tests:

- `worker/tests/test_agent_finding_confidence.py`
- `control-plane/tests/test_risk_score.py`

Objective:

Verify the Vector Agent can no longer assert `validated` confidence or a
self-chosen severity for a finding it did not technically demonstrate, and
that a claim without a demonstrating observation is scored by the platform
rather than by the agent. R3 requirement: negative cases are mandatory and
must fail closed.

Expected results:

- `evidence_basis="direct_technical_proof"` -> `client.add_finding` receives
  `confidence="validated"` and the agent's `severity_override`.
- `evidence_basis="tool_signal"` -> `confidence="inferred"` and
  `severity_override` is NOT passed.
- `evidence_basis="contextual_inference"` -> `confidence="inferred"` and
  `severity_override` is NOT passed.
- NEGATIVE: a missing, unknown, empty, or non-string `evidence_basis` never
  yields `confidence="validated"` and never passes `severity_override`
  (fail-closed).
- `evidence["evidence_basis"]` records the effective basis on every path.
- A finding persisted with `severity_override=None` and no EPSS/CVSS gets a
  `compute_severity`-derived severity, not `critical`.
- Tool paths that legitimately set `severity_override` (nuclei, testssl) are
  unchanged; REQ-FIDELITY-004 continues to hold for them.

## TC-AGENT-022: Run-scoped session continuity, isolated per host

Requirements:

- REQ-AGENT-022

Automated tests:

- `worker/tests/test_agent_session_continuity.py`

Objective:

Verify the agent carries an authenticated session across calls to the same
host within a run, and — the R3 invariant — never replays it to a different
host, across runs, or into the audit log.

Expected results:

- `Set-Cookie` (CRLF or LF, any header casing) is captured; attributes
  including `Domain` are discarded; an over-long value is skipped.
- A later `Set-Cookie` for the same name wins, so a re-login rotates the id.
- The jar is bounded in count and total header length; over-length produces no
  header rather than a truncated one.
- NEGATIVE: a cookie captured from host A yields nothing for host B.
- NEGATIVE: a fresh run's context starts with an empty jar.
- NEGATIVE: an explicit agent-supplied `Cookie` header (any casing) is never
  overwritten by the jar.
- NEGATIVE: a response with no `Set-Cookie` leaves the jar untouched.
- The audit event records cookie names and count, never values.

## TC-AGENT-024: A demonstrated CVE can be recorded on the finding, fail-closed

Requirements:

- REQ-AGENT-024

Automated tests:

- `worker/tests/test_agent_finding_confidence.py`

Objective:

Verify `report_finding`'s optional `cve_id` is attached only when the finding
is actually proven, normalized consistently, and never lets an inference
masquerade as a confirmed CVE.

Expected results:

- A well-formed `cve_id` with `evidence_basis: direct_technical_proof` is
  normalized to uppercase and appears in the persisted finding's `cve_ids`.
- NEGATIVE: the same `cve_id` with any other `evidence_basis` is silently
  dropped — `cve_ids` is `None`, not an error.
- NEGATIVE: a malformed value (not `CVE-YYYY-NNNN...` shape) is dropped even
  when the finding is otherwise proven.
- A missing `cve_id` is simply absent, not an error — most findings have none.
- The tool schema documents `cve_id` as optional, not required.
