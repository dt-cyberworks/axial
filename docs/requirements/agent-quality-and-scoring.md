---
title: Agent quality and scoring fixes (risk scoring, default prompt visibility, prompt content, finding attribution)
status: implemented
risk: R2
owner: security-engineering
---

# Agent Quality and Scoring Fixes

Four defects reported after live-testing the Vector Agent against real
engagements. None touch the Scope Gateway's authorization decision or any
network-egress boundary; all four are correctness/usability fixes to
reporting, configuration visibility, and agent guidance.

**Risk class: R2** (persistence/business-logic + UI changes; no new active
capability, no widened egress). Agent prompt content changes are explicitly
safe per `AGENTS.md`/`CLAUDE.md`: "the Vector Agent only proposes; the gateway
decides — no prompt can cause an out-of-scope action."

---

## REQ-AGENT-010: Risk score is consistent with an explicit severity assessment

Context: `compute_risk_score` is EPSS/CVSS-dominated (weights 0.35/0.20) with a
20%/15%/10% weighting for exposure/business-context/validated-confidence. This
works well for CVE-backed findings (nuclei, known-vulns lookup), where real
EPSS/CVSS values differentiate scores. But every non-CVE finding (testssl
misconfig, wafw00f WAF detection, nikto headers, and every Vector-Agent
`report_finding` call) carries no EPSS/CVSS and was scored with hardcoded
`exposure_factor=1.0, business_factor=0.5` — which computes to exactly
`37.5` for every single one of them, regardless of whether the agent assessed
it as "critical" (e.g. an unauthenticated PII exposure) or "low". The numeric
score was not just uninformative — it actively contradicted the displayed
severity (a "critical"-labelled finding numerically looked "medium").

Acceptance criteria:
- A finding with an explicit `severity_override` gets a `risk_score` that
  falls inside that severity's own band as defined by `compute_severity`
  (critical ≥85, high ≥70, medium ≥40, low ≥15, info <15) — the score is
  `max(computed_score, floor_for_that_band)`, never silently lower.
- Two findings with different `severity_override` values (and no EPSS/CVSS)
  produce different, correctly-banded risk scores — not the same constant.
- A finding that already has a real EPSS/CVSS-driven score higher than its
  severity's floor keeps that higher, more informative score (the floor is a
  minimum, not a clamp).
- `rescore_open_findings` re-applies the floor using the finding's current
  (possibly earlier-observation-derived) `severity_override`, so a later,
  override-less re-observation of the same finding does not regress its score
  back to the generic, inconsistent value while its severity label stays
  protected (REQ-FIDELITY-004).
- A finding with no `severity_override` at all is entirely unaffected — pure
  EPSS/CVSS/exposure/business-factor scoring, unchanged from before.

## REQ-AGENT-011: The default agent prompt is visible and editable at both layers

Context: the Vector Agent's actual runtime instructions were a Python
constant hardcoded in the worker (`agent.py`), never exposed to the
control-plane or the operator console. `GET /settings/agent-prompt` (and the
per-engagement effective-config endpoint) returned an empty string whenever
no override existed at that layer, so the Settings page and the campaign
"Vector Agent instructions" box both rendered blank — even though the agent
was, in fact, running a long, specific built-in prompt. An operator had no way
to see, let alone start editing from, what was actually running.

Acceptance criteria:
- The global effective prompt (`get_global_agent_prompt` / `GET
  /settings/agent-prompt`) is never an empty string: it returns the stored
  global override if set, otherwise the built-in default text — so the
  Settings page always shows the real, currently-running instructions.
- Editing and saving the Settings page prompt persists it as the global
  override (unchanged mechanism); saving an empty box reverts to the built-in
  default (also unchanged mechanism — now simply starting from real text
  instead of blank).
- The per-engagement "campaign override" box shows the campaign's EFFECTIVE
  prompt (its own override if set, else the global/built-in default) — never
  blank — and is directly editable.
- Editing that box and saving the campaign config sets a campaign-specific
  override. Saving the campaign config WITHOUT having touched the prompt box
  (e.g. only changing a tool grant) must NOT silently freeze the currently
  -displayed effective text as a new campaign override — it must leave the
  campaign's prompt override state untouched, so future changes to the global
  default keep propagating to campaigns that never explicitly overrode it.
- Clearing the campaign override box to empty and saving reverts that
  campaign to inheriting the global/default prompt again.

## REQ-AGENT-012: The default prompt explains the ASM platform, engagement parameters, and a structured check checklist

Context: the existing built-in prompt covered persona, operating model,
scope/impact rules, and a reasoning loop well, but never explained (a) how the
larger ASM pipeline around the agent works (discovery → fingerprint → agent →
validate → score → report, and the two independent enforcement layers), (b)
that the agent receives concrete per-run engagement parameters (authorized
window, engagement type, port restriction, enabled tools) and must treat them
as binding, or (c) a structured, named checklist of vulnerability classes to
actively consider per host rather than only reactive hypothesis-forming.

Acceptance criteria:
- The default prompt includes a section explaining the ASM pipeline (what ran
  before the agent phase, what the Scope Gateway and egress-proxy each
  enforce, what happens after the agent phase) so the agent understands its
  place in the system, not just its own tool loop.
- The default prompt tells the agent it will receive concrete engagement
  parameters per run and to treat them as binding (a stated port restriction
  is already applied automatically; it must not try to specify one itself).
- The per-run initial context (not the static prompt, since these values
  differ per engagement) includes an "ENGAGEMENT PARAMETERS" block with the
  real title, engagement type/source, authorized time window, effective port
  restriction (or "standard" when unrestricted), and the AI-testing opt-in
  status — sourced from the same internal config endpoint as the prompt and
  enabled-tools list.
- The default prompt includes a structured checklist of what to check for,
  organized by OWASP Top 10 (2021) risk categories, each mapped to which of
  the agent's actual tools/capabilities can validate it (or explicitly noted
  as not externally testable) — so hypothesis-forming has a systematic backbone
  instead of being purely reactive to whatever the automated scan happened to
  flag.

## REQ-AGENT-013: Findings are attributed to the tool that actually detected them

Context: the Findings UI labels each finding "Detected by {evidence.tool}",
falling back to "unknown tool" when that key is absent. Two finding-creation
paths never set `evidence.tool`: the Vector Agent's own `report_finding` calls
(evidence carried only `reported_by`/`rationale`), and the nmap-driven
known-vulnerable-version lookup (evidence carried only `nmap_product`/
`port`/`protocol`). Every agent-reported finding — including the exact
critical PII-exposure findings the agent is specifically designed to surface
— displayed as "Detected by unknown tool", indistinguishable from a genuine
attribution gap.

Acceptance criteria:
- Every finding created via the Vector Agent's `report_finding` tool carries
  `evidence.tool = "vector_agent"`.
- Every finding created via the nmap-version known-vulnerability lookup
  carries `evidence.tool = "nmap"`.
- The Findings UI renders `evidence.tool = "vector_agent"` as "Vector Agent"
  (not the raw snake_case token); all other tool identifiers render as-is,
  unchanged from before.
- No existing finding-creation path that already set `evidence.tool`
  (nikto/wafw00f/testssl/nuclei) is affected.

## REQ-AGENT-021: An agent-reported finding's confidence and severity reflect its actual evidence

**Risk class: R3** (this one requirement only — it governs the trust
semantics of what the platform reports to a customer and changes the
risk-score/severity computation path for agent findings). Approved by
johannes 2026-08-03. Negative tests are mandatory per `CLAUDE.md`.

Context: `_handle_report_finding` (`worker/app/tasks/agent.py`) hardcoded
`confidence="validated"` on **every** Vector-Agent finding, and passed the
agent's self-claimed `severity` straight through as `severity_override`.
The `report_finding` tool schema had no parameter by which the model could
signal that a claim was inference rather than proof — it was structurally
incapable of expressing doubt. Downstream, `confidence` feeds
`compute_risk_score`'s `W_VALID` term, and `severity_override` is used
verbatim as the finding's displayed severity
(`control-plane/app/api/internal.py`, both the create and the rescore path),
bypassing `compute_severity` entirely and then flooring `risk_score` *up* to
match the claim (REQ-AGENT-010). The `validate` phase that is supposed to
earn `validated` is still a stub (`worker/app/tasks/validate.py`), so nothing
in the system ever promotes `inferred` → `validated` on evidence.

Measured on the dev database 2026-08-03: 47 of 47 `vector_agent` findings
were `confidence=validated`, zero `inferred`. Examples stored as
`validated / critical / risk_score 85.0` with `cve_ids = NULL` included
*"Apache Struts2 S2-045 (CVE-2017-5638) RCE — Likely Present but
Unconfirmed"* and an ActiveMQ finding whose own rationale conceded it was
derived from the engagement's title rather than from any observation. A
speculative guess and a demonstrated exploit were indistinguishable to an
operator, and both inflated the risk score identically.

This is not fixable by prompt guidance alone: the default prompt already
said "Only for things you confirmed — never speculative"
(`control-plane/app/default_prompts.py`) and was ignored. The fix must be
structural.

Acceptance criteria:

- The `report_finding` tool schema exposes a required `evidence_basis`
  parameter with exactly three values: `direct_technical_proof` (the
  observation itself demonstrates the weakness), `tool_signal` (a tool
  asserted it and the agent is relaying it), `contextual_inference`
  (reasoned from version/banner/naming without a demonstrating observation).
- A finding reported with `evidence_basis="direct_technical_proof"` is
  persisted with `confidence="validated"` and keeps its agent-assessed
  severity as `severity_override` (REQ-AGENT-010's banding behaviour is
  unchanged for this case).
- A finding reported with any other `evidence_basis` is persisted with
  `confidence="inferred"` **and no `severity_override` at all**, so its
  severity is computed by `compute_severity` from the real risk score rather
  than asserted by the agent.
- A missing, unrecognised, or non-string `evidence_basis` fails closed to
  `contextual_inference` handling — never to `validated`. (Mirrors the
  existing `severity`/`category` normalisation in the same function.)
- The chosen basis is persisted at `evidence.evidence_basis` so an operator,
  the report, and `benchmark/scoring/ladder.py` can all see it.
- Tool-driven `severity_override` callers (nuclei, testssl, and the nikto/
  known-vulns paths) are **not** affected — their overrides remain
  legitimate and REQ-FIDELITY-004 ("an explicit severity assessment survives
  rescoring") must continue to hold for them.
- The default prompt explains the three levels, states that labelled
  inference is welcome and useful (so the model is not pushed toward either
  over-claiming or silence), and instructs the agent not to file
  non-findings — unreachable service, no live HTTP — as findings at all.

## REQ-AGENT-022: The agent carries an authenticated session across calls within a run

**Risk class: R3** (agent containment: the scanner holds and replays a
customer's authenticated session). Approved by johannes 2026-08-03.
Cross-host isolation negative tests are mandatory per `CLAUDE.md`.

Context: every `http_request` the Vector Agent makes was independent and
unauthenticated. Measured live (`docs/benchmarking/benchmark-design.md` §14):
all four of DVWA's curated vulnerabilities — SQL injection, command injection,
reflected XSS, CSRF — sit behind a login form, so the scanner reached none of
them. That single gap accounts for 100% of that suite's false negatives, and
real customer applications gate their interesting functionality the same way.
An unauthenticated-only scan systematically under-reports the attack surface
while looking clean.

The building blocks already existed and were simply never connected: the
runner's curl invocation uses `-i`, so `Set-Cookie` already reaches the agent
in the response it reads, and `args_safety._http_request_args_safe` already
permits arbitrary request headers (≤30, ≤1024 bytes, CRLF-rejected) including
`Cookie`. **This requirement therefore widens no safety envelope** — it makes
the agent reliable at something it could already technically do by hand, and
which it demonstrably failed to do (it managed a bearer token against VAmPI
but never a cookie+CSRF login against DVWA).

Explicitly out of scope: sourcing credentials. There is no engagement-level
credential concept in the data model, and adding one means new persistence,
secret handling, GUI, audit and legal review — a separate cycle ("Part B").
This requirement covers only carrying a session the agent legitimately
obtained (supplied credentials, or open self-registration).

Acceptance criteria:

- `Set-Cookie` values observed in a response are captured into scan-run-scoped
  state and automatically attached to subsequent `http_request` calls **to the
  same host** in that run.
- **A session captured from host A is never attached to a request for host B**,
  including for two in-scope hosts in the same run. Cookie `Domain` attributes
  are discarded rather than honoured — `Domain` is the one input that could
  widen replay beyond the issuing host.
- Session state is never persisted: it lives on the run's in-memory context,
  starts empty for every run, and cannot cross runs or engagements.
- Cookies are merged into the proposed arguments **before** `authorize()`, so
  the Scope Gateway validates the exact request that will be sent. This adds no
  path around the gateway, and the approval flow shows the operator the real
  request; the approved call is still replayed verbatim, never re-injected.
- An explicit `Cookie` header set by the agent always wins over the jar — the
  model may be deliberately testing a forged, downgraded or absent session.
- The jar is bounded (cookie count, value length, total header length) so it can
  never push an otherwise-valid request past the gateway's own header limits.
- Establishing a session is audited by cookie **name** and count; cookie values
  are never written to the audit log.
- The default prompt instructs the agent to authenticate where it legitimately
  can, to verify that it actually is authenticated before concluding
  functionality is absent, and to report anything behind a login it could not
  reach as UNTESTED rather than clean.

## REQ-AGENT-024: A proven finding can carry the specific CVE it demonstrates

Context: found live 2026-08-04, running the Vector Agent against every
deployed benchmark target. Against the Spring4Shell suite, the agent
correctly identified and directly demonstrated CVE-2022-22965 — critical
severity, `evidence_basis: direct_technical_proof` — but `report_finding`
had no field to carry a structured CVE ID, only a free-text title and
rationale. The CVE never reached the finding's `cve_ids`, so it could not
feed the live correlation/EPSS/KEV pipeline (REQ-CORR-001..008) the way a
nuclei-sourced finding does, and — the benchmark-visible symptom — could
never structurally satisfy a CVE-keyed ground-truth case even when perfectly
evidenced.

Acceptance criteria:

- `report_finding` accepts an optional `cve_id`.
- A well-formed CVE ID (`CVE-YYYY-NNNN...`, case-insensitive input) is
  normalized to MITRE's uppercase convention and attached to the finding's
  `cve_ids` — but **only when `evidence_basis` is `direct_technical_proof`**,
  mirroring `severity_override`'s existing fail-closed gate (REQ-AGENT-021).
  An inference or tool-relayed CVE guess must never buy a structured CVE
  attribution it hasn't earned — that would let a hedge masquerade as a
  confirmed CVE downstream.
- A malformed or absent `cve_id` is silently dropped (never passed to
  `add_finding`), never an error — most findings legitimately have none, and
  a hallucinated ID must not reach the correlation pipeline at all.
- The default prompt tells the agent when and why to set it, and that
  guessing one in for a mere inference has no effect.
