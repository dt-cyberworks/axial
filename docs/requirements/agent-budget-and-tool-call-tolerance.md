---
title: Configurable agent iteration budget and tool-call-shape tolerance
status: implemented
risk: R2
owner: product-engineering
---

# Agent Iteration Budget & Tool-Call Tolerance

This document is the requirement source for four Vector Agent effectiveness
fixes found while reviewing live runs:

1. `budget_max_iterations` (the agent loop's own cap on LLM round-trips) was a
   hardcoded `50` with no way to tune it per engagement or globally.
2. The LLM sometimes calls a function literally named after a tool (e.g.
   `nuclei(...)`) instead of `run_check({"tool": "nuclei", ...})`. The
   orchestrator rejected this as `"unbekanntes Werkzeug"` (unknown tool),
   wasting one of the scarce iterations on a pure request-shape mistake instead
   of the intended check.
3. A brief upstream LLM-provider blip (a transient `502`) exhausted the
   `openai` SDK's own default retry budget and ended an otherwise-healthy
   agent phase early, with no report content and no additional findings.
4. The agent repeatedly re-checked the same already-confirmed-dead hosts in
   every scan run on the same engagement, wasting iteration budget that could
   have gone toward deeper coverage of the actually-live hosts.

Neither change touches the Scope Gateway or authorization: the iteration budget
is a soft agent-loop cap (independent of the Gateway's own hard
`budget_tool_calls_max` on `scan_run`), and the tool-call tolerance only
normalizes the *shape* of an already-valid tool proposal before it reaches the
exact same `run_check` validation and gateway authorization path. No new
capability, no widened scope. Tests must verify these requirements directly.

**Risk class: R2** (agent behavior / config tuning, no offensive capability
change).

---

## REQ-AGENT-008: The agent iteration budget is configurable

The Vector Agent's iteration cap must be configurable, layered like other agent
settings (registry floor → global default → per-engagement override).

Acceptance criteria:
- A global default (`app_setting`) for `agent_max_iterations` exists, editable
  via `GET/PUT /settings/agent-max-iterations`, defaulting to `50` when unset.
- An engagement may override it (`engagement.agent_max_iterations_override`);
  `null`/unset inherits the global default. The engagement config endpoint
  reports the effective value and whether it is overridden.
- `POST /engagements/{id}/scan` resolves the effective value (campaign → global
  → built-in `50`) and passes it to the enqueued scan; the agent phase runs with
  that many iterations, not a hardcoded constant.
- Bounds: the value must be a positive integer within a sane range (1–500);
  out-of-range values are rejected, not silently clamped.

## REQ-AGENT-009: A tool-shaped function call is accepted like `run_check`

If the model calls a function whose name is itself a known, dispatchable tool
name (e.g. `nuclei`, `httpx`) instead of `run_check({"tool": "<name>", ...})`,
the orchestrator must treat it as an implicit `run_check` proposal for that
tool, rather than rejecting it as an unknown tool.

Acceptance criteria:
- If `tool_call.function.name` is a member of the agent's allowed tool list
  (the same list offered in the `run_check` enum) and is not one of the five
  real dispatcher function names, its arguments are passed to the exact same
  `run_check` handling path with `tool` set to that function name (any `tool`
  key the model also supplied is superseded by the function name it actually
  called).
- The normalized call is authorized through the identical Scope Gateway path as
  a genuine `run_check` call — no bypass, no new capability, no widened target
  set.
- The normalization is recorded as a distinguishable audit event (not
  indistinguishable from a well-formed `run_check` proposal), so model
  reliability remains observable.
- A function name that is neither a real dispatcher function nor a known tool
  (e.g. `nmap`, which is pipeline-owned and deliberately excluded from the
  agent's tool list) is still rejected as unknown/unavailable exactly as before
  — tolerance does not extend the agent's actual capabilities.

## REQ-AGENT-014: The agent's LLM client tolerates a brief upstream provider blip

Found live in production (2026-07-28): a real scan's agent phase made 6
successful LLM calls, then the 7th hit a transient `502 Bad Gateway` from the
provider gateway. The `openai` SDK's own default retry budget (`max_retries=2`,
~3 total attempts spanning under 2 seconds of backoff) was exhausted before the
provider recovered, so the agent phase ended early with `stop_reason=error` -
no report content from the agent, no additional findings from its
(unfinished) exploration, even though the identical endpoint had just been
working fine and most likely would have answered within a few more seconds.

Acceptance criteria:
- The agent's LLM client is constructed with a materially more patient retry
  budget than the SDK's own default (`AGENT_LLM_MAX_RETRIES`, env-overridable,
  bounded 0–10, default 5) - not left to the SDK's out-of-the-box behavior.
- This does not change the existing fail-closed design: once retries are
  genuinely exhausted, the phase still ends cleanly (`llm_call_failed` audit
  event, `agent_step` with `stop_reason=error`), never crashes the scan run,
  and the deterministic tool-based phases' results are unaffected either way.
- The configured retry count is directly observable in a test (not just
  "the SDK will retry something") - a regression in this value must fail a
  test, not only be noticed live.

## REQ-AGENT-015: The agent knows which hosts are already confirmed dead before it starts

Found live (2026-07-28), comparing scan output against a real, documented
training target (DVWA on `pentest-ground.com:4280`) across 3 consecutive scan
runs on the same engagement: in every single run, the agent's first batch of
iterations re-ran `httpx` liveness checks against the same handful of
subdomains that were already confirmed dead (no live HTTP service) in every
prior run. The deterministic fingerprint phase had already established this
for each of them before the agent even started - the agent simply had no way
to see that, since a host with no recorded `service` looks identical whether
nobody has checked it yet or it was already checked and found dead.

Acceptance criteria:
- `discovered_asset` records the outcome of every httpx liveness probe
  (live or dead), not only live ones - both the deterministic fingerprint
  phase and the agent's own `httpx` tool calls record it.
- The agent's evidence context distinguishes, per host: never checked vs.
  already checked and confirmed dead (with when), so the agent's very first
  iteration already has this information - it must not need to spend an
  iteration re-discovering it.
- A host correctly marked dead this way does not silently become
  unreachable forever - the language used is advisory ("do not re-check
  unless you have a specific new reason"), not a hard block, since a host
  could legitimately come back up between runs.

**Live-verified (2026-07-29):** three consecutive real scan runs on the same
engagement against `pentest-ground.com`. Run 1 (first-ever): all 6 dead
subdomains correctly recorded `http_live=false`. Run 2 exposed a real
deployment gap - `worker/app/tasks/agent.py` (the file that *renders* the
dead-host evidence) had been missed in the manual file-by-file sync to
int/prod, so the recording worked but the surfacing didn't; the agent still
re-probed all 6 hosts. Fixed by syncing the missed file and rebuilding.
Run 3 (after the fix): iteration 1's rendered evidence correctly read
"httpx already confirmed no live HTTP service ... Do not re-run httpx", and
the agent's actual first proposals contained zero `httpx` calls against any
of the 6 dead hosts - it went straight to deep manual work on the one live
host, explicitly reasoning "This is the only live host." Pending johannes's
review (R2, but touches the same live production engagement data as the R3
UAT work).
