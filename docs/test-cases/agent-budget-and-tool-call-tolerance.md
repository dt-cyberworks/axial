---
title: Agent iteration budget and tool-call tolerance verification
status: ready
risk: R2
owner: product-engineering
---

# Agent Iteration Budget & Tool-Call Tolerance Verification

Verifies [`../requirements/agent-budget-and-tool-call-tolerance.md`](../requirements/agent-budget-and-tool-call-tolerance.md).

## TC-AGENT-008: Iteration budget resolves campaign → global → default

Requirements:

- REQ-AGENT-008

Automated tests:

- `control-plane/tests/integration/test_config_layers.py`
- `control-plane/tests/integration/test_agent_max_iterations_api.py`

Objective:

Verify the effective iteration budget resolves through the layering, the
settings/config endpoints round-trip correctly, and out-of-range values are
rejected.

Expected results:

- No override anywhere → `50`.
- Global default set, no campaign override → the global value.
- Campaign override set → the campaign value (wins over global).
- `PUT /settings/agent-max-iterations` and the engagement config update reject
  values outside 1–500.
- The engagement config response reports `agent_max_iterations` and
  `agent_max_iterations_overridden` correctly.

## TC-AGENT-009: A tool-named function call is handled like `run_check`

Requirements:

- REQ-AGENT-009

Automated tests:

- `worker/tests/test_agent.py`

Objective:

Verify a tool_call whose function name is a known tool (e.g. `nuclei`) is
dispatched through the same path as `run_check({"tool": "nuclei", ...})`, is
authorized identically, is audited distinguishably from a normal proposal, and
that a non-tool, non-dispatcher function name (`nmap`, or a made-up name) is
still rejected as before.

Expected results:

- Calling function `nuclei` with `{"target": "host"}` produces the same
  authorization call and observation as `run_check({"tool": "nuclei", "target":
  "host"})` would.
- The audit event for the normalized path uses a distinct reason
  (e.g. `llm_proposed_tool_as_function_name`), not `llm_proposed_tool`.
- Calling function `nmap` directly is still rejected (pipeline-owned, excluded
  from the agent's tool list) — tolerance does not add capability.
- Calling a nonexistent function name is still rejected as unknown.

## TC-AGENT-014: The agent's LLM client is configured with a resilient retry budget

Requirements:

- REQ-AGENT-014

Automated tests:

- `worker/tests/test_agent.py`

Objective:

Confirm the agent constructs its `openai` client with `max_retries` set to
`AGENT_LLM_MAX_RETRIES`, and that this value is materially higher than the
SDK's own default - found live: a transient 502 on the 7th LLM call of an
otherwise-healthy run exhausted the SDK's default 3-attempt budget in under 2
seconds and ended the agent phase early with no report content, no additional
findings, even though the provider had just answered 6 prior calls
successfully.

Expected results:

- `test_agent_configures_the_llm_client_with_resilient_retries` passes: the
  fake `OpenAI` client instance the agent constructs has
  `max_retries == agent.AGENT_LLM_MAX_RETRIES`, and that constant is strictly
  greater than 2 (the `openai` SDK's own default).
- The existing fail-closed behavior on a genuinely-exhausted LLM call
  (`llm_call_failed` audit event, `stop_reason=error`, clean phase end, scan
  run still reaches a terminal state) is unaffected.

## TC-AGENT-015: The agent's evidence context tells a confirmed-dead host apart from an unchecked one

Requirements:

- REQ-AGENT-015

Automated tests:

- `control-plane/tests/integration/test_http_probe_liveness.py`
- `worker/tests/test_http_probe_liveness.py`

Objective:

Confirm the httpx liveness outcome (live or dead) is durably recorded
regardless of result, surfaced through `agent-context`, and rendered
distinctly in the agent's evidence text - found live: the agent re-probed the
same confirmed-dead subdomains with httpx in every one of 3 consecutive scan
runs, since a host with no recorded service looked identical whether nobody
had checked it yet or it was already checked and found dead.

Expected results:

- A host nobody has probed yet reports `http_checked_at: null`,
  `http_live: null` via `agent-context`, and renders as
  "(none recorded yet)" - unchanged from before.
- A host the deterministic fingerprint phase's `httpx` probe found dead
  records `http_live: false` with a timestamp, and the agent's rendered
  evidence explicitly says so and advises against re-checking it.
- The same recording happens when the agent's own `httpx` tool call (not just
  the deterministic phase) finds a host dead.
- `record_http_probe` rejects an `asset_id` that belongs to a different
  engagement (404), matching every other engagement-scoped internal endpoint.
