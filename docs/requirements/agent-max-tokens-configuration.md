---
title: Vector Agent completion-token cap is configurable, not an env var
status: implemented
risk: R2
owner: engineering
---

**Incident, 2026-08-11:** live on a 12-engagement benchmark run, 2 of 12
(Confluence OGNL, Jenkins CVE-2024-23897) got **zero** agent-phase tool calls.
Both hit `finish_reason: length` on the model's very first response, retried
once per `AGENT_LENGTH_RETRIES`, hit the identical 8192-token ceiling again,
and gave up. Root cause: `retry_max_tokens = max(max_tokens,
AGENT_RETRY_MAX_TOKENS)` (worker/app/tasks/agent.py) technically satisfied
the letter of the acceptance criterion below - the ceiling never sat *below*
the configured cap - but because `AGENT_RETRY_MAX_TOKENS`'s own env-var
default (8192) equals `AGENT_MAX_TOKENS`'s default, `token_budget = min(max_tokens
* 2, retry_max_tokens)` on retry evaluated to `max_tokens` itself in the
default configuration, and in *every* configuration where an operator raised
`agent_max_tokens` without also separately discovering and raising the
undocumented `ASM_AGENT_RETRY_MAX_TOKENS` env var. A retry ceiling that can
never exceed the value that already truncated the first attempt is not a
retry with more room - it is the same failed call twice. Fixed by deriving
the ceiling from the run's own resolved `max_tokens` (`max(max_tokens * 2,
AGENT_RETRY_MAX_TOKENS)`), guaranteeing real escalation headroom regardless
of configuration. The acceptance criterion below is rewritten to make this
explicit so it cannot be satisfied by ceiling-tracking alone again.

**Follow-up, same day, live-reverified:** the first fix deployed and was
re-tested against the same two engagements. Confluence recovered fully (hit
the limit again at iteration 20 mid-run, retried into the doubled 16384
budget, and continued for 24+ more iterations to completion). Jenkins did
not - even the doubled budget was not enough for this model's response on
that context, and gave up again. Root cause of the second failure: the fixed
ceiling (`max_tokens * 2`) does not scale with `AGENT_LENGTH_RETRIES` - a
third attempt would ask for `max_tokens * 4` per the retry loop's own
exponential formula, but was being clamped back down to the SAME doubled
ceiling as the second attempt, so raising the retry count could never reach
further. Fixed by scaling the ceiling to `max_tokens * 2 ** AGENT_LENGTH_RETRIES`
- the actual maximum a full retry sequence can ask for - and raising the
default retry count from 1 to 2 (three total attempts: 8192, 16384, 32768 -
reaching this platform's absolute token ceiling before giving up, maximizing
recovery odds). A third acceptance criterion below captures this.

# Vector Agent Max-Tokens Configuration

Context: reported 2026-08-09 - the agent's LLM completion cap was only
settable via `ASM_AGENT_MAX_TOKENS`, read once at worker import time. Every
comparable global agent knob (iteration budget, manual-approval timeout)
already follows an established end-to-end pattern instead: a bounded value in
`app_setting`, a nullable per-engagement `*_override` column, a
`config_resolver.effective_*` function, GET/PUT settings endpoints, and a
Settings UI section. `max_tokens` had none of it, so changing it meant editing
container environment config and restarting the worker.

The default also moves from 4096 to 8192. `max_tokens` bounds a single
completion's **output**, and in a tool-calling loop that output contains both
the model's reasoning and the tool-call JSON itself. A turn truncated at the
cap mid-JSON does not merely produce a shorter answer - the tool call fails to
parse and the agent stalls with no obvious cause. 8192 leaves real headroom for
a reasoning-plus-tool-call turn while still bounding latency and cost.

**Risk class: R2** (settings persistence, an API endpoint, a nullable column
with an idempotent migration, and worker orchestration). No Scope Gateway,
authorization, egress, or audit-integrity change: this only bounds how many
tokens the agent's own LLM call may return. The agent still only proposes; the
gateway still decides every tool call.

## REQ-AGENT-026: The agent's completion-token cap is a configurable setting

Acceptance criteria:

- A global default lives in `app_setting` under `agent_max_tokens`, bounded to
  1024-32768, defaulting to 8192 when unset or invalid - matching the clamp
  the worker env var already enforced.
- Values outside the bounds are rejected by the setter with an error, and by
  the API with a 422, rather than being silently clamped on write.
- A per-engagement override column exists (nullable; NULL = inherit the global
  default), added by an idempotent migration whose CHECK constraint enforces
  the same 1024-32768 range at the database level.
- `config_resolver.effective_agent_max_tokens` resolves campaign override ->
  global setting -> built-in default, exactly like
  `effective_agent_max_iterations`.
- `GET`/`PUT /settings/agent-max-tokens` read and write the global value.
- The engagement config endpoint reports both the effective value and whether
  it is overridden, and the config `PUT` distinguishes "field absent" (leave
  unchanged) from "field null" (clear the override) via `model_fields_set`,
  matching the existing iteration-budget behavior.
- The worker reads the resolved value from the control plane's agent-config
  response for each run, rather than the env var fixed at process start. The
  env var remains only as the fallback used if that lookup fails.
- The worker re-clamps whatever value it receives to its own 1024-32768 bounds
  before using it: the worker's own limits are the last word on what it will
  ask a provider for, independent of what any caller supplies.
- Raising the configured cap actually raises the cap used - the length-retry
  ceiling is lifted to at least the configured value, so a configured increase
  is not silently clamped back down on retry.
- A retry must be able to gain **real headroom over the run's own resolved
  max_tokens**, not merely sit at or above it: the retry ceiling is derived
  from that run's resolved value (at least double it), never from a static
  module-level default alone. Ceiling-tracking the configured cap is
  necessary but not sufficient - a retry ceiling that equals the value which
  already truncated the first attempt cannot help the second attempt either.
- The retry ceiling scales with the CONFIGURED retry count
  (`max_tokens * 2 ** AGENT_LENGTH_RETRIES`), not a fixed multiple - so
  raising `AGENT_LENGTH_RETRIES` actually reaches further each additional
  step, matching the exponential budget the retry loop itself already asks
  for on later attempts, rather than clamping every attempt after the first
  back down to the same doubled value.
- Settings exposes a "Vector Agent max tokens (global default)" section
  mirroring the iteration-budget section, and its help text states that this
  bounds output (reasoning plus tool-call JSON), not the context window, and
  that setting it too low breaks tool calls rather than shortening answers.
