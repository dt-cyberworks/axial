---
title: Vector Agent max-tokens configuration verification
status: ready
risk: R2
owner: engineering
---

# Vector Agent Max-Tokens Configuration Verification

Verifies [`../requirements/agent-max-tokens-configuration.md`](../requirements/agent-max-tokens-configuration.md).

## TC-AGENT-026: The completion-token cap is configurable and resolves through the layers

Requirements:

- REQ-AGENT-026

Automated tests:

- `control-plane/tests/test_agent_max_tokens_settings.py`
- `worker/tests/test_agent_max_tokens.py`
- `frontend/tests/agent_max_tokens_settings.test.mjs`

Objective:

Verify the setting round-trips with its bounds enforced, resolves
campaign-over-global-over-default, and is actually what the worker asks the
provider for.

Expected results:

- Unset reads the built-in default of 8192.
- A valid value round-trips through set/get.
- Values below 1024 and above 32768 are rejected by the setter with an error
  and are not persisted; a corrupt stored value falls back to the default
  rather than propagating.
- `effective_agent_max_tokens` returns the engagement override when set, the
  global value when the override is NULL, and the built-in default when
  neither is set.
- The internal agent-config response carries the resolved value.
- The worker uses the delivered value for its completion request, falls back
  to the env-var default when the config lookup fails, and re-clamps an
  out-of-range delivered value to its own bounds.
- A configured value above the built-in retry ceiling is not clamped back down
  on a length retry.
- **Negative (the 2026-08-11 incident regression test):** at the built-in
  default (8192), with no operator configuration, a length retry asks for
  strictly MORE tokens than the first (already-truncated) attempt — not
  merely a ceiling that happens to equal the configured cap. This is the
  distinction the previous test above does not catch: the pre-fix formula
  passed "ceiling >= configured cap" while still giving a retry zero real
  headroom, which is exactly how two live benchmark engagements
  (Confluence, Jenkins) got zero agent tool calls despite the ceiling
  "correctly" tracking the cap.
- The same real-headroom property holds at every configured cap
  (1024/8192/16384/32768), not only the default.
- Settings renders a max-tokens section with 1024/32768 input bounds, wired to
  its own query and mutation.
