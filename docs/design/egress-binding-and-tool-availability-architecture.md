# Architecture & Design: Egress Binding & Tool Availability

Design for the requirements in
[`../requirements/egress-binding-and-tool-availability.md`](../requirements/egress-binding-and-tool-availability.md).
SDLC phases 2–3. One row per requirement.

## Problem recap (evidence)

- Running egress-proxy has `ASM_ENGAGEMENT_ID` empty → multiplex mode → every
  request needs `X-ASM-Engagement-Id`. No CLI tool can send it on a `CONNECT`
  → every target-touching call returned `407 missing_engagement_id_header`.
- Tools reported that block as empty results ("keine Treffer"), so the agent
  concluded "WAF/clean" — silently wrong. Recent runs added **0** findings.
- `enabled_tools` was `registry.default_enabled` only. 5 enabled-but-not-
  dispatched tools (amass, default-cred-check, sslscan, subfinder, whatweb) were
  advertised to the agent → wasted `unbekanntes Tool` rejections.

## 1. REQ-EGRESS-001 — proxy resolves the engagement (no tool cooperation)

The proxy already has DB access and `evaluate(engagement_id, host, path)` already
enforces status/window/deny/allow/rate. Only the *selection* of engagement_id
changes.

**`egress-proxy/app/proxy.py` — resolution order in `handle_client`:**
1. `DEFAULT_ENGAGEMENT_ID` (env `ASM_ENGAGEMENT_ID`) — unchanged.
2. `X-ASM-Engagement-Id` header — unchanged.
3. **New fallback:** `resolve_engagement_for_host(host)` — pick the single active,
   in-window engagement whose allow-scope matches `host` and whose deny-scope does
   not. Ambiguous (>1) or none → fail closed (`407 engagement_unresolved` /
   `403 not_in_scope`).

**`egress-proxy/app/db.py` — new `candidate_engagements()`** returns active,
in-window engagements with their allow+deny scope assets in one query; the proxy
matches `host` in Python reusing the existing `_matches_host` (domain-suffix,
wildcard, ip/cidr). This keeps host-matching identical to `evaluate()`.

Safety: resolution never bypasses `evaluate()` — the chosen engagement still runs
the full chain, so an out-of-scope host is still denied. Resolution is a *lookup*,
not a permission. The audit entry records how the engagement was resolved
(`env` / `header` / `host`).

## 2. REQ-EGRESS-002 — surface egress blocks as errors

**`worker/app/tasks/dispatch.py`** — add `_egress_blocked(result) -> str | None`
that inspects the tool-runner result (stdout + stderr + exit_code) for proxy
failure signatures:
- `407` / `missing_engagement_id_header` / `engagement_unresolved`
- `CONNECT tunnel failed` / `Received HTTP code 40x from proxy` / `connect_failed`
- non-zero exit with empty stdout while a proxy is configured

Every `_dispatch_*` (and the `http_request`/`ffuf` handlers) checks it first and,
if matched, returns `Observation(tool, target, "EGRESS BLOCKED: <reason> — not a
clean result; the request never reached the target")`. This is distinct from the
existing empty-but-clean messages ("no findings", "keine Treffer"). The agent
then treats it as a failed action, not evidence.

No change to a genuinely clean scan: those still return the empty-result message.

## 3. REQ-TOOL-004 — enabled_tools = enabled ∩ dispatchable

The registry already carries the truth: `ToolSpec.dispatched`. The 5 offending
tools are exactly the `dispatched=False` ones.

- `config_resolver.enabled_tools(...)` → filter to `registry.get(tool).dispatched`.
- Add `registry.agent_dispatchable() -> set[str]` (tools with `dispatched=True`)
  as the SSOT; `enabled_tools` and any UI read from it.
- `effective_tool_policy` / the config GUI gains an `agent_dispatchable` flag per
  tool so an operator sees "known but not agent-runnable" instead of a usable
  toggle that does nothing for the agent.
- The gateway whitelist (`enabled_whitelist`) is unchanged — it governs
  authorization, not what the agent is offered. (A non-dispatched tool proposed
  anyway is still rejected by the worker; REQ-TOOL-005 stops that at the source.)

## 4. REQ-TOOL-005 — prompt + proposal hygiene

- `worker/app/tasks/agent.py`: the initial context already lists ENABLED TOOLS;
  strengthen the wording so the model treats it as authoritative and does not
  propose tools outside it (fixes the `nuclei` attempt). Keep the generic toolkit
  description but subordinate it to the enabled list.
- `_handle_run_check` / dispatch routing: skip empty/blank tool names without
  recording a confusing error or consuming an iteration meaningfully.

## 5. QA plan (SDLC phase 5)

- **egress-proxy** unit tests: resolution order (env > header > host), host
  ambiguity → fail closed, out-of-scope host still denied after host-resolution.
- **worker** tests: `_egress_blocked` detection for 407/tunnel-failed/empty-exit;
  a clean empty result is NOT flagged; agent observation wording.
- **control-plane** tests: `enabled_tools` excludes `dispatched=False` tools;
  `agent_dispatchable()` SSOT.
- **Live**: recreate egress-proxy (no env), start a real run against the
  `Codex scoped agent test example.com` engagement, confirm the deterministic
  scan now produces findings dated today and the agent's `http_request` returns
  real response bodies (not 407). This is the acceptance proof.

## 6. Non-goals

- Changing the K8s per-engagement pod model (still valid; env path unchanged).
- Making the CLI tools send headers (unworkable; that's why we resolve at the proxy).
- Multi-tenant host-overlap resolution beyond fail-closed-on-ambiguity.
