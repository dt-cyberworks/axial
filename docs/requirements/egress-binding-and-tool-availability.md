---
title: Egress binding and tool availability
status: implemented
risk: R3
owner: security-engineering
---

# Egress Binding & Tool Availability Requirements

This document is the requirement source for two defects that made scans (both the
deterministic pipeline and the Vector Agent) silently ineffective:

1. The shared egress-proxy could not associate a request with an engagement, so
   every target-touching call was blocked with `407 missing_engagement_id_header`
   — and the tools reported the block as "nothing found", not as a failure.
2. The agent was offered tools the worker cannot execute, wasting its budget on
   `unbekanntes Tool` rejections.

Tests must verify these requirements directly. Do not weaken tests to match
implementation; update implementation when it violates this document.

Context: the CLI scan tools (nikto, testssl, httpx, ffuf, curl-based
`http_request`) reach targets through the egress-proxy using generic proxy flags
(`-useproxy`, `-proxy`, `--proxy`, `-x`). None of them can attach a custom
`X-ASM-Engagement-Id` header to an HTTPS `CONNECT`. Any engagement-binding
scheme that depends on the tools sending that header is therefore unworkable for
these tools.

---

## REQ-EGRESS-001: Every proxied request is bound to the correct engagement without tool cooperation

The egress-proxy must reliably determine which engagement a request belongs to,
for all scan tools, without requiring the tool to send an engagement identifier.

Acceptance criteria:
- Engagement resolution order at the proxy:
  1. `ASM_ENGAGEMENT_ID` env (per-engagement proxy, e.g. the K8s per-run pod) — used as-is.
  2. `X-ASM-Engagement-Id` request header, when present (for callers that can send it).
  3. Otherwise, resolve from the requested target host: the single **active**
     engagement whose allow-scope matches that host.
- Host-based resolution is safe by construction: the resolved engagement still
  passes the full `evaluate()` chain (status active, time window, deny-precedence,
  allow-scope, rate limit). Resolution only selects *which* engagement's rules
  apply; it never bypasses them.
- If host-based resolution is **ambiguous** (two or more active engagements match
  the host) or matches **none**, the proxy fails closed (denies with a specific
  reason), never guesses.
- With this in place, a standard local run (one active engagement, shared proxy,
  no `ASM_ENGAGEMENT_ID`) reaches its in-scope targets; an out-of-scope host is
  still denied.

## REQ-EGRESS-002: A proxy block is surfaced as an error, not as "nothing found"

When a tool's traffic is blocked or fails at the egress-proxy, the dispatch layer
must return a distinguishable error observation — never an empty/clean result
that reads as "target is fine".

Acceptance criteria:
- The tool-runner/dispatch detects proxy-level failure signals (HTTP `407`/`403`
  from the proxy, `connect_failed`, or an otherwise empty result caused by a
  non-zero tool exit) and returns an explicit error observation identifying the
  egress block.
- The Vector Agent observation for such a call states the request was blocked at
  egress, so the agent does not conclude "no findings" or "WAF".
- A genuinely empty-but-successful scan (tool ran, target reachable, nothing
  found) remains reported as an empty result, distinct from an egress block.

## REQ-TOOL-004: The agent is only offered tools the worker can actually execute

`enabled_tools` presented to the Vector Agent (and, by extension, what the gateway
treats as runnable for agent proposals) must be the intersection of registry-
enabled tools and tools the worker can dispatch.

Acceptance criteria:
- `enabled_tools` for a campaign excludes any tool not present in the worker's
  dispatch mapping (`dispatch.TOOL_CATEGORY`), even if the registry marks it
  `default_enabled`.
- The capability registry exposes, per tool, whether it is agent-dispatchable, and
  this is the single source both the agent-config endpoint and any UI use.
- A tool that is registry-enabled but not dispatchable is reported as
  "installed/known but not agent-runnable" (not silently advertised as usable).
- Proposing a non-dispatchable tool cannot happen through the normal enabled list;
  if it still occurs, it is rejected with a clear, non-repeating reason.

## REQ-TOOL-005: The agent prompt reflects only the campaign's enabled tools

The agent must not be nudged toward tools that are disabled for the campaign.

Acceptance criteria:
- The instruction context makes the campaign `ENABLED TOOLS` list authoritative;
  the generic toolkit description must not cause the agent to propose a tool
  absent from that list (e.g. proposing `nuclei` when it is disabled).
- An empty or malformed tool proposal is skipped without consuming budget and
  without a confusing error.
