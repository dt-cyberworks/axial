---
title: Scan rate policy
status: implemented
risk: R3
owner: security-engineering
---

# Scan Rate Policy Requirements

This document is the requirement source for operator-configurable scan rate limiting. Tests must verify these requirements directly. Do not weaken tests to match implementation; update implementation when it violates this document.

## REQ-RATE-001: Rate Limit Is Operator Configurable

The operator must be able to configure the default maximum number of gateway-approved tool calls per second from the Settings page.

Acceptance criteria:
- Settings includes a `Scan rate policy` section.
- Settings includes an input labelled `Maximum allowed tool calls per second`.
- The frontend API exposes `getScanPolicy` and `updateScanPolicy`.
- The backend exposes `GET /settings/scan-policy` and `PUT /settings/scan-policy`.
- The scan policy is persisted in `app_setting` so it can be changed without redeploy.

## REQ-RATE-002: Auto Slow Down Can Replace Hard Rate Denial

The operator must be able to switch on automatic slow down. When enabled, a rate-limited tool proposal should not be treated as a hard deny. The gateway must return a retry delay, the worker must wait, and the worker must re-authorize before dispatching.

Acceptance criteria:
- Settings includes a toggle labelled `Automatically slow down and retry rate-limited tool calls`.
- The gateway returns a `THROTTLE` audit decision with reason `rate_limited_wait` and `retry_after_seconds` when the rate bucket is full and auto slow down is enabled.
- The internal authorization API returns `is_throttled` and `retry_after_seconds` to workers.
- The deterministic fingerprint worker waits and retries throttled decisions instead of skipping immediately.
- The Vector Agent waits and retries throttled decisions and records `proposal_throttled` telemetry.
- Tool execution still happens only after a later normal `ALLOW`; throttling is not a bypass.

## REQ-RATE-003: Hard Deny Remains Available

If auto slow down is disabled, exceeding the rate limit remains a hard gateway denial.

Acceptance criteria:
- The gateway still returns `DENY rate_limited` when auto slow down is disabled.
- The Audit view explains both hard `rate_limited` and soft `rate_limited_wait` outcomes.
- Live Scan displays `THROTTLE` as a slowing-down/retry activity, not as an allowed execution.

## REQ-RATE-004: A Bug-Bounty Program's Rate Cap Is Honored Inside Multi-Request Tools, Not Only At Dispatch

Context: found while reviewing a real Intigriti program (Aylo/Brazzers, "max.
7 requests/sec") against this platform's existing bounty-rate enforcement.
`BountyProgram.max_rps` was already enforced at two real chokepoints - the
Scope Gateway's per-call authorization (`authorize.py`) and the egress
proxy's own `recent_allowed_count` check (`proxy.py`) - but neither sees
inside a single tool invocation. `nuclei` and `ffuf` each fire many requests
per gateway-authorized call, at their own hardcoded internal pace
(`-rate-limit 50`, `-rate 20`), never reading the engagement's configured
cap. For an HTTPS target the egress proxy's rate check runs once per
`CONNECT` (new TCP connection); a tool that reuses that connection via HTTP
keep-alive - the normal behavior of both tools' underlying Go HTTP client -
can then issue requests to the real target at its own hardcoded rate, not
the program's, with no further check in between. A program with an explicit
low numeric cap would be silently exceeded.

Acceptance criteria:

- When a `bug_bounty` engagement's configured `max_rps` is lower than a
  tool's own hardcoded default rate, `nuclei` (both the headless and
  non-headless passes) and `ffuf` are invoked with their own rate flag
  (`-rate-limit`, `-rate`) set to the engagement's `max_rps`, never the
  hardcoded default.
- When `max_rps` is unset (non-`bug_bounty` engagement) or is greater than or
  equal to a tool's own hardcoded default, that tool's existing hardcoded
  rate is used unchanged - this requirement only ever tightens the rate, never
  loosens it.
- The injection point is the same server-side chokepoint as REQ-AUTH-006
  (`ToolRunnerClient.run()`), sourced from the same cached-per-run bounty
  policy lookup - no new control-plane round trip per tool call.
- **NEGATIVE**: a non-`bug_bounty` engagement's `nuclei`/`ffuf` invocations are
  byte-for-byte unaffected - same hardcoded rate as before this change.
- **NEGATIVE**: a lookup failure degrades to each tool's existing hardcoded
  rate, exactly like a non-`bug_bounty` engagement - it must never abort the
  scan or fail closed to a rate of zero.
