---
title: BOLA/IDOR differential testing verification
status: ready
risk: R4
owner: security-engineering
---

# BOLA/IDOR Differential Testing Verification

Verifies [`../requirements/bola-idor-differential-testing.md`](../requirements/bola-idor-differential-testing.md).

## TC-AGENT-023: Second-identity BOLA/IDOR proof, isolated per identity and host

Requirements:

- REQ-AGENT-023

Automated tests:

- `worker/tests/test_agent_bola_identity.py`

Objective:

Verify the agent can carry a second, independent session (`identity:
"secondary"`) alongside its primary one, self-register that second identity
only through the existing mandatory-approval `http_request` path with a
worker-side synthetic-payload guard, and — the R4 invariant — never let a
secondary session leak into a primary request, or vice versa.

Expected results:

- `http_request` with no `identity` (or `identity: "primary"`) uses the
  `"primary"` jar for that host, unchanged from REQ-AGENT-022 behaviour.
- `http_request` with `identity: "secondary"` uses the `"secondary"` jar for
  that host only.
- NEGATIVE: when both a `"primary"` and a `"secondary"` jar exist for the
  same host in the same run, a `"secondary"`-identity request's Cookie
  header contains only the secondary session value — the primary session
  value never appears in the sent headers.
- NEGATIVE: an unrecognised `identity` value (not `"primary"`/`"secondary"`)
  fails closed to `"primary"`.
- A response is captured into the jar matching the identity that made the
  request (`"secondary"` stays `"secondary"`, never spills into
  `"primary"`).
- `register_test_identity` is authorized and dispatched as an ordinary
  `http_request` tool call (`tool="http_request"`) — no bespoke gateway
  registry entry — so it is always routed to mandatory operator approval as
  a write.
- NEGATIVE: a registration payload containing an email on a well-known
  real-world public mail-provider domain (e.g. `gmail.com`) is rejected
  **before** it is ever proposed to `authorize()` — the gateway never sees
  it, and it is recorded as `denied`, not merely as a lower-confidence
  finding.
- NEGATIVE: a registration with an invalid method (not POST/PUT), a missing
  path, or a missing body is rejected without reaching `authorize()`.
- A registration for an out-of-scope target is rejected the same way as any
  other proposal (`not_in_scope_list`), whether allowed immediately or
  routed through the approval-and-claim path.
- A successful registration's session lands in `"secondary"`, not
  `"primary"`, on both the immediate-allow path and the
  approval-then-claim path (mirroring REQ-AGENT-022's own approval-path
  capture).
- `session_state.looks_synthetic_registration_body` rejects a body
  containing a well-known real-world email domain (case-insensitively) and
  passes a body with a custom/example domain or no email at all.
