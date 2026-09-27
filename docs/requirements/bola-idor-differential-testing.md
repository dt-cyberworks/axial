---
title: BOLA/IDOR differential testing via a second identity
status: implemented
risk: R4
owner: security-engineering
---

# BOLA/IDOR Differential Testing

Derived from a live gap found while benchmarking the Vector Agent against
VAmPI (`benchmark/ground-truth/vampi.yaml`): the agent authenticated
successfully but never tested whether its own session could access another
user's object, because it only ever held one identity
([`REQ-AGENT-022`](agent-quality-and-scoring.md)). Proving BOLA (Broken
Object Level Authorization) / IDOR requires comparing what TWO independent
identities can access — a single-identity agent can only ever guess at an ID
change and hope, never actually observe the cross-user access.

**Risk class: R4** (`docs/engineering/sdlc.md`: a new active capability that
systematically requests another identity's data on a customer system).
Approved by johannes (project/security owner) 2026-08-04. Cross-identity
jar-isolation negative tests are mandatory, mirroring the cross-host
isolation discipline already established for REQ-AGENT-022.

This document covers **Part A only**: a second, self-registered SYNTHETIC
identity, for targets that visibly offer open signup. Part B (an
operator-supplied second-identity credential store, for targets with no open
registration) is deliberately out of scope here — it needs new encrypted
persistence, a migration, and its own GUI/legal review, and lands as a
separate follow-on requirement once Part A is validated live.

Tests must verify this requirement directly. Do not weaken tests to match
implementation; update implementation when it violates this document.

---

## REQ-AGENT-023: The agent can prove BOLA/IDOR with a second, synthetic identity

Context: the existing A01 guidance told the agent to "try IDOR-style ID
changes" with no way to observe the result — a single session can request a
different object id and get denied or allowed, but without a second
identity's own legitimate object to compare against, the agent cannot tell
"this endpoint has no authorization check" from "this object id does not
exist". The building blocks already existed and needed only to be extended,
not invented: `SimpleContext.cookies_by_host` (REQ-AGENT-022) already
captured one session per host; the mandatory per-call operator-approval flow
(REQ-APPROVAL-002) already routes every state-changing request — including a
registration POST — through human review before it is ever sent. **This
requirement therefore widens no safety envelope on its own**: it reuses the
`http_request` gateway/dispatch path verbatim (registration dispatches with
`tool="http_request"`, no new tool-runner or Scope-Gateway registry entry),
and adds a second, independently-isolated session slot plus a worker-side
synthetic-payload guard as defense-in-depth on top of the approval that was
already mandatory.

Acceptance criteria:

- `http_request` accepts an optional `identity` parameter (`"primary"`
  default, or `"secondary"`); the request's Cookie header is built from the
  session captured for that host **and that identity slot only**.
- **A session captured under `"secondary"` is never attached to a
  `"primary"` request for the same host, and vice versa** — the mandatory
  negative invariant, exactly mirroring REQ-AGENT-022's cross-host isolation.
  A secondary session also still never crosses to a different host.
- A missing, unrecognised, or non-string `identity` value fails closed to
  `"primary"` (today's well-tested behaviour) rather than being rejected or
  silently treated as `"secondary"`.
- A new `register_test_identity` tool lets the agent self-register a second
  account: it is authorized and dispatched as an ordinary state-changing
  `http_request` (`tool="http_request"`, `category="vuln"`), so it inherits
  the existing `_http_request_args_safe` structural checks and — being a
  POST/PUT — **always requires operator approval** like any other write; no
  new gateway concept is introduced.
- Before a registration proposal is even sent to `authorize()`, a worker-side
  guard rejects any payload containing an email address on a well-known
  real-world public mail-provider domain (defense-in-depth; the mandatory
  approval remains the actual safety mechanism). A body with no email at all
  passes through to approval unchanged.
- A successful registration's response is captured into the run's
  `"secondary"` jar for that host, never `"primary"` — including when the
  registration itself went through the approval-and-claim path (the
  approval path is where the actual write happens, exactly as for a login,
  REQ-AGENT-022).
- The default prompt instructs the agent: prove BOLA/IDOR by requesting the
  SAME object reference as both identities and comparing, not by guessing at
  an ID change alone; check the object is not legitimately reachable fully
  unauthenticated before concluding BOLA; stay to 2–3 object references
  (proof, not enumeration); and report BOLA/IDOR coverage as UNTESTED — not
  "clean" — when no open registration and no second credential set exist.
