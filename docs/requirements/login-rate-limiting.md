---
title: Login rate limiting and client address
status: implemented
risk: R3
owner: security-engineering
---

# Login Rate Limiting

GitHub issue #31 (split from #23): the per-account lockout was the only brake
in front of the login endpoints. An attacker spreading guesses across many
accounts, or timing them to stay under each account's lockout, met no other
friction. While fixing it, a second problem showed up: the client address
(used in the account audit log and now for the limit) was taken from the
first `X-Forwarded-For` value, which any client can write itself when it
reaches the control plane directly.

**Risk class: R3** (authentication). Negative tests and a human security
review are required.

**Security review:** approved by johannes (project/security owner) on
2026-09-29 ("I approve all changes"), after the negative tests and the
mutation checks listed in the linked test cases. Live verification on the
dev stack is still owed at deploy time and is recorded in the test case.

Tests must verify these requirements directly. Do not weaken tests to match
implementation; update implementation when it violates this document.

## REQ-IAM-016: A source address that tries too often is throttled

Acceptance criteria:

- The unauthenticated login steps (`/auth/login`, `/auth/login/mfa`,
  `/auth/password/set-first`, `/auth/mfa/enroll`,
  `/auth/mfa/enroll/confirm`) share one counter per source address:
  default 30 attempts per 5 minutes (`LOGIN_RATE_LIMIT_ATTEMPTS`,
  `LOGIN_RATE_LIMIT_WINDOW_SECONDS`; 0 disables it).
- Above the limit the answer is `429` with `Retry-After` (seconds until the
  window ends), whatever the account.
- [Negative test] A burst from one address across many accounts is throttled.
- A different address, against the same account, is not affected.
- [Negative test] Being throttled is not a failed login: it never moves an
  account's lockout counter, so the limit cannot lock anyone out.
- Signed-in requests are not limited.
- The counter lives in Redis (shared by all workers and replicas, one atomic
  transaction per attempt). If Redis is unreachable, a per-process window
  keeps throttling and Redis is not asked again for 30 seconds.
- The login page says "Too many sign-in attempts from your network" for a
  `429` instead of "Invalid email or password".

## REQ-IAM-017: The client address comes from the edge, not from the client

Acceptance criteria:

- `X-Forwarded-For` is used only when the direct peer is a trusted proxy
  (`TRUSTED_PROXY_CIDRS`, default loopback and private ranges, where the edge
  reaches the control plane from). The client is the nearest forwarded
  address that is not itself a trusted proxy; a malformed hop falls back to
  the peer.
- [Negative test] A client talking to the control plane directly cannot pick
  its address by sending `X-Forwarded-For`: rotating it does not reset its
  limit.
- The same address is recorded in session and account audit entries (login
  and admin actions).

Security invariants:

- The limit only adds a brake; the per-account lockout and MFA are
  unchanged.
- The edge (Caddy) overwrites `X-Forwarded-For` for untrusted clients, so the
  address behind the edge is the real client address.
