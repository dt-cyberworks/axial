---
title: Agent containment hardening (execution-boundary auth, egress SSRF guard)
status: verified
risk: R3
owner: security-engineering
---

# Agent Containment Hardening

Derived from the rogue-agent threat model
([`../security/rogue-agent-threat-model.md`](../security/rogue-agent-threat-model.md)),
which asks: if the Vector Agent (or a target-facing component it drives) goes
rogue and tries to escape the platform's boundaries, what real gaps remain?
Most escape paths are already deterministically blocked by the Scope Gateway,
the fixed tool-argument envelope, per-engagement grants, mandatory approval for
writes, and network segmentation. Two concrete gaps remained; this document
specifies closing them.

**Risk class: R3** (`docs/engineering/sdlc.md` §2: "Scope Gateway, auth, audit,
runner, proxy, secrets"). REQ-HARDEN-001 changes the runner boundary;
REQ-HARDEN-002 changes the egress-proxy's connection behavior — both are
network security boundaries. Each requires positive and negative tests and,
per the SDLC, human security review; an automated agent cannot self-approve.

**Security review:** approved by johannes (project/security owner) on
2026-07-28, after review of the negative tests
(`tool-runner/tests/test_runner_auth.py`, `worker/tests/test_runner_auth_header.py`,
`egress-proxy/tests/test_ssrf_guard.py`) and the live verification (the runner
rejects an unauthenticated `/api/command` with 401 while `/health` stays open;
the egress-proxy refuses loopback/link-local/metadata targets while normal
in-scope scans are unaffected).

Tests must verify these requirements directly. Do not weaken tests to match
implementation; update implementation when it violates this document.

---

## REQ-HARDEN-001: The execution boundary authenticates every request

Context: the tool-runner runs HexStrike, which exposes `/api/command`
(arbitrary shell execution) and `/api/tools/*`, ships upstream with **no
authentication**, and binds `0.0.0.0:8888`. In the Compose topology the runner
shares a network namespace with `raw-egress-gateway` and is reachable from the
`runner`, `egress`, and `control` networks — including from the `egress-proxy`,
which parses untrusted scan-target responses. A single parsing bug in any
target-facing component would therefore escalate directly to arbitrary command
execution in the offensive runner.

Acceptance criteria:

- Every request to the runner except the liveness probe (`/health`) requires a
  caller-supplied shared secret (`X-ASM-Runner-Token`) that matches the
  runner's configured `RUNNER_API_TOKEN` in constant time; non-matching or
  absent tokens are rejected (HTTP 401) before any route logic runs.
- The check fails closed: if no token is configured, every non-health request
  is denied rather than silently accepted.
- The worker presents the token on **every** request it makes to the runner
  (tool dispatch and process-termination alike).
- `/health` remains reachable without a token (Compose/K8s liveness) and
  reveals nothing sensitive.
- In production, a missing or dev-default runner token makes the runner refuse
  to start (consistent with the raw-egress-gateway and egress-proxy startup
  guards), rather than run with a guessable secret.
- The authentication predicate is unit-testable without Flask, and the
  build-time patch that injects it into the vendored server is verified
  end-to-end (the gate is wired in before any route).

## REQ-HARDEN-002: The egress proxy refuses never-legitimate target addresses

Context: the egress-proxy authorizes a request against engagement scope by host
**name** (or an audited materialized IP), then connected with
`open_connection(host, port)` — resolving at connect time with no address
vetting. A scoped name that resolves, now or via DNS rebinding, to the cloud
metadata address (`169.254.169.254`), loopback, or a neighbouring container's
address would let an in-scope-looking request reach the proxy host, its
neighbours, or the instance metadata service, entirely inside "allowed" scope.

Acceptance criteria:

- Before connecting, the proxy resolves the target once and refuses — with an
  audited `blocked_*` DENY reason and HTTP 403 — any target that is, or
  resolves to, a never-legitimate address class: loopback, link-local
  (including `169.254.169.254` cloud metadata and `fe80::/10`), unspecified,
  multicast, or reserved, including their IPv4-mapped IPv6 forms.
- If **any** resolved address of a name is blocked, the whole name is refused
  (no salvaging a split-horizon answer into its public address).
- The proxy connects to the **vetted, pinned IP**, not by re-resolving the
  name, closing the resolve-then-connect DNS-rebinding window. The outbound
  `Host` header still carries the original name for correct virtual-host
  routing.
- This applies to both the CONNECT (TLS tunnel) and plaintext-HTTP paths.
- Private ranges (RFC1918, ULA) remain permitted: lab targets and internal
  own-domain engagements legitimately use them, and engagement scope continues
  to gate them. Only address classes that can never be a legitimate scan target
  are refused.
- The block is a creation/connection-time network control that does not change
  the scope-authorization decision itself; scope remains the primary gate.
