---
title: Agent containment hardening verification
status: ready
risk: R3
owner: security-engineering
---

# Agent Containment Hardening Verification

Verifies [`../requirements/agent-containment-hardening.md`](../requirements/agent-containment-hardening.md).
R3: negative paths (unauthorized runner request rejected; SSRF target refused)
are required and are the primary evidence.

## TC-HARDEN-001: The execution boundary rejects unauthenticated requests

Requirements:

- REQ-HARDEN-001

Automated tests:

- `tool-runner/tests/test_runner_auth.py`
- `worker/tests/test_runner_auth_header.py`

Objective:

Verify the runner's shared-secret gate authenticates every non-health request,
fails closed when misconfigured, refuses an insecure production token, and that
the worker always presents the token.

Expected results:

- `/api/command` and every `/api/tools/*` / `/api/processes/*` path are allowed
  only with a token matching the configured `RUNNER_API_TOKEN`; a wrong,
  empty, or absent token is denied.
- With no token configured, every non-health request is denied; `/health`
  stays open with or without a token.
- `enforce_production_token` raises for a missing or dev-default token when
  `ENVIRONMENT=production`, and is a no-op in development.
- The build-time patch injects the `@app.before_request` gate — importing the
  testable predicate and returning `runner_auth_required` (401) — before the
  first route, exactly once.
- The worker's `ToolRunnerClient` attaches `X-ASM-Runner-Token` as a default
  header when `RUNNER_API_TOKEN` is set, and attaches nothing when it is not.

## TC-HARDEN-002: The egress proxy refuses never-legitimate target addresses

Requirements:

- REQ-HARDEN-002

Automated tests:

- `egress-proxy/tests/test_ssrf_guard.py`

Objective:

Verify the proxy's address guard refuses loopback/link-local/metadata/
unspecified/multicast/reserved targets (including via DNS resolution and
rebinding) while permitting public and private-lab targets, and pins the vetted
IP.

Expected results:

- Literal loopback (`127.0.0.1`, `::1`), link-local / cloud metadata
  (`169.254.169.254`, `fe80::1`), unspecified (`0.0.0.0`), and IPv4-mapped
  forms (`::ffff:127.0.0.1`, `::ffff:169.254.169.254`) are refused with the
  matching `blocked_*` reason.
- A name resolving to the metadata address is refused; a split-horizon answer
  containing one blocked address refuses the whole name (no salvage).
- A public IP / a name resolving to a public IP returns that IP to connect to;
  private IPs (`10/8`, `172.16/12`, `192.168/16`) and names resolving to them
  are permitted (lab + internal own-domain targets).
- An unresolvable name fails closed (`dns_resolution_failed`).
