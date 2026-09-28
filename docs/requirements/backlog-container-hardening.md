---
title: Container hardening for control-plane, worker, egress-proxy, and edge
status: backlog
risk: R3
owner: security-engineering
---

# Container Hardening

From the 2026-09-27 review (finding B6): the runner and the raw-egress
gateway already drop all capabilities, run read-only, and forbid privilege
escalation. The control plane, worker, egress proxy, and edge do not.

## REQ-HARDEN-003: Least-privilege containers everywhere

Acceptance criteria:

- control-plane, worker, egress-proxy, and edge run with
  `cap_drop: [ALL]` (adding back only what a service provably needs, for
  example `NET_BIND_SERVICE` for the edge), `no-new-privileges`, and a
  read-only root filesystem with explicit writable mounts where needed.
- The edge runs as a non-root user.
- Verified by starting the full stack and running the UAT golden path and
  scan journey on the dev environment, then int.

Value and context:

- Limits what an attacker gains from a compromised service; cheap once
  verified.

Open questions and dependencies:

- Which paths each service writes (temp files, report rendering, caches).
- Needs a live stack for verification; coordinate with the other agent
  working on this host's containers.

Implementation authorization:

- None until this requirement is promoted out of `backlog` through SDLC
  review.

Backlog decision log:

- 2026-09-27 — proposed by the review agent; not implemented in the review
  change set because it needs a full live-stack verification.

Security invariants:

- No service gains privileges; the runner and raw-egress gateway settings
  are unchanged.
