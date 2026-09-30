---
title: Edge proxy as a non-root user
status: backlog
risk: R3
owner: security-engineering
---

# Edge Proxy Non-Root

Split from the container-hardening requirement
([`container-hardening.md`](container-hardening.md), REQ-HARDEN-003), which
drops all capabilities from the edge but leaves it running as root.

## REQ-HARDEN-004: The edge runs as a non-root user

Acceptance criteria:

- The edge proxy (shared edge and single-host `caddy`) runs as a non-root
  user, still able to bind 80/443 and to renew certificates.
- Its named volumes (`/data`, `/config`) are writable by that user, including
  volumes that already exist from earlier deployments.
- Verified on the dev stack, then int: both sites serve, certificates renew,
  and the security headers are unchanged (REQ-WEBSEC-001..003).

Value and context:

- Defence in depth on the one container that faces the internet. With
  `cap_drop: [ALL]` and no-new-privileges (REQ-HARDEN-003) the remaining
  benefit is smaller, but a root process can still read every file the
  container mounts.

Open questions and dependencies:

- Existing `edge_data`/`edge_config` volumes are owned by root; migrating them
  needs a one-time `chown` step and a plan for the shared edge on the live
  server, where a failed certificate volume means a public outage.

Implementation authorization:

- None until this requirement is promoted out of `backlog` through SDLC
  review.

Backlog decision log:

- 2026-09-29 - split out of REQ-HARDEN-003 by the implementing agent; flagged
  to johannes because it touches the live server's certificate volumes.

Security invariants:

- The edge never gains a capability beyond `NET_BIND_SERVICE`.
