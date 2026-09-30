---
title: Container hardening for control-plane, worker, egress-proxy, and edge
status: implemented
risk: R3
owner: security-engineering
---

# Container Hardening

From the 2026-09-27 review (finding B6): the runner and the raw-egress
gateway already drop all capabilities, run read-only, and forbid privilege
escalation. The control plane, worker, egress proxy, and edge did not.

**Risk class: R3.** This limits what an attacker gains from a compromised
service; it changes no application behaviour and no authorization.

**Security review:** approved by johannes (project/security owner) on
2026-09-29 ("I approve all changes"), after the negative tests and the
mutation checks listed in the linked test cases. Live verification on the
dev stack is still owed at deploy time and is recorded in the test case.

Tests must verify these requirements directly. Do not weaken tests to match
implementation; update implementation when it violates this document.

Decision log:

- 2026-09-27: proposed by the review agent as backlog `REQ-HARDEN-003`.
- 2026-09-29: promoted and implemented on johannes's instruction to finish all
  remaining follow-ups (follow-up 03). Human security review (R3): approved by johannes 2026-09-29. The edge running as a non-root user was split out as backlog
  `REQ-HARDEN-004` (see [`backlog-container-hardening.md`](backlog-container-hardening.md)),
  because it changes how Caddy owns its certificate volumes and needs its own
  live verification.

---

## REQ-HARDEN-003: Least-privilege containers everywhere

Acceptance criteria:

- control-plane, worker, and egress-proxy run with `cap_drop: [ALL]` and
  nothing added back, `no-new-privileges`, and a read-only root filesystem.
  Their only writable path is a `tmpfs` at `/tmp` (temp files; the Celery beat
  schedule).
- The edge proxy (the shared edge and the `caddy` service of the single-host
  production overlay) runs with `cap_drop: [ALL]`, adding back only
  `NET_BIND_SERVICE`, plus `no-new-privileges` and a read-only root
  filesystem; its state lives in its named volumes (`/data`, `/config`) and a
  `/tmp` tmpfs.
- [Negative test] An automated test renders the real merged compose config
  (dev, single-host production, no-edge production, shared edge) and fails if
  any of these settings is missing, if a service adds a capability other than
  the documented one, or if a new long-running service is neither hardened nor
  listed with a reason. The tool-runner, raw-egress-gateway and third-party
  images are listed as explicit exceptions.
- Verified on a running stack: `docker diff` shows no writes outside the
  mounted paths, effective capabilities are empty (edge: exactly
  `NET_BIND_SERVICE`), a write outside the mounted paths fails, and the UAT
  golden path, a PDF report render and the edge's security headers are
  unchanged.

Security invariants:

- No service gains privileges; the runner and raw-egress gateway settings are
  unchanged.
