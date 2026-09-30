---
title: Container hardening verification
status: ready
risk: R3
owner: security-engineering
---

# Container Hardening Verification

Verifies [`../requirements/container-hardening.md`](../requirements/container-hardening.md).
R3: the negative tests are the primary evidence.

## TC-HARDEN-003: Long-running services run with least privilege

Requirements:

- REQ-HARDEN-003

Automated tests:

- `scripts/tests/test_container_hardening.py`

Objective:

Prove from the rendered compose config that control-plane, worker and
egress-proxy drop every capability, forbid privilege gain and run read-only,
that the edge keeps only `NET_BIND_SERVICE`, and that a new service cannot slip
in unhardened.

Expected results:

- `test_negative_python_services_*` fails when a setting is missing or a
  capability is added, for dev, single-host production and no-edge production.
- `test_negative_the_edge_keeps_only_net_bind_service` covers the shared edge
  and the production `caddy`.
- `test_writable_paths_are_explicit_tmpfs_or_volumes` and
  `test_every_long_running_service_is_either_hardened_or_a_documented_exception`
  pass.
- Live checks (at deploy, recorded in the memory note): `docker diff`, effective
  capabilities and a failing write outside `/tmp`.
