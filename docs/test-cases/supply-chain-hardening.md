---
title: Supply-chain hardening verification
status: ready
risk: R2
owner: engineering
---

# Supply-Chain Hardening Verification

Verifies [`../requirements/supply-chain-hardening.md`](../requirements/supply-chain-hardening.md).

## TC-SUPPLY-001: Every image is digest-pinned

Requirements:

- REQ-SUPPLY-001

Automated tests:

- `scripts/tests/test_image_pinning.py`

Objective:

Verify every Dockerfile base image and every compose `image:` is pinned by
`@sha256:` digest, that no floating `:latest` survives without a digest, and
that multi-stage internal references are correctly exempt.

Expected results:

- Every external `FROM` and every compose `image:` carries an `@sha256:` digest.
- No `:latest`/tag-only reference remains unpinned.
- The guard is pure-text (runs without Docker) so it blocks regressions in CI.

## TC-SUPPLY-002: The supply-chain scan is wired and blocking

Requirements:

- REQ-SUPPLY-002

Automated tests:

- `Makefile`
- `.github/workflows/sdlc.yml`

Objective:

Verify a Trivy scan runs locally (`make scan`) and in CI, failing on fixable
HIGH/CRITICAL dependency vulnerabilities, committed secrets, and Dockerfile/
compose misconfigurations, with documented exceptions only.

Expected results:

- `make scan` runs the image-pin guard plus `trivy fs` (vuln+secret, fixable
  HIGH/CRITICAL, exit-code 1) and `trivy config` (HIGH/CRITICAL, exit-code 1)
  against the documented ignore allowlist.
- The SDLC CI workflow runs the same two Trivy scans as a `supply-chain` job.
- Intentional exceptions live in `.trivyignore.yaml` with justifications; the
  real `cryptography` HIGH finding was fixed (dependency upgraded), not ignored.

## TC-SUPPLY-003: Hash-locked runner dependencies and SBOMs

Requirements:

- REQ-SUPPLY-003

Automated tests:

- `scripts/tests/test_tool_runner_supply_chain.py`
- `.github/workflows/ci.yml`

Objective:

Verify the runner installs only from the hash-locked file, the lock is complete
(exact versions, hashes), and CI emits SBOMs. Manual verification on the built
image is listed below.

Expected results:

- The tests above pass; a lock entry without `==` or without a hash fails
  `test_negative_every_locked_package_is_pinned_and_hashed`.
- Built image (2026-09-29, dev): `GET /health` answers; a call without the
  shared secret is rejected; `getcap` shows `cap_net_raw` on nmap; `nmap`,
  `nuclei`, `testssl`, `ffuf`, `curl` (`--globoff`) run.

