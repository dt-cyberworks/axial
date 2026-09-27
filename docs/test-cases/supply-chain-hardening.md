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
