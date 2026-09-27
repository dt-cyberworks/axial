---
title: Supply-chain hardening (pinned images + automated scanning)
status: implemented
risk: R2
owner: engineering
---

# Supply-Chain Hardening

Part of the production-readiness work (see `docs/deployment-ionos.md`). The
deployment hardening checklist calls for pinned image digests and an image/
dependency scan; this closes both. It is behavior-preserving — pinning locks the
*current* image content and scanning is additive tooling — so R2, not R3.

Tests must verify these requirements directly. Do not weaken tests to match
implementation; update implementation when it violates this document.

## REQ-SUPPLY-001: Every container image is pinned by digest

Floating tags (`:latest`, `:16`, `:3.12-slim`) let the content behind a build
change silently between builds. Every image the stack builds from or runs must
be pinned by `@sha256:` digest.

Acceptance criteria:

- Every `FROM` base image in every Dockerfile, and every `image:` in the compose
  files, is pinned with an `@sha256:` digest (a readable tag may remain for
  humans, but the digest is authoritative). Multi-stage `FROM <stage>`
  references to an earlier build stage are exempt (not external images).
- No `:latest` reference survives without an accompanying digest.
- A pure-text guard test enforces this so an unpinned image cannot regress into
  the tree, independently of whether Docker is available.
- A helper (`scripts/pin_images.sh`) reports drift between the pinned digest and
  the digest a tag currently resolves to, so bumping (e.g. the rolling Kali
  runner base for security fixes) is an auditable diff.

## REQ-SUPPLY-002: Automated supply-chain scanning blocks known-fixable issues

The build must fail on a known, fixable high-severity dependency vulnerability,
a committed secret, or a Dockerfile/compose misconfiguration — with a small,
documented allowlist for intentional, compensated exceptions.

Acceptance criteria:

- `make scan` and CI run a filesystem scan (dependency vulnerabilities +
  secrets) that fails on fixable HIGH/CRITICAL findings, and a config scan
  (Dockerfile/compose misconfiguration) that fails on HIGH/CRITICAL findings.
- Intentional exceptions are recorded in a version-controlled ignore allowlist
  (`.trivyignore.yaml`), each with an explicit justification/compensating
  control — e.g. the raw-egress-gateway and Caddy containers that intentionally
  run as root, and the not-yet-deployed Kubernetes manifests.
- The scan currently passes: the one real finding it surfaced (a HIGH
  `cryptography` CVE in the control-plane, used for MFA secret encryption) was
  fixed by upgrading the pinned dependency, not ignored.
