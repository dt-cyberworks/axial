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

## REQ-SUPPLY-003: The tool-runner image builds, from hash-locked dependencies, with an SBOM

GitHub issue #43 and follow-up 06. HexStrike's own `requirements.txt` is loose
version ranges, so every image rebuild installed whatever PyPI served that day,
unverified. Separately, the image build broke (CI red) because Kali's rolling
Python moved to 3.14 and `cffi` had to be compiled without the libffi headers.
The runner is the component that talks to targets, so this is R3.

Acceptance criteria:

- The Dockerfile installs HexStrike's Python dependencies only from the
  vendored `tool-runner/hexstrike-requirements.lock.txt`, with
  `pip install --require-hashes --no-deps`; it never installs from the live
  `requirements.txt` of the cloned repository.
- [Negative test] Every package in the lock file is pinned to an exact version
  and carries at least one sha256 hash, so pip cannot fall back to an unpinned
  or unverified install. `pwntools` and `angr` are not in the lock (the image
  build already refuses them).
- `libffi-dev` is installed with a comment saying why, so the image builds on
  the current Kali Python.
- `scripts/regenerate_hexstrike_lock.sh` regenerates the lock from the pinned
  `HEXSTRIKE_SHA` inside the pinned base image, and the Dockerfile documents
  when to run it.
- CI builds every image and publishes a CycloneDX SBOM per image as a workflow
  artifact.
- The SBOM job has enough disk for the ~5 GB tool-runner image plus Trivy's
  export of it: runner disk is freed first, the five small images are removed
  from the image store before the tool-runner is built, and the tool-runner is
  built and scanned last. (The job failed with `no space left on device` at the
  tool-runner SBOM step on 2026-09-30.)
- The built image still starts `hexstrike_server.py` and answers `/health`,
  rejects calls without the shared secret (REQ-HARDEN-001), has
  `cap_net_raw` on nmap, and runs the allowlisted tools.
- [Negative test] `tool-runner/hexstrike-overrides.txt` lifts `tornado`,
  `pyOpenSSL` and `cryptography` above what HexStrike's pinned mitmproxy 10.4.2
  allows, because those releases carry known HIGH CVEs. The lock generator
  applies it (`uv pip compile --override`); verified in the image that
  `hexstrike_server.py`'s mitmproxy imports, `DumpMaster` and CA generation
  work with the overridden versions. Other CVEs in HexStrike's own upstream
  pins (fastmcp, h11, protobuf, msgpack, Brotli, mitmproxy, and newer
  cryptography advisories) remain and are tracked in
  the private review follow-up 12 (tool-runner dependency CVEs);
  they do not gate CI (the Trivy steps only create SBOMs).

