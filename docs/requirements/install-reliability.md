---
title: A published release installs and works from its own instructions
status: implemented
risk: R3
owner: platform-engineering
---

# A Published Release Installs and Works From Its Own Instructions

Context: on 2026-10-01 the published release v0.3.0 was installed, exactly as
`INSTALL.md` says, on a clean Ubuntu 24.04 virtual machine (local) and on a
short-lived cloud instance (production path). It did not install. The
findings were: the object-store image the stack pinned had been withdrawn
upstream (`minio/minio` no longer exists on Docker Hub; quay.io requires
authentication; the upstream repository is archived); the development
configuration left an encryption key empty so the first user could never
finish MFA enrollment although `/health` was green; the production
configuration block in the guide omitted four settings the production gate
requires, so the stack refused to start; and the guide pointed at a make
target and scripts that are not part of the public export.

A development machine hides every one of these: images are cached, tools and
keys are already present, and nobody follows the guide literally. The
requirements below make "a stranger can install it from the instructions" a
property that is tested, not hoped for.

**Risk class: R3.** The change generates and handles secrets, changes the
authentication error path, and replaces a container image that holds the
evidence store, including its network exposure. Per the SDLC an agent cannot
approve this; the owner's human security review is recorded as pending in the
decision log.

Tests must verify these requirements directly. Do not weaken tests to match
implementation; update implementation when it violates this document.

Decision log:

- 2026-10-01 - the clean-host install test (above) was run by johannes's
  request ("a good open-source project installs flawlessly from its
  instructions"). It was repeated on a real virtual machine rather than a
  container because the devbox has the prerequisites already installed.
- 2026-10-01 - decisions by johannes: (1) migrate the object store to
  SeaweedFS; (2) generate the secrets with a script instead of documenting
  them by hand (recommended); (3) run an install smoke test on each release;
  (4) implement it, fix everything that did not work, and release v0.3.1.
  This authorizes implementation and creating the v0.3.1 release candidate;
  merging it to the public `main` remains a separate decision.
- 2026-10-01 - finding recorded for the review: no application code reads or
  writes object storage today (no S3 client library is installed; evidence and
  report PDFs are kept in Postgres, see migration `0025_report.sql`). The
  object store is a placeholder for a planned evidence store. Consequently the
  migration moves no data, and the choice is reversible. Johannes's decision
  to migrate stands.
- 2026-10-01 - the old requirement that the object store's *console* binds to
  loopback in production (REQ-PRODDEPLOY-001) is replaced by a stricter one:
  the object store publishes no host port at all, in any profile. SeaweedFS
  has no authenticated console and its admin interfaces must never be
  reachable (REQ-INSTALL-002). This tightens, and does not weaken, the
  earlier exposure rule.
- Pending: human security review of this record and its implementation.

## REQ-INSTALL-001: The documented install is executed, end to end, from a clean checkout

Acceptance criteria:

- A script (`scripts/install_smoke.sh`) performs the install exactly as
  `INSTALL.md` documents it, from a fresh checkout of the exported tree, and
  fails on the first step that does not work. It has two stages:
  **local** (configuration, `make up`, health check, first administrator,
  complete first login with TOTP enrollment, a second login, an authenticated
  API call) and **production** (generated production configuration, the
  documented `config --quiet` validation, start of the production stack with
  its reverse proxy, a TLS check of the console, the documented first
  administrator command, a login through the proxy, and a check that only
  ports 80 and 443 are published on every interface).
- [Negative test] The smoke script's own checks fail when the stack is
  healthy but the first login cannot complete (the 2026-10-01 defect: an
  empty MFA encryption key), and when a production setting the gate requires
  is missing.
- The smoke script runs on a clean virtual machine with only the documented
  prerequisites installed, and the result is recorded in the release evidence.
- Every make target and repository path that `INSTALL.md` instructs the reader
  to use exists in the public export. [Negative test] A guide that names a
  target or path the export omits fails the check.

## REQ-INSTALL-002: The object store is obtainable, pinned, authenticated and isolated

Acceptance criteria:

- The compose file's object-store image is SeaweedFS, pinned by version and
  content digest (the supply-chain pin guard of REQ-SUPPLY accepts it) and
  pulls on a host with an empty image cache. No image reference in the stack
  points at a withdrawn repository.
- The S3 endpoint requires credentials: an anonymous request and a request
  with a wrong secret are denied, and a request with the configured
  credentials can create a bucket and write, read, list and delete an object.
  [Negative test] Verified against the real image in the install smoke.
- Only the S3 gateway is reachable from the network. The master, volume and
  filer interfaces, which have no authentication, are bound to the container's
  loopback, and the optional Iceberg and Lance endpoints are disabled.
  [Negative test] A request to the filer or master port from another
  container is refused.
- The object store joins one dedicated internal network that only the
  control-plane also joins; the worker, the egress proxy and every other
  service cannot reach it. It publishes no host port in any profile.
  [Negative test] The rendered compose configuration is checked for each
  of these, for development, production, and both named environments.
- Production refuses to start with a default S3 credential: both the
  previous default (`minioadmin`) and the current development default are
  rejected by the production gate. [Negative test]
- The service is hardened like its neighbours where the image allows it
  (no added capabilities, no privilege escalation) and has a health check.
- Upgrading from v0.3.0 needs no data migration (nothing stores objects, see
  the decision log); the old `miniodata` volume is left untouched and is
  documented as safe to remove after the upgrade.

## REQ-INSTALL-003: Secrets are generated, never shipped, and complete

Acceptance criteria:

- `make env` creates `.env` from `.env.example` when it is missing and fills
  every secret that is empty (the MFA and the settings encryption keys) with a
  freshly generated, valid Fernet key. It never changes a value that is already
  set, never writes a key into a tracked file, and leaves a production `.env`
  (`ENVIRONMENT=production`) untouched. It needs only `python3`'s standard
  library, because the documented prerequisites contain no Python packages.
  `make up` runs it first, so an existing `.env` that has the empty keys
  from v0.3.0 is repaired by the same command.
- [Negative test] Running it twice, or on a file with set values, changes
  nothing; the two generated keys differ from each other (a leak of one must
  not expose the other); a production file is not modified.
- The production generator (`scripts/gen_production_env.py`) emits every
  setting the production gate and the production compose files require,
  including `SETTINGS_ENCRYPTION_KEY`, `PUBLIC_BASE_URL` (https, derived from
  the domain), `OOB_TOKEN` and `RAW_EGRESS_API_TOKEN`, and no setting that
  no longer exists. `INSTALL.md` uses the generator instead of a hand-typed
  block.
- [Negative test] The generated production file passes the control-plane's
  real production validation and the documented `docker compose config
  --quiet`; removing any one required setting from it makes validation fail
  (the gate fails closed), so the generator cannot silently fall behind the
  gate again.
- The generator refuses to overwrite an existing file without `--force` and
  writes the file with mode `0600`.

## REQ-INSTALL-004: A missing encryption key fails clearly, not with a server error

Acceptance criteria:

- [Negative test] When the MFA encryption key is empty or malformed, the
  MFA enrollment and login endpoints answer `503` with a message that names
  the setting and how to create it, never an unhandled exception (`500`),
  and no TOTP secret is stored. The settings endpoint already behaves this
  way for its own key.
- The message does not contain the key, the secret, or any other credential.
- With a valid key the behavior is unchanged: the full first-login flow
  succeeds, including backup codes and a second login.

## REQ-INSTALL-005: The first administrator can always log in

Acceptance criteria:

- [Negative test] `scripts/bootstrap_admin.py` validates the address with the
  same validator the login endpoint uses and exits non-zero, without creating
  an account, when the address would later be rejected (for example a
  reserved name such as `.test`, `.local`, `.localhost`, or a missing domain),
  printing the reason and a valid example.
- A valid address creates the account exactly as before and the temporary
  password is still shown once.

## REQ-INSTALL-006: The public tree contains no instruction that cannot work

Acceptance criteria:

- Make targets that need files the public export omits (the lab, UAT and
  reference-scan harnesses) live in `Makefile.private`, which the export
  excludes; the public `Makefile` includes it only if present. `make help` in
  the public tree lists only targets that work there.
- [Negative test] Every target in the public tree's Makefile refers only to
  scripts and directories that exist in the public export, and `Makefile`
  keeps its optional include of the private file.
- A pre-scan safety check that needs no lab exists in the public tree:
  `make scope-check` runs the Scope Gateway's deny-path tests inside the
  built control-plane image and fails when any out-of-scope target is
  authorized. `INSTALL.md` uses it where it previously referred to the
  lab loop.

## REQ-INSTALL-007: The guide is complete for a reader who starts from nothing

Acceptance criteria:

- The prerequisite list names everything the guide's commands need (Git, GNU
  Make, Docker Engine with Compose v2, curl, OpenSSL and Python 3), and the
  local section ends with creating the first administrator, signing in, and a
  link to the user manual.
- The guide states what does not work with the shortcuts a reader is likely to
  try: a bare IP address cannot get a browser-trusted certificate and clients
  do not send a server name for it, so production needs a DNS name.
- The guide documents the v0.3.0 to v0.3.1 upgrade (object store replaced,
  nothing to migrate, new generator, `make env`, and the owner migration 0038
  of #47, which runs automatically and stops without changing anything when
  ownerless engagements exist but no active administrator does).
- [Negative test] A repository test fails when the guide mentions a removed
  setting (`MINIO_`), the withdrawn image, or the lab target.

## REQ-INSTALL-008: Every release is install-tested before it can be merged

Acceptance criteria:

- The public repository's CI runs the install smoke (REQ-INSTALL-001) on a
  fresh GitHub-hosted runner for every release pull request (`release/*`
  branches), for every `v*` tag, and on demand. A failure blocks the release
  pull request's checks.
- The job pulls every image from the registry without a cache, so an upstream
  image that has been withdrawn fails the release before users see it.
- [Negative test] A repository test asserts that the workflow exists, runs
  the smoke script, and has all three triggers; the exporter ships it.
