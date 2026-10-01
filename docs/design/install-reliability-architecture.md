# Install Reliability — Architecture

Specifies how [`REQ-INSTALL-001..008`](../requirements/install-reliability.md)
are met. Verification: [`TC-INSTALL-001..008`](../test-cases/install-reliability.md).
Risk class **R3** (secrets generation, authentication error path, the evidence
store's image and network exposure); human security review approved by johannes
on 2026-10-01 (see the decision log of the requirement record).

## 1. What was wrong, and the shape of the fix

A clean-machine install of v0.3.0 failed in five different ways that no
developer-machine check could see. They share one cause — the guide, the
configuration and the tree were maintained separately and nothing ever ran them
together on a machine that had nothing cached — so the fix is one mechanism plus
the individual repairs:

```
 INSTALL.md ──documents──▶ Makefile ─▶ scripts/ ─▶ docker-compose*.yml ─▶ images
     ▲                                                    │
     │      scripts/install_smoke.sh follows the guide    │
     └──────── on a CLEAN runner, on every release ◀──────┘
              .github/workflows/install-smoke.yml
```

Static tests (`scripts/tests/test_install_docs.py`) keep the guide and the tree in
step on every change; the smoke script proves the whole path on a clean machine
before a release can be merged.

## 2. Object store: MinIO → SeaweedFS (REQ-INSTALL-002)

**Why.** `minio/minio` was withdrawn from Docker Hub and quay.io requires
authentication; the upstream repository is archived. A fresh `make up` could not
pull the stack. No application code reads or writes object storage today (no S3
client library is installed; evidence and report PDFs are stored in Postgres, see
migration `0025_report.sql`), so the store is a placeholder for a planned evidence
store and the migration moves no data.

**Choice.** SeaweedFS (Apache-2.0), decided by johannes on 2026-10-01. Pinned
`chrislusf/seaweedfs:4.48@sha256:4e61d15f…` (images are cosign-signed upstream).

**The security delta, found by testing the real image** before adopting it:

| Finding (default `weed server -s3`) | Consequence | Mitigation in `docker-compose.yml` |
|---|---|---|
| Master (9333), volume (8080), filer (8888) HTTP APIs have **no authentication**; the filer reads/writes every object | anyone on the network bypasses the S3 credentials | `-ip.bind=127.0.0.1` (all three on the container's loopback), S3 alone on `-s3.ip.bind=0.0.0.0` |
| Optional Iceberg (8181) and Lance (9101) endpoints listen | extra unauthenticated surface | `-s3.port.iceberg=0 -s3.port.lance=0` |
| The S3 gateway's own gRPC port (18333) cannot be bound separately | a network peer could speak to it | dedicated internal network `objstore`, joined only by the control-plane |
| Without `AWS_ACCESS_KEY_ID/SECRET` S3 serves **anonymously** | open store | defaults are never empty; production overlay requires the injected values (`:?`) and the control-plane gate rejects every public default and empty |
| Entrypoint starts as root, drops to uid 1000 with `su-exec` | `cap_drop: [ALL]` alone makes it crash | `cap_add: [CHOWN, SETUID, SETGID]`; the server process then holds no capability (verified: `CapEff` 0, uid 1000) |

Also: `read_only: true` + `tmpfs: /tmp`, `no-new-privileges`, a health check, no
published port in any profile, volume `seaweedfsdata` (the old `miniodata` is left
untouched). The unauthenticated filer UI is the reason there is no console to
publish, in contrast to MinIO's authenticated one.

**Threat model** (added as S13 in [`rogue-agent-threat-model.md`](../security/rogue-agent-threat-model.md)):
the worker is *semi-trusted* and the egress proxy *untrusted-facing*; both share
`ctrl`. Putting the store on `ctrl` would have let either reach the gRPC port.
Residual: a compromised control-plane can reach it — it already holds the S3
credentials and is the trusted zone.

## 3. Configuration (REQ-INSTALL-003)

| Piece | Behavior |
|---|---|
| `.env.example` | still ships **no** key (REQ-IAM-004 invariant); documents `make env` |
| `scripts/init_dev_env.py` (`make env`, run by `make up`) | creates `.env` mode 0600 from the example; fills only **empty** `MFA_ENCRYPTION_KEY` / `SETTINGS_ENCRYPTION_KEY` with distinct Fernet-format keys; never changes a set value; leaves `ENVIRONMENT=production` files untouched; standard library only; prints key names, never values. Repairs a v0.3.0 `.env` |
| `scripts/gen_production_env.py` | now emits `SETTINGS_ENCRYPTION_KEY`, `PUBLIC_BASE_URL=https://<domain>`, `S3_ENDPOINT=http://seaweedfs:8333`; drops the `MINIO_CONSOLE_*` settings (flag kept as an accepted no-op); creates the file 0600 atomically; refuses to overwrite |
| `control-plane/app/config.py` | `s3_*` defaults renamed; the production gate rejects the previous default (`minioadmin`), the current one, and empty |
| `control-plane/tests/test_install_reliability.py` | builds `Settings` from the generator's real output and removes each gate-required field in turn — the generator cannot fall behind the gate again |

## 4. Failure behavior (REQ-INSTALL-004/005)

- `app/mfa.py::_fernet` raises `MfaKeyUnavailable` for an empty or malformed key
  (`from None`, so the cipher's own message cannot leak); `app/main.py` maps it to
  `503 {"detail": "MFA_ENCRYPTION_KEY is not configured. … run make env …"}` and logs
  a startup warning. Nothing is stored on failure; once the key is set the same
  challenge succeeds. No endpoint, schema or table changes.
- `control-plane/scripts/bootstrap_admin.py` validates the address with pydantic's
  `EmailStr` — the validator of `LoginIn` — so the two cannot disagree; an unusable
  address exits 1 before the database is touched.

## 5. Tree hygiene (REQ-INSTALL-006/007)

- `Makefile` holds only targets that work in the public tree; `Makefile.private`
  (lab, UAT, reference scan, manual screenshots) is `-include`d when present and is
  on the export deny list. A latent `make help` bug (garbled with two makefiles) is
  fixed with `grep -h`.
- `make scope-check` runs four database-free Scope Gateway test files inside the
  built control-plane image (`docker compose run --rm --no-deps`, tests bind-mounted
  read-only) — the public replacement for the lab loop the guide wrongly cited.
- `INSTALL.md`, `README.md` and the manual quickstart are rewritten around
  `make env` / the generator; the guide documents the bare-IP pitfall (no SNI for IP
  literals; verified on a cloud host) and the v0.3.0 → v0.3.1 upgrade.

## 6. The smoke test and the release gate (REQ-INSTALL-001/008)

`scripts/install_smoke.sh [local|production|all]` follows the guide on a **copy** of
the tree with its own compose project and network prefix; it refuses when a port it
needs is taken, never touches the caller's `.env` or volumes, and removes only what
carries its own project label. Stages:

| Stage | Steps (each a hard failure) |
|---|---|
| local | `make env` → keys present → `make up` → `/health` → bootstrap rejects `admin@example.test` → bootstrap → full first login (`smoke_first_login.py`: password change, TOTP, backup codes, second sign-in) → **blank-key negative** (503 naming the key) → object-store checks as control-plane and as worker (`smoke_object_store.py`: anonymous and wrong-secret denied, SigV4 CRUD, admin interfaces unreachable, store unresolvable from the worker) → `make scope-check` → console on :5173 |
| production | generator → `config --quiet` → **negative** (missing `OOB_TOKEN` refused) → `up` with Caddy → TLS, HSTS, `/internal/*` 404, unauthenticated 401 → the guide's bootstrap command → login through the proxy → only 80/443 published, object store publishes nothing → object-store checks with the generated credentials |

`SMOKE_RUNNER=1` adds the active-scanning profile (slow, builds the tool-runner).
`.github/workflows/install-smoke.yml` runs both stages on a fresh `ubuntu-24.04`
runner for `release/*` pull requests, `v*` tags and manual dispatch, with read-only
permissions. Because the runner starts with no image cache, a withdrawn upstream
image fails the release.

## 7. Requirement traceability

| Requirement | Implemented by | Verified by |
|---|---|---|
| REQ-INSTALL-001 | `scripts/install_smoke.sh`, `smoke_first_login.py`, `Makefile` (`install-smoke`) | TC-INSTALL-001 |
| REQ-INSTALL-002 | `docker-compose.yml`, `docker-compose.prod.yml`, `control-plane/app/config.py`, `smoke_object_store.py` | TC-INSTALL-002 |
| REQ-INSTALL-003 | `scripts/init_dev_env.py`, `scripts/gen_production_env.py`, `.env.example`, `Makefile` | TC-INSTALL-003 |
| REQ-INSTALL-004 | `control-plane/app/mfa.py`, `control-plane/app/main.py` | TC-INSTALL-004 |
| REQ-INSTALL-005 | `control-plane/scripts/bootstrap_admin.py` | TC-INSTALL-005 |
| REQ-INSTALL-006 | `Makefile`, `Makefile.private`, `scripts/oss-public-paths.deny.txt` | TC-INSTALL-006 |
| REQ-INSTALL-007 | `INSTALL.md`, `README.md`, `docs/manual/quickstart.md` | TC-INSTALL-007 |
| REQ-INSTALL-008 | `.github/workflows/install-smoke.yml` | TC-INSTALL-008 |

## 8. GUI

No console screen changes. The sign-in and MFA screens already surface the API's
`detail` text, so the new 503 message is shown to the user as is.

## 9. Rollout and rollback

- **Data model / API:** none. No migration.
- **Dev, int, prod hosts:** `docker compose up -d` creates the new `seaweedfs`
  service and `objstore` network and leaves the old MinIO container and `miniodata`
  volume orphaned (remove after the upgrade; they were never written to). Each
  `.env.*` should get `S3_ENDPOINT=http://seaweedfs:8333`; until it does the value is
  merely unused. Deploy order stays dev → int → prod.
- **Rollback:** the code is reversible by checking out v0.3.0, **but** the MinIO image
  it pins can no longer be pulled; a host that has pruned it cannot start that
  service. Nothing depends on the service, so a rollback may omit it. This is the
  strongest reason to roll forward.
- **Not run:** `make lab-test` (it exercises the scan pipeline, which this change does
  not touch, and it deletes the main stack's volumes by design). The Scope Gateway's
  deny paths are covered by `make scope-check` and the unchanged unit suite.
