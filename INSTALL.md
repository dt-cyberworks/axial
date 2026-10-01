# Install Axial on a Host

This guide takes you from a clean host to a working Axial installation. It
covers two Docker Compose setups:

- **Local evaluation** — API and operator console on a private workstation.
- **Single-host production** — a persistent server with the UI and API behind
  Caddy and automatic HTTPS.

Docker Compose supplies Postgres, Redis, the object store, the control plane,
worker, egress proxy, and isolated execution services. A production host does
not need separate Python packages, PostgreSQL, Redis, or Node.js installations.

Every release is tested by following this guide on a fresh machine
(`scripts/install_smoke.sh`, run by the release workflow), so an instruction
that stops working is found before you are.

> [!WARNING]
> Install Axial only on infrastructure you control. Do not scan a system until
> you have written authorization, an explicit scope, and an active test
> window. See [docs/legal.md](docs/legal.md).

## 1. Choose the installation type

| Goal | Follow |
|---|---|
| Try the API and UI locally | [Local evaluation](#3-local-evaluation) |
| Run authorized active scans from a workstation | Local evaluation, then [enable active scanning](#enable-active-scanning) |
| Install a persistent internet-facing service | [Single-host production](#4-single-host-production) |
| Isolate each customer in Kubernetes | [Kubernetes](#7-kubernetes) |

## 2. Prepare the host

### Hardware

Actual requirements depend on scope and concurrency. For an initial
single-host installation, start with:

- 4 CPU cores
- 8 GB RAM
- 40 GB free SSD storage
- a 64-bit Linux host

The first build downloads about 9 GB of images, most of it the scanning tools.
Monitor storage as evidence and scan history accumulate. Production data is
stored in Docker volumes and survives normal container restarts.

### Software

Install Git, GNU Make, Docker Engine, Docker Compose v2 (the `docker compose`
command), curl, and Python 3.8 or newer (the standard library is enough; the
setup scripts use no packages). Local UI development also requires Node.js 20;
production does not.

Use Docker's installation instructions for your Linux distribution, then
confirm that the current user can access it:

```bash
docker --version
docker compose version
docker run --rm hello-world
git --version
make --version
curl --version
python3 --version
```

If Docker reports a permission error, follow Docker's post-installation
instructions and sign out and back in. Docker access effectively grants
root-level control of the host, so restrict it to trusted administrators.

### Get the source

```bash
git clone https://github.com/dt-cyberworks/axial.git
cd axial
```

To install a specific release, check out its tag first (for example
`git checkout v0.3.1`). If you already have the source, run every command below
from the directory containing `docker-compose.yml` and `Makefile`.

## 3. Local evaluation

### Create the configuration

```bash
make env
```

This creates `.env` from `.env.example` and generates the two encryption keys
(for MFA secrets and for stored provider API keys) that Axial deliberately
does not ship. It never changes a value that is already set, so it is safe to
run again, and `make up` runs it first. Do not use `.env` on a shared or
internet-reachable host: the remaining values are public development defaults,
and production refuses to start with them (see [section 4](#4-single-host-production)).

An LLM provider is optional: leave `LLM_BASE_URL`, `LLM_API_KEY`, and
`LLM_MODEL` empty to skip the agent phase, or configure the provider later
under **Settings**.

### Start and verify the backend

```bash
make up
docker compose ps
curl --fail http://localhost:8000/health
```

The first start builds images and downloads base layers, which may take
several minutes. Compose waits for Postgres and applies migrations, and
`make up` returns only once the control plane answers, so the health request
works the first time you type it. It should print:

```json
{"status":"ok"}
```

Open <http://localhost:8000/docs> for the interactive API documentation. The
object store has no web console and publishes no port; it is reachable only by
the control plane.

### Start the operator console

In a second terminal, from the repository root:

```bash
cd frontend
npm ci
npm run dev
```

Open <http://localhost:5173> and keep that command running while using the UI.

### Create the first administrator and sign in

There is no public sign-up; the first account is created from the command
line, once. Use a real address (a reserved name such as `.test`, `.local`, or
`localhost` is refused, because the sign-in form would reject it):

```bash
INITIAL_ADMIN_EMAIL=you@example.com make bootstrap-admin
```

It prints a one-time temporary password. Sign in at <http://localhost:5173>
with it, choose a new password, enroll an authenticator app (TOTP), and store
the ten backup codes. The [user manual](docs/manual/quickstart.md) continues
from here: your first engagement, scan, and report.

If enrollment answers `503` and names `MFA_ENCRYPTION_KEY`, the key is missing
from `.env`: run `make env` and restart with `make up`.

### Enable active scanning

The basic stack does not start the offensive execution layer. Enable it only
for an authorized, in-scope target:

```bash
docker compose --profile runner up -d --build
docker compose --profile runner ps
```

Before a real scan, prove that the safety boundary denies what it must:

```bash
make scope-check
```

This runs the Scope Gateway's deny-path tests (out-of-scope targets, unsafe
arguments, raw-egress policy, rate limits) inside the built image. It needs no
lab, no database, and starts nothing. See [docs/testing.md](docs/testing.md).

### Stop the local installation

Preserve the database and evidence volumes:

```bash
docker compose --profile runner down
```

`--profile runner` makes `down` include the active-scanning services
(`tool-runner` and `raw-egress-gateway`); a plain `docker compose down` leaves
them running. It is harmless if you never enabled active scanning.

Start again with `make up`. Do **not** use `make down` unless you intend to
delete local data: that target also removes the volumes (`down -v`).

## 4. Single-host production

This setup builds the frontend, serves it through Caddy, obtains and renews a
TLS certificate, and binds the direct control-plane port to loopback. The
object store publishes no port at all. Production refuses to start while
required secrets contain development defaults.

### Prepare DNS and the firewall

1. Assign a stable public IP to the host.
2. Create a DNS `A` record, and `AAAA` if IPv6 is configured, for a dedicated
   name such as `asm.example.com`.
3. Confirm that DNS resolves to this host.
4. Allow inbound TCP ports 80 and 443 for HTTPS issuance and traffic.
5. Do not expose ports 8000, 5432, 6379, 3128, 8765, or 8888 publicly.

A DNS name is required; the bare IP address of the host does not work.
Browsers and curl send no server name for an IP address, so Caddy cannot pick a
certificate and the TLS handshake fails, and no public certificate authority
issues one for the address. For a short test without your own domain, a
wildcard-DNS name such as `203-0-113-10.sslip.io` resolves to that IP and gets a
real certificate.

### Generate the production configuration

```bash
python3 scripts/gen_production_env.py --domain asm.example.com --out .env
```

This writes `.env` (mode `0600`) with every secret and setting production
needs, each generated fresh: database and proxy-database passwords, the S3
credentials, the API, scope-signing, runner, raw-egress and interaction-server
tokens, two different encryption keys, the loopback binding of the control-plane
port, and `PUBLIC_BASE_URL` (`https://` plus your domain). It refuses to
overwrite an existing file unless you add `--force`. Production validation
checks all of it; a value left at a development default stops the stack
instead of running it insecurely.

The file contains no LLM provider on purpose; configure it after login under
**Settings** (or add `LLM_BASE_URL`, `LLM_API_KEY`, and `LLM_MODEL`). Never
commit `.env`, and keep an encrypted copy in your secrets manager: without
`MFA_ENCRYPTION_KEY`, enrolled MFA secrets cannot be recovered.

### Validate and start

Validate without printing the resolved configuration and secrets:

```bash
docker compose -f docker-compose.yml -f docker-compose.prod.yml --profile runner --profile production config --quiet
```

Start the complete stack:

```bash
docker compose -f docker-compose.yml -f docker-compose.prod.yml --profile runner --profile production up -d --build
```

Inspect startup:

```bash
docker compose -f docker-compose.yml -f docker-compose.prod.yml --profile runner --profile production ps
docker compose -f docker-compose.yml -f docker-compose.prod.yml --profile runner --profile production logs --tail=100 control-plane caddy
```

Do not continue while a service is repeatedly restarting. Verify the public
endpoint after Caddy obtains its certificate:

```bash
curl --fail --show-error https://asm.example.com/
```

The command should return the operator-console HTML. A TLS, connection, proxy,
or HTTP error is not acceptable. Production intentionally disables `/docs`,
`/redoc`, and the OpenAPI document.

### Create the first administrator

```bash
docker compose -f docker-compose.yml -f docker-compose.prod.yml exec -e INITIAL_ADMIN_EMAIL=you@example.com control-plane python scripts/bootstrap_admin.py
```

The temporary password is displayed once. Open `https://asm.example.com`, sign
in, replace that password, enroll a TOTP authenticator, and store the one-time
backup codes securely. Create additional users under **Admin → Users**; there
is no public sign-up.

### Verify before use

- The browser reports a valid certificate for the expected hostname.
- Login requires both password and TOTP.
- Compose reports the expected services running.
- Only ports 80 and 443 answer from another host; 8000 is bound to loopback
  and the object store publishes nothing.
- Backups are configured and a restore has been tested.
- `make scope-check` passes.
- The engagement records authorization, scope, window, and emergency contacts.

## 5. Operations

### Status and logs

Local commands:

```bash
docker compose ps
docker compose logs --tail=200
docker compose logs -f control-plane worker egress-proxy
```

Production commands:

```bash
docker compose -f docker-compose.yml -f docker-compose.prod.yml --profile runner --profile production ps
docker compose -f docker-compose.yml -f docker-compose.prod.yml --profile runner --profile production logs -f
```

`Ctrl+C` stops following logs, not the services. Check logs for customer data,
target details, tokens, and evidence before sharing them.

### Backups

Back up the Postgres `pgdata` volume and the object-store `seaweedfsdata`
volume. Also retain an encrypted copy of `.env`, especially `MFA_ENCRYPTION_KEY`
and the signing keys; a database backup without the encryption key cannot
recover enrolled MFA secrets. Use your organization's encrypted volume-snapshot
or backup tooling and test a full restore on a separate host.

### Upgrade

1. Announce maintenance and stop new scan runs.
2. Create and verify Postgres, object-store, and secret backups.
3. Record the deployed Git commit for rollback.
4. Fetch and check out the approved release.
5. Review its release notes and migration files.
6. Run the same production `up -d --build` command used for installation.
7. Verify service status, logs, login, MFA, and a controlled test engagement.

Migrations run automatically. Rollback may require restoring the pre-upgrade
database and evidence snapshots; older code alone may not be sufficient.

#### From v0.3.0 to v0.3.1

- **The object store changed from MinIO to SeaweedFS**, because the MinIO images
  were withdrawn upstream and a fresh install could no longer pull them. Nothing
  in Axial stores objects there yet (evidence and reports live in Postgres), so
  there is nothing to migrate. The old `miniodata` volume is left untouched; after
  the upgrade, `docker volume ls` shows it as `<project>_miniodata` and
  `docker volume rm` removes it. The MinIO console and its published port no
  longer exist.
- **Local installs**: run `make env` (or `make up`, which runs it). It repairs an
  existing `.env` that has the empty encryption keys the v0.3.0 guide left behind.
- **Production installs**: your `.env` keeps working. Change `S3_ENDPOINT` to
  `http://seaweedfs:8333`; the old `MINIO_CONSOLE_PUBLISH_HOST` and
  `MINIO_CONSOLE_PUBLISH_PORT` are no longer used. Any S3 credential you
  generated yourself stays valid.
- **Every engagement now has an owner, and every signed-in user can read every
  engagement** (read-only). Changing, scanning, activating, deleting, and deciding
  tool-call approvals stay with the owner and administrators; anyone else gets a
  `403`. Migration `0038` runs automatically on upgrade: it gives each engagement
  that has no owner to the oldest active administrator (an administrator can
  reassign it) and makes the owner mandatory. If such engagements exist and there
  is **no active administrator**, it stops with an error and changes nothing;
  create an administrator with the first-administrator command of
  [section 3](#create-the-first-administrator-and-sign-in) or
  [section 4](#create-the-first-administrator) and start again. A fresh install
  is not affected.

### Stop or restart safely

Restart production without deleting data:

```bash
docker compose -f docker-compose.yml -f docker-compose.prod.yml --profile runner --profile production restart
```

Stop and remove containers while preserving volumes:

```bash
docker compose -f docker-compose.yml -f docker-compose.prod.yml --profile runner --profile production down
```

Never add `-v` unless you intend to delete the database, evidence, and Caddy
state. Confirm that no engagement is running or awaiting a decision first.

## 6. Troubleshooting

### A service is unhealthy or restarting

```bash
docker compose ps
docker compose logs --tail=200 <service-name>
```

In production, add both Compose files and both profiles. Common causes are a
development secret, malformed database URL, mismatched database passwords, or
a port already in use.

### Production rejects the configuration

Regenerate the file with `scripts/gen_production_env.py` (add `--force` to
replace the old one) rather than editing values by hand. If you did edit it,
confirm that all tokens and signing secrets are unique and non-default;
`DATABASE_URL` matches `POSTGRES_PASSWORD`; `PROXY_DATABASE_URL` matches
`PROXY_DB_PASSWORD`; the S3 credentials are not a development default;
both encryption keys are valid and different; `PUBLIC_BASE_URL` is an
`https://` address; and `CONTROL_PLANE_PUBLISH_HOST` is `127.0.0.1`. Do not
share `docker compose config` output because it may contain resolved secrets.

### HTTPS certificate issuance fails

Confirm the exact `ASM_DOMAIN`, DNS, inbound ports 80 and 443, and that no
other process uses those ports. Inspect `caddy` logs. Do not bypass this by
exposing port 8000.

### The UI opens but API calls fail

Inspect `caddy` and `control-plane`. Production uses the same hostname for UI
and API; do not set a separate public `VITE_API_BASE_URL`. Caddy intentionally
blocks `/internal/*`.

### MFA enrollment or sign-in answers 503

`MFA_ENCRYPTION_KEY` is empty or not a valid key. Locally, run `make env` and
restart; in production, never replace the key of an installation that already
has enrolled users (their MFA secrets would become unreadable) — restore it from
your secrets backup.

### The agent phase does nothing

This is expected without an LLM provider. Configure its base URL, API key, and
model under **Settings**. The Scope Gateway still authorizes every active tool
call independently of the model.

### Active tools are unavailable

Confirm the stack started with `--profile runner`, then inspect
`raw-egress-gateway`, `tool-runner`, `worker`, and `egress-proxy`. Never work
around a failure by broadening networks, capabilities, or firewall rules.

## 7. Kubernetes

Kubernetes is the preferred direction when customer or bug-bounty deployments
need stronger per-engagement isolation. [`deployment/k8s/`](deployment/k8s/)
contains runner Job and NetworkPolicy building blocks, not a turnkey cluster
installer. Complete cluster-specific ingress, secrets, storage, monitoring,
backup, and policy integration before production use. See
[docs/spec/deployment-architecture.md](docs/spec/deployment-architecture.md).

## 8. Security checklist

- [ ] Only ports 80 and 443 are public.
- [ ] The control-plane port binds to `127.0.0.1`; the object store publishes no port.
- [ ] Credentials are unique, non-default, and stored securely.
- [ ] Docker access is limited to trusted administrators.
- [ ] Host and container security updates are scheduled.
- [ ] Postgres, object-store, and secret backups are encrypted and restore-tested.
- [ ] Runner images are pinned and scanned.
- [ ] The audit log is backed up and protected from update or deletion.
- [ ] `make scope-check` passes and every engagement's scope was reviewed.
- [ ] Every engagement has written authorization and deterministic scope.

Architecture and security rationale:
[docs/architecture.md](docs/architecture.md) ·
[docs/security-model.md](docs/security-model.md) ·
[docs/legal.md](docs/legal.md)
