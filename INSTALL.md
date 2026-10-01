# Install ASM on a Host

This guide takes you from a clean host to a working ASM installation. It
covers two Docker Compose setups:

- **Local evaluation** — API and operator console on a private workstation.
- **Single-host production** — a persistent server with the UI and API behind
  Caddy and automatic HTTPS.

Docker Compose supplies Postgres, Redis, MinIO, the control plane, worker,
egress proxy, and isolated execution services. A production host does not
need separate Python, PostgreSQL, Redis, or Node.js installations.

> [!WARNING]
> Install ASM only on infrastructure you control. Do not scan a system until
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

Monitor storage as evidence and scan history accumulate. Production data is
stored in Docker volumes and survives normal container restarts.

### Software

Install Git, GNU Make, Docker Engine, Docker Compose v2 (the `docker compose`
command), and curl. Local UI development also requires Node.js 20; production
does not.

Use Docker's installation instructions for your Linux distribution, then
confirm that the current user can access it:

```bash
docker --version
docker compose version
docker run --rm hello-world
git --version
make --version
curl --version
```

If Docker reports a permission error, follow Docker's post-installation
instructions and sign out and back in. Docker access effectively grants
root-level control of the host, so restrict it to trusted administrators.

### Get the source

Clone the repository URL supplied by your administrator:

```bash
git clone <repository-url> asm-scanner
cd asm-scanner
```

If you already have the source, run every command below from the directory
containing `docker-compose.yml` and `Makefile`.

## 3. Local evaluation

### Create the configuration

```bash
cp .env.example .env
```

The development defaults are suitable only for a private local evaluation.
Do not use them on a shared or internet-reachable host. An LLM provider is
optional: leave `LLM_BASE_URL`, `LLM_API_KEY`, and `LLM_MODEL` empty to skip
the agent phase, or configure the provider later under **Settings**.

### Start and verify the backend

```bash
make up
docker compose ps
curl --fail http://localhost:8000/health
```

The first start builds images and downloads base layers, which may take
several minutes. Compose waits for Postgres and applies migrations. The health
request should print:

```json
{"status":"ok"}
```

Open <http://localhost:8000/docs> for the interactive API documentation. The
MinIO administration console is at <http://localhost:9001> for local
diagnostics.

### Start the operator console

In a second terminal, from the repository root:

```bash
cd frontend
npm ci
npm run dev
```

Open <http://localhost:5173> and keep that command running while using the UI.

### Enable active scanning

The basic stack does not start the offensive execution layer. Enable it only
for an authorized, in-scope target:

```bash
docker compose --profile runner up -d --build
docker compose --profile runner ps
```

Before a real scan, prove that the safety boundary blocks an unauthorized
target:

```bash
make lab-test
```

The lab uses intentionally vulnerable targets on isolated networks. It checks
both the permitted path and the more important out-of-scope denial. See
[docs/testing.md](docs/testing.md).

### Stop the local installation

Preserve the database and evidence volumes:

```bash
docker compose down
```

Start again with `make up`. Do **not** use `make down` unless you intend to
delete local data: that target runs `docker compose down -v`.

## 4. Single-host production

This setup builds the frontend, serves it through Caddy, obtains and renews a
TLS certificate, and binds the direct control-plane and MinIO ports to
loopback. Production refuses to start while required secrets contain
development defaults.

### Prepare DNS and the firewall

1. Assign a stable public IP to the host.
2. Create a DNS `A` record, and `AAAA` if IPv6 is configured, for a dedicated
   name such as `asm.example.com`.
3. Confirm that DNS resolves to this host.
4. Allow inbound TCP ports 80 and 443 for HTTPS issuance and traffic.
5. Do not expose ports 8000, 9001, 5432, 6379, 3128, 8765, or 8888 publicly.

### Create production secrets

Copy the template and restrict access:

```bash
cp .env.example .env
chmod 600 .env
```

Generate an independent value for every secret. Use this command for tokens,
passwords, and signing secrets, running it once per value:

```bash
openssl rand -hex 32
```

Generate the Fernet-compatible MFA encryption key separately:

```bash
openssl rand -base64 32 | tr '+/' '-_'
```

Edit `.env` and replace every value inside angle brackets (without retaining
the brackets):

```dotenv
ENVIRONMENT=production
ASM_DOMAIN=asm.example.com

POSTGRES_USER=asm
POSTGRES_PASSWORD=<database-password>
POSTGRES_DB=asm
DATABASE_URL=postgresql+psycopg://asm:<database-password>@postgres:5432/asm

PROXY_DB_PASSWORD=<proxy-database-password>
PROXY_DATABASE_URL=postgresql+psycopg://asm_proxy_ro:<proxy-database-password>@postgres:5432/asm

S3_ENDPOINT=http://minio:9000
S3_ACCESS_KEY=asm-storage
S3_SECRET_KEY=<s3-secret>
S3_BUCKET=asm-evidence

INTERNAL_API_TOKEN=<internal-api-token>
OPERATOR_API_TOKEN=<operator-compatibility-token>
SCOPE_SIGNING_SECRET=<scope-signing-secret>
RAW_EGRESS_SIGNING_SECRET=<raw-egress-signing-secret>
RUNNER_API_TOKEN=<runner-api-token>
MFA_ENCRYPTION_KEY=<fernet-key>

CONTROL_PLANE_PUBLISH_HOST=127.0.0.1
MINIO_CONSOLE_PUBLISH_HOST=127.0.0.1
```

`OPERATOR_API_TOKEN` must be non-default because production validation checks
it, but users authenticate with individual accounts and MFA; shared-token
login is disabled. Hexadecimal database passwords are safe in these connection
URLs without extra URL encoding.

Optionally configure an OpenAI-compatible LLM provider:

```dotenv
LLM_BASE_URL=https://provider.example/v1
LLM_API_KEY=<provider-api-key>
LLM_MODEL=<provider-model-name>
```

You can instead configure it after login under **Settings**. Never commit
`.env`; keep an encrypted copy in your secrets manager.

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
or HTTP error is not acceptable. Production intentionally disables `/docs`, `/redoc`, and
the OpenAPI document.

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
- Ports 8000 and 9001 are unreachable from another host.
- Backups are configured and a restore has been tested.
- `make lab-test` passes on an isolated test installation.
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

Back up the Postgres `pgdata` volume and MinIO `miniodata` volume. Also retain
an encrypted copy of `.env`, especially `MFA_ENCRYPTION_KEY` and signing keys;
a database backup without the encryption key cannot recover enrolled MFA
secrets. Use your organization's encrypted volume-snapshot or backup tooling
and test a full restore on a separate host.

### Upgrade

1. Announce maintenance and stop new scan runs.
2. Create and verify Postgres, MinIO, and secret backups.
3. Record the deployed Git commit for rollback.
4. Fetch and check out the approved release.
5. Review its release notes and migration files.
6. Run the same production `up -d --build` command used for installation.
7. Verify service status, logs, login, MFA, and a controlled test engagement.

Migrations run automatically. Rollback may require restoring the pre-upgrade
database and evidence snapshots; older code alone may not be sufficient.

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

Confirm that all tokens and signing secrets are unique and non-default;
`DATABASE_URL` matches `POSTGRES_PASSWORD`; `PROXY_DATABASE_URL` matches
`PROXY_DB_PASSWORD`; S3 credentials are not `minioadmin`;
`MFA_ENCRYPTION_KEY` is valid; and `CONTROL_PLANE_PUBLISH_HOST` is
`127.0.0.1`. Do not share `docker compose config` output because it may contain
resolved secrets.

### HTTPS certificate issuance fails

Confirm the exact `ASM_DOMAIN`, DNS, inbound ports 80 and 443, and that no
other process uses those ports. Inspect `caddy` logs. Do not bypass this by
exposing port 8000.

### The UI opens but API calls fail

Inspect `caddy` and `control-plane`. Production uses the same hostname for UI
and API; do not set a separate public `VITE_API_BASE_URL`. Caddy intentionally
blocks `/internal/*`.

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
- [ ] Control-plane and MinIO ports bind to `127.0.0.1`.
- [ ] Credentials are unique, non-default, and stored securely.
- [ ] Docker access is limited to trusted administrators.
- [ ] Host and container security updates are scheduled.
- [ ] Postgres, MinIO, and secret backups are encrypted and restore-tested.
- [ ] Runner images are pinned and scanned.
- [ ] The audit log is backed up and protected from update or deletion.
- [ ] Lab isolation and the negative out-of-scope test pass.
- [ ] Every engagement has written authorization and deterministic scope.

Architecture and security rationale:
[docs/architecture.md](docs/architecture.md) ·
[docs/security-model.md](docs/security-model.md) ·
[docs/legal.md](docs/legal.md)
