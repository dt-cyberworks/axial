# Operations: install, back up, upgrade, harden

**Who this is for:** the person who installs and looks after an Axial installation.
**After this page you can:** choose an installation type, know what runs and what to watch, back up and upgrade safely, check the audit chain, and find the hardening checklist.

<!-- ui-labels: Admin | Operational settings -->

The step-by-step instructions live in [`INSTALL.md`](../../INSTALL.md), so that they are kept in one place. This page tells you what to do when, and what the manual adds on top.

## Choose an installation

| Goal | Follow |
|---|---|
| Try it, or scan from a workstation | [Local evaluation](../../INSTALL.md#3-local-evaluation) |
| Run a persistent service with HTTPS | [Single-host production](../../INSTALL.md#4-single-host-production) |
| Isolate every customer in Kubernetes | [Kubernetes](../../INSTALL.md#7-kubernetes), building blocks only, not a turnkey installer |

Plan for roughly 4 CPU cores, 8 GB of memory and 40 GB of disk for one host to start with, and watch the disk: evidence and scan history accumulate. Install Axial only on infrastructure you control.

## What is running

| Service | Does |
|---|---|
| Control plane | the API and the console's backend; authorises every tool call; the only service that writes to the database |
| Worker | runs the scan pipeline and the AI agent; never touches a target directly |
| Egress proxy | the only way the web tools reach a target; re-checks every request against the scope |
| Tool runner | the isolated place where the scanning tools run |
| Raw egress gateway | gives network scans (nmap) a short-lived, scope-bound network permission |
| Postgres, Redis, SeaweedFS | database, queue, object storage for evidence and reports (the object store has no console and no published port) |
| Caddy (production) | HTTPS and the public routes; only the public API prefixes are reachable, never the internal ones |

The tool runner and the raw egress gateway start only with the `runner` profile; without it the console works but a scan has nothing to run with. Why they are separated: [`docs/security-model.md`](../security-model.md).

## Day to day

- **Is it up?** `curl --fail http://localhost:8000/health` answers `{"status":"ok"}`; on a production host check through the public address. `docker compose ps` shows the services; see [Status and logs](../../INSTALL.md#status-and-logs).
- **Logs** can contain customer data, target details and evidence. Look through them before you share them.
- **A stuck or failing scan** is nearly always explained by the run's reason; see [Troubleshooting](troubleshooting.md). Installation problems (a service that restarts, a certificate that is not issued, an API that does not answer) are in [INSTALL.md §6](../../INSTALL.md#6-troubleshooting).

## Back up

Back up the Postgres volume and the object-store volume (`seaweedfsdata`), **and keep an encrypted copy of the `.env` file**, especially the MFA encryption key and the signing keys. A database backup without those keys cannot recover enrolled authenticators. Test a full restore on a separate host. See [Backups](../../INSTALL.md#backups).

## Upgrade

Follow [Upgrade](../../INSTALL.md#upgrade). In addition:

- Do not upgrade while a scan is running if you can avoid it. A run whose worker is replaced is resumed automatically after a few minutes, at most twice, and continues after the last phase that finished; a phase that was interrupted starts from its beginning. Waiting for the run to end is still simpler.
- Migrations run on their own. Rolling back may need the pre-upgrade database snapshot; older code alone may not be enough.
- After the upgrade, sign in, check that MFA works, and run a controlled test engagement.

## Restart safely

Restart or stop with the commands in [Stop or restart safely](../../INSTALL.md#stop-or-restart-safely). Never add `-v` to `down` unless you mean to delete the database, the evidence and the certificates. Confirm first that no engagement is running or waiting for a decision.

## Verify the audit chain

The audit log of an engagement is hash-chained, and the control plane can verify a chain end to end: each row's hash must match its content, and each row must point at its predecessor. A modified, removed, inserted or re-ordered row makes it fail and names the first bad row. Use it before you hand the log to a customer or an auditor:

```bash
docker compose exec -e ENGAGEMENT_ID=<engagement id> control-plane python -c "
import os, uuid
from app.db.base import SessionLocal
from app.gateway.audit import verify_audit_chain
with SessionLocal() as db:
    print(verify_audit_chain(db, uuid.UUID(os.environ['ENGAGEMENT_ID'])))
"
```

`ok=True` with the number of rows means the chain is intact. The account audit (sign-ins and admin actions) is a separate chain.

## Settings you may change

- **In the console** (administrators): the AI provider, the scan rate, the global tool policy, the agent budgets and the approval timeout, under **Admin → Operational settings**. See [Settings](reference/settings.md).
- **In `.env`**: secrets, ports, host names and a few limits such as the database pool. Every variable is listed with a comment in [`.env.example`](../../.env.example). Production refuses to start while a secret is still at its development default.
- **At build time**: the console can show a **Manual** link in its navigation if it is built with `VITE_MANUAL_URL` set to the address of this manual, for example `VITE_MANUAL_URL=https://github.com/<owner>/<repo>/tree/main/docs/manual`. Without it there is no link, and the console carries no documentation pages of its own.

## Harden

Work through the [security checklist](../../INSTALL.md#8-security-checklist): only ports 80 and 443 public, unique non-default credentials, limited Docker access, encrypted and restore-tested backups, pinned and scanned runner images, and a written authorisation with a deterministic scope for every engagement. Run the isolation check (`make lab-test`, see [`docs/testing.md`](../testing.md)) on a **separate test installation**: it tears the stack down, including its data, unless told otherwise.
