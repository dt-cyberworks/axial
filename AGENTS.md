# AGENTS.md

## Mandatory engineering lifecycle

All non-trivial changes must follow [`docs/engineering/sdlc.md`](docs/engineering/sdlc.md).
Before editing, classify the change, locate or create its `REQ-*` record, and
identify the applicable `TC-*` records and verification gates. Work is not
complete until the applicable [`Definition of Done`](docs/engineering/definition-of-done.md)
is satisfied and `make requirements-check` passes.

Security-sensitive `R3`/`R4` changes require negative tests and human security
review. Automated agents cannot approve their own SDLC exceptions or weaken a
requirement or test to make a gate pass.

Guidance for coding agents working in this repository.

## Project Purpose

This repository implements an Attack Surface Management scanner for managed security work with SMB customers. The scanner combines a FastAPI control plane, a Celery worker pipeline, an isolated tool runner, an egress proxy, and a React operator console.

The central security idea is:

> The LLM or worker may propose actions, but deterministic control-plane state decides whether anything active is allowed.

The Scope Gateway in `control-plane/app/gateway/authorize.py` is the core safety boundary. Treat it as a product-critical component, not a helper.

## Architecture Map

- `control-plane/`: FastAPI orchestrator, REST/SSE APIs, SQLAlchemy models, schemas, migrations, Scope Gateway, audit log, risk scoring. It is the only normal writer to Postgres.
- `worker/`: Celery scan pipeline. It orchestrates phases and may call the control-plane internal API, but it must not directly bypass authorization or write to the DB.
- `tool-runner/`: isolated offensive execution layer using HexStrike/Kali tools. It is disposable and must stay outside the control-plane network.
- `egress-proxy/`: second network-level scope enforcement layer for HTTP-aware tools.
- `raw-egress-gateway/`: Compose-only deny-all network namespace for Nmap. It accepts only short-lived control-plane-signed leases and owns NET_ADMIN; the offensive runner never does.
- `frontend/`: React + TypeScript operator console built with Vite.
- `lab/`: isolated vulnerable targets and end-to-end test loop. The negative out-of-scope test is a hard safety gate.
- `docs/`: developer-facing architecture, security, API, deployment, data model, testing, legal, and roadmap docs.
- `docs/spec/`: the original product specification (business, legal, and architecture requirements), translated from the former Word documents.
- `deployment/k8s/`: Kubernetes job and NetworkPolicy manifests for later maturity stages.

## Non-Negotiable Invariants

- Every active tool call must pass through `authorize()` in the Scope Gateway before dispatch.
- Deny rules take precedence over allow rules.
- Fail closed. Missing engagement, inactive status, invalid window, missing grant, unsafe args, unknown tool, or ambiguous scope should deny.
- Do not let prompts, LLM output, UI state, or worker assumptions grant permission.
- Keep the control plane free of offensive tool execution.
- Keep the worker as an orchestrator; it should not run target-facing tools directly.
- Keep the tool runner isolated from the control-plane/DB network.
- Keep the egress proxy as defense in depth for HTTP-aware tools; do not remove the second scope check to simplify networking.
- Raw Nmap in Compose may run only through `raw-egress-gateway`: bounded FIFO reservation, signed current lease, audited materialized IP, exact configured TCP or fixed opt-in UDP ports, deny-all baseline, one active lease, heartbeat-bound kernel expiry, and immediate cleanup. Never set general runner Internet egress or move NET_ADMIN into the runner.
- Preserve the append-only audit hash-chain behavior in `control-plane/app/gateway/audit.py`.
- Do not introduce destructive exploitation, credential attacks, mass scanning, or out-of-scope network behavior. The current allowlist intentionally excludes dangerous tools.
  - **Documented exception (R4, security-engineering):** the Vector Agent may *propose* state-changing HTTP requests (`http_request` with POST/PUT/DELETE/PATCH or a body). These never run autonomously — the Scope Gateway routes them to mandatory, per-command human approval with an LLM-assessed risk statement (the compensating control). Reads stay autonomous; scope/deny/window/egress isolation are unchanged. See `docs/requirements/manual-approval-and-full-http.md`.
- Lab targets must remain isolated. Never expose Metasploitable2, DVWA, Juice Shop, or similar vulnerable targets on host/public ports.

## Implementation Notes

- Python targets Python 3.12. Backend uses FastAPI, SQLAlchemy 2.x, Pydantic 2, Celery, Redis, and psycopg.
- Frontend uses React 18, TypeScript, React Router, TanStack Query, and Vite.
- Migrations are SQL files in `control-plane/migrations/`. Keep models, schemas, and migrations aligned when changing persistence.
- API contracts are described in `docs/api.md`; update docs when changing external behavior.
- The scan state machine lives in `worker/app/tasks/pipeline.py`: `discovery -> fingerprint -> correlate -> agent -> validate -> score -> report`.
- Tool argument safety is enforced in `control-plane/app/gateway/args_safety.py`; update tests when widening accepted arguments.
- Known lab vulnerability inference is intentionally local/reproducible in `worker/app/known_vulns.py`.
- The UI and many docs are German-facing. Preserve existing German copy/comment style unless there is a clear reason to change it.

## Common Commands

```bash
make help
make up
make down
make logs
make test-unit
make test-integration
make test
make lab-test
make frontend-build
```

Targeted commands:

```bash
cd control-plane && python -m pytest tests -q --ignore=tests/integration
cd control-plane && python -m pytest tests/integration -q
cd frontend && npm run build
```

Integration tests require Postgres and `TEST_DATABASE_URL`; see `docs/testing.md`.

`make lab-test` starts a fuller Docker/lab loop and must keep the isolation and negative scope gates intact. Prefer it for changes touching gateway authorization, egress enforcement, tool dispatch, or lab behavior.

## Testing Expectations

- Gateway, scope matching, argument safety, risk scoring, audit, and approval behavior need focused tests for any behavior change.
- Worker changes that alter tool dispatch should test both allowed and denied paths where practical.
- Frontend changes should at least pass `npm run build`.
- For DB shape changes, add/update migrations and run affected integration tests.
- For security-sensitive changes, include a negative test. In this project, proving a blocked action is often more important than proving a successful scan.

## Safety When Working

- Do not run real scans against public or third-party targets unless the user explicitly provides authorization and scope.
- Do not broaden tool allowlists, `active_allowed` behavior, egress routing, Docker capabilities, or NetworkPolicies casually.
- Do not add dependencies that download or execute offensive tooling at runtime without a clear review path.
- Treat `.env` as local secret/config material. Do not print secrets or commit real credentials.
- Be careful with Docker commands that remove volumes (`make down`, lab teardown). They are normal here, but still destructive to local state.

## Documentation Touchpoints

Update these docs when changing corresponding behavior:

- Architecture or component boundaries: `docs/architecture.md`
- Gateway, proxy, isolation, audit, threat model: `docs/security-model.md`
- API shape or SSE behavior: `docs/api.md`
- Data model, scope resolution, scoring: `docs/data-model.md`
- Test commands or lab loop: `docs/testing.md`
- Deployment topology, Compose/K8s, hardening: `INSTALL.md`
- Maturity/status changes: `docs/roadmap.md`
- Legal/authorization workflow: `docs/legal.md`

## Review Checklist

Before finishing a change, ask:

- Does every active operation still go through the Scope Gateway?
- Does an explicit deny still win over allow/wildcard/CIDR matches?
- Does the worker still avoid direct DB writes and direct target scanning?
- Does the runner remain isolated from control-plane resources?
- Are audit entries still written for gateway decisions?
- Did I add or update tests for both allowed and denied paths?
- Did docs change when contracts or safety behavior changed?

