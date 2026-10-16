# AGENTS.md

## Mandatory engineering lifecycle

All non-trivial changes follow the same order: describe the behaviour change,
classify its risk (`R0`-`R4`, defined in [CONTRIBUTING.md](CONTRIBUTING.md#risk-classes)),
add tests that verify it directly, and run the public gates (`make verify`)
before it is considered done. A change to user-visible behaviour also updates the
matching page of the user manual.

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
  - **Documented exception (R4, security-engineering):** the Vector Agent may *propose* state-changing HTTP requests (`http_request` with POST/PUT/DELETE/PATCH or a body). These never run autonomously — the Scope Gateway routes them to mandatory, per-command human approval with an LLM-assessed risk statement (the compensating control). Reads stay autonomous; scope/deny/window/egress isolation are unchanged. See REQ-HTTP-002/003 and REQ-APPROVAL-001..006.
- Lab targets must remain isolated. Never expose Metasploitable2, DVWA, Juice Shop, or similar vulnerable targets on host/public ports.

## Implementation Notes

- Python targets Python 3.12. Backend uses FastAPI, SQLAlchemy 2.x, Pydantic 2, Celery, Redis, and psycopg.
- Frontend uses React 18, TypeScript, React Router, TanStack Query, and Vite.
- Migrations are SQL files in `control-plane/migrations/`. Keep models, schemas, and migrations aligned when changing persistence.
- API contracts are described in `docs/api.md`; update docs when changing external behavior.
- The scan state machine lives in `worker/app/tasks/pipeline.py`: `discovery -> fingerprint -> correlate -> agent -> score -> report`.
- The fingerprint phase (`worker/app/tasks/fingerprint.py`) is discover -> plan -> execute (REQ-PIPE): open ports become surfaces (`surfaces.py`, `tech_profile.py`), the pure planner (`planner.py`) turns them into a stored plan of `scan_check` rows, and `scan_executor.py` runs it (two checks at a time, resumable per check). nuclei templates are selected from an index baked into the tool-runner image (`tool-runner/nuclei_index.py`), never by path; every check is still one gateway-authorized call. The `thorough` profile adds an `ffuf:deep` check (`raft-medium-dirs`, budget sized to the list by `tool_runner_client.ffuf_budget_s`, REQ-PIPE-017); the agent context lists the run's finished checks (`scan_plan.agent_check_summary`) and an agent ffuf stopped by its 240 s limit is reported PARTIAL, never as "no hits" (REQ-PIPE-018).
- Operating modes: an engagement is `monitoring` (unattended; nothing waits for a person, a call that needs a decision is withdrawn and kept as an inbox suggestion) or `assessment` (attended or semi-attended; a semi-attended run parks on a decision and resumes). Every run starts through `control-plane/app/operating_modes.py::begin_scan`; the capabilities of a monitoring engagement are a view over its grants and switches (`control-plane/app/capabilities.py`); the worker's waiting and withdrawing of approvals is `worker/app/approval_wait.py`. A monitoring engagement can run by itself every N days (`control-plane/app/scheduling.py`, one interval stored on the engagement; the worker's beat task only pokes `POST /internal/monitoring/run-due-schedules`, and the run still starts through `begin_scan`). A mode never widens what the Scope Gateway allows. See the manual's *Operating modes* and *Monitor an attack surface*.
- Tool argument safety is enforced in `control-plane/app/gateway/args_safety.py`; update tests when widening accepted arguments.
- Known lab vulnerability inference is intentionally local/reproducible in `worker/app/known_vulns.py`.
- Everything is English: UI, docs, API errors, agent messages, log lines, and code comments (REQ-TEXT-001). `scripts/tests/test_english_runtime_text.py` fails on German text in runtime strings. Many older modules still have German comments: write new comments in English, and when you change a module, translate the German comments of the code you touch - in a separate commit, never mixed with a behavior change.

## Common Commands

```bash
make help
make up
make down
make logs
make test-unit
make test-integration
make test
make verify
make frontend-build
```

Targeted commands:

```bash
cd control-plane && python -m pytest tests -q --ignore=tests/integration
cd control-plane && python -m pytest tests/integration -q
cd frontend && npm run build
```

Integration tests require Postgres and `TEST_DATABASE_URL`; see `docs/testing.md`.

For changes touching gateway authorization, egress enforcement or tool dispatch, `make scope-check` proves that the Scope Gateway denies out-of-scope targets and unsafe arguments, and the negative tests must stay in place. The maintainers also run a private end-to-end lab loop against deliberately vulnerable targets; it is not part of this repository.

## Testing Expectations

- Gateway, scope matching, argument safety, risk scoring, audit, and approval behavior need focused tests for any behavior change.
- Worker changes that alter tool dispatch should test both allowed and denied paths where practical.
- Frontend changes should at least pass `npm run build`.
- For DB shape changes, add/update migrations and run affected integration tests.
- For security-sensitive changes, include a negative test. In this project, proving a blocked action is often more important than proving a successful scan.

## Safety When Working

- Do not run real scans against public or third-party targets unless the user explicitly provides authorization and scope.
- Do not broaden tool allowlists, `active_allowed` behavior, egress routing, Docker capabilities, or network isolation casually.
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
- Deployment topology, Compose, hardening: `INSTALL.md`
- Capability status changes: `docs/roadmap.md`
- Legal/authorization workflow: `docs/legal.md`
- User-visible behavior (a screen, a field, a flow, a message or code the console shows, a tool): the matching page of `docs/manual/`, then `make manual-check`. The console has no documentation pages of its own. A changed screen also changes its screenshots: `make manual-screenshots` (throwaway stack, demo data only)

## Review Checklist

Before finishing a change, ask:

- Does every active operation still go through the Scope Gateway?
- Does an explicit deny still win over allow/wildcard/CIDR matches?
- Does the worker still avoid direct DB writes and direct target scanning?
- Does the runner remain isolated from control-plane resources?
- Are audit entries still written for gateway decisions?
- Did I add or update tests for both allowed and denied paths?
- Did docs change when contracts or safety behavior changed?

