# Test Concept & Lab Test Loop

Source: [`docs/spec/lab-environment.md`](spec/lab-environment.md).
Test infrastructure: `lab/` and
[`control-plane/tests/`](../control-plane/tests/).

The lab harness (`lab/`) and the UAT harness (`uat/`) are not yet in the public release.
The sections about them describe how the maintainers run them.

## Two testing directions — both mandatory

The lab environment verifies not only that the scanner **finds**
vulnerabilities, but equally that the Scope Gateway correctly **blocks**.

| Direction | Question | Target type |
|---|---|---|
| **Positive test** | Does the scanner find real, known vulnerabilities? | vulnerable targets (Metasploitable2, Juice Shop, DVWA) |
| **Negative test** | Does the gateway block what's outside scope? | `clean-nginx` — same network, but `deny` |
| **Regression test** | Do findings stay stable across runs? | the same targets, repeated runs (fingerprint/diff) |

### The negative test: the most important one

A second, deliberately **not** authorized target on the same lab network is
the most important security test: the scanner must be able to *see* it, but
the gateway **and** the egress proxy must reject every active access to it.
Only once this test is reproducibly green is scope enforcement demonstrably
proven.

## Test levels

```mermaid
flowchart TB
    subgraph unit["Unit — no infra (fast, always green)"]
        U1["args_safety (argument hardening)"]
        U2["scope_matching (allow/deny/wildcard/CIDR)"]
        U3["risk_score (EPSS/KEV/severity)"]
    end
    subgraph integ["Integration — real Postgres"]
        I1["Gateway positive/negative"]
        I2["Status/time-window/whitelist"]
        I3["Audit hash chain"]
    end
    subgraph e2e["E2E — full stack + lab targets"]
        E0["Isolation verification (gate)"]
        E1["Scope enforcement via API (gate)"]
        E2["Findings vs. oracle (informational)"]
    end
    subgraph uat["UAT — real browser, real deployment (dev/int/prod)"]
        A1["Golden path: login/MFA + CRUD (every deployment)"]
        A2["Scan journey: a real scan against a pre-authorized target"]
    end
    unit --> integ --> e2e --> uat
```

| Level | Where | Prerequisite | Command |
|---|---|---|---|
| Unit | [`tests/test_*.py`](../control-plane/tests/) | none | `make test-unit` |
| Integration | [`tests/integration/`](../control-plane/tests/integration/) | Postgres (`TEST_DATABASE_URL`) | `make test-integration` |
| E2E lab | `lab/run-lab-test.sh` | Docker + full stack | `make lab-test` |
| UAT | `uat/` | deployed dev/int/prod + `make uat-venv` | `make uat ENV=dev\|int\|prod` |

## The lab test loop

```mermaid
sequenceDiagram
    participant Op as run-lab-test.sh
    participant Lab as lab-compose (targets)
    participant CP as control-plane
    participant GW as Scope Gateway

    Op->>Lab: start targets (internal network)
    Op->>CP: start the stack, wait for /health
    Op->>Op: Phase 0 — check isolation (GATE)
    Op->>CP: seed the lab engagement (source=lab)
    Note over Op,GW: Phase 1 — scope enforcement (GATE)
    Op->>GW: authorize(clean-nginx, active)
    GW-->>Op: DENY explicit_out_of_scope ✓
    Op->>GW: authorize(metasploitable2, active)
    GW-->>Op: ALLOW ✓
    Op->>CP: Phase 2 — findings vs. oracle (informational)
```

**Hard gates:** Phase 0 (isolation) and Phase 1 (scope enforcement). If
either fails, the loop ends with exit 1. Phase 2 is informational as long
as the scan phases (fingerprint/vuln/agent) are still stubs (roadmap
M2/M3/M5).

## Isolation is mandatory (Phase 0)

Before **every** lab use, `lab/verify-isolation.sh`
enforces four checks. Vulnerable targets must never be exposed to the
internet.

1. The target does **not** reach the internet (`internal:true` holds)
2. The negative target does **not** reach the internet
3. no default route on the lab network
4. no port mapping of the targets to the host

## Test oracle (ground truth)

Because Metasploitable2 & co.'s vulnerabilities are documented, they serve
as the expected list (`lab/expected_findings.yaml`).
The comparison measures false negatives (missed) and false positives
(wrongly reported). The negative target carries `must_not_appear: true` —
any finding on it is a failure.

## Live scan against the lab

Since the M3 pull-forward ([roadmap.md](roadmap.md#where-the-project-stands)),
`run-lab-test.sh` triggers a **real** scan, not just gateway decisions:

```mermaid
sequenceDiagram
    participant WK as worker
    participant CP as control-plane
    participant TR as tool-runner-lab (HexStrike)

    WK->>CP: POST .../gateway/authorize (nmap, metasploitable2)
    CP-->>WK: ALLOW
    WK->>TR: POST /api/tools/nmap {target, scan_type: "-sV", ...}
    TR->>TR: execute_command() -> subprocess
    TR-->>WK: {stdout, return_code, success}
    WK->>WK: parse_nmap_grepable() + known_vulns.lookup()
    WK->>CP: POST .../services, POST .../findings
```

`tool-runner/runner.Dockerfile` builds the **real** HexStrike (MIT-licensed,
with three surgical fixes: `pwntools`/`angr` removed from `requirements.txt`
- source-code review confirms the main server never imports either at module
level -, the log path redirected to `/tmp` because of
`readOnlyRootFilesystem`, `--host`/env-var mismatches corrected). Details
and the current capability status: the tool registry (`control-plane/app/tools/registry.py`) and [roadmap.md](roadmap.md#where-the-project-stands).
`worker/app/tool_runner_client.py` talks to the real HexStrike endpoints,
reverse-engineered from its source (`/api/tools/nmap|nuclei|nikto|subfinder|
amass|wafw00f|httpx`).

`tool-runner/lab_runner.py` (a minimal HTTP wrapper around just `nmap`, no
HexStrike/Kali) stays in the repo as a proven-working fallback - it's what
first proved the complete control flow gateway → runner → findings (12
findings, see below), before switching over to the real HexStrike
integration. Detected versions (e.g. `vsftpd 2.3.4`) are matched, in both
variants, against a small local CVE table
([`worker/app/known_vulns.py`](../worker/app/known_vulns.py)) - an
alternative to the NVD API specifically for reproducible lab runs without
an internet dependency.

**Important when polling for scan completion:** the scan is a single
synchronous Celery task that blocks per host (a `-sV` scan against
Metasploitable2 takes 20-30s) and then writes many results at once. A
"the finding count hasn't changed in N seconds" heuristic is therefore
misleading - it can misinterpret a silent pause mid-scan as "done". Only
the real status is reliable: `GET /engagements/{id}/scan-runs` →
`state == "done"`.

A regression bug found by exactly this live test: the `rescore` route
originally computed severity with `is_kev` hardcoded to `False`, because the
flag only existed transiently at finding creation. Every rescore (the
"score" phase) demoted KEV findings (e.g. vsftpd/CVE-2011-2523) from
`critical` back down to their raw score. Fix: `is_kev` is now a persistent
column (`Finding.is_kev`); regression test:
[`test_rescore_kev.py`](../control-plane/tests/integration/test_rescore_kev.py).

## Running locally

```bash
# Unit (no infra):
make test-unit

# Integration (Postgres via Docker):
docker run -d --rm --name pg -e POSTGRES_USER=asm -e POSTGRES_PASSWORD=asm \
  -e POSTGRES_DB=asm_test -p 5432:5432 postgres:16
export TEST_DATABASE_URL=postgresql+psycopg://asm:asm@localhost:5432/asm_test
make test-integration

# Full lab test loop:
make lab-test
```

## CI

[`.github/workflows/ci.yml`](../.github/workflows/ci.yml) runs three jobs:
`backend` (unit + integration against a Postgres service), `frontend`
(typecheck + build), and `images` (Docker builds).

The E2E lab loop (`make lab-test`, above) intentionally does **not** run in
GitHub Actions. It spins up known-vulnerable targets (Metasploitable2, DVWA,
Juice Shop) and runs a real scan against them; that stays confined to a
developer's own machine, not a shared/hosted CI runner. Run it locally before
merging `R3`/`R4` changes, per the
[Definition of Done](engineering/definition-of-done.md).

## Requirement-based GUI tests

GUI tests are derived from documented requirements, not from the current
implementation. The process is binding:

1. A UI requirement is documented in `docs/requirements/` with a stable
   requirement ID and testable acceptance criteria.
2. A test references that requirement ID and verifies the acceptance
   criteria against the UI/API surface.
3. If the test fails, first check whether the implementation or the
   requirement is wrong. The test is never weakened just to make it pass.
4. Internal technical fields may be tested when they're part of the GUI
   contract; the visible operator-facing language remains authoritative.

Current GUI requirement tests:

| Requirement document | Test | Command |
|---|---|---|
| [`docs/requirements/operator-authorization.md`](requirements/operator-authorization.md) | [`frontend/tests/operator_authorization_requirements.test.mjs`](../frontend/tests/operator_authorization_requirements.test.mjs) | `cd frontend && npm run test:requirements` |
| [`docs/requirements/scan-rate-policy.md`](requirements/scan-rate-policy.md) | [`frontend/tests/scan_rate_policy_requirements.test.mjs`](../frontend/tests/scan_rate_policy_requirements.test.mjs) | `cd frontend && npm run test:requirements` |
| [`docs/requirements/tool-grants.md`](requirements/tool-grants.md) | [`frontend/tests/tool_grants_requirements.test.mjs`](../frontend/tests/tool_grants_requirements.test.mjs) | `cd frontend && npm run test:requirements` |
| [`docs/requirements/agent-naming-and-lens.md`](requirements/agent-naming-and-lens.md) | [`frontend/tests/agent_lens_requirements.test.mjs`](../frontend/tests/agent_lens_requirements.test.mjs) | `cd frontend && npm run test:requirements` |
| [`docs/requirements/live-activity-progress.md`](requirements/live-activity-progress.md) | [`frontend/tests/live_activity_progress_requirements.test.mjs`](../frontend/tests/live_activity_progress_requirements.test.mjs) | `cd frontend && npm run test:requirements` |

The test is deliberately implemented without an additional browser-test
dependency, because the current frontend has no installed E2E/DOM test
stack yet. It statically checks the documented GUI contract against the
relevant frontend/API/backend sources. Once Playwright or a DOM test stack
enters the repo, these requirement IDs should be reused as E2E/component
tests, not replaced by ad hoc scenarios.

## Automated user-acceptance testing (UAT)

Playwright is now in the repo (`uat/requirements.txt`) - exactly the step
flagged above, but as its own UAT layer rather than a replacement for the
existing GUI requirement tests. Details, risk classification (R3), and
acceptance criteria: `docs/requirements/user-acceptance-testing.md`
(REQ-UAT-001..004), verified via `docs/test-cases/user-acceptance-testing.md`.

Two tiers, both against a real, running deployment (never a mock):

- **Golden Path** (`uat/golden_path.py`): a real login incl. MFA challenge,
  create/open/edit/audit/delete an engagement, logout - safe enough for
  every deployment across all three environments, runs in seconds, never
  creates an activatable/scannable engagement (the scope value uses the
  reserved `.invalid` TLD).
- **Scan Journey** (`uat/scan_journey.py`): a real, full scan against a
  dedicated, permanently pre-authorized engagement - a subdomain of your own
  domain for `int`/`prod` (explicitly confirmed by you as safe to use), the
  isolated `lab/` target for `dev`. Runs after every deployment to
  `int`/`prod` (per your own requirement), opt-in separately for `dev`
  (`--tier all`), since it's noticeably slower (real tool execution).

One-time setup per environment: `make seed-uat-account` (idempotent,
creates the service account with `role=operator`) followed by
`python uat/bootstrap_credentials.py --env <env>` (a real first login incl.
MFA enrollment, persists the password + TOTP secret to
`secrets/uat/<env>.env`, gitignored). After that:

```bash
make uat-venv            # once: Playwright/pyotp/httpx (uses system Chrome)
make uat ENV=dev         # golden path against the running dev stack
make uat ENV=int         # golden path + scan journey against your int deployment
make uat ENV=prod        # golden path + scan journey against your prod deployment
```

## Minimum safe-operation checks

The baseline is covered by `control-plane/tests/test_production_config.py`, `control-plane/tests/test_operator_auth.py`, `control-plane/tests/integration/test_manual_approval_http.py`, `control-plane/tests/integration/test_audit_serialization.py`, `worker/tests/test_agent.py`, and `egress-proxy/tests/test_audit_client.py`. Run the integration suite against PostgreSQL because approval row locks and audit advisory locks are PostgreSQL behavior.

## Scan-integrity checks

The scan-integrity contract is covered by `worker/tests/test_scan_integrity.py`, `worker/tests/test_raw_nmap.py`, `worker/tests/test_raw_egress_client.py`, `worker/tests/test_nmap_parse.py`, the length-retry cases in `worker/tests/test_agent.py`, `control-plane/tests/integration/test_engagement_scan_envelope.py`, `control-plane/tests/integration/test_raw_egress_lease.py`, `control-plane/tests/integration/test_tool_execution_audit.py`, `raw-egress-gateway/tests/test_gateway.py`, `egress-proxy/tests/test_backpressure.py`, `frontend/tests/scan_envelope_requirements.test.mjs`, and `frontend/tests/agent_finish_reason.test.mjs`. These verify signed target/run binding, FIFO fairness/cancellation, heartbeat-bound kernel expiry, persisted TCP single/range dispatch, opt-in exact UDP profiles and state truthfulness, materialized-IP dispatch, zero-target/malformed-output failures, durable execution metadata, fingerprint-to-correlation flow, proxy backpressure, and truthful model finish reasons.

Run gateway unit tests with `PYTHONPATH=raw-egress-gateway python3 -m pytest raw-egress-gateway/tests -q`. A real network E2E must use only the isolated lab: activate one signed lab lease, prove the allowed lab IP is reachable, then prove an explicit deny/out-of-scope lab IP remains unreachable. Never substitute a public target for this release gate.
