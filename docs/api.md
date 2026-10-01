# API Contracts

The control-plane exposes REST + SSE. The operator console is a pure client
of these contracts and gets no direct access to the DB or the tools.
Interactive OpenAPI UI available at `/docs` when running.

Source: [Technical Architecture Ch. 6.3](spec/technical-architecture.md#63-dashboard-api-excerpt),
[Operator Console UI Ch. 5.2](spec/operator-console-ui.md#52-integration-with-the-existing-api).
Implementation: [`control-plane/app/api/`](../control-plane/app/api/).

## Public endpoints (operator console)

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/health` | liveness |
| `GET` | `/tools/capabilities` | capability matrix from the registry (installed/authorized/mapped/dispatched/parsed) |
| `GET` | `/engagements` | dashboard cards |
| `POST` | `/engagements` | wizard: engagement + persisted TCP port interval (`tcp_port_from/to`, default 1–65535) + explicit `udp_discovery_enabled` |
| `GET` | `/engagements/{id}` | engagement details incl. the TCP/UDP scan envelope |
| `PATCH` | `/engagements/{id}` | metadata; the TCP/UDP envelope is only changeable in status `draft`. The four discovery switches `subfinder_enabled`, `crawling_enabled`, `oob_enabled`, `screenshots_enabled` are changeable at any status and audited (REQ-COVER-007); `scan_profile` (`standard`/`thorough`, REQ-PIPE-005) too |
| `GET` | `/engagements/{id}/endpoints` | crawled and archived endpoints (URL, method, parameter names, source; max 1000; REQ-COVER-003) |
| `GET` | `/engagements/{id}/screenshots` | screenshot metadata (REQ-COVER-006) |
| `GET` | `/engagements/{id}/screenshots/{screenshot_id}/image` | the PNG; `nosniff`, `Cache-Control: private, no-store`; 404 for another owner's engagement |
| `POST` | `/engagements/{id}/scope-assets` | wizard step 3 (allow/deny) |
| `GET` | `/engagements/{id}/scope-assets` | scope list |
| `GET` | `/engagements/{id}/tool-grants` | the granted categories with their manual-approval tools |
| `POST` | `/engagements/{id}/tool-grants` | grant a category (`tool_category`, `mode` passive/active, `manual_tools`). Allowed until the engagement is `completed`/`revoked` (REQ-TOOL-006); an ACTIVE category on an engagement that has left draft needs `confirm_widening: true` (else 409 `confirmation_required`); refused with 409 `scan_run_active` while a scan runs; audited as `tool_grant_added`. Saving never resets a campaign's per-tool on/off switch |
| `DELETE` | `/engagements/{id}/tool-grants/{category}/{mode}` | take a grant away (204; 404 if none; 409 when completed/revoked); allowed while a scan runs; the gateway denies the category from the next call; audited as `tool_grant_removed` (REQ-TOOL-007) |
| `GET` | `/engagements/{id}/config` | the effective per-tool configuration; per tool `granted` (is its category granted here) and `unavailable_reason` (`not_installed`, `category_not_granted`, `off_for_campaign`, `off_in_settings`, `off_by_default`) |
| `POST` | `/engagements/{id}/bounty-program` | wizard step 5 (conditional) |
| `POST` | `/engagements/{id}/activate` | wizard step 6 (authorization checklist) |
| `GET` | `/engagements/{id}/stream` (SSE) | live log + phase progress |
| `POST` | `/engagements/{id}/scan` | enqueues the scan pipeline on the worker (discovery → report) |
| `GET` | `/engagements/{id}/scan-runs` | `scan_run` history/status (`state`: running/done/failed/aborted) |
| `GET` | `/engagements/{id}/scan-runs/{run_id}/plan` | the run's scan plan (REQ-PIPE-003/010): surfaces (host, port, class `web`/`web_alias`/`tls_service`/`service`/`unknown`, technology profile) and per surface every planned or skipped check with reason, state (`planned`/`running`/`complete`/`partial`/`failed`/`skipped`), duration, findings; response headers are not part of the shape; 404 for another owner's engagement |
| `POST` | `/engagements/{id}/scan-runs/{run_id}/cancel` | immediately sets the run terminal to `aborted`, closes approvals, and terminates the exact bound runner process; terminal runs return 409 |
| `DELETE` | `/engagements/{id}` | atomically deletes the complete engagement data graph (204), keeps the audit trail; active runs return 409 |
| `GET` | `/engagements/{id}/findings` | results list (filters: `severity`, `status`) |
| `PATCH` | `/engagements/{id}/findings/{finding_id}` | triage: `{status, note}` with status `open`, `accepted_risk`, `false_positive`, or `resolved`; a note (≥3 characters) is required for `accepted_risk` and `false_positive`; records who/when/why and writes an audit entry; a later scan keeps the decision (REQ-TRIAGE-001/002) |
| `GET` | `/findings` | findings across every engagement the caller can see (operators: own engagements; admins: all). Filters `status` (default `open`), `severity`, `engagement_id`, `q` (title or target, literal text); paging `limit` (1–200, default 50) and `offset`. Returns `{items, total, limit, offset, counts_by_status, counts_by_severity}`; each item is a finding plus `engagement_title`. The ownership filter is part of the query, so totals and counts never include other users' findings (REQ-PORTFOLIO-001) |
| `POST` | `/engagements/{id}/findings/{finding_id}/lens-explanation` | the Lens Agent explains a finding, its impact, and remediation; cached in `finding.evidence.lens_agent` |
| `GET` | `/engagements/{id}/summary` | risk light, open-finding counts by severity, `counts_by_status` for all four statuses, top actions |
| `POST` | `/engagements/{id}/report` | PDF export (async, returns `job_id`) |
| `GET` | `/approvals?state=requested` | operator queue |
| `POST` | `/approvals/{id}/approve` | authorizes exactly one tool call ⚖ |
| `POST` | `/approvals/{id}/reject` | rejects an authorization |
| `GET` | `/settings/llm` | Vector/Lens Agent LLM provider (OpenAI-compatible); `api_key` masked (`api_key_set`) |
| `PUT` | `/settings/llm` | set the provider (`base_url`/`model`/`api_key`); an empty `api_key` keeps the stored one |
| `GET` | `/settings/nvd` | optional NVD API key for live CVE correlation (REQ-CORR-008); `api_key` masked (`api_key_set`); unset is valid (public rate limit) |
| `PUT` | `/settings/nvd` | set the key; left empty keeps the stored one |
| `GET` | `/settings/subfinder` | optional subfinder provider keys (REQ-COVER-001): per provider only `key_set`, never the key |
| `PUT` | `/settings/subfinder` | set keys; provider names from an allowlist, key characters restricted, empty keeps the stored key |

Every `/settings/*` endpoint — the two above and the scan policy, tool policy, agent prompt, agent budgets, and approval timeout — requires the `admin` role for reading and writing (REQ-IAM-013), because it affects every user's engagements. Per-engagement configuration (`/engagements/{id}/config`) stays with the engagement's owner.

## Internal endpoints (worker → control-plane)

Do not expose publicly — in production, reachable only cluster-internally
(no ingress). Every `/internal/*` route additionally requires
`X-ASM-Internal-Token` (`INTERNAL_API_TOKEN` on both control-plane and
worker), because the local Compose API is published on `:8000` for the
operator console. The worker executes nothing itself and never writes to
the DB directly; it goes exclusively through these endpoints
([`api/internal.py`](../control-plane/app/api/internal.py)).

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/internal/engagements/{id}/gateway/authorize` | **the Scope Gateway** — every tool-call proposal |
| `GET` | `/internal/llm-config` | the full LLM provider config incl. `api_key` (cluster-internal only) for the Vector Agent; the public Lens endpoint uses the same provider config server-side |
| `POST` | `/internal/engagements/{id}/materialize-dns` | audited DNS resolution of the name scope to IPs (raw egress); deny takes precedence at the IP level |
| `POST` | `/internal/engagements/{id}/rate-reservation` | the egress proxy reserves a bug-bounty `max_rps` slot before forwarding (limit taken from the program; REQ-RATE-005) |
| `GET` | `/internal/engagements/{id}/raw-egress-policy` | the generated NetworkPolicy for nmap/raw-scan IP/CIDR egress (incl. materialized IPs) |
| `POST` | `/internal/engagements/{id}/raw-egress-leases` | a short-lived signed nmap lease for `configured_tcp` or opt-in `targeted_udp`; the envelope comes only from engagement state |
| `POST` | `/internal/engagements/{id}/scan-runs` | create a scan run |
| `POST` | `/internal/scan-runs/{id}/claim` | a worker task takes ownership of a run and gets `attempt`, `phase`, `checkpoint`; 409 for finished runs or a live foreign attempt (REQ-RESUME-002) |
| `GET` | `/internal/engagements/{id}/scan-settings` | scan depth and the parallel-check limit (2; a bug-bounty program's own concurrency cap can only lower it) |
| `POST` | `/internal/scan-runs/{id}/plan` | store the plan's surfaces and their planned/skipped checks; idempotent (existing rows keep their state); stale `attempt` gets 409 |
| `GET` | `/internal/scan-runs/{id}/plan` | the plan with fingerprints, for the worker's resume |
| `PATCH` | `/internal/scan-checks/{id}` | a check's state/outcome (`running`, `complete`, `partial`, `failed`, `skipped`), findings, duration; stale `attempt` gets 409 |
| `PATCH` | `/internal/scan-surfaces/{id}` | refine a surface's technology profile after the technology check |
| `PATCH` | `/internal/scan-runs/{id}` | phase/state transition, budget, `checkpoint`; a stale `attempt` gets 409 `superseded` |
| `POST` | `/internal/engagements/{id}/discovered-assets` | a discovery result |
| `GET` | `/internal/engagements/{id}/discovery-options` | the four discovery switches (worker fails closed if unreadable) |
| `GET` | `/internal/subfinder-config` | decrypted subfinder provider keys (cluster-internal only) |
| `POST` | `/internal/engagements/{id}/discovered-endpoints` | store crawled endpoints; 409 if crawling is off; out-of-scope URLs dropped |
| `POST` | `/internal/engagements/{id}/web-screenshots` | store one PNG (max 2 MB, cap 200); 409 if screenshots are off |
| `POST` | `/internal/engagements/{id}/services` | a fingerprint result (port/product/version) |
| `POST` | `/internal/engagements/{id}/findings` | a raw finding (scored/fingerprinted server-side, incl. `is_kev`) |
| `POST` | `/internal/engagements/{id}/rescore` | score phase: re-evaluate EPSS/KEV (respects the persisted `is_kev`) |
| `GET` | `/internal/nvd-config` | the full optional NVD API key (cluster-internal only) for the correlation phase (REQ-CORR-008) |
| `GET`/`PUT` | `/internal/cve-lookup-cache` | read-through cache: NVD candidate CVEs per product name (REQ-CORR-001/004) |
| `GET`/`PUT` | `/internal/epss-cache` | read-through cache: EPSS score per CVE, batched (REQ-CORR-002/004) |
| `GET`/`PUT` | `/internal/kev-catalog-cache` | read-through cache: a CISA KEV catalog snapshot (REQ-CORR-003/004) |

## Example: gateway authorization (the core)

```http
POST /internal/engagements/{id}/gateway/authorize
Content-Type: application/json

{ "tool": "httpx", "category": "fingerprint", "mode": "active",
  "target": "clean-nginx", "args": { "method": "GET" } }
```

Response for an out-of-scope target (deny precedence):

```json
{ "allowed": false, "reason": "explicit_out_of_scope",
  "is_pending": false, "approval_request_id": null }
```

For `requires_manual_approval=true` (cred/exploit), the gateway responds
with `is_pending: true` and an `approval_request_id` — the step then waits
in the operator queue (`GET /approvals`).

## SSE live log

`GET /engagements/{id}/stream` delivers `audit_entry` events directly from
`audit_log`. Because that log is already complete, the live view is
effectively a real-time mirror of the audit trail — no separate logging
needed.

```
event: audit_entry
data: {"ts":"…","actor":"gateway","action":"tool_call","decision":"DENY","reason":"explicit_out_of_scope"}
```

## Authentication and approval execution

All operator endpoints require `Authorization: Bearer <OPERATOR_API_TOKEN>`, `X-ASM-Operator-Token`, or the HttpOnly browser session created by `POST /auth/session`. `/health` is unauthenticated. Internal routes require `X-ASM-Internal-Token`.

Approval execution is internal-only: `POST /internal/approvals/{id}/claim` atomically reauthorizes and returns the exact stored call; `POST /internal/approvals/{id}/complete` records either successful consumption or execution failure. The egress proxy submits network decisions to `POST /internal/engagements/{id}/proxy-audit`.

## Internal tool-execution outcomes

`POST /internal/engagements/{engagement_id}/tool-executions` persists the terminal result of a dispatched tool as a hash-chained audit entry. The bounded payload includes `scan_run_id`, tool and phase, the authorized hostname, the materialized target/IP, tested port range, success and exit status, an error reason, a bounded stderr summary, the discovered-service count, and — since REQ-AUDIT-003 — the exact invocation used (`command`, redacted of credentials worker-side per REQ-AUDIT-004; absent, never fabricated, for a tool that never actually ran). A supplied scan run must belong to the engagement.
