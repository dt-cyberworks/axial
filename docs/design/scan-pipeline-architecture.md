---
title: Scan pipeline architecture (v2)
status: implemented
risk: R3
owner: security-engineering
---

# Scan pipeline architecture (v2)

Requirements: [`../requirements/scan-pipeline.md`](../requirements/scan-pipeline.md)
(REQ-PIPE-001..016). Status: approved by johannes on 2026-09-29 together with
decisions D1–D6 (section 8); human security review of the finished R3
implementation is still owed.

## 0. Why this redesign

A live dev run against `cloud.example.com` on 2026-09-29 (engagement
`01a0ede8…`, runs `01a0ede9…` and `01a0ee48…`) showed that the pipeline does a
lot of work that its own evidence says is pointless, and reports some of it
wrongly. Measured, not estimated:

| # | Problem | Evidence |
|---|---|---|
| P1 | Tool selection ignores the fingerprint | Every live web port gets all 5,976 nuclei templates. httpx identified Nextcloud, Nginx, PHP; ~100 templates are tagged for those. 3,734 CVE templates ran regardless. |
| P2 | Templates for ports nmap proved closed | 130 `network/` + `javascript/` templates (113 of them FTP/21) ran against web ports; nmap had found 21 closed. |
| P3 | Executor cap drives the design | HexStrike kills every command at 300 s. The main pass was split into 6, then 9 parts; even the 858-template `http_misconfiguration` part hit 300 s. |
| P4 | Truncated runs recorded as success | nikto ended every run with "Host maximum execution time of 40 seconds reached", audited `success=true`. |
| P5 | Replayed results audited as executions | HexStrike's `/api/tools/*` endpoints ignored `use_cache:false`; resumed attempts got 1-hour-old nmap/nikto/nuclei results in ~20 ms (fixed in the build patch, REQ-CONCUR-001, not yet deployed). |
| P6 | Redirect-only ports fully rescanned | Port 80 only answers `301` to 443; it still got the complete web suite (~20 min of nuclei). |
| P7 | Non-web services get no checks | SMTP 25/465/587 and IMAPS 993 were found open; only NVD correlation touched them. No TLS check on the mail ports. |
| P8 | Low egress throughput | 589 proxy connections in 300 s (~2/s) for an own-domain engagement with no rate cap. Hypothesis: the synchronous per-connection audit write into the hash-chained audit log. Not yet measured in isolation. |
| P9 | Resume granularity is a whole phase | After a worker restart the fingerprint phase started again from the first host (attempt 3 repeated ~40 min of work). |
| P10 | Runner leaks processes | 8 zombie `nuclei` processes after timeouts; HexStrike never reaps what it kills. |
| P11 | Validate phase is a stub | `worker/app/tasks/validate.py` logs "validation checks TODO" and returns nothing. |

One web port currently costs ~30 minutes (nuclei main ~20, OOB ~7, the rest
~3); a single host with ports 80 and 443 took ~1 h 40 min including resumes.

## 1. Current pipeline (as built)

`discovery → [asset review gate] → fingerprint → correlate → agent → validate → score → report`
(`worker/app/tasks/pipeline.py`), one Celery task, strictly sequential, a
checkpoint per phase.

Per host, `fingerprint.run`: DNS materialization → nmap full TCP SYN + `-sV` on
open ports (once per IP) → web candidate ports (open ports, 443 fallback when
no scan evidence) → per port: httpx (liveness, tech) → wafw00f → testssl
(TLS ports only) → [same-surface dedupe] → nikto (40 s cap) → ffuf (90 s cap)
→ screenshot → katana → nuclei main (9 parts) → headless → takeover →
endpoints → OOB (5 parts).

Measured step times on one port: nmap 217 s (per IP), httpx 1 s, wafw00f 3 s,
testssl 30 s, nikto 40 s (always capped), ffuf 90 s (capped), screenshot 1–2 s,
katana 39 s, nuclei main parts 57–300 s each, endpoints 30 s, OOB parts
15–270 s.

What stays: the phase order, the Scope Gateway authorizing every call, the
egress proxy and raw-egress lease as enforcement points, the asset review
gate, NVD/EPSS/KEV correlation, the optional agent, run resume (#42), the
coverage-degraded signal (REQ-SCAN-014), per-engagement switches (REQ-COVER-007).

## 2. Design principles

1. **Evidence drives work.** A check runs against a port, service or
   technology only when the scan observed it. The exceptions are explicit: the
   generic check set, the empty-fingerprint fallback, and the `thorough` profile.
2. **Plan before execute.** A deterministic planner turns observations into a
   persisted check plan. Every planned and every skipped check carries its
   reason. The operator can see the plan before and during the run.
3. **Honest outcomes.** Every check ends as `complete`, `partial` (budget
   reached, results kept), `failed` or `skipped:<reason>`. `partial` never reads
   as clean; the report lists coverage.
4. **Budgets are declared, not inherited.** Each check has its own time budget
   that the runner enforces. No hidden executor cap shapes the check set.
5. **Resume at check granularity.** A restart continues with the next
   unfinished check, not the first host.
6. **The safety boundary does not move.** The planner chooses among fixed,
   worker-built invocations. Every execution is still one gateway-authorized
   tool call through the proxy or a raw-egress lease. The agent still only
   proposes.

## 3. Target stage model

| Stage | Output | Change vs. today |
|---|---|---|
| S1 Discover | assets | unchanged (DNS, CT/OSINT, subfinder, URL history) |
| S2 Asset review gate | approved assets | unchanged |
| S3 Port & service discovery | open ports + `-sV` product/version per IP | unchanged (nmap once per IP) |
| S4 Classify & fingerprint | **surfaces** with service class and technology profile | new |
| S5 Plan | **check plan** per surface | new |
| S6 Execute | check outcomes + findings | replaces the fixed web-suite order |
| S7 Correlate | NVD/EPSS/KEV findings | input becomes the technology profile |
| S8 Agent (optional) | proposals → gateway | gets plan and coverage as context |
| S9 Validate | – | removed until concrete validations are specified (D3) |
| S10 Score & report | report with coverage section | coverage section new |

### S4 Classify & fingerprint

Every open TCP port becomes a **surface** with exactly one service class:

- `web` – httpx confirmed a live HTTP(S) service.
- `web_alias` – the port only redirects (3xx) to another surface of the same
  engagement that is scanned anyway (e.g. `http://host:80 → https://host:443`).
  It keeps its httpx result and nothing else (missing-header findings on a
  redirect response would be noise); deep checks run once on the target.
- `tls_service` – implicit TLS (465, 993, 995, 636, …) or STARTTLS-capable
  (SMTP 25/587, IMAP 143, POP3 110, FTP 21, …) per `-sV`.
- `service` – other identified service (SSH, databases, message queues, …).
- `unknown` – open, not identified.

The **technology profile** of a surface merges httpx tech detection, nmap
`-sV` product/version and nuclei's technology-detection templates
(`http/technologies`, 907 templates, mostly clustered into a few requests).
Entries are normalized product keys with optional version
(`nextcloud`, `nginx`, `php`).

### S5 Plan

The planner is a pure function
`plan(surface, profile, engagement options) → [planned check | skipped check]`,
unit-testable without infrastructure.

**Check catalog.** Each check declares: id, tool, service classes it applies
to, required switch, time budget, and a fixed invocation builder.

**Nuclei selection.** A template index is built once at tool-runner image
build time: path, id, tags, protocol, ports, severity, `metadata.vendor` /
`metadata.product`. Measured on the baked set: 3,957 of 5,976 templates are
product-bound (86 % of CVE templates, 39 % of misconfiguration, 44 % of
default-logins); ~2,000 are generic.

- Generic templates (no product binding): always, for `web` surfaces.
- Product-bound templates: only when the product is in the surface profile.
- Empty profile (nothing identified): generic templates plus the
  product-bound templates of a fixed, reviewed list of common web products
  (D1). The list lives in one place in code and in this document; initial
  proposal: wordpress, drupal, joomla, apache, nginx, iis, tomcat, jenkins,
  gitlab, grafana, confluence, jira, php, spring.
- `network/` and `javascript/` templates: never on a `web` surface, and not
  on other surfaces in this iteration (D4). Port-matched network templates
  through the raw-egress lease are a later, separate R3 item.
- `thorough` profile: the complete former set minus `network/` and
  `javascript/`, which by the rule above never apply to a web surface.

For `cloud.example.com:443` this means ~2,100 templates instead of 5,976.

**Other tools.** testssl runs on `web` over TLS and on every `tls_service`
(with `--starttls <proto>` where needed). nikto is retired (D2); its one
unique contribution, missing-security-header findings, is derived from the
response headers httpx already records (no extra request), so REQ-FPEFF-007's
exclusion of nuclei's header template stays valid. ffuf, katana, screenshots
and OOB keep their switches and apply to `web` only.

### S6 Execute

- A **check job** is one planned check against one surface. Jobs are rows
  (`scan_check`), not an in-memory loop. The job row is the checkpoint.
- The worker executes jobs in plan order, at most two at a time per
  engagement (D6), each through the unchanged gateway → runner path.
- The runner enforces the job's declared budget. HexStrike's fixed 300 s cap
  is replaced by a per-request timeout bounded by a hard maximum (build-time
  patch, the same mechanism as the auth gate and the cache fix). Killed
  process groups are reaped.
- Output printed before a budget is reached is parsed; the job ends `partial`.
- A resumed run skips `complete`, `partial` and `skipped` jobs and restarts
  `running` ones.

### Throughput (P8)

Measure first: requests/s through the egress proxy with and without the
per-connection audit write, for one engagement and for two in parallel. The
requirement sets a target. If the audit write is confirmed as the bottleneck,
a faster audit path is proposed as its own R3/R4 requirement and design for
johannes's security review before any change (D5); every connection stays
audited and scope-checked, fail-closed.

## 4. Data model (proposal)

- `scan_surface`: id, scan_run_id, asset_id, ip, port, scheme,
  service_class, alias_of (nullable), profile (jsonb), fingerprint.
- `scan_check`: id, scan_run_id, surface_id, check_id, tool, planned_reason
  or skip_reason, state (`planned|running|complete|partial|failed|skipped`),
  budget_s, started_at, finished_at, outcome_summary (jsonb), attempt.
- `engagement.scan_profile`: `standard` (default) | `thorough`.

The per-phase `scan_run.checkpoint` stays for discovery/review; the
fingerprint-phase checkpoint is replaced by the job rows.

## 5. Endpoints (proposal)

- `GET /engagements/{id}/scan-runs/{run}/plan` – surfaces and checks with
  reasons, states, durations.
- `PATCH /engagements/{id}` – `scan_profile`.
- Internal: create surfaces/checks, claim next check, finish check.

## 6. GUI (proposal)

- Engagement configuration: "Scan depth" (`Standard – checks chosen from what
  the scan finds` / `Thorough – every template on every web service, much
  slower`).
- Run detail: new "Plan" tab – one row per surface (host:port, class,
  technologies), expandable to its checks (tool, why planned or skipped,
  state, duration, findings).
- Report: coverage section with the same data.

## 7. Delivery in increments

Each increment ships dev → int with tests and a live run, following the SDLC.

1. **Stop the bleeding** (small, independent): deploy the cache fix; reap
   runner processes; per-request runner timeout; `partial` outcome for
   nuclei; retire nikto (header findings from httpx); `web_alias` skip for
   redirect-only ports; no `network/` / `javascript/` templates on web
   surfaces; remove the validate phase.
2. **Plan & select**: template index, surfaces and technology profile,
   planner, standard/thorough profile, plan API.
3. **Job executor**: `scan_check` rows, check-level resume, bounded
   concurrency, Plan tab, report coverage section.
4. **Services & throughput**: testssl on `tls_service`, throughput
   measurement (and, if confirmed, a separate audit-path proposal).

## 8. Decisions (johannes, 2026-09-29)

| # | Question | Decision |
|---|---|---|
| D1 | Empty-fingerprint fallback | Generic templates + product-bound templates of a fixed list of common web products |
| D2 | nikto | Retire it; header findings come from httpx's recorded headers |
| D3 | Validate phase | Remove until concrete validations are specified as their own requirement |
| D4 | Non-web services | testssl only for now; port-matched network templates later as a separate R3 item |
| D5 | Proxy audit path | Measure first; if confirmed, propose a separate R3/R4 requirement for security review |
| D6 | Concurrency | At most two check jobs in parallel per engagement |

## 9. As built (2026-09-30)

All four increments are implemented and were run live on dev. What differs from the
proposal above, and why:

| Topic | As built |
|---|---|
| Template index | Built into the tool-runner image from the baked templates (`tool-runner/nuclei_index.py`, stdlib only, verified against `nuclei -tl` with the same flags: 5,883 templates, exact match, 1,980 generic and 3,903 product-bound). The worker asks the runner for counts and never sends a template path; the runner resolves a selection (`group` generic/products/all, `shard k/n`, product keys) against the index. The gateway accepts only that typed shape (`args_safety._select_args_safe`). |
| Technology profile | httpx tech + server header + nmap product/version, then enriched by a `nuclei:tech` check (nuclei's `http/technologies` templates) before the product check runs; the product check resolves its keys when it executes (`from_profile`). |
| Plan and jobs | `scan_surface` and `scan_check` (migration 0037). The plan is stored before any check runs; `worker/app/scan_executor.py` runs it, at most two checks at a time (`GET /internal/engagements/{id}/scan-settings`; a bug-bounty program's concurrency cap can only lower it). |
| Alias surfaces | Skipped checks include the optional ones (screenshot, katana); no header findings for the redirect response. |
| Header findings | From httpx's recorded headers, five headers as in REQ-PIPE-013 (nikto also reported Permissions-Policy; the approved list does not). |
| Budgets | Table in `worker/app/tool_runner_client.py` (`CHECK_BUDGET_S`, `NUCLEI_BUDGET_S`); a selection call gets 120 s plus 3 s per template. The runner clamps every request to 1800 s (`tool-runner/runner_budget.py`, injected by the build patch). |
| Partial outcome | `budget_reached` (runner kill, tool `timeout`, or a self-limiting tool such as ffuf/katana running its whole deadline); output printed before that is kept; the run's `state_reason` carries `coverage_partial:<tool>=<n>`. |
| Reaping | `init: true` on the tool-runner service (the runner's PID 1 is now an init process). |
| Thorough | Every template of the index (all shards); the index excludes `network/` and `javascript/`, so "the former complete set" reads "minus those two directories" (REQ-PIPE-004 clarified). |
| Throughput (D5) | Measured (see `docs/reviews/2026-09-30-egress-throughput-measurement.md`): the proxy carries 85-220 connections per second and the audit write costs about 5 ms, so the hypothesis is not confirmed and no audit-path change is proposed. |
| Out-of-band pass | Unchanged: still five fixed parts behind its switch. Making it evidence-driven is an open follow-up. |
| TLS on other services | `testssl` on `tls_service` surfaces; `--starttls` protocol is a fixed set validated by the gateway. It follows the engagement's tool list: selected means it runs with no further approval, switched off means the plan skips it (`tool_disabled`, from `disabled_tools` in the scan settings; the gateway refuses it regardless). |
| Product keys at the gateway | Format-checked only (which blocks shell metacharacters); membership in the index is not checked - an unknown key selects nothing (johannes, 2026-09-30). |
