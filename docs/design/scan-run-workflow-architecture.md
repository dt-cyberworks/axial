# Architecture & GUI Design: Scan Run Workflow, Control & Transparency

Design spec for the requirements in
[`../requirements/scan-run-workflow-and-transparency.md`](../requirements/scan-run-workflow-and-transparency.md).
SDLC phases 2 (architecture) and 3 (GUI design). One row per requirement.

## 1. Data model changes

| Change | Table | Purpose | Requirement |
|---|---|---|---|
| `cancel_requested BOOLEAN NOT NULL DEFAULT false`, `state_reason TEXT` | `scan_run` | cooperative stop + why a run ended | REQ-RUN-001 |
| new table `agent_step` | — | per-iteration prompt + response for drill-down | REQ-RUN-006 |

`agent_step`: `id UUID pk`, `engagement_id UUID`, `scan_run_id UUID`,
`iteration INT`, `request_messages JSONB` (system + running message list sent to
the model, api_key never included), `response_text TEXT`, `response_tool_calls
JSONB`, `stop_reason TEXT`, `created_at TIMESTAMPTZ`. Index on
`(scan_run_id, iteration)`. Migration `0006_scan_run_control_and_agent_steps.sql`.

Data reconciliation migration `0009_finalize_cancelled_scan_runs.sql` finalizes
only historical active rows that already carry `cancel_requested=true` and
closes only approvals whose immutable tool-call JSON names that exact run.

## 2. Backend endpoints

| Method / path | Purpose | Requirement |
|---|---|---|
| `POST /engagements/{id}/scan-runs/{run_id}/cancel` | request cooperative stop; 409 if not running | REQ-RUN-001 |
| `GET  /engagements/{id}/scan-readiness` | `{ready, blockers[]}` | REQ-RUN-002 |
| `POST /engagements/{id}/scan` | now pre-checks readiness → 409 + blockers if not ready | REQ-RUN-002 |
| internal `GET /internal/scan-runs/{run_id}/cancel-requested` | worker polls stop flag | REQ-RUN-001 |
| internal `POST /internal/engagements/{id}/agent-steps` | worker records a step | REQ-RUN-006 |
| `GET  /engagements/{id}/scan-runs/{run_id}/agent-steps` | operator drill-down | REQ-RUN-006 |

Readiness logic lives in a reusable `app/scan_readiness.py` (used by both the
readiness endpoint and `start_scan`) so the two never drift. It reuses the same
predicates the gateway enforces (time window, active grant, active-allowed scope,
bounty ident header) — a single source of "can this engagement act at all".

## 3. Worker changes (`worker/`)

- The public cancel endpoint locks the run row and immediately writes the
  terminal cancellation tuple (`cancel_requested`, `aborted`, reason, finish
  time). Internal updates treat that tuple as immutable, so a lost/restarted or
  delayed worker cannot leave the UI active or resurrect the run. (REQ-RUN-001)
- `pipeline.run_scan`: check `client.is_cancel_requested(run_id)` at every phase
  boundary and return without running later phases. (REQ-RUN-001)
- Every fingerprint/agent gateway payload carries `scan_run_id`; authorization
  locks and validates that exact row. The same ID is attached to the runner HTTP
  request. A strict build-time HexStrike patch registers it on the child process,
  creates a separate process group, and exposes run-specific group termination.
- `ToolRunnerClient` waits for the response in a daemon dispatch thread while the
  orchestration thread polls cancellation. Cancel or unavailable control-plane
  state triggers bounded `/api/processes/terminate-scan-run/{id}` retries. Raw
  Nmap always deactivates its lease after the terminated request returns.
- `agent.run`: also check cancellation between iterations; and for every LLM
  iteration call `client.record_agent_step(...)` with the request messages (minus
  secrets), the response text, and tool_calls. (REQ-RUN-006)
- `control_plane_client`: add `is_cancel_requested`, `record_agent_step`.
- No change to how tools are chosen — cancellation is cooperative, not a kill.

## 4. GUI: navigation model (REQ-RUN-005)

Routes:

| Route | Page | Scope |
|---|---|---|
| `/` | Overview (engagement list) | all |
| `/engagements/:id` | **Engagement detail** (NEW) | engagement |
| `/engagements/:id/runs/:runId` | **Run detail** (NEW) | run |
| `/engagements/:id/edit` | Engagement edit (metadata + campaign config) | engagement |
| `/new` | New engagement wizard | — |
| `/settings` | Agent settings | global |
| `/docs` | Documentation (NEW) | — |
| `/engagements/:id/audit` | Audit (full compliance trail) | engagement |

Deprecated/redirected: `/engagements/:id/live` and `/engagements/:id/results`
fold into the new pages (redirect `live`→engagement detail, `results`→engagement
detail). Old `LiveScan`/`Results` logic is split:

- **Engagement detail** = engagement summary + scope/agent readiness banner +
  aggregate findings summary (severity distribution, top actions) + **run list**
  (from Scan history) + `Start run` (guarded by readiness) + link to full findings.
- **Run detail** = tabs:
  - **Progress**: the phase tree (from LiveScan) for THIS run, with per-phase tool
    lists (REQ-RUN-003) and, if the run is live, SSE updates + `Stop scan`
    (REQ-RUN-001). Phase-transition rows filtered out (REQ-RUN-004).
  - **Diff**: new / no-longer-observed vs previous run (existing scan-diff).
  - **Agent**: list of agent steps; click a step → prompt + response (REQ-RUN-006).
  - **Log**: run-scoped activity (gateway allow/deny/throttle), transitions hidden.

Breadcrumb component: `Engagements / {title} / Run #{n} / {tab}` on run pages;
`Engagements / {title}` on engagement detail.

Findings remain engagement-wide (data reality) → shown at engagement level; the
run's contribution is expressed via the Diff tab.

## 5. GUI: per-phase tools (REQ-RUN-003)

Extend the existing `PHASE_COPY` map with a `tools: string[]` (or "internal")
field. Static mapping grounded in what each phase dispatches today:

- discovery: `crt.sh` (passive OSINT) — no target-touching tools
- fingerprint: `httpx, nmap, nikto, wafw00f, testssl`
- correlate: internal (no tools)
- agent: `httpx, nmap, nikto, wafw00f, testssl, nuclei, http_request, ffuf` (gated per config)
- validate: internal
- score: internal
- report: internal

Rendered as chips in the expanded phase panel.

## 6. GUI: documentation page (REQ-DOC-001)

Single `/docs` route, `Documentation.tsx`, content authored as structured
sections (index + anchors) covering every screen and field. Kept in the
component (not fetched) so it ships with the app and needs no backend. Sidebar
gets a `Help` link. Content is the human-facing counterpart to this design.

## 7. QA plan (SDLC phase 5)

- control-plane: unit/integration tests for cancellation state machine, readiness
  predicates (each blocker), agent-step persistence + retrieval, start_scan guard.
- worker: agent-step recording via fake OpenAI; cancellation short-circuits loop.
- frontend: `tsc` clean; Playwright smoke of engagement detail → run detail tabs,
  stop button visibility on a running run, agent step drill-down, docs page.
- `/code-review` (or self review) on the diff before sign-off.

## 8. Non-goals (this iteration)

- Killing unrelated runner processes or entire shared runner containers.
- Per-run findings snapshots beyond the observation-based diff.
- Full-text search of agent steps.
