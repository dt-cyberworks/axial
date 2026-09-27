# Architecture: Attack-Surface Graph & Dashboard

Design spec for the requirements in
[`../requirements/attack-surface-graph.md`](../requirements/attack-surface-graph.md).
SDLC phase 2 (architecture) + phase 3 (GUI). One row per requirement.

## 0. Two upstream facts that shape this design

1. **The relationships already exist as data — just siloed.** `discovered_asset`
   has a self-referential `parent_id` (`control-plane/app/models/asset.py:21`)
   that is *defined but never populated or read*. `dns_record.terminal_ips` +
   `is_shared_infra` (`models/dns_record.py`) and `resolved_host` (name→IP) hold
   the resolution graph. `service.asset_id` + `service.tech_stack.tech[]` hold
   host→service→technology. `finding.asset_id` / `service_id` / `cve_ids` hold
   findings and CVEs. Nothing assembles these into a relationship view. This
   design **materializes** that latent graph; it does not collect new data.

2. **The control-plane is the sole DB writer; the worker executes nothing.** So
   the graph *builder* must run in the control-plane. The worker triggers
   materialization via a new internal endpoint at phase boundaries — the same
   pattern every other worker→DB write already uses.

## 1. Data model changes

| Change | Table | Purpose | Requirement |
|---|---|---|---|
| new table `surface_node` | — | one row per typed graph node | REQ-GRAPH-001/002 |
| new table `surface_edge` | — | one row per typed directed edge | REQ-GRAPH-001 |
| populate existing column | `discovered_asset.parent_id` | subdomain→domain backbone | REQ-GRAPH-006 |

`surface_node`: `id UUID pk`, `engagement_id UUID NOT NULL FK engagement`,
`node_type TEXT NOT NULL` (one of `engagement|domain|subdomain|ip|service|
technology|cve|finding|dns_artifact`), `ref_table TEXT NOT NULL`,
`ref_id TEXT NOT NULL` (natural id of the source row/value; text so value-derived
nodes like an IP or a technology name have a stable key), `label TEXT NOT NULL`,
`scannable BOOLEAN NOT NULL DEFAULT false`, `attrs JSONB NOT NULL DEFAULT '{}'`,
`first_seen TIMESTAMPTZ NOT NULL DEFAULT now()`,
`last_seen TIMESTAMPTZ NOT NULL DEFAULT now()`.
Idempotency key: `UNIQUE (engagement_id, node_type, ref_table, ref_id)`.

`surface_edge`: `id UUID pk`, `engagement_id UUID NOT NULL FK engagement`,
`src_node_id UUID NOT NULL FK surface_node ON DELETE CASCADE`,
`dst_node_id UUID NOT NULL FK surface_node ON DELETE CASCADE`,
`edge_type TEXT NOT NULL` (one of `HAS_SUBDOMAIN|RESOLVES_TO|HAS_SERVICE|
RUNS_TECHNOLOGY|HAS_CVE|FINDING_AT|SHARES_INFRA`), `attrs JSONB NOT NULL
DEFAULT '{}'`. Idempotency key: `UNIQUE (engagement_id, src_node_id, dst_node_id,
edge_type)`. Index on `engagement_id`.

Migration `0021_attack_surface_graph.sql`, idempotent (`CREATE TABLE IF NOT
EXISTS`, `CREATE INDEX IF NOT EXISTS`), mirroring the 0018 style.

**Scannability rule (REQ-GRAPH-002):** `scannable` is set *only* for
`node_type in (domain, subdomain, ip)` **and** only when the originating
`discovered_asset.in_scope` is true. Every value-derived node (`ip` from a shared
`terminal_ips` entry, `technology`, `cve`, `finding`, `dns_artifact`) is
`scannable = false`. The builder never writes `discovered_asset`/`scope_asset`/
`resolved_host`.

## 2. Node & edge derivation (builder)

`control-plane/app/graph/builder.py::materialize_graph(engagement_id, db) -> dict`
— a pure assembly that upserts nodes then edges and returns counts. Sources and
mapping:

| Node | Source | scannable |
|---|---|---|
| `engagement` | the engagement row | false |
| `domain` / `subdomain` | `discovered_asset` (type domain/wildcard→domain, else subdomain) | = `in_scope` |
| `ip` | `resolved_host.ip_address`, `dns_record.terminal_ips[]` | false |
| `service` | `service` (per asset+port) | false |
| `technology` | `service.tech_stack.tech[]` (deduped by name) | false |
| `cve` | `finding.cve_ids[]` (deduped) | false |
| `finding` | `finding` | false |
| `dns_artifact` | `dns_record` (cname terminal / shared-infra marker) | false |

| Edge | From → To | Source |
|---|---|---|
| `HAS_SUBDOMAIN` | domain → subdomain | `discovered_asset.parent_id` (REQ-GRAPH-006) |
| `RESOLVES_TO` | domain/subdomain → ip | `resolved_host`, `dns_record.terminal_ips` |
| `HAS_SERVICE` | domain/subdomain → service | `service.asset_id` |
| `RUNS_TECHNOLOGY` | service → technology | `service.tech_stack.tech[]` |
| `HAS_CVE` | service/finding → cve | `finding.cve_ids` |
| `FINDING_AT` | finding → domain/subdomain/service | `finding.asset_id`/`service_id` |
| `SHARES_INFRA` | ip → (its resolving names) | ≥2 in-scope names share one IP |

Idempotent upsert via `INSERT … ON CONFLICT (unique key) DO UPDATE SET
last_seen = now(), label/attrs = EXCLUDED.…`. Re-running on unchanged data yields
the identical node/edge set (REQ-GRAPH-001).

## 3. Endpoints

- **internal** `POST /internal/engagements/{id}/materialize-graph` — worker
  triggers after discovery/fingerprint/correlate. Body empty; returns counts.
  Calls `materialize_graph`. (`control-plane/app/api/internal.py`.)
- **operator** `GET /engagements/{id}/surface-graph` — returns
  `{nodes: [...], edges: [...]}` for the UI, scoped through the same engagement
  ownership dependency the sibling engagement endpoints use (REQ-GRAPH-005).
  (`control-plane/app/api/engagements.py`.)
- **internal, extended** `GET /internal/engagements/{id}/agent-context`
  (`internal.py:730`) — response gains a `graph: {nodes, edges}` field alongside
  the existing `hosts`. Backward compatible (REQ-GRAPH-003).

Client method `api.surfaceGraph(id)` added to `frontend/src/api/client.ts`; worker
gets `client.materialize_graph(engagement_id)` and `client.get_agent_context`
already returns the enriched payload.

## 4. Worker wiring

- `worker/app/tasks/pipeline.py` — after `discovery.run`, `fingerprint.run`, and
  `correlate.run`, call `client.materialize_graph(engagement_id)` (best-effort,
  fault-isolated: a graph failure never fails the scan).
- `worker/app/tasks/discovery.py` — when registering a subdomain, pass
  `parent_id` = the in-scope parent domain's discovered-asset id when known
  (REQ-GRAPH-006), threaded through `add_discovered_asset` /
  `DiscoveredAssetIn.parent_id` (already an accepted optional field,
  `schemas/internal.py:167`).
- `worker/app/tasks/agent.py` — `_render_evidence` / `_initial_context`
  (`agent.py:603`/`:684`) additionally render a compact **relationship block**
  from `graph`: shared-IP groups, technology fan-out, tech→CVE links. Non-scannable
  nodes are labelled "context only — not a target". Empty/absent graph → existing
  flat evidence unchanged (REQ-GRAPH-003 fallback).
- Prompt: `control-plane/app/default_prompts.py` `DEFAULT_AGENT_PROMPT` gains a
  short paragraph instructing the agent to exploit shared-infra / tech-fan-out
  relationships when prioritizing checks.

## 5. GUI design (phase 3)

New read-only section on the engagement detail page
(`frontend/src/pages/EngagementDetail.tsx`), sibling to `DnsSection` /
`FindingsSection`: **`frontend/src/components/SurfaceGraph.tsx`**.

- **Layout:** [2026-08-11] real engagements outgrew the original hand-rolled-SVG
  assumption ("node counts are small") — up to ~120 nodes per engagement, 60%
  concentrated in `finding` nodes under a handful of `service` parents, which
  produced a single ~3,400px column in the fixed-lane SVG layout. Replaced with
  **Cytoscape.js** (`cytoscape` + `cytoscape-dagre`), rendered into a
  fixed-height, pan/zoomable canvas instead of an ever-growing page. Layout is
  `dagre`, `rankDir: "LR"` — deterministic (no randomized force simulation), so
  the diagram doesn't reshuffle between reloads; findings still cluster near
  their parent service rather than sharing one global lane. `SHARES_INFRA`
  edges render dashed/purple as cross-links. Colors are read from the
  `styles.css` custom properties at mount time (canvas can't resolve CSS
  variables directly), so the palette stays a single source of truth.
- **Encoding:** node fill by `node_type`; in-scope (`scannable`) nodes have a
  solid border, non-scannable nodes a dashed/muted border (REQ-GRAPH-004).
- **Fields per node (detail panel on click):** `label`, `node_type`,
  `scannable`, source (`ref_table`), and — for a `finding` node — severity +
  title pulled from `attrs`.
- **Interaction:** click a node → right-hand detail panel; hover → highlight
  incident edges and dim the rest; scroll to zoom, drag to pan, drag a node to
  reposition it; explicit +/−/fit controls for discoverability. Read-only; no
  action buttons.
- Data via `useQuery(["surface-graph", id], () => api.surfaceGraph(id))`.

## 6. Requirement → design coverage

| Requirement | Where satisfied |
|---|---|
| REQ-GRAPH-001 | §1 tables, §2 builder, §4 phase hooks |
| REQ-GRAPH-002 | §1 scannability rule, §2 (builder writes only graph tables), negative test |
| REQ-GRAPH-003 | §3 agent-context extension, §4 agent rendering + prompt |
| REQ-GRAPH-004 | §5 SurfaceGraph component |
| REQ-GRAPH-005 | §3 operator endpoint under engagement-ownership dependency |
| REQ-GRAPH-006 | §1 column, §4 discovery `parent_id` threading |

## 7. Safety invariants (R3 review gate)

- Builder is read-only on source tables, writes only `surface_node`/`surface_edge`.
- `scannable` derives solely from `discovered_asset.in_scope`; all value-derived
  nodes are non-scannable.
- `authorize.py` is untouched and never reads the graph tables or `parent_id`.
- Agent consumes a rendered read-only structure — no text-to-Cypher, no
  LLM-authored DB query.
