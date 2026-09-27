---
title: Attack-surface graph and dashboard
status: implemented
risk: R3
owner: security-engineering
---

# Attack-Surface Graph & Dashboard

This document is the requirement source for a first-class **attack-surface graph**:
a typed, relationship-native view of one engagement's discovered surface, derived
from the data the deterministic scan phases already collect. The graph powers two
consumers — the **Vector Agent** (relationship-aware context for multi-hop
correlation) and an operator-facing **graph dashboard**.

The design is deliberately **graph-in-Postgres**, not a separate graph database.
At ASM scale (dozens–low-hundreds of nodes per engagement) a typed node/edge model
in the existing store delivers the relationship value without a second stateful
service, a dual-write consistency problem, or an LLM-generated-query (text-to-Cypher)
injection surface. The control-plane remains the sole database writer.

The graph is **derived metadata**, exactly like `dns_record`: it may *describe*
relationships that include out-of-scope nodes (external CNAME targets, shared
infrastructure IPs, technology/CVE nodes), but it must never *widen* what is
actively scanned. Discovery/assembly may only propose; the Scope Gateway
(`control-plane/app/gateway/authorize.py`) remains the sole gate for active scanning.

**Risk class: R3** (scope-adjacent assembly; carries a scope-safety invariant that
requires a negative test). No new active/offensive capability is introduced — the
graph is read-derived from existing rows, and the agent consumes a rendered,
read-only structure, never a query it authored.

Tests must verify these requirements directly. Do not weaken tests to match
implementation; update implementation when it violates this document.

---

## REQ-GRAPH-001: A typed attack-surface graph is materialized per engagement

The system shall assemble, per engagement, a typed graph of nodes and directed
edges derived idempotently from the already-collected scan data.

Acceptance criteria:

- Nodes are typed as one of: `engagement`, `domain`, `subdomain`, `ip`,
  `service`, `technology`, `cve`, `finding`, `dns_artifact`.
- Edges are typed as one of: `HAS_SUBDOMAIN`, `RESOLVES_TO`, `HAS_SERVICE`,
  `RUNS_TECHNOLOGY`, `HAS_CVE`, `FINDING_AT`, `SHARES_INFRA`.
- Nodes are derived from `discovered_asset` (including its `parent_id`
  backbone), `service`, `dns_record`, `resolved_host`, and `finding`; each node
  records the source table and row it was derived from.
- Materialization is idempotent: running it again on unchanged data produces the
  same set of nodes and edges (upsert on a stable natural key), never duplicates.
- The graph is (re)materialized at the end of the discovery, fingerprint, and
  correlate scan phases.

Security invariants:

- Assembly is read-only against source tables and writes only to the graph
  tables. It never mutates `scope_asset`, `resolved_host`, or gateway state.

## REQ-GRAPH-002: The graph is derived metadata and never widens scope

The system shall treat graph nodes and edges as inventory metadata only. A node
that is not itself an in-scope discovered asset must never become a scannable
asset or influence an authorization decision.

Acceptance criteria:

- Every node carries a `scannable` flag set **solely** from the originating
  `discovered_asset.in_scope` value; nodes with no in-scope discovered-asset
  origin (external CNAME targets, shared IPs, technology, CVE, finding, DNS
  artifacts) are `scannable = false`.
- Materializing the graph never inserts or updates a row in `discovered_asset`,
  `scope_asset`, or `resolved_host`.
- The Scope Gateway (`authorize.py`) never reads `surface_node`, `surface_edge`,
  or `discovered_asset.parent_id`; adding the graph does not change any
  authorization outcome for any tool call.

Security invariants:

- **Negative test required (R3):** a non-scannable node (e.g. a shared IP that
  hosts both an in-scope and an out-of-scope name) never appears as a
  `discovered_asset` and never causes an out-of-scope target to be authorized.

## REQ-GRAPH-003: The Vector Agent receives a relationship-structured context

The system shall provide the Vector Agent a context that exposes cross-host
relationships, so it can reason over shared infrastructure and technology
fan-out instead of a flat per-host list.

Acceptance criteria:

- The agent context includes the graph's nodes and edges (or an equivalent
  rendered structure) alongside the existing per-host evidence.
- The rendered context makes at least these relationships legible: hosts that
  share an IP (`SHARES_INFRA`/`RESOLVES_TO`), a technology that appears on
  multiple services (`RUNS_TECHNOLOGY`), and CVEs linked to a technology
  (`HAS_CVE`).
- The agent still receives only in-scope hosts as valid targets; non-scannable
  graph nodes are presented as context, explicitly marked not-a-target.
- When the graph is empty or unavailable, the agent falls back cleanly to the
  existing flat per-host evidence (no error, no empty run).

Security invariants:

- The agent consumes a rendered, read-only structure. No LLM-authored query is
  executed against the database.

## REQ-GRAPH-004: An operator graph dashboard visualizes the attack surface

The system shall present, per engagement, a read-only interactive visualization
of the attack-surface graph in the operator console.

Acceptance criteria:

- The engagement detail view offers an attack-surface graph section that renders
  the engagement's nodes and edges.
- Node and edge types are visually distinguishable (colour/shape/label), and
  non-scannable nodes are visually distinct from in-scope assets.
- Selecting a node reveals its details (type, label, source, and any linked
  findings).
- The view is read-only: it triggers no scan, no authorization, and no mutation.

## REQ-GRAPH-005: The graph API is scoped to the caller's engagement

The system shall expose the graph only to a caller authorized for that
engagement.

Acceptance criteria:

- An operator `GET` endpoint returns the nodes and edges for a given engagement.
- A caller who does not own / is not authorized for the engagement receives the
  same not-found response used elsewhere (no cross-engagement disclosure).
- The response contains only the requested engagement's nodes and edges.

## REQ-GRAPH-006: The discovered-asset parent backbone is populated

The system shall populate the existing `discovered_asset.parent_id` link
(subdomain → parent domain) during discovery, to serve as the graph's structural
backbone.

Acceptance criteria:

- When a subdomain is discovered under an in-scope domain, its
  `discovered_asset.parent_id` references that domain's discovered asset when one
  exists; otherwise it remains null (no synthetic parent is invented).
- Populating `parent_id` changes no authorization outcome: the Scope Gateway does
  not read `parent_id`.

Security invariants:

- `parent_id` is structural metadata only; it must never be consulted by
  `authorize.py` or by scope resolution.
