---
title: Attack-surface graph and dashboard verification
status: ready
risk: R3
owner: security-engineering
---

# Attack-Surface Graph & Dashboard Verification

Verifies [`../requirements/attack-surface-graph.md`](../requirements/attack-surface-graph.md).
R3: a negative scope-safety test is required (TC-GRAPH-002).

## TC-GRAPH-001: The builder materializes a typed, idempotent graph

Requirements:

- REQ-GRAPH-001

Automated tests:

- `control-plane/tests/integration/test_surface_graph.py`

Objective:

Verify that materializing an engagement produces every documented node type and
topology edge, and that re-running on unchanged data yields the identical set
with no duplicates.

Expected results:

- All node types (`engagement`, `domain`, `subdomain`, `ip`, `service`,
  `technology`, `cve`, `finding`, `dns_artifact`) are present.
- All edge types (`HAS_SUBDOMAIN`, `RESOLVES_TO`, `HAS_SERVICE`,
  `RUNS_TECHNOLOGY`, `HAS_CVE`, `FINDING_AT`, `SHARES_INFRA`) are present.
- A second `materialize_graph` returns identical node/edge counts, and the
  persisted row counts match.

## TC-GRAPH-002: The graph never widens scope (negative)

Requirements:

- REQ-GRAPH-002

Automated tests:

- `control-plane/tests/integration/test_surface_graph.py`

Objective:

Verify the R3 invariant: the graph is derived metadata. Only in-scope
discovered assets are `scannable`; value-derived nodes are context; and
materialization neither creates a `discovered_asset` nor changes an
authorization outcome.

Expected results:

- `scannable` is true only for in-scope domain/subdomain/ip nodes; a discovered
  but out-of-scope name is not scannable.
- Every `ip`/`technology`/`cve`/`finding`/`dns_artifact` node is non-scannable.
- Materializing creates no new `discovered_asset` row.
- An out-of-scope target (a shared IP) is `DENY` before and after
  materialization — the graph never flips the decision.

## TC-GRAPH-003: The agent receives relationship context

Requirements:

- REQ-GRAPH-003

Automated tests:

- `worker/tests/test_agent_graph_context.py`

Objective:

Verify the Vector Agent's initial context renders cross-host relationships
(shared infrastructure, technology fan-out, technology→CVE) as read-only context
framed as non-scope-widening, and falls back cleanly when no graph is present.

Expected results:

- Shared-IP groups, multi-service technologies, and tech→CVE links appear in the
  rendered block.
- The block states it does not change scope.
- With no graph (empty or absent), no relationship block is emitted and the
  context still lists the in-scope hosts without error.

## TC-GRAPH-004: The dashboard renders a scoped, read-only graph

Requirements:

- REQ-GRAPH-004
- REQ-GRAPH-005

Automated tests:

- `frontend/tests/surface_graph_requirements.test.mjs`
- `control-plane/tests/integration/test_surface_graph.py`

Objective:

Verify the operator console mounts an attack-surface graph section backed by the
owner-scoped `GET /engagements/{id}/surface-graph` endpoint, distinguishes node
types, marks non-scannable nodes visually, and reveals node details on click;
and that the endpoint is owner-scoped.

Expected results:

- The client exposes `surfaceGraph(id)` and the graph types; `EngagementDetail`
  mounts `<SurfaceGraph>`.
- The component colours node types, draws non-scannable nodes distinct (dashed),
  and opens a detail panel on selection.
- The owner receives nodes+edges from the endpoint; a non-owner receives 404
  (no cross-engagement disclosure).

## TC-GRAPH-006: The subdomain→domain backbone is populated

Requirements:

- REQ-GRAPH-006

Automated tests:

- `worker/tests/test_discovery_parent_backbone.py`
- `control-plane/tests/integration/test_surface_graph.py`

Objective:

Verify discovery links a subdomain to the closest already-registered ancestor
domain (never inventing a parent, never the bare TLD), and that the builder turns
that `parent_id` into a `HAS_SUBDOMAIN` edge.

Expected results:

- `_closest_parent_value` prefers the nearest registered ancestor, falls back to
  the apex, returns `None` with no ancestor, and never returns a TLD.
- The builder emits `HAS_SUBDOMAIN` from a parent domain to its subdomain when
  `parent_id` is set.
