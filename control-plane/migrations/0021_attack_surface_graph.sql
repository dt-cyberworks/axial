-- Attack-surface graph (REQ-GRAPH-001..006).
--
-- A typed, relationship-native view of one engagement's discovered surface,
-- MATERIALIZED from data the deterministic scan phases already collect
-- (discovered_asset(+parent_id), service, dns_record, resolved_host, finding).
-- Deliberately graph-in-Postgres, not a separate graph database: at ASM scale
-- (dozens-low-hundreds of nodes per engagement) a typed node/edge model in the
-- existing store gives the relationship value with no second stateful service
-- and no LLM-authored-query surface.
--
-- These tables are DERIVED METADATA, exactly like dns_record: they may describe
-- relationships that include out-of-scope nodes (external CNAME targets, shared
-- IPs, technology/CVE nodes), but they never widen what is actively scanned.
-- `scannable` is set solely from discovered_asset.in_scope; the Scope Gateway
-- never reads these tables. See
-- docs/requirements/attack-surface-graph.md (REQ-GRAPH-001..006).

CREATE TABLE IF NOT EXISTS surface_node (
    id             UUID PRIMARY KEY DEFAULT uuidv7(),
    engagement_id  UUID NOT NULL REFERENCES engagement(id),
    node_type      TEXT NOT NULL,
    ref_table      TEXT NOT NULL,
    ref_id         TEXT NOT NULL,
    label          TEXT NOT NULL,
    scannable      BOOLEAN NOT NULL DEFAULT false,
    attrs          JSONB NOT NULL DEFAULT '{}'::jsonb,
    first_seen     TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (engagement_id, node_type, ref_table, ref_id)
);

CREATE INDEX IF NOT EXISTS idx_surface_node_engagement ON surface_node (engagement_id);

CREATE TABLE IF NOT EXISTS surface_edge (
    id             UUID PRIMARY KEY DEFAULT uuidv7(),
    engagement_id  UUID NOT NULL REFERENCES engagement(id),
    src_node_id    UUID NOT NULL REFERENCES surface_node(id) ON DELETE CASCADE,
    dst_node_id    UUID NOT NULL REFERENCES surface_node(id) ON DELETE CASCADE,
    edge_type      TEXT NOT NULL,
    attrs          JSONB NOT NULL DEFAULT '{}'::jsonb,
    UNIQUE (engagement_id, src_node_id, dst_node_id, edge_type)
);

CREATE INDEX IF NOT EXISTS idx_surface_edge_engagement ON surface_edge (engagement_id);
