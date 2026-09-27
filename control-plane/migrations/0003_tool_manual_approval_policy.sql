-- Per-tool manual approval policy layered on top of category-level tool grants.
-- Category grants still decide whether a class of tools is allowed; this table
-- lets an operator require one-time approval for selected concrete tools.

CREATE TABLE IF NOT EXISTS tool_approval_policy (
  engagement_id UUID NOT NULL REFERENCES engagement(id),
  tool_name TEXT NOT NULL,
  requires_manual_approval BOOLEAN NOT NULL DEFAULT true,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (engagement_id, tool_name)
);

CREATE INDEX IF NOT EXISTS idx_tool_approval_policy_engagement
  ON tool_approval_policy(engagement_id);
