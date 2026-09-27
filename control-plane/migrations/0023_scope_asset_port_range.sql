-- REQ-PORTSCOPE-001: per-target TCP port scoping. NULL (the default, and the
-- value every existing row gets) means "no override, inherit the
-- engagement's own tcp_port_from/to ceiling" - a plain ADD COLUMN is a
-- zero-behavior-change backfill on its own. When set, both must be set
-- together and from <= to; the "subset of the engagement ceiling" property
-- is enforced at write time (control-plane/app/api/engagements.py) and
-- re-derived fresh at every enforcement point (never trusted from this
-- column alone), so a ceiling that narrows later still applies immediately.

ALTER TABLE scope_asset
  ADD COLUMN IF NOT EXISTS port_from INTEGER,
  ADD COLUMN IF NOT EXISTS port_to INTEGER;

ALTER TABLE scope_asset
  ADD CONSTRAINT scope_asset_port_range_pair_chk
    CHECK ((port_from IS NULL) = (port_to IS NULL)),
  ADD CONSTRAINT scope_asset_port_range_order_chk
    CHECK (port_from IS NULL OR port_from <= port_to),
  ADD CONSTRAINT scope_asset_port_range_bounds_chk
    CHECK (port_from IS NULL OR (port_from BETWEEN 1 AND 65535 AND port_to BETWEEN 1 AND 65535));
