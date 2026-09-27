-- DNS/CNAME inventory + dangling-DNS (subdomain-takeover) metadata.
--
-- Passive discovery metadata only. A `dns_record` describes how an in-scope
-- FQDN resolves (CNAME chain, terminal, hosting provider, dangling status). It
-- is inventory, NOT authorization: the CNAME target stored here is never a
-- scannable asset and never materialized for egress. The Scope Gateway remains
-- the sole gate for active scanning. See
-- docs/requirements/dns-cname-inventory-and-takeover.md (REQ-DNS-001..003).

CREATE TABLE IF NOT EXISTS dns_record (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    engagement_id      UUID NOT NULL REFERENCES engagement(id),
    asset_id           UUID REFERENCES discovered_asset(id),
    fqdn               TEXT NOT NULL,
    cname_chain        JSONB NOT NULL DEFAULT '[]'::jsonb,
    terminal_target    TEXT,
    terminal_ips       JSONB NOT NULL DEFAULT '[]'::jsonb,
    hosting_provider   TEXT,
    is_cdn             BOOLEAN NOT NULL DEFAULT false,
    is_saas            BOOLEAN NOT NULL DEFAULT false,
    is_idp             BOOLEAN NOT NULL DEFAULT false,
    is_shared_infra    BOOLEAN NOT NULL DEFAULT false,
    dns_status         TEXT NOT NULL DEFAULT 'resolved',
    takeover_suspected BOOLEAN NOT NULL DEFAULT false,
    resolved_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- One current row per (engagement, fqdn); the worker upserts on each pass.
CREATE UNIQUE INDEX IF NOT EXISTS uq_dns_record_engagement_fqdn
    ON dns_record(engagement_id, fqdn);

CREATE INDEX IF NOT EXISTS idx_dns_record_engagement
    ON dns_record(engagement_id);

CREATE INDEX IF NOT EXISTS idx_dns_record_takeover
    ON dns_record(engagement_id, takeover_suspected);
