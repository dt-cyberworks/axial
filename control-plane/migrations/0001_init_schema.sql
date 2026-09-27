-- ASM-Scanner: initiales Datenmodell
-- Quelle: Documentation/ASM_Scanner_Technische_Architektur.docx, Kap. 2
-- Alle IDs sind UUIDv7 (zeitsortierbar) -> benoetigt Extension oder App-seitige Erzeugung.

CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- Minimaler UUIDv7-Ersatz falls keine native Funktion verfuegbar ist (PG < 18).
-- App-Layer (SQLAlchemy models) erzeugt UUIDv7 ohnehin selbst; das hier ist nur
-- ein Fallback-Default fuer direktes SQL/psql-Arbeiten.
CREATE OR REPLACE FUNCTION uuidv7() RETURNS uuid AS $$
  SELECT encode(
    set_bit(
      set_bit(
        overlay(uuid_send(gen_random_uuid()) placing
          substring(int8send(floor(extract(epoch from clock_timestamp()) * 1000)::bigint) from 3)
          from 1 for 6),
        52, 1),
      53, 1),
    'hex')::uuid;
$$ LANGUAGE sql VOLATILE;

-- =========================================================================
-- 2.1 Auftrag & Scope (Rechtsgrundlage)
-- =========================================================================

CREATE TYPE engagement_status AS ENUM (
  'draft', 'awaiting_signature', 'active', 'paused', 'completed', 'revoked');

-- source steuert Erlaubnisquelle + Regelwerk (lab -> customer, s. Roadmap Kap. 7)
CREATE TYPE engagement_source AS ENUM (
  'lab', 'own_domain', 'bug_bounty', 'customer');

CREATE TABLE customer (
  id            UUID PRIMARY KEY DEFAULT uuidv7(),
  name          TEXT NOT NULL,
  contact_email TEXT,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Der Auftrag ist die Rechtsgrundlage jedes aktiven Scans.
CREATE TABLE engagement (
  id                UUID PRIMARY KEY DEFAULT uuidv7(),
  customer_id       UUID REFERENCES customer(id),  -- NULL bei lab/bug_bounty
  title             TEXT NOT NULL,
  status            engagement_status NOT NULL DEFAULT 'draft',
  source            engagement_source NOT NULL,
  -- Erlaubnisquelle je nach source:
  --   customer     -> scope_doc_sha256 (signierter Auftrag)
  --   bug_bounty   -> program_ref + platform_policy_sha256 (s. bounty_program)
  --   own_domain   -> ownership-Nachweis genuegt
  --   lab          -> keine (isolierte Umgebung)
  scope_doc_sha256  CHAR(64),
  scope_signed_by   TEXT,
  scope_signed_at   TIMESTAMPTZ,
  authorized_from   TIMESTAMPTZ NOT NULL,
  authorized_until  TIMESTAMPTZ NOT NULL,
  emergency_contact TEXT,
  -- Erlaubt autonome KI-Aktionen (Agent, phase='agent') fuer DIESEN Auftrag.
  -- Gilt fuer ALLE sources, unabhaengig von bounty_program.ai_testing_allowed
  -- (das nur zusaetzlich bei source='bug_bounty' die Programm-Policy spiegelt).
  -- Default false: der Agent ist opt-in, nie versehentlich scharf.
  ai_testing_allowed BOOLEAN NOT NULL DEFAULT false,
  created_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TYPE scope_rule AS ENUM ('allow', 'deny');
CREATE TYPE asset_type AS ENUM ('domain', 'wildcard', 'ip', 'cidr', 'cloud_account');

-- Was getestet werden DARF/NICHT DARF. rule='deny' hat IMMER Vorrang.
CREATE TABLE scope_asset (
  id                  UUID PRIMARY KEY DEFAULT uuidv7(),
  engagement_id       UUID NOT NULL REFERENCES engagement(id),
  rule                scope_rule NOT NULL DEFAULT 'allow',
  asset_type          asset_type NOT NULL,
  value               TEXT NOT NULL,          -- 'api.kunde.de' | '*.kunde.de' | CIDR
  path_pattern        TEXT,                    -- optional: '/admin/*' aus/einschliessen
  ownership_verified  BOOLEAN NOT NULL DEFAULT false,
  ownership_method    TEXT,                    -- 'dns-txt-token'|'signed-list'|'bbp-scope'
  active_allowed      BOOLEAN NOT NULL DEFAULT false,
  UNIQUE (engagement_id, rule, asset_type, value, path_pattern)
);

CREATE TYPE tool_category AS ENUM ('recon', 'fingerprint', 'vuln', 'cred', 'exploit');
CREATE TYPE scan_mode AS ENUM ('passive', 'active');

-- Welche Tool-Kategorien fuer diesen Auftrag erlaubt sind.
CREATE TABLE tool_grant (
  engagement_id            UUID NOT NULL REFERENCES engagement(id),
  tool_category             tool_category NOT NULL,
  mode                      scan_mode NOT NULL,
  requires_manual_approval BOOLEAN NOT NULL DEFAULT true,
  PRIMARY KEY (engagement_id, tool_category, mode)
);

-- =========================================================================
-- 2.3 Bug-Bounty-Programm (source='bug_bounty')
-- =========================================================================

CREATE TABLE bounty_program (
  id                  UUID PRIMARY KEY DEFAULT uuidv7(),
  engagement_id       UUID NOT NULL REFERENCES engagement(id),
  platform            TEXT NOT NULL,           -- 'intigriti'|'hackerone'
  program_ref         TEXT NOT NULL,
  policy_sha256       CHAR(64) NOT NULL,
  automation_allowed  BOOLEAN NOT NULL,
  ai_testing_allowed  BOOLEAN NOT NULL,
  max_rps             NUMERIC(5,2) NOT NULL DEFAULT 2.0,
  max_concurrency     INT NOT NULL DEFAULT 2,
  ident_header_name   TEXT NOT NULL DEFAULT 'X-Bug-Bounty',
  ident_header_value  TEXT NOT NULL,
  ua_suffix           TEXT
);

-- =========================================================================
-- 2.4 Assets, Services, Findings
-- =========================================================================

CREATE TABLE discovered_asset (
  id             UUID PRIMARY KEY DEFAULT uuidv7(),
  engagement_id  UUID NOT NULL REFERENCES engagement(id),
  parent_id      UUID REFERENCES discovered_asset(id),
  asset_type     asset_type NOT NULL,
  value          TEXT NOT NULL,
  in_scope       BOOLEAN NOT NULL,
  discovered_via TEXT NOT NULL,               -- 'crt.sh'|'dns'|'crawler'|...
  first_seen     TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_seen      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE service (
  id           UUID PRIMARY KEY DEFAULT uuidv7(),
  asset_id     UUID NOT NULL REFERENCES discovered_asset(id),
  port         INT,
  protocol     TEXT,
  transport    TEXT,                          -- tcp/udp
  product      TEXT,
  version      TEXT,
  tls_info     JSONB,
  http_headers JSONB,
  tech_stack   JSONB
);

CREATE TYPE finding_category AS ENUM ('cve', 'misconfig', 'exposure', 'logic');
CREATE TYPE finding_confidence AS ENUM ('inferred', 'validated');
CREATE TYPE finding_status AS ENUM ('open', 'accepted_risk', 'resolved', 'false_positive');
CREATE TYPE severity_level AS ENUM ('info', 'low', 'medium', 'high', 'critical');

CREATE TABLE finding (
  id            UUID PRIMARY KEY DEFAULT uuidv7(),
  engagement_id UUID NOT NULL REFERENCES engagement(id),
  asset_id      UUID REFERENCES discovered_asset(id),
  service_id    UUID REFERENCES service(id),
  category      finding_category NOT NULL,
  title         TEXT NOT NULL,
  cve_ids       TEXT[],
  cvss_base     NUMERIC(3,1),
  epss          NUMERIC(5,4),
  confidence    finding_confidence NOT NULL,
  status        finding_status NOT NULL DEFAULT 'open',
  evidence      JSONB,
  raw_ref       TEXT,                          -- S3-Key der Rohausgabe
  -- Persistiert, damit ein Rescore (Kap. 5.2) den KEV-Override nicht verliert.
  is_kev        BOOLEAN NOT NULL DEFAULT false,
  severity      severity_level,
  risk_score    NUMERIC(5,2),
  first_seen    TIMESTAMPTZ NOT NULL DEFAULT now(),
  fingerprint   TEXT NOT NULL
);

-- =========================================================================
-- 3.3 Approval-Workflow
-- =========================================================================

CREATE TABLE approval_request (
  id            UUID PRIMARY KEY DEFAULT uuidv7(),
  engagement_id UUID NOT NULL REFERENCES engagement(id),
  tool_call     JSONB NOT NULL,
  state         TEXT NOT NULL DEFAULT 'requested',  -- requested|approved|rejected|expired|consumed
  approved_by   TEXT,
  approved_at   TIMESTAMPTZ,
  expires_at    TIMESTAMPTZ NOT NULL
);

-- =========================================================================
-- 3.4 Audit-Trail (append-only, Hash-Chain)
-- =========================================================================

CREATE TABLE audit_log (
  id            UUID PRIMARY KEY DEFAULT uuidv7(),
  engagement_id UUID NOT NULL,
  actor         TEXT NOT NULL,     -- 'gateway'|'operator:<name>'|'agent'
  action        TEXT NOT NULL,     -- 'tool_call'|'decision'|'approval'|...
  decision      TEXT,              -- ALLOW|DENY|PENDING
  reason        TEXT,
  payload       JSONB NOT NULL,
  prev_hash     CHAR(64),
  row_hash      CHAR(64) NOT NULL,
  ts            TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- row_hash = sha256(prev_hash || canonical_json(row)) -- siehe app/gateway/audit.py
-- Kein UPDATE/DELETE auf audit_log: nur die control-plane-DB-Rolle darf INSERT.
REVOKE UPDATE, DELETE ON audit_log FROM PUBLIC;

-- =========================================================================
-- 4.1 Scan-Phasen-Zustandsmaschine
-- =========================================================================

CREATE TYPE scan_phase AS ENUM (
  'discovery', 'fingerprint', 'correlate', 'agent', 'validate', 'score', 'report');
CREATE TYPE scan_state AS ENUM (
  'running', 'waiting_approval', 'done', 'failed', 'aborted');

CREATE TABLE scan_run (
  id            UUID PRIMARY KEY DEFAULT uuidv7(),
  engagement_id UUID NOT NULL REFERENCES engagement(id),
  started_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  finished_at   TIMESTAMPTZ,
  phase         scan_phase NOT NULL DEFAULT 'discovery',
  state         scan_state NOT NULL DEFAULT 'running',
  budget_tool_calls_max  INT NOT NULL DEFAULT 200,
  budget_tool_calls_used INT NOT NULL DEFAULT 0
);

-- =========================================================================
-- Auditierte DNS-Materialisierung (raw egress fuer nmap/Raw-Scans)
-- =========================================================================
-- Domain-/Wildcard-Scope kann keine K8s-NetworkPolicy direkt erlauben (die
-- kennt nur IP/CIDR). Vor einem nmap-Job werden die freigegebenen Namen daher
-- zu IPs aufgeloest und HIER auditiert festgehalten. Nur die control-plane
-- (Trust-Anchor) schreibt diese Tabelle; die Aufloesung + Audit + Speicherung
-- sind atomar. deny-Vorrang wird nach der Aufloesung auf IP-Ebene angewandt.
CREATE TABLE resolved_host (
  id             UUID PRIMARY KEY DEFAULT uuidv7(),
  engagement_id  UUID NOT NULL REFERENCES engagement(id),
  scope_asset_id UUID REFERENCES scope_asset(id),  -- freigebende allow-Regel (NULL bei discovered)
  hostname       TEXT NOT NULL,
  ip_address     TEXT NOT NULL,          -- aufgeloeste A/AAAA-Adresse
  resolved_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (engagement_id, hostname, ip_address)
);

-- Betriebs-Einstellungen, zur Laufzeit (auch ueber die GUI) aenderbar.
-- Generisches Key-Value (JSONB); aktuell: 'llm_config' (OpenAI-kompatibler
-- Agent-Provider). api_key im Klartext nur im M1-Skeleton - Produktion:
-- Vault/SOPS.
CREATE TABLE app_setting (
  key        TEXT PRIMARY KEY,
  value      JSONB NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- =========================================================================
-- Indizes fuer die haeufigsten Zugriffspfade
-- =========================================================================

CREATE INDEX idx_scope_asset_engagement ON scope_asset(engagement_id);
CREATE INDEX idx_discovered_asset_engagement ON discovered_asset(engagement_id);
CREATE INDEX idx_finding_engagement ON finding(engagement_id);
CREATE INDEX idx_finding_fingerprint ON finding(engagement_id, fingerprint);
CREATE INDEX idx_audit_log_engagement ON audit_log(engagement_id, ts);
CREATE INDEX idx_scan_run_engagement ON scan_run(engagement_id, started_at DESC);
CREATE INDEX idx_resolved_host_engagement ON resolved_host(engagement_id);
