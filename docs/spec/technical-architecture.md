# Technical Architecture

ASM Scanner with Agent capability. Engineering specification for direct
implementation.

Data models · security layer · evaluation & reporting layer

Version 2.1 · Developer-ready (bug-bounty integration)

> [!NOTE]
> **Relationship to document v1.0.** This document deepens the conceptual
> specification v1.0. It provides concrete schemas, algorithms, interface
> contracts, and state models. The technology stack should be read as a
> reference implementation — swappable as long as the contracts are
> honored. Legally relevant points are again marked ⚖.

## 1. System context & technology stack

### 1.1 Reference stack

| Layer | Technology (reference) | Rationale |
|---|---|---|
| API / orchestrator | Python 3.12 + FastAPI | async, typed, fast tool integration |
| Task queue | Celery + Redis | distributed, repeatable scan jobs |
| Primary DB | PostgreSQL 16 | relational + JSONB for flexible findings |
| Time series/diff | PostgreSQL (temporal tables) | history & diff without an extra system |
| Tool execution | MCP server (in-house) | controlled tool registry per engagement |
| LLM (reasoning) | Claude (tool use) | reliable structured tool use |
| Object storage | S3-compatible (MinIO) | raw output, report PDFs, evidence |
| Secrets | Vault / SOPS | scope signing key, API keys |

### 1.2 Process topology

Fig. 1: control and data flow. Every active tool call passes through the
Scope Gateway.

```
┌─────────────┐   signed scope        ┌──────────────────┐
│  Web UI /   │ ───────────────────▶  │  Orchestrator    │
│  API client │                       │  (FastAPI)       │
└─────────────┘                       └───────┬──────────┘
                                               │ enqueue
                                       ┌───────▼──────────┐
                                       │  Celery worker   │
                                       │  (scan engine)   │
                                       └───────┬──────────┘
                                Tool-call proposal
                 ┌─────────────────────────────┤
                 ▼                             ▼
       ┌──────────────────┐          ┌────────────────────┐
       │  Agent (LLM) │          │  SCOPE GATEWAY      │  ◀── control core
       │  proposes        │ ───────▶ │  checks + decides   │
       └──────────────────┘          └─────────┬──────────┘
                                                │ only if permitted
                                        ┌────────▼─────────┐
                                        │  MCP tool runner │
                                        │  (whitelist)     │
                                        └────────┬─────────┘
                                                 ▼
                                        ┌──────────────────┐
                                        │  Findings store  │──▶ Scoring ──▶ Report
                                        └──────────────────┘
```

## 2. Data model

Core entities in 3NF; findings as JSONB for flexibility. All IDs are UUIDv7
(time-sortable).

### 2.1 Engagement & scope (legal basis)

Listing 1: `engagement` — `source` determines the authorization source and
the rules.

```sql
-- The engagement is the legal basis for every active scan.
CREATE TABLE engagement (
  id            UUID PRIMARY KEY DEFAULT uuidv7(),
  customer_id   UUID REFERENCES customer(id),  -- NULL for lab/bug_bounty
  title         TEXT NOT NULL,
  status        engagement_status NOT NULL DEFAULT 'draft',
  source        engagement_source NOT NULL,    -- drives authorization source + rules

  -- Authorization source depends on `source`:
  --   customer     -> scope_doc_sha256 (signed engagement)
  --   bug_bounty   -> platform + program_ref (see bounty_program, 2.3)
  --   own_domain   -> proof of ownership suffices
  --   lab          -> none (isolated environment)
  scope_doc_sha256   CHAR(64),          -- mandatory only for source='customer'
  scope_signed_by    TEXT, scope_signed_at TIMESTAMPTZ,

  authorized_from    TIMESTAMPTZ NOT NULL,  -- test window start
  authorized_until   TIMESTAMPTZ NOT NULL,  -- test window end
  emergency_contact  TEXT,

  created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TYPE engagement_status AS ENUM (
  'draft','awaiting_signature','active','paused','completed','revoked');

-- Where does the authorization come from? Drives gateway behavior + report template.
CREATE TYPE engagement_source AS ENUM (
  'lab','own_domain','bug_bounty','customer');
```

> [!IMPORTANT]
> **⚖ CONSENT REQUIRED — engagement as a gate, per `source`.**
> `customer`: no transition to `active` without `scope_signed_at` + a valid
> test window. `bug_bounty`: no `active` without a linked, valid
> `bounty_program` (see 2.3) and an accepted platform policy. `own_domain`:
> only after verified proof of ownership. `lab`: only in an isolated,
> non-public environment. In every case, the gateway rejects active calls
> when `now()` falls outside `[authorized_from, authorized_until]` or the
> status ≠ `active`.

Listing 2: `scope_asset` + `tool_grant` — the machine-readable
authorization.

```sql
-- What MAY / MAY NOT be tested. rule='deny' ALWAYS takes precedence.
CREATE TABLE scope_asset (
  id            UUID PRIMARY KEY DEFAULT uuidv7(),
  engagement_id UUID NOT NULL REFERENCES engagement(id),
  rule          scope_rule NOT NULL DEFAULT 'allow',  -- allow|deny
  asset_type    asset_type NOT NULL,   -- domain|wildcard|ip|cidr|cloud_account
  value         TEXT NOT NULL,         -- 'api.customer.com' | '*.customer.com' | CIDR
  path_pattern  TEXT,                  -- optional: include/exclude '/admin/*'

  ownership_verified   BOOLEAN NOT NULL DEFAULT false,
  ownership_method     TEXT,           -- 'dns-txt-token'|'signed-list'|'bbp-scope'
  active_allowed       BOOLEAN NOT NULL DEFAULT false,  -- ⚖

  UNIQUE(engagement_id, rule, asset_type, value, path_pattern)
);
CREATE TYPE scope_rule AS ENUM ('allow','deny');

-- Which tool categories are authorized for this engagement.
CREATE TABLE tool_grant (
  engagement_id UUID NOT NULL REFERENCES engagement(id),
  tool_category tool_category NOT NULL,  -- recon|fingerprint|vuln|cred|exploit
  mode          scan_mode NOT NULL,      -- passive|active
  requires_manual_approval BOOLEAN NOT NULL DEFAULT true,  -- human in the loop
  PRIMARY KEY(engagement_id, tool_category, mode)
);
```

> [!IMPORTANT]
> **⚖ CONSENT REQUIRED — `active_allowed`, `tool_grant` & deny precedence.**
> `active_allowed=true` per asset AND a matching `tool_grant` with
> `mode='active'` are both mandatory preconditions for any active action.
> Missing either → the gateway blocks. Precedence rule: if a target matches
> a `deny` rule (including via wildcard/path), it is blocked — regardless of
> a matching `allow` rule. This models bug-bounty programs' out-of-scope
> lists, whose violation is a serious infraction.

### 2.3 Bug-bounty program (`source='bug_bounty'`)

For testing on platforms like Intigriti or HackerOne, the program policy is
represented in machine-readable form. It drives scope, rate limits, tool
authorization, and identification.

Listing 2b: `bounty_program` — program rules as enforceable configuration.

```sql
CREATE TABLE bounty_program (
  id            UUID PRIMARY KEY DEFAULT uuidv7(),
  engagement_id UUID NOT NULL REFERENCES engagement(id),
  platform      TEXT NOT NULL,        -- 'intigriti'|'hackerone'
  program_ref   TEXT NOT NULL,        -- program handle/URL

  -- Hard operating limits from the program rules:
  automation_allowed   BOOLEAN NOT NULL,  -- automated scanners allowed? ⚖
  ai_testing_allowed   BOOLEAN NOT NULL,  -- AI/agent testing allowed? ⚖
  max_rps       NUMERIC(5,2) NOT NULL DEFAULT 2.0,  -- requests/second
  max_concurrency INT NOT NULL DEFAULT 2,

  -- Optional identification so the blue team recognizes test traffic - not
  -- every program requires one (some identify researchers out-of-band, e.g.
  -- via a program-issued email alias, instead of a header):
  ident_header_name  TEXT NOT NULL DEFAULT 'X-Bug-Bounty',
  ident_header_value TEXT,             -- e.g. your own platform username
  ua_suffix     TEXT                  -- optionally appended to the User-Agent
);
```

> [!IMPORTANT]
> **⚖ CONSENT REQUIRED — the program policy is binding.**
> `automation_allowed` and `ai_testing_allowed` are NOT assumptions — they
> must be read from the concrete program rules. If `ai_testing_allowed =
> false`, the Agent may not run against this program (the gateway
> blocks the entire agent phase). When a program requires an identification
> header, it is enforced on EVERY active HTTP request when
> `source='bug_bounty'` (see 3.5); when a program has no header requirement,
> none is sent. A hit on an out-of-scope domain is a serious violation on
> these platforms — the deny precedence (2.1) protects against it.

### 2.4 Assets, services, findings

Listing 3: `discovered_asset` / `service` / `finding` — the results core.

```sql
-- Discovered (not necessarily authorized) assets.
CREATE TABLE discovered_asset (
  id            UUID PRIMARY KEY DEFAULT uuidv7(),
  engagement_id UUID NOT NULL REFERENCES engagement(id),
  parent_id     UUID REFERENCES discovered_asset(id),  -- discovery graph
  asset_type    asset_type NOT NULL,
  value         TEXT NOT NULL,
  in_scope      BOOLEAN NOT NULL,   -- computed by the gateway against scope_asset
  discovered_via TEXT NOT NULL,      -- 'crt.sh'|'dns'|'crawler'|...
  first_seen    TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_seen     TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE service (
  id            UUID PRIMARY KEY DEFAULT uuidv7(),
  asset_id      UUID NOT NULL REFERENCES discovered_asset(id),
  port          INT, protocol TEXT, transport TEXT,   -- tcp/udp
  product       TEXT, version TEXT,                   -- fingerprint
  tls_info      JSONB, http_headers JSONB, tech_stack JSONB
);

CREATE TABLE finding (
  id            UUID PRIMARY KEY DEFAULT uuidv7(),
  engagement_id UUID NOT NULL REFERENCES engagement(id),
  asset_id      UUID REFERENCES discovered_asset(id),
  service_id    UUID REFERENCES service(id),
  category      finding_category NOT NULL,  -- cve|misconfig|exposure|logic
  title         TEXT NOT NULL,
  cve_ids       TEXT[],
  cvss_base     NUMERIC(3,1), epss NUMERIC(5,4),
  confidence    finding_confidence NOT NULL, -- inferred|validated
  status        finding_status NOT NULL DEFAULT 'open',
  evidence      JSONB,   -- request/response snippet, tool-output ref
  raw_ref       TEXT,    -- S3 key of the raw output
  severity      severity_level,  -- computed, see Ch. 5
  risk_score    NUMERIC(5,2),    -- computed, see Ch. 5
  first_seen    TIMESTAMPTZ NOT NULL DEFAULT now(),
  fingerprint   TEXT NOT NULL   -- dedup hash (see 4.4)
);
```

> [!NOTE]
> **`confidence`: `inferred` vs. `validated`.** `inferred` = derived from a
> version/banner (passive, possibly a false positive). `validated` =
> confirmed via non-destructive active proof. Only `validated` findings
> with evidence carry full weight into customer reporting — this is the
> "no alarm without proof" principle.

## 3. Security layer: the Scope Gateway

The gateway is the only path to tool execution. It is deterministic (no
LLM) and stateless in itself — it decides purely from DB state and input.

### 3.1 Decision pipeline

Every tool call runs through a fixed chain. The first rejecting check ends
the chain (fail-closed).

Listing 4: `authorize()` — fail-closed, now with `source` and BBP checks.

```python
def authorize(call: ToolCall) -> Decision:
    eng = load_engagement(call.engagement_id)

    # 1. Engagement status & time window
    if eng.status != 'active':                 return DENY('engagement_not_active')
    if not (eng.authorized_from <= now() <= eng.authorized_until):
                                                 return DENY('outside_time_window')  # ⚖

    # 2. Scope: deny ALWAYS takes precedence over allow (wildcard + path respected)
    asset = resolve_target(call.target)
    if matches_deny_rule(asset, call.path, eng): return DENY('explicit_out_of_scope') # ⚖
    if not matches_allow_rule(asset, call.path, eng): return DENY('target_out_of_scope') # ⚖

    # 3. Source-specific rules (bug_bounty)
    if eng.source == 'bug_bounty':
        prog = bounty_program_for(eng)
        if call.is_automated and not prog.automation_allowed:
                                                 return DENY('automation_forbidden')  # ⚖
        if call.phase == 'agent' and not prog.ai_testing_allowed:
                                                 return DENY('ai_testing_forbidden')  # ⚖

    # 4. Mode check (passive always ok, active only with a grant)
    if call.mode == 'active':
        if not asset.active_allowed:           return DENY('active_not_allowed')   # ⚖
        grant = tool_grant_for(eng, call.category, 'active')
        if grant is None:                      return DENY('no_tool_grant')        # ⚖

    # 5. Tool whitelist (category + specific tool + arguments)
    if call.tool not in WHITELIST[call.category]: return DENY('tool_not_whitelisted')
    if not args_are_safe(call):                return DENY('unsafe_arguments')

    # 6. Rate limit / blast radius (for bug_bounty, from the program policy)
    limit = prog.max_rps if eng.source=='bug_bounty' else default_rps(eng)
    if exceeds_rate(eng, call, limit):         return DENY('rate_limited')  # ⚖

    # 7. Mandatory identification for bug_bounty (see 3.5) is injected at
    #    execution time; here we only check that it's configured.
    if eng.source == 'bug_bounty' and not ident_header_configured(eng):
                                                 return DENY('missing_ident_header')  # ⚖

    # 8. Human in the loop for anything beyond pure detection
    if grant and grant.requires_manual_approval:
        return PENDING_APPROVAL(create_approval_request(call))  # ⚖

    return ALLOW(reason='all_checks_passed')
```

> [!IMPORTANT]
> **⚖ CONSENT REQUIRED — control is NOT in the prompt.** No check in this
> chain depends on what the LLM "says" or how a prompt is phrased.
> Exclusively signed DB state decides. A model that claims to be authorized
> changes nothing — steps 1–3 remain authoritative.

### 3.2 `args_are_safe` — argument hardening

Even a whitelisted tool can become dangerous through its arguments. Examples
of enforced limits:

| Tool | Enforced limit | Blocked |
|---|---|---|
| nmap | only `-sV -sS`, ports from the grant; no `-sU` flood | `--script=exploit*`, `-sU` full-range |
| nuclei | only templates/ with `tag=safe` | `intrusive`/`dos` tags |
| http-probe | methods GET/HEAD/OPTIONS | PUT/DELETE without a grant |
| cred-check | only the default-credential list, max 3 attempts | brute-force lists |

### 3.3 Approval workflow (state model)

Listing 5: human in the loop as a one-time, expiring authorization.

```
approval_request:  requested ──▶ approved ──▶ consumed
                        │
                        └──────▶ rejected / expired

-- Approvals are one-time (consumed) and time-bound (expires_at).
CREATE TABLE approval_request (
  id UUID PRIMARY KEY DEFAULT uuidv7(),
  engagement_id UUID NOT NULL,
  tool_call     JSONB NOT NULL,     -- the exact call incl. args
  state         TEXT NOT NULL DEFAULT 'requested',
  approved_by   TEXT, approved_at TIMESTAMPTZ,
  expires_at    TIMESTAMPTZ NOT NULL
);
```

### 3.4 Audit trail (append-only)

Listing 6: `audit_log` — hash-chained, append-only, no `UPDATE`/`DELETE`.

```sql
CREATE TABLE audit_log (
  id UUID PRIMARY KEY DEFAULT uuidv7(),
  engagement_id UUID NOT NULL,
  actor         TEXT NOT NULL,    -- 'gateway'|'operator:<name>'|'agent'
  action        TEXT NOT NULL,    -- 'tool_call'|'decision'|'approval'|...
  decision      TEXT,             -- ALLOW|DENY|PENDING
  reason        TEXT,
  payload       JSONB NOT NULL,   -- full call + result ref
  prev_hash     CHAR(64),         -- hash chain for tamper protection
  row_hash      CHAR(64) NOT NULL,
  ts            TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- row_hash = sha256(prev_hash || canonical_json(row)) -> tamper-evident
```

> [!NOTE]
> **Why a hash chain.** The chained hash makes after-the-fact modification
> detectable. This is your proof to the customer, the bug-bounty operator,
> and the professional-liability insurer that every action stayed in scope
> and exactly when it was authorized.

### 3.5 Identification header & `source`-driven behavior

The MCP runner injects the configured identification into EVERY outbound
HTTP request when `source='bug_bounty'`, before the request leaves the
system. This is not the model's option — it's enforced in the runner.

Listing 6b: enforced test-traffic identification for bug-bounty targets.

```python
def outbound_http(req, eng):
    if eng.source == 'bug_bounty':
        prog = bounty_program_for(eng)
        req.headers[prog.ident_header_name] = prog.ident_header_value  # ⚖ mandatory
        if prog.ua_suffix:
            req.headers['User-Agent'] += f' {prog.ua_suffix}'
    return send(req)
```

`source` also centrally drives several other behaviors:

| `source` | Authorization source | Special case in gateway/runner | Report template |
|---|---|---|---|
| `lab` | isolated environment | no egress restriction needed; all tools free | internal/none |
| `own_domain` | proof of ownership | full active testing on your own assets | internal |
| `bug_bounty` | program policy (platform + program reference) | deny precedence, `max_rps`, AI/automation gate, optional ident header | bounty submission |
| `customer` | signed engagement (`scope_doc_sha256`) | scope signature + approval workflow | customer PDF |

> [!NOTE]
> **Two business logics, cleanly separated.** `bug_bounty` serves to harden
> the engine and findings quality against real targets within a legal
> framework — the audience is the program operator. `customer` is the
> actual managed-service business — the audience is the paying customer,
> on their own infrastructure. The same tool, but `source` deterministically
> separates the authorization source, the rules, and the report recipient.

## 4. Scan engine & Agent

### 4.1 Phase pipeline as a state machine

Listing 7: `scan_run` — one phase per step, resumable.

```
engagement.active
  └─ scan_run (id, engagement_id, started_at, phase, state)
        phase: discovery ─▶ fingerprint ─▶ correlate ─▶ agent ─▶ validate ─▶ score ─▶ report
        state: running | waiting_approval | done | failed | aborted

-- Each phase reads the previous phase's results, writes new findings.
-- Transitioning to active phases (active fingerprint, validate) only if
-- the gateway approves the respective call; otherwise waiting_approval.
```

### 4.2 Agent loop (reason–act–observe)

Listing 8: the agent proposes, the gateway decides, the runner executes.

```python
def agent_loop(run, budget):
    context = load_findings_and_services(run)   # what do we already know?
    while budget.remaining() and not context.exhausted:
        # 1. The LLM proposes ONE next check as a structured object
        proposal = llm.propose_next_check(context)   # -> ToolCall (JSON)
        # 2. NEVER execute directly -> always through the gateway
        decision = gateway.authorize(proposal)
        if decision.is_pending:  wait_for_operator(decision)   # ⚖ human in the loop
        if not decision.allowed: context.record_denied(proposal); continue
        # 3. Execute in the MCP runner, observe the result
        result = mcp.run(proposal)
        # 4. Feed the observation back into the model
        context.observe(proposal, result)
        if result.confirms_vuln:
            create_finding(confidence='validated', evidence=result.evidence)
```

> [!NOTE]
> **Budget ceiling.** `budget` caps iterations/cost per run (e.g. max tool
> calls, max LLM tokens, wall-clock time). This prevents infinite loops and
> caps the cost per customer — important in a side-business, one-person
> operation.

> [!IMPORTANT]
> **⚖ CONSENT REQUIRED — the Agent under `bug_bounty`.** The entire
> agent phase is blocked by the gateway if the linked `bounty_program` has
> `ai_testing_allowed=false`. The agent also generates requests on its own —
> so under `bug_bounty` the program policy's `max_rps` limit applies per
> iteration, and every request carries the mandatory ident header (3.5).

### 4.3 MCP tool runner

- A tool set is instantiated per engagement: only the categories authorized
  in `tool_grant` are registered as MCP functions. The model never sees the
  other tools.
- Every tool wrapper normalizes output into a uniform `ToolResult` (stdout
  ref in S3, parsed findings, evidence).
- Timeouts, retry with backoff, and error classification (recoverable vs.
  fatal) per wrapper.

### 4.4 Deduplication & diff

Listing 9: fingerprint + diff logic for trend reporting.

```python
# Stable fingerprint per finding -> dedup across tools & runs
fingerprint = sha256(f"{asset.value}|{service.port}|{category}|{norm_title}|{cve_ids}")

# Diff against the last run:
#   NEW      = fingerprint not present in the previous run
#   RESOLVED = present in the previous run, no longer found now
#   PERSIST  = present in both
```

## 5. Evaluation layer: classification, assessment, scoring

This layer translates raw findings into prioritized, business-relevant
statements — the actual product value.

### 5.1 Finding classification

| `category` | Source | Example | Default confidence |
|---|---|---|---|
| `cve` | version→NVD matching | outdated OpenSSL | `inferred` |
| `misconfig` | rule checks | missing security headers | `validated` |
| `exposure` | discovery/fingerprint | open `.git`, admin panel | `validated` |
| `logic` | Agent | IDOR, broken auth | `validated` (with proof) |

### 5.2 Risk-score model

The risk score prioritizes action — not just severity. Formula (0–100),
weighted factors:

Listing 10: risk score — EPSS-dominated, KEV as a hard override.

```python
risk_score = 100 * normalize(
      w_epss     * epss                     # exploitation likelihood (0..1)
    + w_cvss     * (cvss_base / 10)          # technical severity
    + w_exposure * exposure_factor           # 1.0 public | 0.5 auth | 0.2 internal
    + w_context  * business_factor           # customer weighting of the asset
    + w_valid    * (confidence=='validated') # proof raises priority
)

# Reference weights (sum to 1.0):
w_epss=0.35  w_cvss=0.20  w_exposure=0.20  w_context=0.15  w_valid=0.10

# KEV override: if the CVE is in CISA KEV (known exploited),
# severity is raised to at least 'high', regardless of the score.
```

### 5.3 Severity mapping

| `severity` | `risk_score` | SLA recommendation (report) | Color |
|---|---|---|---|
| critical | ≥ 85 or KEV | immediate / < 24 h | red |
| high | 70–84 | < 7 days | orange |
| medium | 40–69 | < 30 days | yellow |
| low | 15–39 | planned | blue |
| info | < 15 | for awareness | grey |

> [!NOTE]
> **EPSS + KEV instead of raw CVSS.** CVSS measures only severity, not
> likelihood. A CVSS 9.8 with no public exploit is often less urgent than a
> CVSS 7 on the CISA KEV list. That's why EPSS dominates and KEV forces a
> hard raise — this reduces the count of "critical" findings to the ones
> that actually count.

### 5.4 False-positive reduction

- `inferred` findings are checked before reporting via a non-destructive
  validation step (where `active_allowed`); confirmed ones are promoted to
  `validated`, unconfirmed ones are reported separately and weighted lower.
- Cross-tool confirmation: an identical fingerprint from two sources raises
  confidence.
- A per-engagement suppression list (operator-maintained accepted risks /
  known false positives).

## 6. Reporting layer & presentation

Two output forms from the same data: an interactive dashboard (ongoing) and
a PDF report (periodic, the customer product).

### 6.1 Report structure (generated)

| Section | Content | Audience |
|---|---|---|
| Executive summary | risk light, trend vs. previous run, top-3 actions in plain language | SMB leadership |
| Risk overview | findings by severity, NEW/RESOLVED/PERSIST diff | IT owners |
| Detailed findings | per finding: proof, impact, concrete remediation, references | technicians/service providers |
| Asset inventory | discovered assets, shadow-IT hints, certificate expiries | IT owners |
| Methodology & scope | what was tested, time window, exclusions, authorization reference | compliance / proof |

> [!IMPORTANT]
> **⚖ CONSENT REQUIRED — methodology & scope in the report.** Every report
> documents the scope, time window, exclusions, and the authorization
> reference (`scope_doc_sha256`). This closes the loop with the audit trail
> and proves to the customer and the insurer that only authorized testing
> took place.

### 6.2 Plain-language translation (LLM-assisted, controlled)

- Per finding, a template + LLM generate an understandable explanation:
  what is the risk? What could happen? What needs to be done? — for
  non-security readers.
- Raw technical data (requests, tool output) stays in the appendix/evidence,
  not in the main text.
- Remediation is concrete and actionable (config example, upgrade path), not
  generic.

### 6.3 Dashboard API (excerpt)

Listing 11: the REST contract of the evaluation & control layer.

```
GET  /engagements/{id}/summary
  -> { risk_light, counts_by_severity, trend, top_actions[] }
GET  /engagements/{id}/findings?severity=high&status=open
  -> [ { id, title, severity, risk_score, confidence, asset, evidence_ref } ]
GET  /engagements/{id}/assets
  -> discovery graph (nodes/edges)
GET  /engagements/{id}/diff/{run}
  -> { new[], resolved[], persist[] }
POST /engagements/{id}/report
  -> generates a PDF (async), returns job_id
GET  /approvals?state=requested
  -> pending approvals (operator queue) ⚖
POST /approvals/{id}/approve
  -> authorizes exactly one tool call ⚖
```

### 6.4 Data protection in the evaluation

> [!IMPORTANT]
> **⚖ CONSENT REQUIRED — personal data.** Discovery can capture personal
> data (e.g. exposed email addresses, names in certificates). This must be
> marked as such, stored with restricted access, and shown in the report
> only to the extent needed for the risk assessment. Clarify a deletion
> policy and data-processing terms with the customer.

## 7. Implementation order (MVP → expansion)

Interlocked with the maturity path of the authorization source (`source`):
lab → own_domain → bug_bounty → customer. Active capabilities are proven
first where the legal risk is lowest.

| Stage | Scope | `source` / legal status |
|---|---|---|
| M1 | `engagement`/scope model incl. `source` & deny precedence, gateway (Ch. 3), audit log, passive discovery + fingerprint | `lab` — isolated |
| M2 | CVE correlation, scoring (Ch. 5), PDF report, dashboard | `own_domain` — passive |
| M3 | active fingerprinting + safe active checks, approval workflow, rate limiting | `own_domain` — ⚖ active |
| M4 | `bounty_program` model (2.3), ident header (3.5), deny precedence & policy gates verified | `bug_bounty` — ⚖ policy binding |
| M5 | Agent (4.2) with gateway coupling, validated logic findings | `bug_bounty` (only if permitted) — ⚖ |
| M6 | scheduler, diff trend, multi-customer, suppression lists, customer reporting | `customer` — ⚖ engagement mandatory |

> [!NOTE]
> **The ordering logic.** The maturity path runs parallel to the `source`
> model: build in the lab first, then verify on your own domain, then
> harden on authorized bug-bounty scopes within the program's terms — and
> only after that, on a paying customer. The security layer (gateway, deny
> precedence, ident header, audit trail) is in place at every stage before
> that stage's new active capability. The Agent (M5) deliberately comes
> only after the bug-bounty guardrails (M4) are demonstrably working.

---

**Note:** Technical specification, not legal advice. Secure the criminal-law
and contractual assessment (computer-misuse, data-protection,
secondary-employment law, and related law in your jurisdiction) with
qualified legal counsel.
