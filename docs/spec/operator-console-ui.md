# Operator Console

UI/UX specification of the web interface. Create an engagement · follow a
scan live · present results.

Operator view first · customer view as a read-only derivation

Version 1.0 · Companion document to Architecture v2.1

> [!NOTE]
> **Baseline assumptions of this specification.** The primary user is the
> operator (the internal operator console). A separate customer view comes
> later as a reduced, read-only derivation of the same data (Ch. 7).
> Authorization model: authorize up front in the scope, then run
> autonomously up to that boundary. The live view is predominantly
> observation; an approval queue appears only when
> `requires_manual_approval=true` applies, or the agent hits a scope
> boundary.

## 1. Structure & navigation

The console has four main areas that follow an engagement's lifecycle:
create → authorize → track → evaluate.

| Area | Purpose | Data source |
|---|---|---|
| Dashboard | overview of all engagements, status, latest runs | `engagement`, `scan_run` |
| Create engagement | wizard: scope, assets, authorized steps | `engagement`, `scope_asset`, `tool_grant` |
| Live scan | progress, current step, approval queue | `scan_run`, `audit_log`, `approval_request` |
| Results | findings, prioritization, report export | `finding`, diff |

Fig. 1: Dashboard — entry point with engagement cards and a status light.

```
┌───────────────────────────────────────────────────────────┐
│  ASM Console        [Dashboard] Engagements Live Results   │
├───────────────────────────────────────────────────────────┤
│  Active engagements (2)                 + New engagement    │
│  ┌─────────────────────────┐ ┌─────────────────────────┐   │
│  │ customer-a.com          │ │ *.bugbounty-x  (bbp)    │   │
│  │ ● running · Phase: vuln │ │ ○ awaiting authorization│   │
│  │ 12 findings · 2 critical│ │ Scope signed ✓          │   │
│  └─────────────────────────┘ └─────────────────────────┘   │
│  Completed (5) …                                            │
└───────────────────────────────────────────────────────────┘
```

## 2. Creating an engagement (wizard)

A multi-step wizard that captures, 1:1, the fields of the Rules of Engagement
template and the data model. Each step writes to the corresponding table.

### 2.1 Wizard steps

| Step | Input | Writes to |
|---|---|---|
| 1 · Type | `source` (lab/own_domain/bug_bounty/customer) | `engagement.source` |
| 2 · Parties | title, customer, emergency contact, test window | `engagement` |
| 3 · Assets | allow/deny lists, ownership | `scope_asset` |
| 4 · Steps | `tool_grant` per category: passive/active, per-step approval | `tool_grant` |
| 5 · BBP (conditional) | program, policy, ident header | `bounty_program` |
| 6 · Authorize | review checklist, signature/hash | `status→active` |

### 2.2 Core screen: assets & steps

Fig. 2: The core — where the user picks domains AND the desired steps.

```
┌─────────────────────────────────────────────────────────────┐
│  New engagement · Step 3/6: Assets & 4/6: Steps              │
├─────────────────────────────────────────────────────────────┤
│  IN SCOPE (allow)                          [+ Row]           │
│   Type        Value            Path     Active allowed?      │
│   [domain ▼] api.customer.com  /*       [☑]                  │
│   [wildcard] *.customer.com              [☐]                  │
│  OUT OF SCOPE (deny — takes precedence)    [+ Row]            │
│   [domain ▼] internal.customer.com /admin  Reason: prod login│
├─────────────────────────────────────────────────────────────┤
│  Test steps (what the scanner may do)                        │
│   Category       Passive Active⚖  Per-step approval          │
│   recon           [☑]     [☑]     [☐]                         │
│   fingerprint     [☑]     [☑]     [☐]                         │
│   vuln            [☑]     [☑]     [☐]                         │
│   cred            [—]     [☐]     [☑ recommended]             │
│   exploit         [—]     [☐]     [☑ recommended]             │
├─────────────────────────────────────────────────────────────┤
│                       [Back]   [Next: Authorize →]           │
└─────────────────────────────────────────────────────────────┘
```

> [!IMPORTANT]
> **⚖ LEGAL / CONTROL — the UI visibly enforces the rules.** Active
> checkboxes (⚖) only become selectable once the corresponding asset is
> "actively allowed". Deny rows are visually highlighted (precedence). The
> "Next" button toward authorization is locked until ownership is verified
> and — for `customer`/`bug_bounty` — the respective requirement (signature
> or program policy) is satisfied. The UI cannot unlock anything the
> gateway would later reject.

## 3. Live scan: tracking progress

The heart of the requirement: seeing what the scanner is currently doing and
which step it's on. Built from three zones — phase progress, live activity,
approval queue.

### 3.1 Phase progress

The `scan_run` state machine (discovery → fingerprint → correlate → agent →
validate → score → report) rendered as a progress bar. The active step is
highlighted.

Fig. 3: Live view — phase bar, real-time log, approval area.

```
┌─────────────────────────────────────────────────────────────┐
│  Live: customer-a.com          Runtime 04:12    [⏸ Pause]    │
├─────────────────────────────────────────────────────────────┤
│  ✓Discovery ─ ✓Fingerprint ─ ●Vuln ─ ○Agent ─ ○Validate ─    │
│  ○Score ─ ○Report                                            │
│  ───────────────────────────────────────────────  62 %      │
├─────────────────────────────────────────────────────────────┤
│  Current activity (live log)                                 │
│   14:02:11  nuclei  api.customer.com   → 3 hits (safe)       │
│   14:02:09  httpx   api.customer.com   → 200, nginx          │
│   14:02:04  GATEWAY ALLOW  fingerprint/nmap -sV  ✓           │
│   14:01:58  GATEWAY DENY   masscan (not whitelisted) ✕       │
├─────────────────────────────────────────────────────────────┤
│  ⚖ Pending approvals (0)     Everything pre-authorized       │
└─────────────────────────────────────────────────────────────┘
```

> [!NOTE]
> **Mechanism: live updates.** The live log is fed directly from
> `audit_log` (every gateway decision, every tool call). Delivered to the
> frontend via server-sent events or WebSocket. Because `audit_log` is
> already complete, the live view is effectively a real-time mirror of the
> audit trail — no separate logging needed.

### 3.2 Approval queue (only when needed)

With the chosen model — "authorize up front, then run autonomously" — the
queue mostly stays empty. It only fills when a category with
`requires_manual_approval=true` comes up (`cred`/`exploit`) or the agent hits
a scope boundary.

Fig. 4: Approval card — a one-time, expiring authorization
(`approval_request`).

```
┌─────────────────────────────────────────────────────────────┐
│  ⚖ Approval required                                         │
│  The agent wants to execute an active step:                  │
│   Category:   cred (default-credential check)                │
│   Target:     api.customer.com/login (in scope, active)      │
│   Details:    3 vendor-known default logins                  │
│                                                                │
│   [Reject]                    [Approve — runs once]           │
│   Expires in 09:41                                            │
└─────────────────────────────────────────────────────────────┘
```

> [!IMPORTANT]
> **⚖ LEGAL / CONTROL — an approval is one-time and logged.** Clicking
> "Approve" creates a consume-once authorization (`approval_request`), valid
> only for that exact tool call and time-limited. Rejection or timeout stops
> the step, not the whole scan. Every decision lands in `audit_log` with the
> operator's name.

## 4. Presenting results

The evaluation layer (classification, risk score, severity from Ch. 5 of the
Architecture doc) becomes visual here. Three views: summary, findings list,
detail card.

### 4.1 Summary (executive view)

Fig. 5: Summary with a status light, severity distribution, diff trend.

```
┌─────────────────────────────────────────────────────────────┐
│  Result: customer-a.com    completed 14:38     [Report ↧]   │
├─────────────────────────────────────────────────────────────┤
│  Risk light:  ● RED (2 critical)                              │
│  ┌────────┬────────┬────────┬────────┬────────┐             │
│  │crit  2 │high  4 │med   5 │low   8 │info  3 │             │
│  └────────┴────────┴────────┴────────┴────────┘             │
│  Trend vs. last run:  +1 new  · 2 resolved · 9 persisting    │
│  Top actions:                                                 │
│   1. Outdated OpenSSL on api.  (KEV, immediate)               │
│   2. Open .git directory       (< 24 h)                      │
└─────────────────────────────────────────────────────────────┘
```

### 4.2 Findings list & detail card

Fig. 6: Master-detail — list on the left, proof + plain-language
recommendation on the right.

```
┌──────────────────────────┬──────────────────────────────────┐
│ Findings (22)   [Filter▼]│  Detail: Outdated OpenSSL         │
│ ● crit OpenSSL   api.    │  Severity: ● critical (KEV)       │
│ ● crit .git expo web.    │  Risk score: 92   EPSS: 0.79      │
│ ● high Header    api.    │  Confidence: validated ✓          │
│ ○ med  TLS v1.0  mail.   │  Asset: api.customer.com Port 443 │
│ ○ low  Cookie    web.    │  ── Evidence ──                   │
│ …                        │  Banner: OpenSSL/1.0.2 (excerpt)  │
│                          │  ── Recommendation ──              │
│                          │  Upgrade to 3.x; package state …  │
│                          │  [mark accepted] [add to report]  │
└──────────────────────────┴──────────────────────────────────┘
```

> [!NOTE]
> **Making confidence visible.** `validated` findings (with proof) are
> visually clearly separated from `inferred` (derived only) — e.g. via a
> checkmark badge. This turns the "no alarm without evidence" principle into
> a UI reality and helps the operator prioritize the findings that can carry
> weight in the customer report.

## 5. Technical implementation of the frontend

### 5.1 Stack (reference)

| Layer | Technology | Purpose |
|---|---|---|
| Framework | React + TypeScript | component-based, type-safe |
| State/data | React Query | server state, polling/cache |
| Live updates | Server-sent events (SSE) | live log & progress from `audit_log` |
| Charts | Recharts or similar | severity distribution, trend |
| Auth | OIDC / session | operator login; a customer role later |

### 5.2 Integration with the existing API

The UI uses exclusively the REST/SSE contracts from Ch. 6.3 of the
Architecture doc — it has no direct access to the DB or the tools.

Listing 1: the UI is a pure client of the existing API.

```
GET  /engagements                      -> dashboard cards
POST /engagements                      -> wizard steps 1-6
POST /engagements/{id}/scope-assets    -> allow/deny rows
POST /engagements/{id}/tool-grants     -> steps matrix
POST /engagements/{id}/activate        -> after the authorization checklist
GET  /engagements/{id}/stream  (SSE)   -> live log + phase progress
GET  /approvals?state=requested        -> approval queue
POST /approvals/{id}/approve|reject    -> one-time authorization ⚖
GET  /engagements/{id}/findings        -> results list/detail
POST /engagements/{id}/report          -> PDF export (async)
```

> [!IMPORTANT]
> **⚖ LEGAL / CONTROL — the UI enforces nothing, it reflects.** The web
> interface is convenient operation, but NOT a security boundary. All
> authorizations, scope, and tool checks are still decided server-side by
> the Scope Gateway. Even if the UI were manipulated, the gateway remains
> authoritative. The UI only makes the rules visible and convenient.

## 6. States, feedback & error cases

- Status light per engagement: grey (`draft`) · yellow (awaiting
  authorization) · pulsing green (running) · blue (done) · red
  (error/aborted).
- Pause/abort: the operator can pause a running scan (`scan_run` →
  `waiting`) or abort it (→ `aborted`); both land in `audit_log`
  immediately.
- Gateway DENY is visible: blocked actions appear as a clearly marked row in
  the live log (never hidden) — transparency instead of a silent filter.
- Timeout hints: pending approvals show a countdown; once it expires, the
  step is automatically rejected.
- Budget display: tool calls/tokens/time spent against the run's budget —
  prevents cost surprises.

## 7. Future customer view (read-only derivation)

Once the customer later gets access, their interface is a reduced,
read-only subset of the same data — not a second system.

| Element | Operator view | Customer view |
|---|---|---|
| Create engagement | full | — (operator only) |
| Live scan log | full (incl. gateway decisions) | reduced: phase + progress |
| Approval queue | yes (authorize) | — |
| Findings | all, incl. `inferred` | only `validated` + released |
| Report | generate & edit | download the finished report |
| Scope/methodology | fully editable | read-only (proof) |

> [!IMPORTANT]
> **⚖ LEGAL / CONTROL — separating the views = separating data ownership.**
> The customer view shows only data from their own engagement, and only
> released, validated findings. Internal gateway decisions, rejected
> actions, and `inferred` findings stay in the operator view. Role-based
> access control (RBAC) enforces this server-side, not the UI.

---

**Note:** This UI/UX specification describes the interaction; the security
and legal logic remains unchanged in the Scope Gateway (Architecture v2.1).
The contractual/criminal-law safeguards should be secured with qualified
advice.
