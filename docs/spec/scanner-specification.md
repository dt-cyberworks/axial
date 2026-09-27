# Specification Document

Attack Surface Scanner with Agent capability. A managed ASM service for
small and medium businesses.

Technical & organizational specification

Version 1.0 · Draft

> [!IMPORTANT]
> **⚖ LEGAL IMPLICATION — a note on markers.** Every section marked ⚖
> identifies a function or process step that requires the customer's
> express, written consent (an engagement / authorization) before it may be
> executed. Without that consent, the actions in question must not be
> carried out — actively scanning or testing third-party systems without
> authorization can be a criminal offense under computer-misuse law in many
> jurisdictions. This document is a technical specification and does not
> substitute for legal advice.

## 1. Purpose and scope

This document specifies the architecture of an Attack Surface Management
(ASM) scanner that covers every phase of an external security assessment —
from passive reconnaissance to AI-assisted, controlled exploitation testing
(the "Agent"). The target context is a side-business managed service for
small and medium businesses (SMBs).

**Guiding principle of the architecture:** the language model (LLM) plans
and proposes — a deterministic control layer (the Scope Gateway) decides and
executes. Control is enforced technically, not through prompt wording.

### 1.1 Operating model

- Offering shape: managed service / consulting with reporting and advice
  (not a pure self-service tool).
- Operation: side business, one-person operation — capacity deliberately
  capped, a high degree of automation is mandatory.
- The value creation lies in interpreting and prioritizing the results, not
  in the scan itself.

> [!IMPORTANT]
> **⚖ LEGAL IMPLICATION — secondary employment / conflict of interest.**
> Before starting the activity, clarify whether secondary employment is
> permitted under your employment contract (employer approval, possible
> competition or conflict-of-interest issues, especially where there is
> subject-matter overlap with your primary employment). Customers connected
> to your employer's environment (e.g. suppliers) need particularly careful
> review.

## 2. Architecture overview

The scanner is built in layers. Data flows top to bottom; control flows back
from the Scope Gateway into every active layer.

### Layer model (data flow)

| # | Layer | Function | Character |
|---|---|---|---|
| A | Engagement & scope management | Signed scope document, authorized assets, time window, tool profile | Controlling |
| B | Scope Gateway (control core) | Checks every tool call against scope; blocks everything outside it; approval workflow | Deterministic |
| C | Discovery layer | Subdomains (CT logs), DNS/RDAP, ASN/IP ranges, cloud assets | Passive |
| D | Fingerprinting layer | Port/service detection, HTTP headers, TLS/certificates, tech stack | Passive → active |
| E | Vulnerability correlation | Version→CVE matching (NVD), EPSS prioritization, misconfig checks | Passive/active |
| F | Agent (LLM reasoning) | Proposes logical vulnerability hypotheses & safe test steps | Proposing |
| G | Safe active checks / exploitation | Executes authorized, non-destructive checks with proof | Active |
| H | Risk scoring & prioritization | Combines EPSS, CVSS, business context, exposure | Processing |
| I | Orchestration & history | Scheduler, diff detection, asset inventory DB | Processing |
| J | Reporting layer | Plain-language customer report with recommendations (the sales product) | Output |
| K | Audit trail | Complete logging of every action & approval | Cross-cutting |

**Central design rule:** no layer from D onward (the active portions)
executes directly. Every call passes through layer B (the Scope Gateway).

## 3. Scan phases in detail

### 3.1 Phase 1 — Discovery

Goal: establish which assets belong to the customer. Predominantly passive,
from public sources.

- Subdomain enumeration via certificate-transparency logs (crt.sh), DNS
  analysis, search-engine dorking.
- WHOIS/RDAP for domain and IP ownership.
- ASN/IP-range attribution via BGP data.
- Cloud asset discovery (storage buckets) via naming patterns.

> [!IMPORTANT]
> **⚖ LEGAL IMPLICATION — consent, ownership verification.** Passive
> discovery from public sources is legally uncritical. BUT: before an asset
> is added to the active scan scope, it must be verified and confirmed in
> writing that the customer is genuinely the owner/authorized party. Assets
> that were merely "found" but belong to someone else must not be actively
> tested.

### 3.2 Phase 2 — Fingerprinting

Goal: establish which services are running.

- HTTP(S) header analysis (security headers, server banners, cookies) —
  passive.
- TLS/certificate analysis (expiry, cipher suites, outdated protocols) —
  passive.
- Technology-stack detection (CMS, framework, JS libraries) — passive.
- Port/service detection: plain banner-grabbing on standard ports is
  borderline-uncritical; active/aggressive port scanning requires
  authorization. ⚖

> [!IMPORTANT]
> **⚖ LEGAL IMPLICATION — consent, active port scanning.** Aggressive or
> full port scanning of a third-party system goes beyond passive
> observation and is legally risky without authorization. Only execute
> after a signed scope; the gateway must bound it to authorized IP ranges
> and the time window.

### 3.3 Phase 3 — Vulnerability correlation

- Version detection → matched against a CVE database (NVD API or a local
  copy).
- EPSS score (Exploit Prediction Scoring System) for prioritization — more
  informative than a raw CVSS value alone.
- Known misconfigurations: open admin panels, exposed `.git`/`.env` files,
  missing security headers.

The matching itself is computational/passive. As soon as confirmation
requires actively probing the target system, Phase 2's authorization
requirement applies.

### 3.4 Phase 4 — Agent (AI reasoning)

Goal: find logic-driven vulnerabilities that signature-based scanners
structurally cannot detect (e.g. broken authorization, IDOR, missing rate
limits). Architecture follows an "intelligent attacker" pattern:

- **Discover:** aggregating endpoints from API specifications
  (Swagger/OpenAPI), crawling client code to uncover undocumented/shadow
  endpoints.
- **Reason:** the LLM analyzes endpoint behavior (response codes, error
  messages, headers) and proposes plausible vulnerability classes and test
  steps.
- **Adapt:** an iterative process — observed responses feed back into the
  model ("what did you see, what do you check next").

**Critical separation:** the Agent only proposes. Executing any proposed
step runs through the Scope Gateway (layer B) and, where applicable, human
approval.

> [!IMPORTANT]
> **⚖ LEGAL IMPLICATION — consent, AI-assisted active testing.** Every
> active test step the Agent proposes is an active action against the
> customer's system and requires scope coverage plus (for anything beyond
> pure detection) explicit approval. Control must NOT run through prompt
> wording ("I am authorized…") — it must be technically enforced by the
> gateway layer. For cloud assets (e.g. AWS/Azure), customer authorization
> alone is sometimes insufficient — some providers require separate test
> notification/approval.

### 3.5 Phase 5 — Safe active checks / exploitation

Proof, not exploitation. Non-destructive confirmation of real risks:

- Subdomain-takeover proof (CNAME pointing at a no-longer-existing service)
  — harmless, but active.
- Testing for weak/default credentials — only with explicit authorization. ⚖
- Confirming known misconfigurations.

Genuine penetration testing (manual exploitation, SQLi exploitation, RCE) is
a separate category and excluded from the initial offering — to be secured
separately by contract (Rules of Engagement, possibly certification, special
liability coverage).

> [!IMPORTANT]
> **⚖ LEGAL IMPLICATION — consent, active exploitation testing.**
> Default-credential tests, takeover proofs, and any action that
> demonstrates access or impact require explicit written authorization in
> the scope. Exclusions (no DoS, no social engineering, no data
> exfiltration) must be explicitly agreed. Destructive exploitation is not
> part of the initial offering.

## 4. Scope Gateway — the control core

The Scope Gateway is the deterministic layer between model/tools and
execution. It is the service's actual intellectual property — not the tool
collection.

### 4.1 Operating principle

- Every tool call (whether from the Agent or automated) is checked
  against the signed scope document.
- Only permitted: defined domains/IP ranges, authorized tool categories, the
  agreed time window.
- Everything outside that is hard-blocked — regardless of what the model
  "thinks" or how it phrases the request.
- Per-engagement tool whitelisting: a dedicated MCP server registers only
  the functions authorized for this engagement; the model never even sees
  the rest.

### 4.2 Data model (simplified)

| Entity | Fields | Purpose |
|---|---|---|
| Engagement | customer, period, status, signature/authorization reference | legal basis for the scan |
| Asset scope | domains, IP ranges, cloud accounts, ownership proof | what may be tested ⚖ |
| Tool profile | authorized tool categories, passive/active flag | what may be executed ⚖ |
| Time window | start/end, emergency contact | when testing may happen ⚖ |
| Approval log | step, time, approver | human-in-the-loop proof |

### 4.3 Human in the loop

Every step beyond passive detection is confirmed by the operator (not the
AI). This is both risk minimization and a sales argument: "AI-assisted, but
with human approval for every active test."

> [!IMPORTANT]
> **⚖ LEGAL IMPLICATION — consent, the approval workflow.** The approval
> workflow is a mandatory component, not an optional feature. Without a
> signed scope document, the gateway stays in passive-only mode; active
> layers are locked.

## 5. Model, tooling, and integration

### 5.1 Execution framework

An MCP-based framework is a candidate execution layer (e.g. HexStrike-style),
where the operator themself decides which tools get registered. What
matters: authorize only a narrowly scoped, non-destructive toolbox.

| Category | Permitted in the initial offering | Excluded |
|---|---|---|
| Recon/discovery | CT logs, DNS, RDAP, crawler | — |
| Fingerprinting | header, TLS, tech detection; service detection | aggressive full-range floods without a window |
| Vuln checks | Nuclei, `safe` templates only | payload generators, exploit kits |
| Credentials | only with authorization: default-credential check | password crackers, brute force |
| Exploitation | non-destructive proof | RCE, data access, persistence |

> [!IMPORTANT]
> **⚖ LEGAL IMPLICATION — consent, tool activation.** Active tool categories
> are unlocked per engagement and are bound to the signed scope. A
> framework like HexStrike has a documented history of misuse (autonomous
> zero-day exploitation); autonomous exploitation without gateway control
> must be excluded.

### 5.2 Model separation

- Planning model (reasoning, proposing steps) — a strong tool-use model.
- Execution layer (the gateway) — deterministic, no LLM, checks and
  executes.
- The model never executes a tool directly without an intermediate layer.

## 6. Risk scoring, history, and reporting

- Risk scoring: a combination of EPSS (exploitability), CVSS (severity),
  business context (publicly reachable? behind a login?).
- History: an asset-inventory DB with diff detection ("what's new since the
  last scan") — enables trend views instead of one-off snapshots.
- Reporting: an automatically generated customer report with plain-language
  recommendations instead of raw data — the actual sales product.
- Scheduler: recurring scans within the agreed time window.

## 7. Cross-cutting concerns & legal groundwork

A summary of everything that must be in place before the first customer
scan:

- Signed engagement with an exact scope (domains/IP ranges, not "the whole
  company"). ⚖
- Customer's ownership confirmation; for cloud, possibly additional provider
  authorization. ⚖
- Test window & emergency contact at the customer. ⚖
- Explicit exclusions (no DoS, no social engineering, no exfiltration,
  unless agreed). ⚖
- Professional liability insurance with IT-security-testing coverage before
  the first scan. ⚖
- A complete audit trail of every action and approval (proof for the
  customer & the insurer).
- Data-protection compliance where scanning captures personal data (e.g.
  exposed email addresses).
- Employer approval for secondary employment; check for conflicts of
  interest. ⚖

**Note:** This document is a technical specification, not legal advice. The
concrete criminal-law and contractual assessment (computer-misuse,
data-protection, secondary-employment, and related law in your jurisdiction)
should be secured with qualified legal counsel.
