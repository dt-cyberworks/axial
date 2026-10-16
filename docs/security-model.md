# Security Model

Source: [Technical Architecture Ch. 3](spec/technical-architecture.md#3-security-layer-the-scope-gateway) and [Deployment Architecture Ch. 1/5/6](spec/deployment-architecture.md).
The Scope Gateway is the service's actual intellectual property — not the
tool collection.

## Guiding principle: control lives in state, not in the prompt

No authorization depends on what the LLM "says" or how a prompt is phrased.
Exclusively signed DB state decides. A model that claims to be authorized
changes nothing.

## Scope Gateway: the decision pipeline

Deterministic (no LLM), stateless, **fail-closed**: the first rejecting
check ends the chain. Implemented in
[`control-plane/app/gateway/authorize.py`](../control-plane/app/gateway/authorize.py).

```mermaid
flowchart TD
    A["ToolCall"] --> B{"1. status==active<br/>& within the time window?"}
    B -->|no| D1["DENY<br/>engagement_not_active /<br/>outside_time_window"]
    B -->|yes| C{"2. a deny rule matches?<br/>(wildcard/path)"}
    C -->|yes| D2["DENY<br/>explicit_out_of_scope"]
    C -->|no| E{"an allow rule matches?"}
    E -->|no| D3["DENY<br/>target_out_of_scope"]
    E -->|yes| F{"3. bug_bounty:<br/>automation/AI allowed?"}
    F -->|no| D4["DENY<br/>automation/ai_forbidden"]
    F -->|yes| G{"4. active: active_allowed<br/>& tool_grant?"}
    G -->|no| D5["DENY<br/>active_not_allowed /<br/>no_tool_grant"]
    G -->|yes| H{"5. tool whitelisted<br/>& args safe?"}
    H -->|no| D6["DENY<br/>tool_not_whitelisted /<br/>unsafe_arguments"]
    H -->|yes| I{"6. rate limit ok?"}
    I -->|no| D7["DENY rate_limited"]
    I -->|yes| K{"7. requires_manual_approval?"}
    K -->|yes| P["PENDING_APPROVAL<br/>(human in the loop)"]
    K -->|no| AL["ALLOW"]

    classDef deny fill:#5b1b1b,stroke:#d94a4a,color:#fff
    classDef allow fill:#1b5b2b,stroke:#4ad96a,color:#fff
    class D1,D2,D3,D4,D5,D6,D7 deny
    class AL allow
```

GitHub issue #32: a dedicated "bug_bounty: ident header configured?" step
used to sit here (step 7, denying `missing_ident_header`) - removed as dead
code once traced through: step 3 above already denies `bounty_program_missing`
whenever no `bounty_program` row exists for a bug_bounty engagement, and
REQ-AUTH-006's 2026-08-12 amendment made the header itself optional once a
program row exists (some real programs identify researchers out-of-band).
Header injection, when a program configures one, happens downstream in the
egress-proxy/worker, not as a gateway authorization gate.

**Deny precedence** (step 2) models bug-bounty programs' out-of-scope
lists, whose violation is a serious infraction. It's the core of the
[negative test](testing.md#the-negative-test-the-most-important-one).

## Defense in depth: two independent scope checks

The check happens deliberately **twice, redundantly**:

| Layer | Controls | Where |
|---|---|---|
| Scope Gateway | **what** gets commissioned | [`control-plane/app/gateway/`](../control-plane/app/gateway/) |
| Egress proxy | what actually **leaves** the network | [`egress-proxy/app/proxy.py`](../egress-proxy/app/proxy.py) |

```mermaid
flowchart LR
    LLM["Vector Agent"] -->|proposal| GW["Scope Gateway<br/>(control-plane)"]
    GW -->|only if permitted| TR["tool-runner"]
    TR -->|every request| PX["Egress proxy<br/>(2nd scope re-check)"]
    PX -->|scope-compliant only| NET(["target"])
    TR -.->|deny-all nftables<br/>OUTPUT policy| X["✕ everything else"]
```

Even if the gateway were bypassed, the runner has no route out except through
the egress proxy: it has no internet route of its own and shares the network
namespace of the raw-egress gateway, whose nftables OUTPUT policy is deny-all
(it allows the proxy and, while a signed lease is active, one audited target
IP and port set). The proxy only lets scope-compliant targets through. Two
independent layers protect exactly the point where an out-of-scope hit is most
costly. Compose has no further per-engagement network policy engine behind
them; the controls above are everything there is on the wire.

## Isolation boundary

Offensive tools (`tool-runner`) **never** run in the same container as the
gateway, the DB, or the audit log. If a tool breaks out or is compromised
(HexStrike has a documented history of misuse), it must not be able to
reach the control plane or the tamper-evident audit chain. The runner is a
long-running container with a read-only root filesystem and only a `tmpfs`
scratch area. It is **not** recreated per engagement: it keeps no engagement
data of its own (results go to the control plane), its processes are tagged
with the scan run so a cancellation kills only that run's processes, and
scratch files are gone when the container restarts. Customers who must not
share a runner need separate Compose stacks.

## Two layers of tool restriction

Source: [`docs/spec/tool-allowlist.md`](spec/tool-allowlist.md).

1. **Build-time allowlist** ([`tool-runner/runner.Dockerfile`](../tool-runner/runner.Dockerfile))
   — what's installed in the image at all. A tool that's missing here can't
   be misused, regardless of any prompt. A build guard fails the build if
   an excluded tool (hydra, metasploit, sqlmap, masscan …) somehow ends up
   installed.
2. **Runtime grant** (`tool_grant` + `WHITELIST` in
   [`authorize.py`](../control-plane/app/gateway/authorize.py)) — which
   subset may be proposed in a specific engagement.

Additionally, [`args_safety.py`](../control-plane/app/gateway/args_safety.py)
hardens the arguments of even whitelisted tools (e.g. nmap only `-sV/-sS`,
no exploit NSE scripts; nuclei only `safe` templates).

For the exact flag-by-flag rationale of every static tool invocation (which
parameters, why exactly those values), see
[security/tool-catalog.md](security/tool-catalog.md) — written for an
external security researcher.

## Tool grants: passive, active, manual approval

The operator console separates three related but different decisions in the
Tool grants step:

| Control | Meaning | Enforcement |
|---|---|---|
| Passive | Allows OSINT/enrichment tools that query public or third-party data sources, such as certificate transparency or passive subdomain sources. It does not validate live services and is only useful where the registry has real passive tools. | Stored as `tool_grant(mode='passive')`; checked by the Scope Gateway together with the tool registry `execution_class == "passive"`. |
| Active | Allows target-touching tools in a category, but only after scope, time window, allowlist, and argument checks pass. | Stored as `tool_grant(mode='active')`; checked by the Scope Gateway. |
| Manual approval | Marks concrete active tools, such as `nmap` or `nuclei`, that must pause for an operator approval before execution. | Stored in `tool_approval_policy`; creates an `approval_request` when the otherwise-allowed call reaches the gateway. |

Grants can be changed until an engagement is completed or revoked, not only in draft
(REQ-TOOL-006..008). The gateway reads them on every call, so a change applies from the next
call. Granting an ACTIVE category after the engagement left draft widens its authority and
requires an explicit confirmation; nothing is added while a scan is running (removing is always
possible, it only narrows); every addition and removal is written to the hash-chained audit log
with the acting user. Only the owner or an admin can change them (REQ-IAM-023). A campaign's
per-tool switches (Edit engagement) can only narrow what the grants allow: "Force on" never
replaces a grant, and saving grants never resets those switches.

Manual approval is not a separate permission to run a category. If a category is
not active, selected tools in that category cannot run and no manual approval is
requested. The approval prompt only appears after the gateway has already
verified that the engagement is active, the target is in scope, the tool is
whitelisted, and the arguments are safe.

In the current capability registry, passive execution is available only for
recon tools such as `subfinder` and `amass`. Fingerprint, vuln, cred, and
exploit tools are target-touching in this build and therefore require active
permission when they are used.

## Who may see and change an engagement

This boundary answers "may this person look at, or change, this engagement at all"; it never
answers "may this tool call run", which stays the Scope Gateway's job alone.

- Every engagement has exactly one **owner** (`engagement.owner_user_id`, `NOT NULL`;
  REQ-IAM-021).
- Every signed-in user can **read** every engagement in the installation: scope, findings and
  evidence, runs and agent steps, reports, the audit log and the live stream (REQ-IAM-022). The
  boundary is the installation; there are no tenants inside it. Global settings, API keys and user
  management are not part of an engagement and stay admin-only (REQ-IAM-013).
- Only the **owner or an admin** can **change** it: any non-read request under
  `/engagements/{id}/...` answers `403` to anyone else, before the body is read and before
  anything is written; the same holds for deciding an approval (REQ-IAM-023). An id that does not
  exist is `404` for everyone. The pending-approval queue is the owner's own.
- The rule is one dependency, `enforce_engagement_access`, wired once on the public router, so
  every present and future route gets it. A test sweeps every route of the real application and
  fails for a route that lacks it or lets a non-owner change something.
- Reassigning an owner is admin-only. A migration gave every legacy ownerless engagement to the
  oldest active administrator; the benchmark harness's engagements belong to that administrator
  too.

## Audit trail: hash-chained and append-only

[`audit.py`](../control-plane/app/gateway/audit.py) writes every gateway
decision append-only, with `row_hash = sha256(prev_hash ||
canonical_json(row))`. The chaining makes after-the-fact modification
detectable, so it can be shown that every action stayed in scope. In
production, the `audit_log` table gets its own backups and `REVOKE UPDATE,
DELETE` (INSERT only).

## Threat model (excerpt)

| Threat | Countermeasure |
|---|---|
| The LLM proposes an out-of-scope target | gateway deny/allow check (state, not prompt) |
| Prompt injection "I am authorized" | control lives in the DB, not in prompt text |
| Tool breakout / compromise | zone separation, read-only non-root runner, deny-all nftables egress policy |
| Gateway bypass | redundant egress proxy + the runner's deny-all nftables egress policy (defense in depth) |
| out-of-scope network access | egress proxy blocks at the network level |
| after-the-fact audit tampering | hash chain, append-only, restrictive permissions |
| cost explosion / infinite loop | a budget ceiling per run (tool calls/tokens/time); the tool-call ceiling is one global admin setting, copied onto the run at its start, and a run that exhausts it is degraded, never reported clean (REQ-BUDGET-001/002) |
| destructive exploitation | the build-time allowlist excludes exploit tools |
| lateral movement onto the execution engine (unauthenticated `/api/command`) | a shared-secret gate at the tool-runner (REQ-HARDEN-001, `X-ASM-Runner-Token`, fail-closed) |
| SSRF via an in-scope name to cloud metadata/loopback (DNS rebinding) | the egress proxy refuses link-local/loopback/reserved and pins the checked IP (REQ-HARDEN-002) |

A detailed, adversarial treatment of the "what if the Vector Agent goes
rogue and tries to break out of its boundaries" scenario (attack surface,
STRIDE scenarios, countermeasures, residual risk) is in
[`security/rogue-agent-threat-model.md`](security/rogue-agent-threat-model.md).

## Minimum safe-operation baseline

Public operator routes require the single-operator credential. Browser clients exchange the bearer credential for an HttpOnly, SameSite session cookie so SSE and protected downloads remain authenticated. `/health` is public; `/internal/*` continues to use the independent workload credential. Production mode rejects development credentials.

The egress proxy uses a read-only database role and submits bounded audit events to the authenticated control-plane ingestion route. If this audit submission is unavailable, the associated network request is denied. Audit appends take a PostgreSQL transaction advisory lock per engagement, producing one serialized hash chain.

The proxy's reply to an allowed `CONNECT` is one fixed constant with a `Proxy-Agent` header line and nothing derived from the request (REQ-EGRESS-004/005). A reply without any header line left nuclei's raw HTTP client waiting for 60 s and sending nothing, so its raw-request templates never reached a target. A denied request never receives this reply and opens no tunnel. `make verify-tunnel-handshake` runs the real nuclei through the real proxy handler and fails if the proxy slows one of those templates down.

Manual approvals use `requested -> approved -> executing -> consumed|execution_failed`. The claim transition re-runs the complete Scope Gateway against the stored call and is protected by a row lock.

## Raw scan target binding and truthful results

Raw-socket tools cannot traverse the HTTP proxy. In Compose, a run first obtains a bounded FIFO reservation; waiting grants no network access. The control plane then signs a short-lived capability only after the exact Nmap call passes the Scope Gateway. The separate raw-egress gateway requires the matching queue-head run, verifies the capability, and installs the audited materialized IP plus exact TCP or UDP ports in a deny-all namespace shared with the runner. The gateway, not the offensive runner, owns `NET_ADMIN`. One lease is active at a time; a heartbeat refreshes the kernel target timeout only while Nmap is running, and deactivation flushes both target and port sets. Each lease's granted packet rate is additionally enforced by a real kernel-level nftables `limit rate` rule scoped to the lease's concurrency slot (`raw-egress-gateway/app/gateway.py`'s `NftPolicyManager`) - not only by Nmap's own cooperative `--max-rate` flag (`REQ-BOUNTYSCAN-004`). Nmap is started at half the lease's rate so the limiter never has to drop its probes; a scan whose probes were refused anyway, or that no longer finds a port earlier runs found (after one slow second look), is reported `partial`, never clean (`REQ-PORTSCAN-001..004`).

For `bug_bounty`-source engagements, the raw-egress lease path additionally applies the per-program `tcp_syn_scan_profile` tier (`REQ-BOUNTYSCAN-001..004`: `none`/`common`/`full`, default `none`) on top of the Scope Gateway's own checks: only `host_discovery` (a fixed two-port liveness sweep) is exempted from the raw-nmap block by default; `common`/`full` are explicit, separate operator opt-ins, and `full` additionally requires a recorded `network_scan_authorization_evidence` reason - never inferred from `automation_allowed` or any rate figure alone. This is R4 (new active-scanning capability); a profile broader than `host_discovery` requires explicit human security review before use against a real (non-lab) program, per `AGENTS.md`'s documented-exception pattern.

Runner HTTP success is not treated as scan success. Non-zero exits, runner-declared failure, zero-target/malformed XML, policy/heartbeat/cleanup failure, and proxy backpressure are failed outcomes. TCP discovery covers exactly the persisted engagement range; service detection sees only discovered open ports. UDP is default-off, fixed to the approved nine-port profile, and persists open/closed/filtered/open-or-filtered counts while fingerprinting only confirmed-open ports. Tool, target/IP, protocol/range, state summary, stderr summary, and discovered-service count are stored in the append-only audit chain.

## Run-bound cancellation

Target-touching fingerprint and Vector-Agent calls carry an exact `scan_run_id`.
The Scope Gateway locks and verifies that run before authorization; cancelled,
foreign, inactive, or missing run context fails closed. The runner records the
ID as process ownership metadata (not permission), starts each command in its own
process group, and exposes only exact-run group termination to the worker. If the
control plane cannot answer a cancellation poll, the worker terminates the tool.
Raw Nmap retains its independently signed lease and revokes it in `finally` after
the runner returns or is terminated.

## Operating modes

An engagement is `monitoring` (unattended) or `assessment`. The mode never widens what the gateway
allows; it narrows how a decision that needs a person is handled.

- A monitoring engagement refuses configuration that needs a person (an asset review, a per-tool
  approval, a `cred`/`exploit` grant). A call that still needs a decision in a run nobody supervises is
  withdrawn by the worker and recorded as a suggestion; nothing waits and no popup is left.
- A new host of a monitoring engagement can be held: inventoried, not tested, until acknowledged. A
  run limited to some hosts, and a `passive` run, make no call outside what they were asked to.
- A semi-attended run that needs a decision parks: the same run stays open, so the approval stays bound
  to its `scan_run_id` and is re-checked by the gateway when claimed. The stored state holds no session
  cookie and not the call's arguments.
- Alerts carry a kind, a title and a link: no evidence, credential or tool output. A webhook must be a
  public https address, checked when it is saved and again when it is sent; redirects are not followed.
- A monitoring engagement can run by itself every N days (1 to 90). This is the one place the product
  starts a scan without a person pressing a button, so it is bounded: a due run goes through the same
  start path as a manual one (readiness, the one-active-run rule, the Scope Gateway, budgets), and does
  not start while the engagement is not `active`, outside its authorized window, after its review date,
  while another run is active or beyond the installation's capacity cap. Each skip is stored and
  audited once. The scheduler never changes scope, grants, capabilities or the interval, never retries
  a failed run, and its start is audited with the schedule as the actor. The interval is part of the
  authorization document's configuration, so changing it after signing changes the checksum.

**Not part of this change** (withheld; recorded in the engineering requirement records):
the gateway-resident forms of these rules (`approval_unavailable_unattended`, `profile_passive`,
`asset_held_for_review`) and the standing consent to state-changing requests (R4). Until then the worker
enforces the narrowing rules, and a state-changing request still always waits for a person in an
assessment and is never made by a monitor.

