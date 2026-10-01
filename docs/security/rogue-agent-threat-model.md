# Threat Model: A Rogue or Compromised Vector Agent

Scope of this document: what happens if the **Vector Agent goes rogue** — the
LLM is adversarial, is prompt-injected by malicious content it reads from a
scan target, the LLM provider is hostile, or an attacker otherwise controls the
agent's output — and it actively tries to *escape or attack the boundaries* of
the ASM platform. It enumerates the agent's reachable attack surface, walks the
concrete escape/abuse scenarios, states which existing control stops each, and
identifies the residual gaps that the `REQ-HARDEN-*` work closes.

This complements [`../security-model.md`](../security-model.md) (the standing
control description) and [`../../AGENTS.md`](../../AGENTS.md) (the
non-negotiable invariants). It is deliberately adversarial: it assumes the
agent *wants* to break out.

## 1. Trust model and what "the agent" actually is

The Vector Agent is **not code that runs in our process**. It is a sequence of
JSON tool-call proposals produced by an LLM. The worker parses those proposals
and dispatches them through fixed handlers (`worker/app/tasks/agent.py`). The
agent never supplies raw shell, never supplies tool flags, and its text is
never `eval`/`exec`-ed. The design intent (AGENTS.md) is:

> The LLM or worker may propose actions, but deterministic control-plane state
> decides whether anything active is allowed.

So a "rogue agent" is an untrusted **proposer** with these capabilities only:
choose a tool from a fixed enum, choose a target string, choose a small set of
structured, individually-validated arguments, write findings, and read the
observations that come back. Everything else is denied deterministically by the
Scope Gateway (`control-plane/app/gateway/authorize.py`), which is the sole
authorization boundary and fails closed.

### Trust zones (Compose topology)

| Zone | Components | Trust | Reaches |
|---|---|---|---|
| Control | control-plane, postgres, redis | Trusted (sole DB writer, holds secrets) | `ctrl` (internal) |
| Object store | seaweedfs | Trusted; only the control-plane may reach it | `objstore` (internal, control-plane only) |
| Orchestration | worker | Semi-trusted (holds INTERNAL_API_TOKEN; no DB creds) | `ctrl`, `egress`, `control` |
| Execution | tool-runner (HexStrike), raw-egress-gateway | **Untrusted** (touches targets, parses hostile output) | `runner`, `egress`, shared netns |
| Egress enforcement | egress-proxy | **Untrusted-facing** (parses hostile target responses) | `ctrl` (RO DB), `runner`, `egress` |
| Targets | customer / lab hosts | Hostile | — |

The agent's proposals execute in the **Execution** zone and its network
requests transit the **Egress enforcement** zone — both of which are the
untrusted, target-facing zones. That is the surface this model examines.

## 2. Attack surface reachable from the agent

1. **Scope Gateway** (`/internal/.../gateway/authorize`) — every proposal.
2. **Tool argument envelope** (`gateway/args_safety.py`) — per-tool value checks.
3. **Tool dispatch → tool-runner** (`worker/app/tool_runner_client.py` → HexStrike `/api/*`).
4. **Egress proxy** (HTTP-aware tools' only route out).
5. **Raw-egress-gateway** (nmap's only route out; signed leases + nftables).
6. **Control-plane internal API** (worker-mediated; token-gated).
7. **LLM provider channel** (the agent's own context leaves the network to the provider).
8. **Audit log / findings** (agent can append findings; audit is append-only hash-chained).

## 3. Scenarios (STRIDE-flavored) and disposition

Legend: **Blocked** = an existing control fully stops it; **Hardened** = this
work closes a real gap; **Residual** = accepted/known, documented.

### S1 — Out-of-scope targeting (Tampering / Elevation)
*Agent proposes tools against hosts outside the engagement scope, or against a
second customer's infrastructure.*
**Blocked.** Two independent checks: the agent-side in-scope map and, decisively,
the Scope Gateway's deterministic scope match with **deny-over-allow** and
fail-closed on missing/ambiguous scope. No prompt or injected instruction can
produce an allow. The egress-proxy re-checks scope at the network layer
(defense in depth). Cross-engagement: `run(engagement_id)` only loads *that*
engagement's scope/evidence.

### S2 — Command / argument injection (Elevation)
*Agent smuggles shell metacharacters through `target`/`args` to run arbitrary
commands on the runner.*
**Blocked.** Targets must match a strict regex (`_TARGET_RE`); tool bodies are
built by fixed worker-side builders, not the agent; generic `/api/command`
invocations are `shlex.quote`-d; `args_safety.py` whitelists arguments per tool
(wordlists by key not path, FUZZ-only ffuf paths, header/body size + charset
limits, nmap profile lock). The agent chooses *which* tool on *which* in-scope
host, never *how*.

### S3 — Aggressive / destructive tooling (Elevation / DoS)
*Agent tries intrusive templates, brute-force, mass scan, or DoS.*
**Blocked.** The runner image installs only the allowlisted tools (no
hydra/sqlmap/metasploit/masscan/…); `nuclei` is locked to non-intrusive tags
with `-etags intrusive,dos,fuzz` and a rate limit baked in the worker;
per-engagement `tool_grant` gates categories; iteration and tool-call budgets
cap volume; the raw-egress rate is clamped.

### S4 — State-changing HTTP without authorization (Tampering)
*Agent issues POST/PUT/DELETE to alter target state.*
**Blocked (by policy routing).** Write methods / any body are never autonomous:
the gateway routes them to **mandatory per-command human approval** with an
LLM-authored risk statement; the approved *exact stored call* is re-authorized
and claimed atomically before dispatch (captured in-memory args are not
trusted). Reads stay autonomous.

### S5 — Data exfiltration to an attacker endpoint (Info Disclosure)
*Agent tries to POST collected data to attacker.com, or to a DNS/again channel.*
**Blocked** for target-facing egress: the egress-proxy only permits in-scope
hosts, so `attacker.com` is out of scope and denied; nmap egress is deny-all
except the signed lease's exact target/ports. **Residual (inherent):** the
agent's own reasoning context is sent to the configured **LLM provider**, so a
hostile provider sees this engagement's evidence. That is inherent to using an
external LLM and is bounded to a single engagement; mitigation is provider
choice/self-hosting (operational), tracked in §5.

### S6 — SSRF to internal services / cloud metadata (Info Disclosure / Elevation)
*Agent targets an in-scope **name** that resolves (or is rebound at connect
time) to `169.254.169.254` (cloud metadata), `127.0.0.1`, or a neighbouring
container, riding inside "allowed" scope.*
**Hardened — was a real gap.** The egress-proxy authorized by host *name* and
then `open_connection(host, port)`, resolving at connect time with **no address
vetting**. `REQ-HARDEN-002` adds `ssrf_guard.vet_target_host`: resolve once,
refuse loopback / link-local (incl. metadata) / unspecified / multicast /
reserved (and their IPv4-mapped forms) regardless of scope, and connect to the
**pinned vetted IP** (closing the resolve-then-connect rebinding window).
Private RFC1918/ULA ranges stay allowed because lab and internal own-domain
targets legitimately use them; scope still gates those.

### S7 — Lateral movement to the unauthenticated execution engine (Elevation)
*A compromised peer in the target-facing zone (most realistically the
egress-proxy, which parses hostile target responses; or a compromised tool
process) POSTs to the runner's `/api/command` = arbitrary shell in the runner.*
**Hardened — was a real gap.** HexStrike ships with **no authentication** and
binds `0.0.0.0:8888`; in Compose it is reachable from the `runner`/`egress`/
`control` networks. `REQ-HARDEN-001` injects a fail-closed shared-secret gate
(`runner_auth.is_authorized`, `X-ASM-Runner-Token`) via the build-time patch;
only the worker holds the token, `/health` stays open, and a missing/dev-default
token is rejected at startup in production. This does not stop the agent
directly (the agent already can't reach `/api/command`) — it removes the
lateral-movement escalation available to a compromised target-facing component,
which is exactly the "escape the boundary" case.

### S8 — Escaping the worker process (Elevation)
*Agent output executes code in the worker.*
**Blocked.** Agent output is parsed as JSON tool calls and dispatched through
fixed handlers; there is no `eval`/`exec`/template execution of agent content.
Unknown tool names are rejected. Malformed proposals are skipped, not executed.

### S9 — Reaching the control-plane DB / abusing the internal API (Elevation)
*Agent drives the worker into arbitrary internal API calls or direct DB writes.*
**Blocked.** The worker's internal calls are fixed; the agent only influences
`{tool, target, args}` inside fixed handlers. The worker holds no DB
credentials (network-reachability of postgres on `ctrl` is defense-in-depth
only; DB password auth stops it). The internal API is token-gated and not
exposed via ingress.

### S10 — Resource / cost exhaustion (DoS)
*Agent loops forever or maximizes spend.*
**Blocked (bounded).** `budget_max_iterations` + `budget_tool_calls_max`
(gateway-enforced), per-run reaping, egress-proxy client-slot backpressure, and
rate limits bound volume and cost.

### S11 — Secret disclosure via agent telemetry (Info Disclosure)
*The LLM API key or raw provider URL leaks into the audit log / agent steps.*
**Blocked.** The API key is only used to build the client, never placed in
messages; recorded agent steps carry the message array (no key); provider URLs
are passed through `_safe_url` (credentials stripped) before audit.

### S12 — Poisoning findings / audit (Integrity / Repudiation)
*Agent spams false findings.*
**Residual (low).** `report_finding` writes without a gateway check (it touches
no target). Bounded by the iteration budget and clearly attributed
(`reported_by: vector_agent`). This is a data-quality issue, not a boundary
escape; the audit log itself remains append-only and hash-chained (tamper-
evident). Accepted; noted for a future confidence/label control.

### S13 — Reaching the object store's unauthenticated interfaces (Info Disclosure / Tampering)
*A compromised worker or proxy reaches the evidence store without the S3 credentials.*
**Blocked (REQ-INSTALL-002).** SeaweedFS' default single-node mode also starts
master, volume and filer HTTP/gRPC interfaces with **no authentication**; from
any host on its network the filer lets anyone read and write every stored
object, bypassing the S3 credentials entirely (verified against the image
before adopting it). So: those interfaces are bound to the container's loopback
and the optional Iceberg/Lance endpoints are off, leaving only the S3 gateway
(which requires credentials) on the network; the one port that cannot be bound
separately (the gateway's own gRPC port) is protected by network isolation -
the store sits on a dedicated internal `objstore` network that only the
control-plane joins, so the worker (semi-trusted) and the egress proxy
(untrusted-facing) cannot even resolve it; it publishes no host port in any
profile. The install smoke test asserts all of this against the running stack.
Residual: a compromised **control-plane** can reach the gRPC port - it already
holds the S3 credentials and is the trusted zone, so nothing is gained.

## 4. Hardening implemented by this change (`REQ-HARDEN-*`)

- **REQ-HARDEN-001 — authenticate the execution boundary (S7).**
  `tool-runner/runner_auth.py` + build-time patch inject a fail-closed
  `X-ASM-Runner-Token` gate into HexStrike; the worker presents the token on
  every request; `/health` stays open; production refuses a missing/dev-default
  token. Negative tests prove wrong/missing tokens are rejected and health stays
  open.
- **REQ-HARDEN-002 — SSRF containment at the egress proxy (S6).**
  `egress-proxy/app/ssrf_guard.py` refuses never-legitimate address classes and
  pins the vetted IP for the actual connection, for both CONNECT and plaintext
  paths, audited as a single honest DENY. Negative tests prove metadata /
  loopback / rebinding are blocked while public and private-lab targets pass.

Both are **R3** (runner + proxy boundaries) and carry the required negative
tests. Per the SDLC they cannot be self-approved by an automated agent and
require human security review.

## 5. Residual / accepted risk (operational, not code-fixable here)

- **R-1 Hostile LLM provider (S5).** The agent's per-engagement context is
  visible to the configured provider. Mitigation is provider selection or
  self-hosting; single-engagement blast radius. Owner: operator.
- **R-2 Worker↔postgres network reachability (S9).** Worker sits on `ctrl` for
  control-plane access and can *reach* postgres at L3; it holds no DB
  credentials. Defense-in-depth only; a K8s NetworkPolicy / dedicated control
  channel would remove even reachability. Owner: infra.
- **R-3 Agent-authored findings (S12).** Unauthenticated finding creation is
  bounded and attributed; a future confidence-gating control is tracked.
- **R-4 nmap materialized-IP metadata guard.** Raw nmap does not transit the
  egress-proxy, so `REQ-HARDEN-002` does not vet its target; the control-plane
  DNS materialization already applies deny precedence. Extending the loopback/
  link-local refusal into materialization is a recommended follow-up (low
  surface: nmap targets are operator-materialized IPs, not agent-chosen names).

## 6. Verification

- Negative unit tests: `tool-runner/tests/test_runner_auth.py`,
  `worker/tests/test_runner_auth_header.py`,
  `egress-proxy/tests/test_ssrf_guard.py`.
- Live: runner rejects an unauthenticated `/api/command` (401) while the worker
  (token-holding) still drives tools; proxy denies a metadata/loopback target
  with an audited `blocked_*` reason while normal in-scope scans are unaffected.
- The negative out-of-scope lab gate (`make lab-test`) remains the standing
  end-to-end safety check and is unchanged by this work.
