# Deployment Architecture

ASM Scanner with Agent capability. Container topology, isolation &
HexStrike integration.

Compose · Kubernetes · egress proxy · hardening

Version 1.0 · Developer-ready · Companion document to Architecture v2.1

> [!NOTE]
> **Relationship to the other documents.** This document extends the
> Technical Architecture (v2.1) with the operational view: how the
> components are packaged, isolated, and rolled out. The data model, the
> Scope Gateway, and the evaluation layer are specified there and assumed
> here. Legally and security-critically relevant points are marked ⚖.

## 1. Guiding principle: two security zones

The system has two fundamentally different security profiles. The
deployment must physically separate them — they must never share the same
container, the same privileges, or the same network access.

| Zone | Components | Profile | Requirement |
|---|---|---|---|
| Control plane | orchestrator, Scope Gateway, DB, audit log, secrets | must be maximally protected | long-lived, no offensive tool |
| Execution plane | HexStrike + offensive tools (nmap, nuclei, sqlmap …) | potentially dangerous | isolated, ephemeral, disposable |

> [!IMPORTANT]
> **⚖ CONSENT / SECURITY — the isolation boundary.** Offensive tools NEVER
> run in the same container as the gateway/DB/audit log. If a tool breaks
> out or is compromised (HexStrike has a documented history of misuse), it
> must not be able to reach the control plane or the tamper-evident audit
> chain.

### 1.1 Target picture (topology)

Fig. 1: two zones, a single controlled egress path.

```
Internet targets       ▲   only authorized targets — via egress proxy
                        │   (scope re-check + mandatory ident header for bug_bounty) ⚖
   ┌────┴──────────────────────────────┐
   │  EGRESS PROXY  (Ch. 5)             │  enforces scope_asset at the network level
   └────▲──────────────────────────────┘
        │ the only way out
   ┌────┴──────────────────────────────┐
   │  HEXSTRIKE JOB POD  (ephemeral)    │  non-root · NET_RAW only · timeout
   │  only the tool_grant profile loaded│
   │  NetworkPolicy: egress to the proxy only
   └────▲──────────────────────────────┘
        │ commissioned (internally) by
   ┌────┴──────────────────────────────┐        ┌───────────────────────────┐
   │  CONTROL PLANE + SCOPE GATEWAY     │──write─▶│ postgres · audit · s3     │
   │  (long-lived, no tools)            │        │ (long-lived · isolated)   │
   └────▲──────────────────────────────┘        └───────────────────────────┘
        │ reasoning via API (sees only permitted tools)
   ┌────┴───────────┐
   │  Claude API     │  runs outside the cluster
   └────────────────┘
```

## 2. Container roles

| Container | Lifetime | Job | Tools? |
|---|---|---|---|
| `control-plane` | long-lived | FastAPI orchestrator + Scope Gateway; the sole DB writer | no |
| `worker` | long-lived | Celery; orchestrates scans, executes nothing itself | no |
| `postgres` | long-lived | primary DB + audit log (append-only) | no |
| `redis` | long-lived | task queue / broker | no |
| `seaweedfs` | long-lived | S3-compatible object storage: raw output, report PDFs, evidence; on its own network that only the control-plane joins, publishes no port | no |
| `vault` | long-lived | secrets: scope signing key, API keys | no |
| `egress-proxy` | long-lived | network-level scope enforcement + ident header | no |
| `tool-runner` (HexStrike) | ephemeral / per job | offensive execution; fresh per engagement, destroyed afterward | YES (isolated) |

> [!NOTE]
> **Why the runner is ephemeral.** A fresh container per job means no state
> persists across customers or scopes. This enforces the data model's scope
> separation at the infrastructure level, and prevents artifacts from one
> engagement leaking into another.

## 3. HexStrike integration & installation

HexStrike consists of two processes: an HTTP/Flask API server that executes
the tools, and an MCP client the LLM talks to. Installed via a dedicated
Kali-based image.

### 3.1 Principle: HexStrike's own guardrails are NOT the security layer

- HexStrike offers env switches (`HEXSTRIKE_VALIDATE_COMMANDS`,
  `HEXSTRIKE_RATE_LIMIT`) and a prompt role-play mechanism for
  authorization. These are nice extras, but NOT control.
- The actual control stays the deterministic Scope Gateway in front of it.
  HexStrike is only the execution engine behind the gateway — never directly
  reachable by the LLM.
- Tool selection via `--profile` (minimal, web, network, bugbounty, full):
  per engagement, only the profile derived from `tool_grant` is loaded. The
  LLM never even sees the other tools.

> [!IMPORTANT]
> **⚖ CONSENT / SECURITY — prompt-based authorization is NOT used.**
> HexStrike's documented way of getting the LLM to execute via a role-play
> prompt ("my company owns this site…") is a workaround against model
> guardrails and is deliberately NOT used here as an authorization
> mechanism. Authorization happens exclusively via signed DB state in the
> gateway.

### 3.2 Dockerfile (`tool-runner`, Kali-based)

Listing 1: `runner.Dockerfile` — lean, hardened tool execution.

```dockerfile
# runner.Dockerfile - offensive execution plane, isolated
FROM kalilinux/kali-rolling:latest

# 1. Only the needed tools (not the full arsenal)
RUN apt-get update && apt-get install -y --no-install-recommends \
      python3 python3-venv python3-pip git \
      nmap nuclei httpx-toolkit dnsutils whatweb \
  && rm -rf /var/lib/apt/lists/*

# 2. Install HexStrike
WORKDIR /opt/hexstrike
RUN git clone https://github.com/0x4m4/hexstrike-ai.git . \
  && python3 -m venv venv \
  && ./venv/bin/pip install --no-cache-dir -r requirements.txt

# 3. Non-root user; the root FS becomes read-only at runtime
RUN useradd -r -u 10001 -s /usr/sbin/nologin runner

# 4. Raw-socket capability scoped to nmap only (instead of root)
RUN setcap cap_net_raw,cap_net_admin+eip /usr/bin/nmap

USER runner
EXPOSE 8888
# Server start; command validation on, API key enforced
ENV HEXSTRIKE_VALIDATE_COMMANDS=true HEXSTRIKE_REQUIRE_API_KEY=true
ENTRYPOINT ["/opt/hexstrike/venv/bin/python3","hexstrike_server.py"]
CMD ["--host","127.0.0.1","--port","8888"]
```

> [!NOTE]
> **A custom image instead of the public one.** The public
> `dennisleetw/hexstrike-ai:latest` is convenient, but for production you
> build your own, pinned image: a reduced tool set, a known state,
> auditable. A `latest` with 150+ tools is an unnecessarily large attack
> surface for a service you're accountable for to customers.

## 4. Option A — Docker Compose (lab / M1–M3)

For development and the passive-through-early-active stages on your own
domain. Fast, reproducible, one host.

Listing 2: Compose with three separate networks; only the proxy sees the
internet.

```yaml
# docker-compose.yml (excerpt)
services:
  control-plane:
    build: ./control-plane
    depends_on: [postgres, redis, egress-proxy]
    networks: [ctrl]            # NO direct internet egress
    read_only: true
    cap_drop: [ALL]

  postgres:
    image: postgres:16
    networks: [ctrl]
    volumes: [pgdata:/var/lib/postgresql/data]

  egress-proxy:
    build: ./egress-proxy
    networks: [ctrl, egress]    # bridge: internal zone -> internet

  tool-runner:
    build: {context: ., dockerfile: runner.Dockerfile}
    networks: [runner]          # reaches ONLY the egress proxy
    read_only: true
    cap_drop: [ALL]
    cap_add: [NET_RAW]          # nmap only
    security_opt: ["no-new-privileges:true"]
    environment:
      HTTPS_PROXY: http://egress-proxy:3128
      HTTP_PROXY:  http://egress-proxy:3128

networks:
  ctrl:   {internal: true}      # no route to the internet
  runner: {internal: true}      # no route to the internet
  egress: {}                    # only the proxy sits here

volumes: {pgdata: {}}
```

> [!IMPORTANT]
> **⚖ CONSENT / SECURITY — network segmentation is half the job.** `ctrl`
> and `runner` are `internal` — no route to the internet. The only way out
> runs through `egress-proxy`. So even a compromised runner cannot reach
> arbitrary targets, only what the proxy permits against the scope.

## 5. Option B — Kubernetes (bug_bounty / customer, M4+)

For production operation with genuine tenant/engagement separation. Per scan
engagement, the control plane starts a HexStrike pod as a Kubernetes Job —
not as a long-running service.

### 5.1 Ephemeral job per engagement

Listing 3: job manifest — ephemeral, hardened, time- and resource-bounded.

```yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: scan-{engagement_id}
  labels: {app: tool-runner, engagement: "{engagement_id}"}
spec:
  activeDeadlineSeconds: 3600     # hard runtime/cost ceiling
  backoffLimit: 0                 # no auto-retry of offensive jobs
  ttlSecondsAfterFinished: 300    # auto-delete the pod afterward
  template:
    metadata:
      labels: {app: tool-runner, engagement: "{engagement_id}"}
    spec:
      restartPolicy: Never
      automountServiceAccountToken: false
      containers:
      - name: hexstrike
        image: registry.internal/asm/tool-runner:pinned-sha
        securityContext:
          runAsNonRoot: true
          runAsUser: 10001
          readOnlyRootFilesystem: true
          allowPrivilegeEscalation: false
          capabilities: {drop: ["ALL"], add: ["NET_RAW"]}
        env:
        - {name: HTTPS_PROXY, value: "http://egress-proxy:3128"}
        resources:
          limits: {cpu: "2", memory: 2Gi}
```

> [!NOTE]
> **Why a Job instead of a Deployment.** `activeDeadlineSeconds` caps the
> runtime (your budget concept at the infra level). `ttlSecondsAfterFinished`
> auto-deletes the pod → no leftover state. `backoffLimit: 0` prevents an
> offensive scan from retrying uncontrolled on failure.

### 5.2 NetworkPolicy — the scope boundary at the network level

Listing 4: the runner may reach exclusively the egress proxy.

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: runner-egress-only}
spec:
  podSelector: {matchLabels: {app: tool-runner}}
  policyTypes: [Egress]
  egress:
  - to:
    - podSelector: {matchLabels: {app: egress-proxy}}
    ports: [{protocol: TCP, port: 3128}]
  # NO other egress permitted -> everything else is blocked
```

> [!IMPORTANT]
> **⚖ CONSENT / SECURITY — defense in depth at the most critical point.**
> Even if the Scope Gateway were bypassed, the NetworkPolicy blocks any
> traffic that doesn't go to the egress proxy. The proxy, in turn, only lets
> scope-compliant targets through. Two independent layers protect exactly
> the point where an out-of-scope hit is most costly for bug bounty.

## 6. Egress proxy — network-level scope enforcement

The proxy is the component that ties the deployment to the Scope Gateway.
All outbound scan traffic runs through it; it checks `scope_asset` a second
time and injects the mandatory ident header for bug bounty.

### 6.1 Responsibilities

- Allow/deny check: every target is checked against the engagement's
  `scope_asset`; deny rules take precedence (wildcard/path respected). ⚖
- Ident-header injection: for `source='bug_bounty'`, the configured header
  (e.g. `X-Bug-Bounty`) is set on EVERY request — enforced, independent of
  HexStrike or the LLM. ⚖
- Rate limiting: enforces `max_rps` / `max_concurrency` from the
  `bounty_program` policy. ⚖
- Audit: every passed and every blocked request is logged (feeds the audit
  trail).

### 6.2 Decision logic (pseudocode)

Listing 5: the proxy deliberately duplicates the scope check redundantly.

```python
def on_request(req, engagement_id):
    eng   = load_engagement(engagement_id)
    host  = req.host; path = req.path

    # 1. deny takes precedence (out-of-scope protection)
    if matches_deny(host, path, eng):  return BLOCK(403, 'out_of_scope')  # ⚖
    if not matches_allow(host, path, eng): return BLOCK(403, 'not_in_scope') # ⚖

    # 2. time window & status (a second check, independent of the gateway)
    if not window_ok(eng):             return BLOCK(403, 'outside_window') # ⚖

    # 3. bug-bounty obligations
    if eng.source == 'bug_bounty':
        prog = bounty_program(eng)
        req.headers[prog.ident_header_name] = prog.ident_header_value  # ⚖
        if over_rate(eng, prog.max_rps): return BLOCK(429, 'rate_limited')

    audit(eng, req, 'ALLOW')
    return FORWARD(req)
```

> [!NOTE]
> **Why redundant with the gateway?** The double check is deliberate. The
> gateway controls WHAT gets commissioned; the proxy controls what actually
> LEAVES the network. A bug or gap in one layer is caught by the other — the
> right level of paranoia for offensive tools.

## 7. Hardening, secrets & operations

### 7.1 Container hardening (checklist)

- `runAsNonRoot` + a fixed UID; `readOnlyRootFilesystem`;
  `allowPrivilegeEscalation: false`.
- `cap_drop ALL`; only `NET_RAW` for the runner (nmap), nothing for the
  control plane.
- `no-new-privileges`; the seccomp/AppArmor default profile active.
- `automountServiceAccountToken: false` in the runner pod (no cluster access
  from the execution plane).
- Pinned image digests (`sha256`), no `latest` in production; image scanning
  (Trivy) at build time.

### 7.2 Secrets & signing keys

- The scope signing key (for `scope_doc_sha256`) lives in
  Vault; only the control plane reads it, never the runner.
- Claude API key and platform credentials kept separate, with minimal
  scope; rotation documented.

> [!IMPORTANT]
> **⚖ CONSENT / SECURITY — audit-log integrity in deployment.** The
> Postgres instance holding the append-only audit log (hash chain) gets its
> own backups and restrictive permissions: the control plane may insert,
> nobody may `UPDATE`/`DELETE`. This preserves its evidentiary value to the
> customer, the bug-bounty operator, and the professional-liability insurer
> in operation too.

### 7.3 Mapping the maturity path → deployment

| Stage | `source` | Deployment |
|---|---|---|
| M1–M3 | lab / own_domain | Docker Compose (Ch. 4), one host, internal networks |
| M4 | bug_bounty | Kubernetes Jobs (Ch. 5) + egress proxy with ident header |
| M5 | bug_bounty (Agent) | as M4; agent phase only if the policy allows it |
| M6 | customer | as M4/M5 + scope-signature workflow, customer reporting |

> [!NOTE]
> **A pragmatic starting point.** For a side-business start, Compose on a
> hardened host is entirely sufficient for M1–M3. Kubernetes only pays off
> once genuine engagement/tenant separation (`bug_bounty`, `customer`) is
> needed. The zone separation and the egress proxy apply from day one in
> BOTH variants, though.

---

**Note:** Technical specification, not legal advice. Operating offensive
tools and processing scan data is subject to computer-misuse and
data-protection law in your jurisdiction and should be secured with
qualified legal counsel.
