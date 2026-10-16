# Deployment Architecture

ASM Scanner with Agent capability. Container topology, isolation &
HexStrike integration.

Compose · egress proxy · hardening

The data model, the Scope Gateway and the evaluation layer are specified in the
[technical architecture](technical-architecture.md); this document covers
packaging, isolation and rollout.

## 1. Guiding principle: two security zones

The system has two fundamentally different security profiles. The
deployment must physically separate them — they must never share the same
container, the same privileges, or the same network access.

| Zone | Components | Profile | Requirement |
|---|---|---|---|
| Control plane | orchestrator, Scope Gateway, DB, audit log, secrets | must be maximally protected | long-lived, no offensive tool |
| Execution plane | HexStrike + offensive tools (nmap, nuclei, sqlmap …) | potentially dangerous | isolated, holds no engagement data, disposable |

> [!IMPORTANT]
> **The isolation boundary.** Offensive tools NEVER
> run in the same container as the gateway/DB/audit log. If a tool breaks
> out or is compromised (HexStrike has a documented history of misuse), it
> must not be able to reach the control plane or the tamper-evident audit
> chain.

### 1.1 Target picture (topology)

Fig. 1: two zones, a single controlled egress path.

```
Internet targets       ▲   only authorized targets — via egress proxy
                        │   (scope re-check + mandatory ident header for bug_bounty)
   ┌────┴──────────────────────────────┐
   │  EGRESS PROXY  (Ch. 6)             │  enforces scope_asset at the network level
   └────▲──────────────────────────────┘
        │ the only way out
   ┌────┴──────────────────────────────┐
   │  TOOL-RUNNER (HexStrike)           │  non-root · NET_RAW only · timeout
   │  only the tool_grant profile loaded│
   │  internal network: proxy is the only exit
   └────▲──────────────────────────────┘
        │ commissioned (internally) by
   ┌────┴──────────────────────────────┐        ┌───────────────────────────┐
   │  CONTROL PLANE + SCOPE GATEWAY     │──write─▶│ postgres · audit · s3     │
   │  (long-lived, no tools)            │        │ (long-lived · isolated)   │
   └────▲──────────────────────────────┘        └───────────────────────────┘
        │ reasoning via API (sees only permitted tools)
   ┌────┴───────────┐
   │  Claude API     │  runs outside this host   
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
| `tool-runner` (HexStrike) | long-lived, restartable | offensive execution; read-only root filesystem, no engagement data of its own, scan processes tagged per run | YES (isolated) |

> [!NOTE]
> **The runner is not recreated per engagement.** It keeps no engagement data
> (results go to the control plane), its root filesystem is read-only apart
> from a `tmpfs`, and a cancellation kills only the processes tagged with that
> scan run. Customers who must not share a runner need separate Compose
> stacks.

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
> **Prompt-based authorization is NOT used.**
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
> surface.

## 4. Docker Compose

For development, evaluation and production on one host. Fast, reproducible.
This is the only deployment model Axial has.

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
> **Network segmentation is half the job.** `ctrl`
> and `runner` are `internal` — no route to the internet. The only way out
> runs through `egress-proxy`. So even a compromised runner cannot reach
> arbitrary targets, only what the proxy permits against the scope.

## 5. Keeping customers apart

Chapter 4 describes the only deployment model. To keep customers apart, run a
separate Compose stack for each. This chapter number is kept so that existing
references to chapters 6 and 7 stay valid.

## 6. Egress proxy — network-level scope enforcement

The proxy is the component that ties the deployment to the Scope Gateway.
All outbound scan traffic runs through it; it checks `scope_asset` a second
time and injects the mandatory ident header for bug bounty.

### 6.1 Responsibilities

- Allow/deny check: every target is checked against the engagement's
  `scope_asset`; deny rules take precedence (wildcard/path respected).
- Ident-header injection: for `source='bug_bounty'`, the configured header
  (e.g. `X-Bug-Bounty`) is set on EVERY request — enforced, independent of
  HexStrike or the LLM.
- Rate limiting: enforces `max_rps` / `max_concurrency` from the
  `bounty_program` policy.
- Audit: every passed and every blocked request is logged (feeds the audit
  trail).

### 6.2 Decision logic (pseudocode)

Listing 5: the proxy deliberately duplicates the scope check redundantly.

```python
def on_request(req, engagement_id):
    eng   = load_engagement(engagement_id)
    host  = req.host; path = req.path

    # 1. deny takes precedence (out-of-scope protection)
    if matches_deny(host, path, eng):  return BLOCK(403, 'out_of_scope')
    if not matches_allow(host, path, eng): return BLOCK(403, 'not_in_scope')

    # 2. time window & status (a second check, independent of the gateway)
    if not window_ok(eng):             return BLOCK(403, 'outside_window')

    # 3. bug-bounty obligations
    if eng.source == 'bug_bounty':
        prog = bounty_program(eng)
        req.headers[prog.ident_header_name] = prog.ident_header_value
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

- A non-root user with a fixed UID; `read_only` root filesystem.
- `cap_drop ALL`; only `NET_RAW` for the runner (nmap), nothing for the
  control plane.
- `no-new-privileges`; the seccomp/AppArmor default profile active.
- Pinned image digests (`sha256`), no `latest` in production; image scanning
  (Trivy) at build time.

### 7.2 Secrets & signing keys

- The scope signing key (for `scope_doc_sha256`) lives in
  Vault; only the control plane reads it, never the runner.
- Claude API key and platform credentials kept separate, with minimal
  scope; rotation documented.

> [!IMPORTANT]
> **Audit-log integrity in deployment.** The
> Postgres instance holding the append-only audit log (hash chain) gets its
> own backups and restrictive permissions: the control plane may insert,
> nobody may `UPDATE`/`DELETE`. This keeps its value as evidence intact in
> operation too.

---

This is a technical document, not legal advice. Only test systems you are authorized to test; see `docs/legal.md`.
