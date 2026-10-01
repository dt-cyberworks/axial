# Architecture

Source: [`docs/spec/technical-architecture.md`](spec/technical-architecture.md)
(v2.1) and [`docs/spec/scanner-specification.md`](spec/scanner-specification.md) (v1.0).

## Overview

The scanner covers every phase of an external security assessment — from
passive reconnaissance to controlled, non-destructive exploitation testing
(the "Vector Agent"). Target context: a side-business managed service for
SMBs. The value creation lies in **interpreting and prioritizing** the
results, not in the scan itself.

## Components and zones

Two security zones that never share a container, privileges, or network
access (Deployment Architecture Ch. 1):

```mermaid
flowchart TB
    subgraph client["Client"]
        UI["Operator console<br/>(React/TS)"]
    end

    subgraph control["Control plane — maximally protected, no offensive tool"]
        CP["control-plane<br/>FastAPI + Scope Gateway<br/>(sole DB writer)"]
        WK["worker<br/>Celery — orchestrates,<br/>executes nothing itself"]
        DB[("postgres<br/>data + audit log")]
        RD[("redis")]
        S3[("seaweedfs<br/>evidence, reports")]
    end

    subgraph exec["Execution plane — isolated, ephemeral, disposable"]
        TR["tool-runner<br/>HexStrike + Kali tools"]
        RG["raw-egress-gateway<br/>signed lease + nftables deny-all"]
    end

    EP["egress-proxy<br/>HTTP network-level scope enforcement"]
    LLM["Claude API<br/>(outside the cluster)"]
    NET(["Internet targets<br/>authorized only"])

    UI -->|REST/SSE| CP
    CP --> DB
    CP --> S3
    CP <-->|enqueue| RD
    WK <-->|tasks| RD
    WK -->|"authorize()<br/>internal"| CP
    WK -.->|reasoning| LLM
    CP -->|commissions| TR
    TR -->|"HTTP-aware tools"| EP
    EP -->|"scope re-check +<br/>ident header"| NET
    CP -.->|"signed short-lived lease"| RG
    TR -->|"nmap in the shared namespace"| RG
    RG -->|"lease IP/ports only"| NET

    classDef ctrl fill:#1b3a5b,stroke:#4a90d9,color:#fff
    classDef exe fill:#5b1b1b,stroke:#d94a4a,color:#fff
    class CP,WK,DB,RD,S3 ctrl
    class TR,RG exe
```

**Core rule:** no layer with active components executes directly. Every
active tool call passes through the Scope Gateway (details:
[security-model.md](security-model.md)).

## Layer model (data flow)

| # | Layer | Function | Character |
|---|---|---|---|
| A | Engagement & scope management | Signed scope, authorized assets, time window, tool profile | controlling |
| B | **Scope Gateway** | Checks every tool call; blocks everything outside it; approval workflow | deterministic |
| C | Discovery | Subdomains (CT logs), DNS/RDAP, ASN/IP, cloud assets | passive |
| D | Fingerprinting | Port/service detection, HTTP headers, TLS, tech stack | passive → active |
| E | Vulnerability correlation | Version→CVE (NVD), EPSS, misconfig checks | passive/active |
| F | Vector Agent (LLM) | Proposes vulnerability hypotheses & safe test steps | proposing |
| G | Safe active checks | Executes authorized, non-destructive checks | active |
| H | Risk scoring | EPSS + CVSS + business context + exposure | processing |
| I | Orchestration & history | Scheduler, diff detection, asset inventory | processing |
| J | Reporting | Plain-language customer report (the sales product) | output |
| K | Audit trail | Complete logging of every action & approval | cross-cutting |

## Scan-phase pipeline

A state machine per `scan_run` (Technical Architecture Ch. 4.1), resumable:

```mermaid
stateDiagram-v2
    [*] --> discovery
    discovery --> fingerprint
    fingerprint --> correlate
    correlate --> agent
    agent --> validate
    validate --> score
    score --> report
    report --> [*]

    note right of fingerprint
        Transitioning to active phases only
        if the gateway approves the call —
        otherwise waiting_approval
    end note
```

Implemented in [`worker/app/tasks/`](../worker/app/tasks/): `pipeline.py`
drives the machine, each phase is its own module. Per-phase maturity is
tracked in [roadmap.md](roadmap.md).

## Technology stack (reference)

| Layer | Technology | Rationale |
|---|---|---|
| API / orchestrator | Python 3.12 + FastAPI | async, typed, fast tool integration |
| Task queue | Celery + Redis | distributed, repeatable scan jobs |
| Primary DB | PostgreSQL 16 | relational + JSONB for flexible findings |
| Tool execution | MCP server + HexStrike | controlled tool registry per engagement |
| LLM (reasoning) | Claude (tool use) | reliable structured tool use |
| Object storage | S3-compatible (SeaweedFS) | raw output, report PDFs, evidence |
| Secrets | Vault / SOPS | scope signing key, API keys |
| Frontend | React + TypeScript | component-based, type-safe |

The stack is a reference implementation — swappable as long as the
contracts ([api.md](api.md)) are honored.
