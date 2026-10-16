# tool-runner

Isolated execution plane (HexStrike + Kali tools): the `tool-runner` service in
`docker-compose.yml` (profile `runner`). It is not on the control plane's
network and is never addressed by the LLM directly.

Two independent layers of restriction (see `docs/spec/tool-allowlist.md`):

1. **Build-time allowlist** (`runner.Dockerfile`) - what is installed in the
   image at all. A tool that is missing here cannot be called by HexStrike or
   the LLM, regardless of any prompt or bug.
2. **Runtime grant** (`tool_grant` table + Scope Gateway,
   `control-plane/app/gateway/authorize.py::WHITELIST`) - which subset of the
   installed tools may be proposed at all in this particular engagement.

By default the tool-runner itself has no direct network access except to the
`egress-proxy` (the internal `runner` network in `docker-compose.yml`) and is
never addressed by the LLM directly - every proposal first goes through
`POST /internal/engagements/{id}/gateway/authorize` in the control plane.

nmap/raw scans take a separate path: in Compose this runner shares the network
namespace of the `raw-egress-gateway`. Its nftables OUTPUT policy is deny-all
and accepts only a short-lived lease signed by the control plane, for the
audited materialized IP. Only the gateway owns `NET_ADMIN`; this runner stays
non-root with `NET_RAW`. Domain/wildcard scope has to be materialized first;
until then raw egress stays fail-closed.

Build:

```
docker build -f tool-runner/runner.Dockerfile -t asm/tool-runner:dev tool-runner
```

**TODO:** an MCP server/client that instantiates HexStrike's HTTP API with the
authorized `--profile` and returns normalized ToolResults (Architecture
Ch. 4.3). Currently this directory holds only the image definition, no runner
code yet.

## Scan-run cancellation

`runner.Dockerfile` applies `patch_hexstrike.py` strictly at build time. The patch
tags each HexStrike subprocess from `X-ASM-Scan-Run-ID`, isolates the command in
a process group, makes `/api/processes/list` JSON-safe, and adds
`POST /api/processes/terminate-scan-run/{scan_run_id}`. The endpoint terminates
only process groups carrying that exact ID. A changed upstream HexStrike source
causes the image build to fail rather than silently dropping cancellation.
