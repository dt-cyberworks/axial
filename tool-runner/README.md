# tool-runner

Ephemere Ausfuehrungsebene (HexStrike + Kali-Tools). Wird **nie** dauerhaft
betrieben, sondern pro Auftrag frisch gestartet und danach zerstoert
(`deployment/k8s/job-tool-runner.yaml` bzw. der `tool-runner`-Service in
`docker-compose.yml` fuer M1-M3 auf einem Host).

Zwei unabhaengige Beschraenkungsebenen (s. `docs/spec/tool-allowlist.md`):

1. **Build-Zeit-Allowlist** (`runner.Dockerfile`) - was ueberhaupt im Image
   installiert ist. Ein Tool, das hier fehlt, kann von HexStrike oder dem
   LLM nicht aufgerufen werden, unabhaengig von jedem Prompt oder Fehler.
2. **Laufzeit-Grant** (`tool_grant`-Tabelle + Scope Gateway,
   `control-plane/app/gateway/authorize.py::WHITELIST`) - welche Teilmenge
   der installierten Tools in diesem konkreten Auftrag ueberhaupt
   vorgeschlagen werden darf.

Der tool-runner selbst hat standardmaessig keinen direkten Netzzugang ausser zum
`egress-proxy` (s. `deployment/k8s/networkpolicy-runner-egress.yaml`) und
wird niemals direkt vom LLM angesprochen - jeder Vorschlag geht zuerst durch
`POST /internal/engagements/{id}/gateway/authorize` in der control-plane.

Fuer nmap/raw scans gilt ein separater Pfad: In Compose teilt dieser Runner
den Netzwerk-Namespace des `raw-egress-gateway`. Dessen nftables-OUTPUT-Policy
ist deny-all und akzeptiert nur eine Control-Plane-signierte, kurzlebige Lease
fuer die auditierte materialisierte IP. Nur das Gateway besitzt `NET_ADMIN`;
dieser Runner bleibt non-root mit `NET_RAW`. In Kubernetes gilt weiterhin die
per-Engagement-NetworkPolicy aus
`GET /internal/engagements/{id}/raw-egress-policy`. Domain-/Wildcard-Scope muss
vorher materialisiert werden; bis dahin bleibt raw egress fail-closed.

Build:

```
docker build -f tool-runner/runner.Dockerfile -t asm/tool-runner:dev tool-runner
```

**TODO(M3):** MCP-Server/-Client, der HexStrikes HTTP-API mit dem
freigegebenen `--profile` instanziiert und ToolResults normalisiert
zurueckgibt (Architektur Kap. 4.3). Aktuell enthaelt dieses Verzeichnis nur
die Image-Definition, noch keinen Runner-Code.

## Scan-run cancellation

`runner.Dockerfile` applies `patch_hexstrike.py` strictly at build time. The patch
tags each HexStrike subprocess from `X-ASM-Scan-Run-ID`, isolates the command in
a process group, makes `/api/processes/list` JSON-safe, and adds
`POST /api/processes/terminate-scan-run/{scan_run_id}`. The endpoint terminates
only process groups carrying that exact ID. A changed upstream HexStrike source
causes the image build to fail rather than silently dropping cancellation.
