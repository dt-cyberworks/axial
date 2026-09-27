"""HTTP-Client zur internen control-plane-API.

Der Worker fuehrt selbst nichts aus und schreibt nicht in die DB
(Deployment-Architektur Kap. 2: control-plane ist der einzige DB-Schreiber).
Jeder vorgeschlagene Tool-Call geht ausschliesslich ueber
POST /internal/engagements/{id}/gateway/authorize - die Kontrolle liegt im
Scope Gateway, nicht im Worker.
"""

import os
import uuid

import httpx

CONTROL_PLANE_URL = os.environ.get("CONTROL_PLANE_URL", "http://control-plane:8000")
INTERNAL_API_TOKEN = os.environ.get("INTERNAL_API_TOKEN", "change-me-in-dev")
ENVIRONMENT = os.environ.get("ENVIRONMENT", "development").lower()
if ENVIRONMENT == "production" and INTERNAL_API_TOKEN in {"", "change-me-in-dev"}:
    raise RuntimeError("insecure production configuration: internal_api_token")


class ControlPlaneClient:
    def __init__(self, base_url: str = CONTROL_PLANE_URL, timeout: float = 30.0):
        headers = {"X-ASM-Internal-Token": INTERNAL_API_TOKEN} if INTERNAL_API_TOKEN else {}
        self._client = httpx.Client(base_url=base_url, timeout=timeout, headers=headers)

    def authorize(self, engagement_id: uuid.UUID, tool_call: dict) -> dict:
        r = self._client.post(f"/internal/engagements/{engagement_id}/gateway/authorize", json=tool_call)
        r.raise_for_status()
        return r.json()

    def acquire_raw_egress_lease(self, engagement_id: uuid.UUID, **fields) -> dict:
        r = self._client.post(
            f"/internal/engagements/{engagement_id}/raw-egress-leases", json=fields
        )
        r.raise_for_status()
        return r.json()

    def create_openwire_callback_token(self, engagement_id: uuid.UUID, *, scan_run_id: str | None = None) -> dict:
        """REQ-AGENT-027: {token, callback_url, expires_at} for one probe attempt."""
        r = self._client.post(
            f"/internal/engagements/{engagement_id}/openwire-callback-tokens",
            json={"scan_run_id": scan_run_id},
        )
        r.raise_for_status()
        return r.json()

    def get_openwire_callback_status(self, engagement_id: uuid.UUID, token: str) -> dict:
        r = self._client.get(f"/internal/engagements/{engagement_id}/openwire-callback-tokens/{token}")
        r.raise_for_status()
        return r.json()

    def create_scan_run(self, engagement_id: uuid.UUID, budget_tool_calls_max: int = 200) -> dict:
        r = self._client.post(
            f"/internal/engagements/{engagement_id}/scan-runs",
            json={"budget_tool_calls_max": budget_tool_calls_max},
        )
        r.raise_for_status()
        return r.json()

    def reap_all_stale_runs(self) -> int:
        """GitHub issue #29: periodic reconciliation (Celery beat), not
        scoped to any one engagement - see app/tasks/reap.py."""
        r = self._client.post("/internal/scan-runs/reap-stale")
        r.raise_for_status()
        return r.json()["reaped"]

    def update_scan_run(self, scan_run_id: uuid.UUID, **fields) -> dict:
        r = self._client.patch(f"/internal/scan-runs/{scan_run_id}", json=fields)
        r.raise_for_status()
        return r.json()

    def get_approval(self, approval_id: str) -> dict:
        """Freigabe-Status pollen (REQ-APPROVAL-003). Bei Netzfehler: 'unknown'
        (der Agent behandelt das wie 'noch offen' und pollt weiter / laeuft ab)."""
        try:
            r = self._client.get(f"/internal/approvals/{approval_id}")
            r.raise_for_status()
            return r.json()
        except Exception:  # noqa: BLE001
            return {"state": "unknown"}

    def claim_approval(self, approval_id: str) -> dict:
        """Atomically claim and reauthorize the exact approved call."""
        r = self._client.post(f"/internal/approvals/{approval_id}/claim")
        r.raise_for_status()
        return r.json()

    def complete_approval(self, approval_id: str, *, success: bool, error: str | None = None) -> dict:
        """Persist consumed/execution_failed; failures are not swallowed."""
        r = self._client.post(
            f"/internal/approvals/{approval_id}/complete",
            json={"success": success, "error": error},
        )
        r.raise_for_status()
        return r.json()

    def is_cancel_requested(self, scan_run_id: uuid.UUID) -> bool:
        """Return the authoritative cancellation flag.

        Cancellation status is a safety decision, not best-effort telemetry. If
        the control plane cannot answer promptly, callers fail closed and stop
        the current target-facing process instead of silently continuing.
        """
        r = self._client.get(
            f"/internal/scan-runs/{scan_run_id}/cancel-requested", timeout=2.0
        )
        r.raise_for_status()
        return bool(r.json().get("cancel_requested"))

    def record_agent_step(self, engagement_id: uuid.UUID, **fields) -> None:
        """Vector-Agent-Transparenz (REQ-RUN-006): Prompt + Antwort je Iteration.
        Best effort - Telemetrie darf einen Scan nie abreissen."""
        try:
            self._client.post(f"/internal/engagements/{engagement_id}/agent-steps", json=fields)
        except Exception:  # noqa: BLE001
            pass

    def heartbeat_scan_run(self, scan_run_id: str) -> None:
        """Lebenszeichen fuer den Reaper (REQ-RAWLEASE-001), best effort - waehrend
        langer Operationen (mehrminuetiger Nmap) haelt es den Lauf 'lebendig', darf
        ihn aber bei einem Fehler nie abreissen."""
        try:
            self._client.post(f"/internal/scan-runs/{scan_run_id}/heartbeat", timeout=2.0)
        except Exception:  # noqa: BLE001
            pass

    def add_discovered_asset(self, engagement_id: uuid.UUID, **fields) -> dict:
        r = self._client.post(f"/internal/engagements/{engagement_id}/discovered-assets", json=fields)
        r.raise_for_status()
        return r.json()

    def list_discovered_assets(self, engagement_id: uuid.UUID, in_scope: bool | None = None) -> list[dict]:
        params = {} if in_scope is None else {"in_scope": str(in_scope).lower()}
        r = self._client.get(f"/internal/engagements/{engagement_id}/discovered-assets", params=params)
        r.raise_for_status()
        return r.json()

    def get_scan_envelope(self, engagement_id: uuid.UUID, host: str | None = None) -> dict:
        """REQ-FIDELITY-003/REQ-PORTSCOPE-004: autorisiertes TCP-Portfenster,
        best effort - mit `host` das fuer DIESES Ziel wirksame (per-Target-
        Override x Engagement-Deckel), sonst der Engagement-Deckel. Ein
        Fehler hier darf HTTP-Fingerprinting nicht abreissen lassen - Aufrufer
        faellt dann auf das bisherige Verhalten (impliziter Port 443) zurueck."""
        try:
            params = {"host": host} if host else {}
            r = self._client.get(f"/internal/engagements/{engagement_id}/scan-envelope", params=params)
            r.raise_for_status()
            return r.json()
        except Exception:  # noqa: BLE001
            return {"tcp_port_from": 1, "tcp_port_to": 65535}

    def get_bounty_ident(self, engagement_id: uuid.UUID) -> dict:
        """GitHub issue #12: the mandatory self-identification (header name/
        value, optional User-Agent suffix) to inject into every HTTP-proxied
        tool call when this engagement runs under a bug-bounty program's
        rules of engagement - null values for the common non-bug_bounty case.
        Also carries `max_rps` (REQ-RATE-004), used to tighten a multi-request
        tool's own internal rate flag. Best effort, like get_scan_envelope
        above: a lookup failure must never abort a scan; it just means this
        call goes out unidentified/at each tool's own default rate, exactly
        as it would for a non-bug_bounty engagement."""
        try:
            r = self._client.get(f"/internal/engagements/{engagement_id}/bounty-ident")
            r.raise_for_status()
            return r.json()
        except Exception:  # noqa: BLE001
            return {"ident_header_name": None, "ident_header_value": None, "ua_suffix": None, "max_rps": None}

    def asset_review_required(self, engagement_id: uuid.UUID) -> bool:
        """REQ-ASSETREVIEW-001: reiner Config-Read, best effort. Ein Fehler hier
        darf ein NICHT opt-in Engagement nie in eine Pause zwingen -> False."""
        try:
            r = self._client.get(f"/internal/engagements/{engagement_id}/asset-review-required")
            r.raise_for_status()
            return bool(r.json().get("required"))
        except Exception:  # noqa: BLE001
            return False

    def create_asset_review(self, engagement_id: uuid.UUID, scan_run_id: uuid.UUID, candidate_assets: list[dict]) -> dict:
        r = self._client.post(
            f"/internal/engagements/{engagement_id}/scan-runs/{scan_run_id}/asset-review",
            json={"candidate_assets": candidate_assets},
        )
        r.raise_for_status()
        return r.json()

    def get_asset_review(self, review_id: str) -> dict:
        r = self._client.get(f"/internal/asset-reviews/{review_id}")
        r.raise_for_status()
        return r.json()

    def add_dns_record(self, engagement_id: uuid.UUID, **fields) -> dict:
        r = self._client.post(f"/internal/engagements/{engagement_id}/dns-records", json=fields)
        r.raise_for_status()
        return r.json()

    def add_service(self, engagement_id: uuid.UUID, **fields) -> dict:
        r = self._client.post(f"/internal/engagements/{engagement_id}/services", json=fields)
        r.raise_for_status()
        return r.json()

    def record_http_probe(self, engagement_id: uuid.UUID, asset_id: str, live: bool) -> None:
        """Records the fingerprint phase's httpx outcome regardless of live/dead
        - best effort, a telemetry failure must never break fingerprinting."""
        try:
            r = self._client.patch(
                f"/internal/engagements/{engagement_id}/discovered-assets/{asset_id}/http-probe",
                json={"live": live},
            )
            r.raise_for_status()
        except Exception:  # noqa: BLE001
            pass

    def add_finding(self, engagement_id: uuid.UUID, **fields) -> dict:
        r = self._client.post(f"/internal/engagements/{engagement_id}/findings", json=fields)
        r.raise_for_status()
        return r.json()

    def materialize_dns(self, engagement_id: uuid.UUID, scan_run_id: str | None = None) -> dict:
        params = {"scan_run_id": scan_run_id} if scan_run_id else None
        r = self._client.post(f"/internal/engagements/{engagement_id}/materialize-dns", params=params)
        r.raise_for_status()
        return r.json()

    def materialize_graph(self, engagement_id: uuid.UUID) -> dict:
        """REQ-GRAPH-001: (re)build the attack-surface graph at a scan-phase
        boundary. Best effort - a graph failure must never fail the scan; the
        deterministic phases and findings stand on their own."""
        try:
            r = self._client.post(f"/internal/engagements/{engagement_id}/materialize-graph")
            r.raise_for_status()
            return r.json()
        except Exception:  # noqa: BLE001
            return {"nodes": 0, "edges": 0}

    def get_agent_config(self, engagement_id: uuid.UUID) -> dict:
        """Effektive Agent-Konfig: aufgeloeste Anweisung + fuer diese Kampagne
        aktivierte Tools (Schichtenmodell im control-plane-Resolver)."""
        r = self._client.get(f"/internal/engagements/{engagement_id}/agent-config")
        r.raise_for_status()
        return r.json()

    def get_agent_context(self, engagement_id: uuid.UUID) -> dict:
        """Kompakte Evidenz je In-Scope-Host (Services + offene Findings) fuer
        das Reasoning des Vector Agent."""
        r = self._client.get(f"/internal/engagements/{engagement_id}/agent-context")
        r.raise_for_status()
        return r.json()

    def get_llm_config(self) -> dict:
        """OpenAI-kompatible Vector-Agent-Provider-Konfig (inkl. api_key). Nur
        ueber das cluster-interne Netz erreichbar; der Schluessel verlaesst das
        interne Netz nie."""
        r = self._client.get("/internal/llm-config")
        r.raise_for_status()
        return r.json()

    def get_nvd_config(self) -> dict:
        """Optionaler NVD-API-Key (REQ-CORR-008); unset ist ein gueltiger
        Zustand - die Korrelation nutzt dann NVDs oeffentliches Rate-Limit."""
        r = self._client.get("/internal/nvd-config")
        r.raise_for_status()
        return r.json()

    def get_cve_lookup_cache(self, product_key: str) -> dict | None:
        """Cached NVD-Kandidaten fuer ein Produkt (REQ-CORR-001/004). None =
        noch nie/nicht mehr gecacht - der Aufrufer fragt live bei NVD nach."""
        r = self._client.get("/internal/cve-lookup-cache", params={"product_key": product_key})
        if r.status_code == 404:
            return None
        r.raise_for_status()
        return r.json()

    def put_cve_lookup_cache(self, product_key: str, candidates: list[dict], source: str = "nvd") -> dict:
        r = self._client.put(
            "/internal/cve-lookup-cache",
            json={"product_key": product_key, "candidates": candidates, "source": source},
        )
        r.raise_for_status()
        return r.json()

    def get_epss_cache(self, cve_ids: list[str]) -> dict:
        """Batched (REQ-CORR-002/004). Response omits cache misses; the
        caller fetches those live from EPSS and writes them back."""
        if not cve_ids:
            return {"scores": {}, "fetched_at": {}}
        r = self._client.get("/internal/epss-cache", params={"cve_ids": ",".join(cve_ids)})
        r.raise_for_status()
        return r.json()

    def put_epss_cache(self, scores: dict[str, float]) -> None:
        if not scores:
            return
        entries = [{"cve_id": cid, "epss": epss} for cid, epss in scores.items()]
        r = self._client.put("/internal/epss-cache", json={"entries": entries})
        r.raise_for_status()

    def get_kev_catalog_cache(self) -> dict:
        r = self._client.get("/internal/kev-catalog-cache")
        r.raise_for_status()
        return r.json()

    def put_kev_catalog_cache(self, cve_ids: list[str], catalog_version: str | None) -> dict:
        r = self._client.put(
            "/internal/kev-catalog-cache",
            json={"cve_ids": cve_ids, "catalog_version": catalog_version},
        )
        r.raise_for_status()
        return r.json()

    def agent_event(self, engagement_id: uuid.UUID, **fields) -> dict:
        r = self._client.post(f"/internal/engagements/{engagement_id}/agent-events", json=fields)
        r.raise_for_status()
        return r.json()

    def record_tool_execution(self, engagement_id: uuid.UUID, **fields) -> dict:
        r = self._client.post(f"/internal/engagements/{engagement_id}/tool-executions", json=fields)
        r.raise_for_status()
        return r.json()

    def rescore(self, engagement_id: uuid.UUID) -> dict:
        r = self._client.post(f"/internal/engagements/{engagement_id}/rescore")
        r.raise_for_status()
        return r.json()

    def get_engagement(self, engagement_id: uuid.UUID) -> dict:
        r = self._client.get(f"/engagements/{engagement_id}")
        r.raise_for_status()
        return r.json()

    def list_scope_assets(self, engagement_id: uuid.UUID) -> list[dict]:
        r = self._client.get(f"/internal/engagements/{engagement_id}/scope-assets")
        r.raise_for_status()
        return r.json()

    def request_report(self, engagement_id: uuid.UUID, scan_run_id: uuid.UUID | None = None) -> dict:
        # REQ-REPORT-003: scoping the report to the run that just finished is
        # what makes its trend/diff section meaningful.
        params = {"scan_run_id": str(scan_run_id)} if scan_run_id else None
        r = self._client.post(f"/internal/engagements/{engagement_id}/report", params=params)
        r.raise_for_status()
        return r.json()


client = ControlPlaneClient()
