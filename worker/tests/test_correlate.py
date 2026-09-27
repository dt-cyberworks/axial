"""REQ-CORR-001..008: live NVD/EPSS/KEV correlation phase."""

from __future__ import annotations

import datetime as dt

from app.tasks import correlate


class RecordingClient:
    def __init__(self):
        self.nvd_api_key = None
        self._cve_cache: dict[str, dict] = {}
        self._epss_scores: dict[str, float] = {}
        self._kev = {"cve_ids": [], "catalog_version": None, "fetched_at": None}
        self.findings: list[dict] = []
        self.put_cve_calls: list[tuple] = []
        self.put_epss_calls: list[dict] = []
        self.put_kev_calls: list[tuple] = []

    def seed_cve_cache(self, product_key: str, candidates: list[dict], *, stale: bool = False):
        fetched_at = dt.datetime.now(dt.timezone.utc) - (
            dt.timedelta(hours=48) if stale else dt.timedelta(minutes=1)
        )
        self._cve_cache[product_key] = {
            "product_key": product_key, "candidates": candidates,
            "fetched_at": fetched_at.isoformat(), "source": "nvd",
        }

    def seed_kev_cache(self, cve_ids: list[str], *, stale: bool = False):
        fetched_at = dt.datetime.now(dt.timezone.utc) - (
            dt.timedelta(hours=48) if stale else dt.timedelta(minutes=1)
        )
        self._kev = {"cve_ids": cve_ids, "catalog_version": "seed", "fetched_at": fetched_at.isoformat()}

    def get_nvd_config(self):
        return {"api_key": self.nvd_api_key, "source": "unset"}

    def get_cve_lookup_cache(self, product_key):
        return self._cve_cache.get(product_key)

    def put_cve_lookup_cache(self, product_key, candidates, source="nvd"):
        self.put_cve_calls.append((product_key, candidates))
        self._cve_cache[product_key] = {
            "product_key": product_key, "candidates": candidates,
            "fetched_at": dt.datetime.now(dt.timezone.utc).isoformat(), "source": source,
        }
        return self._cve_cache[product_key]

    def get_epss_cache(self, cve_ids):
        scores = {c: self._epss_scores[c] for c in cve_ids if c in self._epss_scores}
        return {"scores": scores, "fetched_at": {}}

    def put_epss_cache(self, scores):
        self.put_epss_calls.append(dict(scores))
        self._epss_scores.update(scores)

    def get_kev_catalog_cache(self):
        return self._kev

    def put_kev_catalog_cache(self, cve_ids, catalog_version):
        self.put_kev_calls.append((cve_ids, catalog_version))
        self._kev = {"cve_ids": cve_ids, "catalog_version": catalog_version,
                     "fetched_at": dt.datetime.now(dt.timezone.utc).isoformat()}
        return self._kev

    def add_finding(self, engagement_id, **fields):
        self.findings.append(fields)
        return {"id": f"finding-{len(self.findings)}"}


def _nmap_service(**overrides) -> dict:
    base = {
        "product": "OpenSSH 8.9p1", "product_name": "OpenSSH", "version": "8.9p1",
        "asset_id": "asset-1", "service_id": "service-1", "target": "real.example.com",
        "port": 22, "protocol": "tcp",
    }
    base.update(overrides)
    return base


def test_skips_lab_targets_without_any_network_call(monkeypatch):
    rec = RecordingClient()
    monkeypatch.setattr(correlate, "client", rec)
    monkeypatch.setattr(correlate, "fetch_nvd_candidates", lambda *a, **k: (_ for _ in ()).throw(AssertionError("must not call NVD for lab targets")))

    services = [_nmap_service(target="metasploitable2")]
    result = correlate.run("eng-1", services)

    assert result == []
    assert rec.findings == []


def test_nmap_banner_in_range_produces_kev_and_epss_enriched_finding(monkeypatch):
    rec = RecordingClient()
    monkeypatch.setattr(correlate, "client", rec)
    monkeypatch.setattr(
        correlate, "fetch_nvd_candidates",
        lambda key, api_key=None: [{
            "cve_id": "CVE-2024-1111", "cvss_base": 9.8,
            "version_start_including": "8.0", "version_end_excluding": "9.0",
        }],
    )
    monkeypatch.setattr(correlate, "fetch_epss_scores", lambda ids: {"CVE-2024-1111": 0.87})
    monkeypatch.setattr(correlate, "fetch_kev_catalog", lambda: (["CVE-2024-1111"], "2026.07.01"))

    result = correlate.run("eng-1", [_nmap_service()])

    assert len(result) == 1
    f = rec.findings[0]
    assert f["cve_ids"] == ["CVE-2024-1111"]
    assert f["cvss_base"] == 9.8
    assert f["epss"] == 0.87
    assert f["is_kev"] is True
    assert f["confidence"] == "inferred"
    assert f["category"] == "cve"
    assert f["evidence"]["source"] == "nmap_banner"
    assert f["asset_id"] == "asset-1" and f["service_id"] == "service-1"
    # cache was populated for reuse
    assert rec.put_cve_calls and rec.put_cve_calls[0][0] == "openssh"


def test_version_out_of_range_produces_no_finding(monkeypatch):
    rec = RecordingClient()
    monkeypatch.setattr(correlate, "client", rec)
    monkeypatch.setattr(
        correlate, "fetch_nvd_candidates",
        lambda key, api_key=None: [{
            "cve_id": "CVE-2024-2222", "cvss_base": 9.8,
            "version_start_including": "1.0", "version_end_excluding": "2.0",
        }],
    )
    monkeypatch.setattr(correlate, "fetch_epss_scores", lambda ids: {})
    monkeypatch.setattr(correlate, "fetch_kev_catalog", lambda: ([], None))

    result = correlate.run("eng-1", [_nmap_service(version="8.9p1")])

    assert result == []
    assert rec.findings == []


def test_httpx_tech_stack_entry_with_version_is_correlated(monkeypatch):
    rec = RecordingClient()
    monkeypatch.setattr(correlate, "client", rec)
    monkeypatch.setattr(
        correlate, "fetch_nvd_candidates",
        lambda key, api_key=None: [{"cve_id": "CVE-2024-3333", "cvss_base": 7.5}],
    )
    monkeypatch.setattr(correlate, "fetch_epss_scores", lambda ids: {})
    monkeypatch.setattr(correlate, "fetch_kev_catalog", lambda: ([], None))

    entry = {
        "tech": ["WordPress:6.4.2", "nginx"], "asset_id": "asset-2", "service_id": "service-2",
        "target": "real.example.com", "url": "https://real.example.com",
    }
    result = correlate.run("eng-1", [entry])

    assert len(result) == 1
    f = rec.findings[0]
    assert f["evidence"]["source"] == "httpx_tech_stack"
    assert f["evidence"]["product"] == "WordPress"
    assert f["epss"] is None  # REQ-CORR-002: no score available -> None, not 0


def test_tech_entry_without_version_is_never_correlated(monkeypatch):
    rec = RecordingClient()
    monkeypatch.setattr(correlate, "client", rec)
    monkeypatch.setattr(correlate, "fetch_nvd_candidates", lambda *a, **k: (_ for _ in ()).throw(AssertionError("no version -> must not query NVD")))

    entry = {"tech": ["nginx"], "asset_id": "asset-3", "service_id": "service-3", "target": "real.example.com"}
    result = correlate.run("eng-1", [entry])

    assert result == []


def test_fresh_cve_cache_is_used_without_a_new_nvd_call(monkeypatch):
    rec = RecordingClient()
    rec.seed_cve_cache("openssh", [{"cve_id": "CVE-2024-4444", "cvss_base": 6.0}], stale=False)
    monkeypatch.setattr(correlate, "client", rec)
    monkeypatch.setattr(correlate, "fetch_nvd_candidates", lambda *a, **k: (_ for _ in ()).throw(AssertionError("fresh cache must short-circuit NVD")))
    monkeypatch.setattr(correlate, "fetch_epss_scores", lambda ids: {})
    monkeypatch.setattr(correlate, "fetch_kev_catalog", lambda: ([], None))

    result = correlate.run("eng-1", [_nmap_service()])

    assert len(result) == 1
    assert rec.put_cve_calls == []  # never re-written, cache hit


def test_stale_cve_cache_triggers_refetch(monkeypatch):
    rec = RecordingClient()
    rec.seed_cve_cache("openssh", [{"cve_id": "CVE-OLD", "cvss_base": 1.0}], stale=True)
    monkeypatch.setattr(correlate, "client", rec)
    called = []
    monkeypatch.setattr(
        correlate, "fetch_nvd_candidates",
        lambda key, api_key=None: called.append(key) or [{"cve_id": "CVE-NEW", "cvss_base": 9.0}],
    )
    monkeypatch.setattr(correlate, "fetch_epss_scores", lambda ids: {})
    monkeypatch.setattr(correlate, "fetch_kev_catalog", lambda: ([], None))

    result = correlate.run("eng-1", [_nmap_service()])

    assert called == ["openssh"]
    assert len(result) == 1
    assert rec.findings[0]["cve_ids"] == ["CVE-NEW"]


def test_nvd_unreachable_returns_no_findings_without_raising(monkeypatch):
    rec = RecordingClient()
    monkeypatch.setattr(correlate, "client", rec)
    monkeypatch.setattr(correlate, "fetch_nvd_candidates", lambda *a, **k: None)  # simulated failure
    monkeypatch.setattr(correlate, "fetch_epss_scores", lambda ids: {})
    monkeypatch.setattr(correlate, "fetch_kev_catalog", lambda: ([], None))

    result = correlate.run("eng-1", [_nmap_service()])

    assert result == []
    assert rec.findings == []
    assert rec.put_cve_calls == []  # a failed fetch is never cached as if it were a real (empty) result


def test_epss_and_kev_are_fetched_at_most_once_per_run(monkeypatch):
    rec = RecordingClient()
    monkeypatch.setattr(correlate, "client", rec)
    monkeypatch.setattr(
        correlate, "fetch_nvd_candidates",
        lambda key, api_key=None: [
            {"cve_id": "CVE-A", "cvss_base": 5.0},
            {"cve_id": "CVE-B", "cvss_base": 6.0},
        ],
    )
    epss_calls = []
    kev_calls = []
    monkeypatch.setattr(correlate, "fetch_epss_scores", lambda ids: epss_calls.append(sorted(ids)) or {"CVE-A": 0.1, "CVE-B": 0.2})
    monkeypatch.setattr(correlate, "fetch_kev_catalog", lambda: kev_calls.append(1) or (["CVE-A"], "v1"))

    services = [
        _nmap_service(asset_id="a1", service_id="s1", product_name="OpenSSH", version="8.9p1"),
        _nmap_service(asset_id="a2", service_id="s2", product_name="OpenSSH", version="8.9p2"),
    ]
    result = correlate.run("eng-1", services)

    assert len(epss_calls) == 1  # one batched call, not per-service/per-CVE
    assert len(kev_calls) == 1
    assert len(result) == 4  # 2 services x 2 CVE candidates each (no version constraint on these candidates)
