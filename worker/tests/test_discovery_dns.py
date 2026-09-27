"""TC-DNS-003: Discovery-Integration der DNS-Anreicherung.

Prueft die Scope-Invariante (REQ-DNS-001) END-TO-END im Discovery-Schritt:
- ein CNAME-Ziel wird NIE per add_discovered_asset angelegt,
- ein Dangling-FQDN erzeugt genau ein inferred Takeover-Finding,
- fuer in-scope FQDN wird ein dns_record geschrieben,
- out-of-scope und Lab-Hosts (ohne Punkt) werden uebersprungen.
"""

from app.tasks import discovery


class FakeResolver:
    """Dict-basierter Resolver: cnames[name]=target, addrs[name]=[ips]."""

    def __init__(self, cnames: dict, addrs: dict):
        self._cnames = cnames
        self._addrs = addrs

    def cname(self, name: str):
        return self._cnames.get(name.lower().rstrip("."))

    def addresses(self, name: str):
        return list(self._addrs.get(name.lower().rstrip("."), []))


class RecordingClient:
    def __init__(self):
        self.discovered_assets = []
        self.dns_records = []
        self.findings = []

    def add_discovered_asset(self, engagement_id, **fields):
        self.discovered_assets.append(fields)
        return {"id": "asset-x"}

    def add_dns_record(self, engagement_id, **fields):
        self.dns_records.append(fields)
        return {"id": "dns-x"}

    def add_finding(self, engagement_id, **fields):
        self.findings.append(fields)
        return {"id": "finding-x"}


def _assets():
    return [
        {"value": "app.example.com", "asset_id": "a1", "in_scope": True},
        {"value": "orphan.example.com", "asset_id": "a2", "in_scope": True},
        {"value": "metasploitable2", "asset_id": "a3", "in_scope": True},   # Lab-Host, kein Punkt
        {"value": "external.other.com", "asset_id": "a4", "in_scope": False},  # out of scope
    ]


def test_enrich_dns_never_creates_asset_for_cname_target(monkeypatch):
    rec = RecordingClient()
    monkeypatch.setattr(discovery, "client", rec)
    resolver = FakeResolver(
        cnames={
            "app.example.com": "x.elb.amazonaws.com",
            "orphan.example.com": "deleted.github.io",
        },
        addrs={"x.elb.amazonaws.com": ["1.2.3.4"]},  # orphan-Ziel loest NICHT auf
    )

    discovery._enrich_dns("eng-1", _assets(), resolver=resolver)

    # NEGATIV-KERN: die Anreicherung legt KEINE Assets an - schon gar nicht das
    # CNAME-Ziel x.elb.amazonaws.com.
    assert rec.discovered_assets == []
    all_dns_targets = {r["terminal_target"] for r in rec.dns_records}
    assert "x.elb.amazonaws.com" in all_dns_targets      # nur als Metadatum
    assert "deleted.github.io" in all_dns_targets


def test_enrich_dns_writes_record_only_for_inscope_dotted_fqdns(monkeypatch):
    rec = RecordingClient()
    monkeypatch.setattr(discovery, "client", rec)
    resolver = FakeResolver(
        cnames={"app.example.com": "x.elb.amazonaws.com", "orphan.example.com": "deleted.github.io"},
        addrs={"x.elb.amazonaws.com": ["1.2.3.4"]},
    )

    discovery._enrich_dns("eng-1", _assets(), resolver=resolver)

    fqdns = {r["fqdn"] for r in rec.dns_records}
    assert fqdns == {"app.example.com", "orphan.example.com"}
    assert "metasploitable2" not in fqdns      # Lab-Host ohne Punkt: uebersprungen
    assert "external.other.com" not in fqdns   # out of scope: uebersprungen


def test_enrich_dns_raises_takeover_finding_for_dangling(monkeypatch):
    rec = RecordingClient()
    monkeypatch.setattr(discovery, "client", rec)
    resolver = FakeResolver(
        cnames={"app.example.com": "x.elb.amazonaws.com", "orphan.example.com": "deleted.github.io"},
        addrs={"x.elb.amazonaws.com": ["1.2.3.4"]},
    )

    discovery._enrich_dns("eng-1", _assets(), resolver=resolver)

    # Genau EIN Takeover-Finding: fuer den Dangling-FQDN, nicht fuer den gesunden.
    assert len(rec.findings) == 1
    f = rec.findings[0]
    assert f["asset_id"] == "a2"
    assert f["category"] == "misconfig"
    assert f["confidence"] == "inferred"
    assert f["evidence"]["detection"] == "dns-only"


def test_enrich_dns_survives_resolver_error(monkeypatch):
    rec = RecordingClient()
    monkeypatch.setattr(discovery, "client", rec)

    class BoomResolver:
        def cname(self, name): raise RuntimeError("dns down")
        def addresses(self, name): return []

    # darf nicht werfen (DNS-Fehler bricht Discovery nie ab)
    discovery._enrich_dns("eng-1", _assets(), resolver=BoomResolver())
    assert rec.dns_records == [] and rec.findings == []
