"""TC-DNS-001 / TC-DNS-003: passive DNS-Intelligenz (CNAME-Kette, Provider,
Dangling-Erkennung). Hermetisch - kein Netz, ein Fake-Resolver injiziert."""

from app import dns_intel


class FakeResolver:
    """Dict-basierter Resolver: cnames[name]=target, addrs[name]=[ips]."""

    def __init__(self, cnames: dict, addrs: dict):
        self._cnames = cnames
        self._addrs = addrs

    def cname(self, name: str):
        return self._cnames.get(name.lower().rstrip("."))

    def addresses(self, name: str):
        return list(self._addrs.get(name.lower().rstrip("."), []))


# --- REQ-DNS-001 / REQ-DNS-002: Kette + Klassifikation --------------------

def test_resolves_cname_chain_and_terminal_ips():
    r = FakeResolver(
        cnames={"app.example.com": "myapp-prod-123.eu-central-1.elb.amazonaws.com"},
        addrs={"myapp-prod-123.eu-central-1.elb.amazonaws.com": ["1.2.3.4"]},
    )
    intel = dns_intel.resolve_chain("app.example.com", r)

    assert intel.cname_chain == ["app.example.com", "myapp-prod-123.eu-central-1.elb.amazonaws.com"]
    assert intel.terminal_target == "myapp-prod-123.eu-central-1.elb.amazonaws.com"
    assert intel.terminal_ips == ["1.2.3.4"]
    assert intel.hosting_provider == "aws-elb"
    assert intel.is_shared_infra is True
    assert intel.dns_status == "resolved"
    assert intel.takeover_suspected is False


def test_direct_a_record_no_cname_no_provider():
    r = FakeResolver(cnames={}, addrs={"www.example.com": ["93.184.216.34"]})
    intel = dns_intel.resolve_chain("www.example.com", r)

    assert intel.cname_chain == ["www.example.com"]
    assert intel.terminal_target is None
    assert intel.hosting_provider is None
    assert not any([intel.is_cdn, intel.is_saas, intel.is_idp, intel.is_shared_infra])
    assert intel.dns_status == "resolved"


def test_idp_classification_okta():
    r = FakeResolver(
        cnames={"portal.example.com": "company.okta.com"},
        addrs={"company.okta.com": ["5.6.7.8"]},
    )
    intel = dns_intel.resolve_chain("portal.example.com", r)
    assert intel.hosting_provider == "okta"
    assert intel.is_idp is True and intel.is_saas is True


def test_cname_loop_terminates_without_error():
    r = FakeResolver(
        cnames={"a.example.com": "b.example.com", "b.example.com": "a.example.com"},
        addrs={},
    )
    intel = dns_intel.resolve_chain("a.example.com", r)
    # bricht ab, keine Endlosschleife; Terminal ist der Loop-Punkt
    assert "a.example.com" in intel.cname_chain and "b.example.com" in intel.cname_chain
    assert intel.dns_status == "dangling"  # keine Adresse aufloesbar


def test_deep_chain_capped():
    cnames = {f"h{i}.example.com": f"h{i+1}.example.com" for i in range(50)}
    r = FakeResolver(cnames=cnames, addrs={})
    intel = dns_intel.resolve_chain("h0.example.com", r)
    assert len(intel.cname_chain) <= dns_intel._MAX_CNAME_DEPTH + 1


# --- REQ-DNS-001 NEGATIV: CNAME-Ziel wird nie zum Asset -------------------

def test_cname_target_is_metadata_only_never_an_asset():
    """Die Scope-Invariante: das CNAME-Ziel taucht NUR in den Metadaten auf,
    nie als eigenstaendiger Asset-Wert. as_record() traegt den FQDN als Asset,
    das Ziel steckt ausschliesslich in chain/terminal_target."""
    r = FakeResolver(
        cnames={"app.example.com": "x.elb.amazonaws.com"},
        addrs={"x.elb.amazonaws.com": ["1.2.3.4"]},
    )
    intel = dns_intel.resolve_chain("app.example.com", r)
    record = intel.as_record(asset_id="asset-123")

    assert record["fqdn"] == "app.example.com"
    assert record["asset_id"] == "asset-123"
    # das CNAME-Ziel ist NUR Metadatum
    assert record["terminal_target"] == "x.elb.amazonaws.com"
    assert "x.elb.amazonaws.com" in record["cname_chain"]
    # es gibt keinen Weg, ueber das record das Ziel als eigenes Asset zu setzen
    assert record["fqdn"] != record["terminal_target"]


# --- REQ-DNS-003: Dangling / Takeover -------------------------------------

def test_dangling_cname_to_nxdomain_flags_takeover():
    r = FakeResolver(
        cnames={"orphan.example.com": "deleted-bucket.s3.amazonaws.com"},
        addrs={},  # Ziel loest nicht auf -> NXDOMAIN
    )
    intel = dns_intel.resolve_chain("orphan.example.com", r)
    assert intel.dns_status == "dangling"
    assert intel.takeover_suspected is True
    assert intel.hosting_provider == "aws-s3"
    assert intel.provider_takeoverable is True


def test_takeover_finding_body_is_inferred_and_dns_only():
    r = FakeResolver(cnames={"orphan.example.com": "deleted.github.io"}, addrs={})
    intel = dns_intel.resolve_chain("orphan.example.com", r)
    finding = dns_intel.takeover_finding(intel, asset_id="asset-9")

    assert finding["category"] == "misconfig"
    assert finding["confidence"] == "inferred"
    assert finding["asset_id"] == "asset-9"
    assert finding["evidence"]["detection"] == "dns-only"
    assert finding["evidence"]["cname_chain"] == intel.cname_chain
    assert finding["severity_override"] == "high"  # github-pages ist takeoverable


def test_resolving_chain_produces_no_takeover():
    r = FakeResolver(
        cnames={"cdn.example.com": "d123.cloudfront.net"},
        addrs={"d123.cloudfront.net": ["13.14.15.16"]},
    )
    intel = dns_intel.resolve_chain("cdn.example.com", r)
    assert intel.dns_status == "resolved"
    assert intel.takeover_suspected is False
    assert intel.is_cdn is True


def test_fqdn_without_any_record_is_unresolved_not_dangling():
    r = FakeResolver(cnames={}, addrs={})
    intel = dns_intel.resolve_chain("gone.example.com", r)
    assert intel.dns_status == "unresolved"
    assert intel.takeover_suspected is False
