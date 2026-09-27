"""Passive DNS-Intelligenz fuer die Discovery-Phase (REQ-DNS-001..003).

Loest die CNAME-Kette eines in-scope FQDN auf, klassifiziert den Hosting-Provider
und erkennt Dangling-DNS (Subdomain-Takeover) - AUSSCHLIESSLICH auf DNS-Ebene.

Sicherheits-/Scope-Prinzip (siehe docs/requirements/dns-cname-inventory-and-takeover.md):
  - Der FQDN ist das Asset. Das CNAME-Ziel (elb.amazonaws.com, okta.com, ...) ist
    NUR Metadatum - es wird nie zu einem scanbaren Asset und nie materialisiert.
  - Dangling-Erkennung macht KEINE HTTP-Anfrage an das Drittziel (das waere ein
    Scan fremder Infrastruktur). Der DNS-Level-Befund wird als *inferred* Finding
    gemeldet; die Bestaetigung macht der Mensch.

Die eigentlichen DNS-Lookups liegen hinter einem schmalen `Resolver`-Protokoll,
damit die Logik hermetisch (ohne Netz) testbar ist. `SystemResolver` ist die
dnspython-Implementierung fuer den Produktivbetrieb.
"""

from __future__ import annotations

import dataclasses
from typing import Protocol

# Max. CNAME-Tiefe bevor abgebrochen wird (schuetzt gegen Ketten/Schleifen).
_MAX_CNAME_DEPTH = 10


class Resolver(Protocol):
    def cname(self, name: str) -> str | None:
        """Direktes CNAME-Ziel von `name` oder None, wenn keins existiert."""
        ...

    def addresses(self, name: str) -> list[str]:
        """A/AAAA-Adressen von `name`. Leer, wenn keine (NXDOMAIN/kein Record)."""
        ...


# (suffix, provider, {flags}, takeoverable) - Terminal (bzw. eine Kettenstufe)
# wird gegen diese Suffixe gematcht. takeoverable = bekannt claimbarer Dienst,
# erhoeht den Kontext eines Dangling-Befunds.
_PROVIDER_MAP: list[tuple[str, str, dict, bool]] = [
    (".elb.amazonaws.com", "aws-elb", {"is_shared_infra": True}, False),
    (".s3.amazonaws.com", "aws-s3", {"is_shared_infra": True}, True),
    (".s3-website", "aws-s3", {"is_shared_infra": True}, True),
    (".cloudfront.net", "aws-cloudfront", {"is_cdn": True}, True),
    (".execute-api.", "aws-apigateway", {"is_shared_infra": True}, False),
    (".elasticbeanstalk.com", "aws-elasticbeanstalk", {"is_shared_infra": True}, True),
    (".azurewebsites.net", "azure-appservice", {"is_shared_infra": True}, True),
    (".cloudapp.azure.com", "azure", {"is_shared_infra": True}, False),
    (".cloudapp.net", "azure", {"is_shared_infra": True}, True),
    (".trafficmanager.net", "azure-trafficmanager", {"is_shared_infra": True}, True),
    (".blob.core.windows.net", "azure-blob", {"is_shared_infra": True}, True),
    (".azureedge.net", "azure-cdn", {"is_cdn": True}, True),
    (".azurefd.net", "azure-frontdoor", {"is_cdn": True}, False),
    (".appspot.com", "gcp-appengine", {"is_shared_infra": True}, True),
    (".storage.googleapis.com", "gcp-storage", {"is_shared_infra": True}, True),
    (".fastly.net", "fastly", {"is_cdn": True}, True),
    (".cloudflare.net", "cloudflare", {"is_cdn": True}, False),
    (".cloudflare.com", "cloudflare", {"is_cdn": True}, False),
    (".github.io", "github-pages", {"is_saas": True}, True),
    (".herokuapp.com", "heroku", {"is_saas": True}, True),
    (".herokudns.com", "heroku", {"is_saas": True}, True),
    (".netlify.app", "netlify", {"is_saas": True}, True),
    (".netlify.com", "netlify", {"is_saas": True}, True),
    (".myshopify.com", "shopify", {"is_saas": True}, True),
    (".zendesk.com", "zendesk", {"is_saas": True}, True),
    (".readthedocs.io", "readthedocs", {"is_saas": True}, True),
    (".ghost.io", "ghost", {"is_saas": True}, True),
    (".surge.sh", "surge", {"is_saas": True}, True),
    (".okta.com", "okta", {"is_saas": True, "is_idp": True}, False),
    (".oktapreview.com", "okta", {"is_saas": True, "is_idp": True}, False),
    (".auth0.com", "auth0", {"is_saas": True, "is_idp": True}, False),
    (".onelogin.com", "onelogin", {"is_saas": True, "is_idp": True}, False),
]

_ALL_FLAGS = ("is_cdn", "is_saas", "is_idp", "is_shared_infra")


@dataclasses.dataclass
class DnsIntel:
    fqdn: str
    cname_chain: list[str]          # [fqdn, cname1, ..., terminal]
    terminal_target: str | None     # letztes CNAME-Ziel (None wenn kein CNAME)
    terminal_ips: list[str]
    hosting_provider: str | None
    is_cdn: bool
    is_saas: bool
    is_idp: bool
    is_shared_infra: bool
    dns_status: str                 # resolved | dangling | unresolved
    takeover_suspected: bool
    provider_takeoverable: bool

    def as_record(self, asset_id: str | None = None) -> dict:
        """JSON-Body fuer POST /internal/.../dns-records."""
        return {
            "asset_id": asset_id,
            "fqdn": self.fqdn,
            "cname_chain": self.cname_chain,
            "terminal_target": self.terminal_target,
            "terminal_ips": self.terminal_ips,
            "hosting_provider": self.hosting_provider,
            "is_cdn": self.is_cdn,
            "is_saas": self.is_saas,
            "is_idp": self.is_idp,
            "is_shared_infra": self.is_shared_infra,
            "dns_status": self.dns_status,
            "takeover_suspected": self.takeover_suspected,
        }


def _classify(names: list[str]) -> tuple[str | None, dict, bool]:
    """Provider + Flags + takeoverable fuer die erste passende Kettenstufe
    (Terminal zuerst, da am aussagekraeftigsten)."""
    for name in names:
        low = name.lower().rstrip(".")
        for suffix, provider, flags, takeoverable in _PROVIDER_MAP:
            if suffix in low:
                full = {f: bool(flags.get(f, False)) for f in _ALL_FLAGS}
                return provider, full, takeoverable
    return None, {f: False for f in _ALL_FLAGS}, False


def resolve_chain(fqdn: str, resolver: Resolver) -> DnsIntel:
    """Loest die CNAME-Kette + Terminal-Adressen auf und klassifiziert.

    Rein DNS-basiert; wirft nicht. Ein Aufloesungsfehler fuehrt zu
    dns_status='unresolved', nicht zu einer Exception."""
    fqdn = fqdn.lower().rstrip(".")
    chain = [fqdn]
    name = fqdn
    seen = {fqdn}
    for _ in range(_MAX_CNAME_DEPTH):
        target = resolver.cname(name)
        if not target:
            break
        target = target.lower().rstrip(".")
        chain.append(target)
        if target in seen:  # Schleife: abbrechen (Terminal ist der Loop-Punkt)
            break
        seen.add(target)
        name = target

    terminal_target = chain[-1] if len(chain) > 1 else None
    terminal_ips = sorted(resolver.addresses(name))

    # Klassifikation ueber Terminal zuerst, dann restliche Ketten-Hops.
    classify_order = [chain[-1]] + list(reversed(chain[:-1]))
    provider, flags, takeoverable = _classify(classify_order)

    has_cname = terminal_target is not None
    if terminal_ips:
        dns_status = "resolved"
        takeover_suspected = False
    elif has_cname:
        # CNAME zeigt ins Leere (NXDOMAIN / kein A/AAAA) -> Dangling.
        dns_status = "dangling"
        takeover_suspected = True
    else:
        # FQDN selbst ohne CNAME und ohne Adresse -> schlicht nicht aufloesbar.
        dns_status = "unresolved"
        takeover_suspected = False

    return DnsIntel(
        fqdn=fqdn,
        cname_chain=chain,
        terminal_target=terminal_target,
        terminal_ips=terminal_ips,
        hosting_provider=provider,
        is_cdn=flags["is_cdn"],
        is_saas=flags["is_saas"],
        is_idp=flags["is_idp"],
        is_shared_infra=flags["is_shared_infra"],
        dns_status=dns_status,
        takeover_suspected=takeover_suspected,
        provider_takeoverable=takeoverable,
    )


def takeover_finding(intel: DnsIntel, asset_id: str | None) -> dict:
    """Baut den Finding-Body fuer einen Dangling-/Takeover-Verdacht (inferred).

    Kein Nachweis per HTTP - der Befund ist DNS-Level und braucht menschliche
    Bestaetigung. Provider-Kontext hebt/senkt die Aussagekraft."""
    provider = intel.hosting_provider or "unknown"
    confidence_note = (
        f"points to a known claimable service ({provider})"
        if intel.provider_takeoverable
        else f"points to a non-resolving target (provider: {provider}, lower confidence)"
    )
    return {
        "asset_id": asset_id,
        "category": "misconfig",
        "title": "Potential subdomain takeover (dangling DNS)",
        "confidence": "inferred",
        "severity_override": "high" if intel.provider_takeoverable else "medium",
        "evidence": {
            "cname_chain": intel.cname_chain,
            "terminal_target": intel.terminal_target,
            "hosting_provider": provider,
            "detection": "dns-only",
            "note": (
                f"The CNAME chain for {intel.fqdn} {confidence_note} that returns no "
                "A/AAAA record. If the target service is unclaimed it may be "
                "registrable by an attacker (subdomain takeover). Verify manually; "
                "the scanner does not fetch the third-party target."
            ),
        },
        "raw_ref": " -> ".join(intel.cname_chain),
    }


class SystemResolver:
    """dnspython-basierter Resolver fuer den Produktivbetrieb."""

    def __init__(self, timeout: float = 5.0):
        import dns.resolver

        self._r = dns.resolver.Resolver()
        self._r.lifetime = timeout
        self._r.timeout = timeout

    def cname(self, name: str) -> str | None:
        import dns.resolver

        try:
            answer = self._r.resolve(name, "CNAME")
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
            return None
        except Exception:  # noqa: BLE001 - DNS-Fehler nie fatal fuer Discovery
            return None
        for rdata in answer:
            return str(rdata.target).rstrip(".")
        return None

    def addresses(self, name: str) -> list[str]:
        import dns.resolver

        ips: list[str] = []
        for rrtype in ("A", "AAAA"):
            try:
                for rdata in self._r.resolve(name, rrtype):
                    ips.append(str(rdata))
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
                continue
            except Exception:  # noqa: BLE001
                continue
        return ips
