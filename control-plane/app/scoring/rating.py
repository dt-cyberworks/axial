"""What a finding may be rated (REQ-SCORE-001..005, GitHub #87).

A tool's severity label is EVIDENCE of what the tool saw, not the platform's rating. testssl rates any trust failure `HIGH`, so a
certificate-name mismatch on an IMAPS port was shown as "high, 70.0": the label was copied into the severity and the score was then
pinned to the floor of the band (REQ-AGENT-010). A configuration or hygiene note with no demonstrated exploit is not a high finding.

The rule is a small table, written down so it can be read, tested and changed in one place. A finding is put in a CLASS, and the
class decides the highest severity it can have:

  proven     a vulnerability with a CVE, a known-exploited one, or one a curated probe demonstrated  - the label is kept, as before
  weakness   a real weakness with a realistic attack path that needs preconditions                    - at most `medium`
  hardening  a hardening gap with limited effect                                                      - at most `low`
  hygiene    a configuration or hygiene note with no demonstrated exploit                             - `info`

The rule applies to the findings whose label is a tool's opinion about a CONFIGURATION: today the testssl checks. It does not touch a
finding that carries its own proof: an agent finding with direct technical proof (REQ-FIDELITY-004), a curated probe's confirmed result,
a nuclei template hit, or anything with a CVE, KEV or high EPSS. Those keep their label and go through the CVE model as before.

`rate_finding` is the only function that decides this; `add_finding` and the re-score both call it, so a new observation and an old
row end up with the same rating.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# The highest severity a class can reach. `proven` has no ceiling: the label stands.
CLASS_CEILING: dict[str, str | None] = {"proven": None, "weakness": "medium", "hardening": "low", "hygiene": "info"}

# The score of a finding rated by class (REQ-SCORE-003): a fixed point inside its band, not a measurement. Every value sits in the
# band `compute_severity` maps to the same severity, so the number never contradicts the word.
CLASS_SCORE = {"info": 5.0, "low": 25.0, "medium": 55.0}

# EPSS at or above this makes a finding `proven` whatever else is said: it is being exploited or is likely to be.
HIGH_EPSS = 0.10

# --- the testssl table ---------------------------------------------------------------------------------------------------
# Keys are lower-case testssl check ids. An id in the table is classed by the table alone, even if testssl also names a CVE
# for it: the issue's own examples (LUCKY13: CBC ciphers that are weak but unbroken) are in the table on purpose.
# Anything NOT in the table is classed `proven` if testssl names a CVE for it, else `weakness` (a label cannot claim more than
# `medium` for a configuration it cannot show to be exploitable).

TESTSSL_CLASS: dict[str, str] = {}


def _put(cls: str, *ids: str) -> None:
    for check in ids:
        TESTSSL_CLASS[check] = cls


# Certificate and trust notes, TLS feature notes, banners, CBC ciphers that are weak but unbroken.
_put("hygiene",
     "cert_trust", "cert_chain_of_trust", "cert_commonname", "cert_commonname_wo_sni", "cert_subjectaltname",
     "cert_caissuers", "cert_crldistributionpoints", "cert_ocspurl", "cert_mustStapleExtension".lower(),
     "ocsp_stapling", "dns_caarecord", "certificate_transparency", "cert_certificatepolicies_ev", "cert_extlifespan",
     "cert_serialnumber", "cert_numbers", "intermediate_cert", "cert_compression",
     "tls_extensions", "session_ticket", "sessionresumption_ticket", "sessionresumption_id", "ssl_sessionid_support",
     "tls_timestamp", "http_clock_skew", "banner_server", "banner_application", "banner_reverseproxy",
     "lucky13", "beast", "beast_cbc_tls1")

# Hardening gaps with limited effect: header and cookie hygiene, cipher preference, cipher classes that are old but not broken,
# deprecated protocol versions, certificate lifetime. DEFAULTS that johannes may change in this table (GitHub #87 left an
# expired certificate and a deprecated protocol to him): an expired or not-yet-valid certificate and TLS 1.0/1.1 stay above `info`, at `low`.
_put("hardening",
     "hsts", "hsts_time", "hsts_subdomains", "hsts_preload", "hpkp", "cookie_count", "security_headers",
     "fallback_scsv", "cipher_order", "cipherlist_average", "cipherlist_obsoleted", "cipherlist_3des_idea",
     "tls1", "tls1_1", "cert_expirationstatus", "cert_notafter", "cert_notbefore", "cert_validityperiod")

# Real weaknesses an attacker can use under conditions: protocols and cipher classes with known breaks, a short key, a weak signature.
_put("weakness",
     "sslv2", "sslv3", "cipherlist_null", "cipherlist_anull", "cipherlist_export", "cipherlist_low",
     "cert_keysize", "cert_signaturealgorithm")

_CHECK_SUFFIX = re.compile(r"\s*<[^>]*>\s*$|\s+#\d+\s*$")


def normalize_check_id(check: str | None) -> str:
    """testssl numbers repeated checks ("cert_trust <cert#1>"); the table is keyed by the plain id."""
    return _CHECK_SUFFIX.sub("", str(check or "")).strip().lower()


@dataclass(frozen=True)
class Rating:
    severity: str
    risk_score: float | None      # None: the caller keeps its own score (a `proven` finding, rated as before)
    rating_class: str
    tool_label: str | None
    why: str

    def as_evidence(self) -> dict:
        return {"class": self.rating_class, "tool_label": self.tool_label, "why": self.why}


_WHY = {
    "hygiene": "A configuration or hygiene note with no demonstrated exploit, so it is rated informational. The tool's own label ({label}) "
               "is kept as evidence, not as the rating.",
    "hardening": "A hardening gap with limited effect and no demonstrated exploit, so it is rated at most low. The tool's own label "
                 "({label}) is kept as evidence, not as the rating.",
    "weakness": "A weakness that needs preconditions to be used and has no demonstrated exploit, so it is rated at most medium. The tool's "
                "own label ({label}) is kept as evidence, not as the rating.",
}


def rate_finding(
    *, label: str | None, evidence: dict | None, cve_ids: list[str] | None, is_kev: bool, epss: float | None,
) -> Rating | None:
    """The rating of a finding whose label is a tool's opinion about a configuration, or None when this rule does not apply.

    None means: keep the label and score as `add_finding` always did (an agent finding with direct proof, a nuclei hit, a curated
    probe, a CVE-based finding)."""
    ev = evidence if isinstance(evidence, dict) else {}
    if ev.get("tool") != "testssl" or label not in SEVERITY_RANK:
        return None
    check = normalize_check_id(ev.get("check"))
    named_cves = bool(cve_ids) or bool(ev.get("cve"))
    cls = TESTSSL_CLASS.get(check)
    if cls is None:
        cls = "proven" if named_cves else "weakness"
    # A known-exploited or likely-exploited vulnerability is `proven` unless the table says it is only a note.
    if cls != "hygiene" and (is_kev or (epss is not None and epss >= HIGH_EPSS)):
        cls = "proven"
    ceiling = CLASS_CEILING[cls]
    if ceiling is None:
        return Rating(label, None, "proven", label, "Rated by the vulnerability model: the finding names a CVE or is known to be exploited, "
                      f"so the tool's label ({label}) is kept.")
    severity = label if SEVERITY_RANK[label] <= SEVERITY_RANK[ceiling] else ceiling
    return Rating(severity, CLASS_SCORE[severity], cls, label, _WHY[cls].format(label=label))
