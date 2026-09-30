"""Lokale CVE-Zuordnung fuer bekannte, offensichtlich verwundbare Versionen.

Alternative zur NVD-API (Spezifikation Kap. 3.3: "Versionserkennung ->
Abgleich gegen CVE-Datenbank (NVD-API oder lokale Kopie)"). Bewusst klein und
statisch gehalten - deckt die Ziele aus lab/expected_findings.yaml ab
(Metasploitable2-Familie), damit der Lab-Testloop echte, korrekte
CVE-Findings ohne Internet-Abhaengigkeit erzeugt. Fuer echte Kundenziele
(M2) durch einen NVD-API-Abgleich ersetzen/ergaenzen (s. TODO in
worker/app/tasks/correlate.py).
"""

from __future__ import annotations

import dataclasses


@dataclasses.dataclass
class KnownVuln:
    product_contains: str          # lowercase Teilstring im nmap-Produktnamen
    cve_ids: list[str]
    cvss_base: float
    epss: float
    is_kev: bool
    title: str
    version_prefix: str | None = None  # optionaler Versions-Praefix-Filter


# Referenz-Gewichte: CVSS aus der jeweiligen NVD-Eintragung, EPSS grob
# approximiert (real: EPSS-API). is_kev nur bei tatsaechlich in der
# CISA-KEV-Liste gefuehrten CVEs auf True gesetzt.
KNOWN_VULNS: list[KnownVuln] = [
    KnownVuln("vsftpd", ["CVE-2011-2523"], 9.8, 0.94, True,
              "vsftpd 2.3.4 - Backdoor Command Execution", "2.3.4"),
    KnownVuln("distccd", ["CVE-2004-2687"], 9.8, 0.90, False,
              "distcc daemon - Remote Command Execution"),
    KnownVuln("samba", ["CVE-2007-2447"], 10.0, 0.85, False,
              "Samba usermap_script - Remote Command Execution", "3.0.2"),
    KnownVuln("unrealircd", ["CVE-2010-2075"], 9.8, 0.88, False,
              "UnrealIRCd - Backdoor Command Execution"),
    KnownVuln("proftpd", ["CVE-2010-4221"], 7.5, 0.60, False,
              "ProFTPd - Remote Command Execution (Telnet IAC)"),
    KnownVuln("openssh", ["CVE-2016-6210"], 5.9, 0.10, False,
              "OpenSSH - outdated version"),
    KnownVuln("apache tomcat", ["CVE-2009-2693"], 6.4, 0.20, False,
              "Apache Tomcat - outdated version"),
    KnownVuln("mysql", ["CVE-2012-2122"], 7.5, 0.30, False,
              "MySQL - authentication bypass on repeated login"),
]


def lookup(product: str | None, version: str | None) -> KnownVuln | None:
    if not product:
        return None
    normalized = product.lower()
    for entry in KNOWN_VULNS:
        if entry.product_contains not in normalized:
            continue
        # REQ-CORR-006: an entry that requires a specific version_prefix must
        # NOT match when no version was supplied at all - previously `version`
        # being falsy short-circuited the check entirely, so any product-name
        # substring match fired regardless of detected version (e.g. every
        # vsftpd version, not just 2.3.4). Fail closed instead: no version
        # data means no confirmed match for a version-gated entry.
        if entry.version_prefix and not (version and version.startswith(entry.version_prefix)):
            continue
        return entry
    return None
