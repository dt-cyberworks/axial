"""Shared lab-vs-real-target detection (REQ-CORR-006).

A scope value without a dot cannot be a real DNS name (Docker-internal lab
hostnames like 'metasploitable2' have no public DNS/certificate-transparency
entry) - discovery.py already uses exactly this rule to route lab hosts
around the passive-OSINT-only real-domain path. Extracted here so any other
module that needs the same lab/real distinction (e.g. correlate.py routing
between the static lab CVE table and live NVD/EPSS/KEV) uses one definition,
not a second ad hoc flag.
"""

from __future__ import annotations


def is_lab_host(value: str) -> bool:
    return "." not in value
