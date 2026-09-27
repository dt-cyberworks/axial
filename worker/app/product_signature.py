"""Normalizes free-text product/tech signals into (name, version) pairs for
live CVE correlation (REQ-CORR-001/007). Pure, DB-free functions.
"""

from __future__ import annotations

import re


def normalize_product_key(name: str) -> str:
    """Cache/NVD-keywordSearch key: collapse whitespace, lowercase. Deliberately
    simple - the NVD lookup itself (correlate.py) tolerates an imprecise key,
    it only widens/narrows candidate recall, never scope or safety."""
    return re.sub(r"\s+", " ", name.strip().lower())


def split_tech_entry(raw: str) -> tuple[str, str | None]:
    """httpx/Wappalyzer-style tech-stack entries are commonly 'Name:Version'
    when a version was detected and bare 'Name' otherwise (REQ-CORR-007) -
    to be confirmed against real httpx output during QA, same as any other
    tool-output assumption in this project."""
    raw = raw.strip()
    if ":" in raw:
        name, _, version = raw.partition(":")
        name, version = name.strip(), version.strip()
        return name, (version or None)
    return raw, None
