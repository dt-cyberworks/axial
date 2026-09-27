"""Best-effort version ordering/range check for live CVE correlation
(REQ-CORR-001). Real-world nmap/httpx version strings ('8.9p1', '2.4.52',
'Ubuntu-3ubuntu0.6') are not semver or Debian-policy versions, so this is a
deliberately approximate, "good enough for range checks" comparator - not a
claim of full correctness for every upstream versioning scheme. Pure,
DB-free functions.
"""

from __future__ import annotations

import re

_TOKEN_RE = re.compile(r"\d+|[A-Za-z]+")


def _tokenize(version: str) -> list[int | str]:
    return [int(t) if t.isdigit() else t.lower() for t in _TOKEN_RE.findall(version)]


def compare_versions(a: str, b: str) -> int:
    """-1 if a<b, 0 if equal (by tokenization), 1 if a>b."""
    ta, tb = _tokenize(a), _tokenize(b)
    for x, y in zip(ta, tb):
        if x == y:
            continue
        if type(x) is type(y):
            return -1 if x < y else 1
        # Mismatched token types at the same position (e.g. a numeric build
        # tag lined up against a letter suffix) - compare as strings rather
        # than raising, this is inherently a fuzzy comparison already.
        xs, ys = str(x), str(y)
        if xs == ys:
            continue
        return -1 if xs < ys else 1
    if len(ta) != len(tb):
        return -1 if len(ta) < len(tb) else 1
    return 0


def version_in_range(
    version: str,
    *,
    start_including: str | None = None,
    start_excluding: str | None = None,
    end_including: str | None = None,
    end_excluding: str | None = None,
    exact_versions: list[str] | None = None,
) -> bool:
    """True if `version` falls inside the given NVD-style affected-version
    constraint. A candidate with none of these set has no version constraint
    at all (NVD's own data model for "every version of this CPE is
    affected") and matches any supplied version."""
    if exact_versions:
        return version in exact_versions
    if start_including is not None and compare_versions(version, start_including) < 0:
        return False
    if start_excluding is not None and compare_versions(version, start_excluding) <= 0:
        return False
    if end_including is not None and compare_versions(version, end_including) > 0:
        return False
    if end_excluding is not None and compare_versions(version, end_excluding) >= 0:
        return False
    return True
