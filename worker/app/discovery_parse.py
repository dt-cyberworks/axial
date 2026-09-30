"""Parsers for crawler / URL-history output (REQ-COVER-003).

Pure functions: no network, no control-plane access. Scope filtering is NOT
done here - callers filter with the engagement's rules before anything is
stored or handed to another tool.
"""

from __future__ import annotations

import json
from urllib.parse import parse_qsl, urlsplit, urlunsplit

MAX_URL_LEN = 2048
MAX_PARAMS = 50
# Endpoints that are static assets say nothing about attack surface.
_STATIC_SUFFIXES = (
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".css", ".woff", ".woff2", ".ttf",
    ".eot", ".mp4", ".mp3", ".pdf", ".zip", ".gz", ".map",
)


def _clean(url: str, method: str, source: str) -> dict | None:
    if not isinstance(url, str) or len(url) > MAX_URL_LEN:
        return None
    parts = urlsplit(url.strip())
    if parts.scheme not in ("http", "https") or not parts.hostname or parts.username or parts.password:
        return None
    if parts.path.lower().endswith(_STATIC_SUFFIXES):
        return None
    names = sorted({k for k, _ in parse_qsl(parts.query, keep_blank_values=True) if k})[:MAX_PARAMS]
    return {
        "url": urlunsplit((parts.scheme, parts.netloc, parts.path or "/", "", "")),
        "full_url": urlunsplit((parts.scheme, parts.netloc, parts.path or "/", parts.query, "")),
        "method": method if method in ("GET", "POST") else "GET",
        "source": source,
        "param_names": names,
    }


def _merge(items: list[dict]) -> list[dict]:
    """One entry per (method, url without query); parameter names are unioned."""
    merged: dict[tuple[str, str], dict] = {}
    for item in items:
        key = (item["method"], item["url"])
        if key in merged:
            if item["param_names"] and not merged[key]["param_names"]:
                merged[key]["full_url"] = item["full_url"]
            merged[key]["param_names"] = sorted(set(merged[key]["param_names"]) | set(item["param_names"]))[:MAX_PARAMS]
        else:
            merged[key] = dict(item)
    return list(merged.values())


def parse_katana_jsonl(stdout: str) -> list[dict]:
    items = []
    for line in (stdout or "").splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            request = (json.loads(line).get("request") or {})
        except (ValueError, AttributeError):
            continue
        cleaned = _clean(request.get("endpoint", ""), str(request.get("method") or "GET").upper(), "katana")
        if cleaned:
            items.append(cleaned)
    return _merge(items)


def parse_url_list(text: str, source: str) -> list[dict]:
    """Plain one-URL-per-line history (Wayback / CommonCrawl)."""
    items = []
    for line in (text or "").splitlines():
        cleaned = _clean(line.strip(), "GET", source)
        if cleaned:
            items.append(cleaned)
    return _merge(items)


def nuclei_candidate_urls(endpoints: list[dict], limit: int = 50) -> list[str]:
    """Parameterized GET URLs worth a DAST pass: those carrying query parameters."""
    seen: set[str] = set()
    urls = []
    for e in endpoints:
        if e["method"] != "GET" or not e["param_names"] or e["url"] in seen:
            continue
        seen.add(e["url"])
        urls.append(e["full_url"])
        if len(urls) >= limit:
            break
    return urls
