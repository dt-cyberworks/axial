"""Technology profile of a surface (REQ-PIPE-002). Pure functions.

A profile is a list of normalized product keys, each with an optional version
(`nginx`, `nginx@1.25.3`), merged from httpx's technology detection, nmap's
`-sV` product/version and nuclei's technology-detection templates. An empty
profile stays empty: nothing is guessed.

The keys are what the nuclei template index matches its product-bound
templates against (tool-runner/nuclei_index.py), so the normalization mirrors
the index's own (`normalize_key`).
"""

from __future__ import annotations

import re
from collections.abc import Iterable

MAX_PROFILE_ENTRIES = 24

# Words that carry no product identity on their own.
_STOP_WORDS = frozenset({
    "the", "and", "for", "server", "web", "http", "httpd", "https", "smtpd", "imapd", "pop3d", "ftpd", "daemon",
    "framework", "cms", "engine", "service", "library", "software", "system", "app", "application",
})
# Detected technologies that say nothing about which template set applies.
_NOISE = frozenset({
    "hsts", "http_3", "http/3", "http2", "http_2", "ssl", "tls", "html", "html5", "css", "unknown", "tcpwrapped",
    "open", "linux", "unix", "windows", "ubuntu", "debian", "centos", "red_hat", "cloudflare", "cdn",
})
_VERSION_RE = re.compile(r"^\d+(?:\.\d+){0,3}[a-z0-9.+_-]{0,12}$")


def normalize_key(value: str) -> str:
    """`Nextcloud Server` -> `nextcloud_server` (the template index's own rule)."""
    return re.sub(r"[^a-z0-9.+]+", "_", str(value or "").strip().strip("'\"").lower()).strip("_")


def _split_version(raw: str) -> tuple[str, str | None]:
    """`jQuery:3.6.0` -> (`jquery`, `3.6.0`); `Apache httpd 2.4.57` -> (`apache httpd`, `2.4.57`)."""
    text = str(raw or "").strip()
    if ":" in text:
        name, _, version = text.partition(":")
        if _VERSION_RE.match(version.strip().lower()):
            return name, version.strip()
        return name, None
    tokens = text.split()
    if len(tokens) > 1 and _VERSION_RE.match(tokens[-1].lower()) and any(ch.isdigit() for ch in tokens[-1]):
        return " ".join(tokens[:-1]), tokens[-1]
    return text, None


def keys_for(raw: str, version: str | None = None) -> list[str]:
    """Profile entries for one detected technology or product string.

    The full normalized name first, then each meaningful word of a multi-word
    name (`Apache httpd` -> `apache_httpd`, `apache`), so it can meet whichever
    form a template's product/tag uses. A known version is attached to the full
    name only."""
    name, parsed_version = _split_version(raw)
    version = version or parsed_version
    full = normalize_key(name)
    if not full or full in _NOISE or len(full) < 2:
        return []
    entries = [f"{full}@{version}" if version else full]
    words = [normalize_key(w) for w in re.split(r"[\s/_-]+", name) if w]
    if len(words) > 1:
        for word in words:
            if len(word) >= 3 and word not in _STOP_WORDS and word not in _NOISE and word != full:
                entries.append(word)
    return entries


def build_profile(
    httpx_tech: Iterable[str] = (), webserver: str | None = None,
    nmap_products: Iterable[tuple[str, str | None]] = (), extra: Iterable[str] = (),
) -> list[str]:
    """The merged, de-duplicated profile of one surface (most specific first:
    products nmap versioned, then httpx's detections, then the server header,
    then whatever nuclei's technology templates added)."""
    entries: list[str] = []
    for product, version in nmap_products:
        entries += keys_for(product, version)
    for tech in httpx_tech:
        entries += keys_for(tech)
    if webserver:
        entries += keys_for(webserver)
    for item in extra:
        entries += keys_for(item)
    merged: dict[str, str] = {}
    for entry in entries:
        key, _, version = entry.partition("@")
        if key not in merged or (version and "@" not in merged[key]):
            merged[key] = entry
    return list(merged.values())[:MAX_PROFILE_ENTRIES]


def product_keys(profile: Iterable[str]) -> list[str]:
    """The keys of a profile without versions, in order, unique."""
    seen: dict[str, None] = {}
    for entry in profile:
        seen.setdefault(str(entry).partition("@")[0], None)
    return list(seen)
