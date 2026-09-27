"""Parser fuer nikto-Klartextausgabe: fehlende Security-Header (Kap. 5.1,
category=misconfig). Reine, DB-freie Funktion (ohne Infra testbar).

Deckt ZWEI nikto-Ausgabeformate ab:
  - nikto >= 2.5: "Suggested security header missing: content-security-policy"
  - nikto  < 2.5: "The X-Frame-Options header is not present."
Der Live-Test gegen eine echte Domain (nikto 2.6.0/nginx) deckte auf, dass
das alte Muster allein nichts findet - daher beide.
"""

from __future__ import annotations

import re

_KNOWN = {
    "x-content-type-options",
    "x-frame-options",
    "content-security-policy",
    "strict-transport-security",
    "permissions-policy",
    "referrer-policy",
}

# Format A (nikto >= 2.5): "Suggested security header missing: <name>"
_SUGGESTED = re.compile(r"Suggested security header missing:\s*([a-z-]+)", re.I)

# Format B (aeltere nikto): "The <Name> header is not present/set/defined"
_NOT_PRESENT = re.compile(
    r"(x-content-type-options|x-frame-options|content-security-policy|"
    r"strict-transport-security|permissions-policy|referrer-policy|HSTS)"
    r".{0,40}?not (set|defined|present)",
    re.I,
)


def parse_nikto_missing_headers(stdout: str) -> list[str]:
    found: set[str] = set()
    for m in _SUGGESTED.finditer(stdout):
        name = m.group(1).lower()
        if name in _KNOWN:
            found.add(name)
    for m in _NOT_PRESENT.finditer(stdout):
        name = m.group(1).lower()
        name = "strict-transport-security" if name == "hsts" else name
        found.add(name)
    return sorted(found)
