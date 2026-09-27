"""Parser fuer wafw00f-Ausgabe: erkennt das WAF-Produkt (falls vorhanden).

wafw00f meldet mit stabilen Textmustern:
  "[+] The site https://x is behind <Produkt> WAF."   -> WAF erkannt
  "[-] No WAF detected by the generic detection"       -> kein WAF
Reine, DB-freie Funktion (ohne Infra testbar).
"""

from __future__ import annotations

import re

# "is behind X (Vendor) WAF" bzw. "is behind X WAF"
_BEHIND = re.compile(r"is behind\s+(.+?)\s+WAF", re.I)


def parse_wafw00f(stdout: str) -> str | None:
    """Gibt den erkannten WAF-Produktnamen zurueck, oder None (kein WAF)."""
    m = _BEHIND.search(stdout)
    if m:
        # Klammer-Zusatz (Vendor) und ANSI-Reste entfernen
        name = re.sub(r"\s*\(.*?\)\s*", " ", m.group(1)).strip()
        return name or None
    return None
