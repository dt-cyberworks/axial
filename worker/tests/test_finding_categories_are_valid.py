"""Every finding category the worker writes must exist in the database enum.

Found while testing #87: the curated OpenWire probe wrote `category="rce"`, which `finding_category` does not have
(`cve`, `misconfig`, `exposure`, `logic`, migration 0001). The database would have refused that finding, so a confirmed
remote-code-execution proof would have been lost. A test of the string alone cannot see it; this one reads every literal."""

from __future__ import annotations

import pathlib
import re

VALID = {"cve", "misconfig", "exposure", "logic"}
APP = pathlib.Path(__file__).resolve().parent.parent / "app"
LITERAL = re.compile(r"""\bcategory\s*[=:]\s*["']([a-z_]+)["']""")


def test_every_category_literal_in_the_worker_is_a_database_value():
    seen = {}
    for path in APP.rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        for match in re.finditer(r"add_finding\(|_add_finding\(|\"category\":\s*\"", text):
            window = text[match.start(): match.start() + 600]
            for found in LITERAL.findall(window):
                seen.setdefault(found, set()).add(path.name)
    # tool categories (recon, fingerprint, vuln, cred, exploit) are a different field and are not findings
    finding_values = {k: v for k, v in seen.items() if k not in {"recon", "fingerprint", "vuln", "cred", "exploit"}}
    invalid = {k: sorted(v) for k, v in finding_values.items() if k not in VALID}
    assert not invalid, f"finding categories that the database enum does not have: {invalid}"
    assert VALID & set(finding_values), "the scan found no category literal at all, so it proves nothing"
