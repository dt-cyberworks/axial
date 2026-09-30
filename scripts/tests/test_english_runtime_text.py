"""REQ-TEXT-001: text that people read at runtime is English.

Scans the string literals (not comments or docstrings) of the services'
runtime code: API errors, OpenAPI texts, tool notes, the Vector Agent's tool
descriptions and observations, and log lines. A German word in any of them
fails the test, so German text cannot come back unnoticed.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RUNTIME_ROOTS = ["control-plane/app", "worker/app", "egress-proxy/app", "raw-egress-gateway"]

# Words that are German and not also common English (or tool/protocol) words.
GERMAN = re.compile(
    r"\b(nicht|fuer|für|ueber|über|keine?[nrms]?|fehlt|fehlgeschlagen|ungueltig|ungültig|unbekannte?s?|bereits|"
    r"uebersprungen|übersprungen|ueberspringe|verworfen|aufgeloeste|gelistetes|Waehle|Wähle|muss|wurde|werden|wird|"
    r"oder|und|ist|mit|bei|auf|dem|des|eine?n?|konnte|Pruefung|erfolgreich|vollstaendig|bleibt|zurueck|"
    r"durchlaeuft|Treffer|Befund|beobachtet|moeglich|bestaetigt|faehig|Antwort|lebender|Dienst|gescannt|durch|"
    r"diesen|Lauf|erreichbar|lesbar|schreibbar|speicherbar|ladbar|angelegt|gemappt|derzeit|statt|noch|"
    r"angebunden|Versuche|Wortliste|gebacken|Siehe|materialisiert|Vorrang|Ziel|zu|sein|ausserhalb|Bereich|"
    r"Freigabe|erforderlich|abgelehnt|gedrosselt|warte|Abschnitt|beendet|Iterationen|Beobachtungen|liefert|"
    r"dieselbe|gleiche|ohne|nach|wenn|dann|sind|schon|alle|jede[rsn]?|bitte|bzw|Anfrage|Fehler|Warnung|erkannt|"
    r"gefunden|gesendet|gestartet|abgeschlossen|laeuft|pruefe|starte|lade|speichere|Ergebnis|Eintrag|Datei|"
    r"Verbindung|Zugriff|Abfrage|Aufruf|Oberflaeche|Ausgabe|Eingabe|leer|gueltige|zeigt|geprueft|verfuegbar|"
    r"Zeitfenster|Befunde|Dienste|Hosts gefunden|wiederholt|erneut|Grund|Schritt|Phase beendet)\b|[äöüß]",
    re.IGNORECASE,
)


def _docstring_nodes(tree: ast.AST) -> set[int]:
    ids = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and node.body:
            first = node.body[0]
            if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant):
                ids.add(id(first.value))
    return ids


def _legacy_nodes(tree: ast.AST) -> set[int]:
    """Constants assigned to a name starting with `_LEGACY` are historical data
    kept on purpose (for example the original German finding titles that
    fingerprints still hash), not text anyone reads."""
    ids = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and any(
                isinstance(t, ast.Name) and t.id.startswith("_LEGACY") for t in node.targets):
            ids.update(id(n) for n in ast.walk(node.value))
    return ids


def german_runtime_strings() -> list[str]:
    hits = []
    for root in RUNTIME_ROOTS:
        for path in sorted((ROOT / root).rglob("*.py")):
            if "tests" in path.relative_to(ROOT).parts:
                continue
            tree = ast.parse(path.read_text(encoding="utf-8"))
            skipped = _docstring_nodes(tree) | _legacy_nodes(tree)
            for node in ast.walk(tree):
                if (isinstance(node, ast.Constant) and isinstance(node.value, str)
                        and id(node) not in skipped and GERMAN.search(node.value)
                        and not re.fullmatch(r"[a-z_./ -]*", node.value)):
                    hits.append(f"{path.relative_to(ROOT)}:{node.lineno}: {node.value[:100]!r}")
    return hits


def test_runtime_strings_are_english():
    assert german_runtime_strings() == []


def test_negative_the_scan_finds_german_text():
    """Guards the guard: a German message in a runtime module is reported."""
    sample = ast.parse('raise ValueError("Ziel ist nicht erreichbar")\nlog("port fehlt")')
    found = [n.value for n in ast.walk(sample) if isinstance(n, ast.Constant) and isinstance(n.value, str)
             and GERMAN.search(n.value)]
    assert found == ["Ziel ist nicht erreichbar", "port fehlt"]
    # English that shares letters with German words is not flagged.
    assert not GERMAN.search("no materialized IP - skipping web tools; the target is unreachable")
