"""Tests der Capability-Registry (app/tools/registry.py).

Reine Unit-Tests (keine DB). Verifizieren, dass die Registry die einzige
Quelle der Wahrheit ist und nur tatsaechlich verfuegbare Tools whitelisted.
"""

from app.tools import registry
from app.tools.registry import CATEGORIES, EXECUTION_CLASSES


def test_whitelist_contains_only_enabled_available_defaults():
    assert registry.enabled_whitelist() == {
        "recon": {"subfinder", "amass"},
        "fingerprint": {"httpx", "whatweb", "nmap", "sslscan", "testssl", "wafw00f",
                        "redis-probe", "activemq-banner"},
        "vuln": {"nuclei", "nikto", "http_request", "ffuf", "activemq-openwire-probe"},
        "cred": {"default-cred-check"},
        "exploit": set(),
    }


def test_every_category_present_even_if_empty():
    wl = registry.enabled_whitelist()
    assert set(wl.keys()) == CATEGORIES
    assert wl["exploit"] == set()  # Startangebot: keine Exploitation


def test_all_specs_have_valid_category_and_execution_class():
    for spec in registry.REGISTRY.values():
        assert spec.category in CATEGORIES, spec.name
        assert spec.execution_class in EXECUTION_CLASSES, spec.name


def test_validate_args_delegates_to_tool_validator():
    # nmap: sichere Flags erlaubt, Exploit-Skripte blockiert (Regel lebt in args_safety).
    assert registry.validate_args("nmap", {"flags": ["-sV"]})
    assert not registry.validate_args("nmap", {"flags": ["--script=exploit-all"]})


def test_validate_args_unknown_tool_only_empty_args():
    # Tool ohne eigenen Validator -> fail-closed: nur leere Argumente.
    assert registry.validate_args("whatweb", {})
    assert not registry.validate_args("whatweb", {"anything": "x"})
    assert registry.validate_args("does-not-exist", {}) is True
    assert registry.validate_args("does-not-exist", {"x": 1}) is False


def test_enabled_but_not_installed_is_empty_by_default():
    # Uninstallierte Tools bleiben in der Matrix sichtbar, duerfen aber nicht
    # in die Gateway-Whitelist gelangen.
    assert registry.enabled_but_not_installed() == []
    assert registry.REGISTRY["dnsx"].installed is False
    assert registry.REGISTRY["dnsx"].default_enabled is False
    assert registry.REGISTRY["tlsx"].installed is False
    assert registry.REGISTRY["tlsx"].default_enabled is False


def test_capability_matrix_is_serializable_and_complete():
    rows = registry.capability_matrix()
    assert len(rows) == len(registry.REGISTRY)
    names = {r["name"] for r in rows}
    assert {"nmap", "nikto"} <= names
    # nikto ist der einzige voll bewiesene Pfad (dispatcht + geparst).
    nikto = next(r for r in rows if r["name"] == "nikto")
    assert nikto["dispatched"] and nikto["has_parser"]


def test_dispatched_tools_have_parser_and_endpoint():
    # Was heute wirklich laeuft, muss auch geparst und (bei aktiven) gemappt sein.
    for spec in registry.REGISTRY.values():
        if spec.dispatched:
            assert spec.parser is not None, f"{spec.name} dispatcht ohne Parser"
            assert spec.hexstrike_endpoint is not None, f"{spec.name} dispatcht ohne Endpoint"
            assert spec.worker_mapped, f"{spec.name} dispatcht, aber nicht im Client gemappt"
