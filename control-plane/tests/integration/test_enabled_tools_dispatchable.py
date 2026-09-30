"""enabled_tools = enabled ∩ dispatchable (REQ-TOOL-004): der Vector Agent wird
nie mit Tools beliefert, die der Worker nicht ausfuehren kann."""

from __future__ import annotations

from app import config_resolver
from app.tools import registry


# Der Worker kann genau diese Tools fuer Agent-Vorschlaege dispatchen
# (Spiegel von worker/app/tasks/dispatch.TOOL_CATEGORY).
_WORKER_DISPATCHABLE = {
    "httpx", "nmap", "wafw00f", "testssl", "nikto", "nuclei", "http_request", "ffuf",
    "redis-probe", "activemq-banner", "activemq-openwire-probe",
}
# Diese sind zwar default_enabled, aber NICHT dispatch-faehig -> duerfen dem
# Agenten nie angeboten werden.
# Nur noch subfinder (REQ-COVER-001: laeuft im Worker-Image, der Discovery-Task ruft es
# direkt, nicht ueber den Tool-Runner); die uebrigen
# Tools ohne Aufrufer wurden mit REQ-COVER-005 aus der Whitelist genommen.
_ENABLED_BUT_NOT_DISPATCHABLE = {"subfinder"}
_RETIRED = {"whatweb", "sslscan", "amass", "default-cred-check"}


def test_agent_dispatchable_matches_worker():
    assert registry.agent_dispatchable() == _WORKER_DISPATCHABLE


def test_enabled_tools_excludes_non_dispatchable(db, lab_engagement):
    tools = set(config_resolver.enabled_tools(db, lab_engagement.id))
    # Kein nicht-dispatch-faehiges Tool ist enthalten...
    assert tools.isdisjoint(_ENABLED_BUT_NOT_DISPATCHABLE)
    # ...aber dispatch-faehige, enabled Tools schon (nuclei/nikto/http_request/ffuf sind vuln-enabled).
    assert {"httpx", "nmap", "nikto", "http_request", "ffuf"} <= tools


def test_registry_still_lists_non_dispatchable_as_enabled():
    # Die Registry darf sie weiter als default_enabled fuehren (Whitelist/Grants),
    # nur das AGENT-Angebot ist eingeschraenkt.
    for name in _ENABLED_BUT_NOT_DISPATCHABLE:
        spec = registry.get(name)
        assert spec is not None and spec.default_enabled and not spec.dispatched


def test_every_enabled_tool_has_a_caller_except_the_documented_one():
    """REQ-COVER-005: the runtime whitelist holds no tool that nothing dispatches."""
    without_caller = {n for n, s in registry.REGISTRY.items() if s.default_enabled and not s.dispatched}
    assert without_caller == _ENABLED_BUT_NOT_DISPATCHABLE


def test_negative_retired_tools_stay_out_of_whitelist_and_agent_offer(db, lab_engagement):
    whitelisted = set().union(*registry.enabled_whitelist().values())
    assert whitelisted.isdisjoint(_RETIRED)
    assert set(config_resolver.enabled_tools(db, lab_engagement.id)).isdisjoint(_RETIRED)
    for name in _RETIRED:  # still catalogued, so the matrix shows why they are off
        spec = registry.get(name)
        assert spec is not None and not spec.default_enabled
