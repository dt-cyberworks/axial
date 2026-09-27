"""Subdomain->domain backbone helper (REQ-GRAPH-006).

`_closest_parent_value` picks the closest ancestor name already registered as a
discovered_asset, so the graph's HAS_SUBDOMAIN edges hang subdomains off their
parent. It never invents a parent and never returns the bare TLD.
"""

from __future__ import annotations

from app.tasks import discovery


def test_closest_parent_prefers_nearest_registered_ancestor():
    present = {"example.com": "a1", "v2.example.com": "a2"}
    assert discovery._closest_parent_value("api.v2.example.com", present) == "v2.example.com"


def test_closest_parent_falls_back_to_apex_when_intermediate_absent():
    present = {"example.com": "a1"}
    assert discovery._closest_parent_value("api.example.com", present) == "example.com"


def test_closest_parent_none_when_no_ancestor_registered():
    assert discovery._closest_parent_value("api.example.com", {}) is None
    # never returns the bare TLD
    assert discovery._closest_parent_value("example.com", {"com": "x"}) is None


def test_apex_itself_has_no_parent():
    present = {"example.com": "a1"}
    assert discovery._closest_parent_value("example.com", present) is None
