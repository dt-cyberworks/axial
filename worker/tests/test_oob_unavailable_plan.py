"""REQ-OOB-001 (GitHub #76): a missing interaction server costs only the callback-dependent templates.

The issue read the missing server as "the whole `http/cves` tree is not run". It is not: the main passes (generic,
product-bound, every template in thorough depth) run for every surface with `-no-interactsh`, which makes nuclei drop
the templates that need a callback and keep all the others. Only the `nuclei:oob:*` passes need the server. These
tests lock that, so that a later change cannot quietly move non-callback templates behind the switch."""

from __future__ import annotations

import pytest

from app import planner
from app import tool_runner_client as trc
from app.planner import IndexInfo, Options, SurfaceInput, plan_surface

WEB = SurfaceInput(host="h.example", port=443, service_class="web", scheme="https", profile=("nginx",))


def _plan(**options):
    return plan_surface(WEB, Options(**options), IndexInfo())


@pytest.mark.parametrize("profile", ["standard", "thorough"])
def test_without_an_interaction_server_only_the_callback_passes_are_skipped(profile):
    checks = _plan(oob=True, oob_available=False, scan_profile=profile)
    by_id = {c.check_id: c for c in checks}
    for part in planner.NUCLEI_OOB_PARTS:
        check = by_id[f"nuclei:oob:{part}"]
        assert (check.state, check.reason) == ("skipped", "oob_unavailable")
    # every other nuclei check is planned exactly as it would be with a server
    others = [c for c in checks if c.tool == "nuclei" and not c.check_id.startswith("nuclei:oob:")]
    assert others and all(c.state == "planned" or c.reason.startswith("switch_") for c in others)
    selection = [c for c in others if c.args.get("mode") == "select"]
    assert selection, "the template selection passes (generic / products / all) are still planned"
    assert all(c.state == "planned" for c in selection)


@pytest.mark.parametrize("profile", ["standard", "thorough"])
def test_negative_the_missing_server_changes_nothing_but_the_callback_passes(profile):
    with_server = {c.check_id: (c.state, c.reason, c.args) for c in _plan(oob=True, oob_available=True, scan_profile=profile)}
    without = {c.check_id: (c.state, c.reason, c.args) for c in _plan(oob=True, oob_available=False, scan_profile=profile)}
    assert with_server.keys() == without.keys()
    differing = {cid for cid in with_server if with_server[cid] != without[cid]}
    assert differing == {f"nuclei:oob:{p}" for p in planner.NUCLEI_OOB_PARTS}


def test_with_a_server_every_callback_pass_is_planned_and_without_the_switch_none_is():
    assert all(c.state == "planned" for c in _plan(oob=True, oob_available=True) if c.check_id.startswith("nuclei:oob:"))
    off = [c for c in _plan(oob=False, oob_available=False) if c.check_id.startswith("nuclei:oob:")]
    assert off and all((c.state, c.reason) == ("skipped", "switch_off") for c in off)


@pytest.mark.parametrize("args", [
    {"mode": "select", "group": "generic", "shard": "1/5"},
    {"mode": "select", "group": "products", "products": ["nginx"]},
    {"mode": "select", "group": "all", "shard": "1/15"},
    {"mode": "endpoints", "urls": ["https://h.example/?a=1"]},
])
def test_negative_the_template_passes_that_do_not_call_back_never_use_the_interaction_server(args):
    command = trc._nuclei_command("https://h.example", args)
    assert "-no-interactsh" in command and "-iserver" not in command and "-itoken" not in command


@pytest.mark.parametrize("mode", ["tech", "headless", "takeover"])
def test_negative_the_single_call_passes_do_not_use_it_either(mode):
    additional = trc._nuclei_body("h.example", {"mode": mode})["additional_args"]
    assert "-no-interactsh" in additional and "-iserver" not in additional


def test_only_the_callback_passes_name_the_interaction_server():
    command = trc._nuclei_command("https://h.example", {"mode": "oob", "part": "cves_recent", "_oob_server": "http://x:8080"})
    assert "-iserver http://x:8080" in command and "-no-interactsh" not in command
