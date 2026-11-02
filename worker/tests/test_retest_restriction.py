"""REQ-RETEST-002: the plan of a restricted run (pure), and the families of sharded checks."""

from __future__ import annotations

import pytest

from app.planner import (
    NOT_IN_THIS_RUN, Options, SurfaceInput, check_family, plan_surface, restrict_checks,
)

HOST = "app.example.test"


def _web_plan(profile="standard"):
    return plan_surface(
        SurfaceInput(host=HOST, port=443, service_class="web", scheme="https", profile=("nginx",)),
        Options(scan_profile=profile, crawling=True),
    )


def _states(checks):
    return {c.check_id: (c.state, c.reason) for c in checks}


def test_a_full_run_is_unchanged():
    plan = _web_plan()
    assert restrict_checks(plan, HOST, 443, None) == plan


def test_only_the_selected_check_stays_planned_and_the_rest_is_left_out_with_the_reason():
    plan = _web_plan()
    out = _states(restrict_checks(plan, HOST, 443, [{"host": HOST, "port": 443, "check": "ffuf"}]))
    assert out["ffuf"][0] == "planned"
    for check_id, (state, reason) in out.items():
        if check_id != "ffuf" and dict((c.check_id, c.state) for c in plan)[check_id] == "planned":
            assert (state, reason) == ("skipped", NOT_IN_THIS_RUN), check_id


def test_a_planner_skip_keeps_its_own_reason_and_nothing_is_added():
    plan = _web_plan()  # screenshots are off: skipped, switch_off
    out = _states(restrict_checks(plan, HOST, 443, [{"host": HOST, "tool": "screenshot"}]))
    assert out["screenshot"] == ("skipped", "switch_off")
    assert set(out) == {c.check_id for c in plan}


def test_a_selected_check_brings_the_check_it_depends_on():
    plan = _web_plan()
    out = _states(restrict_checks(plan, HOST, 443, [{"host": HOST, "check": "nuclei:products"}]))
    assert out["nuclei:products"][0] == "planned"
    assert out["nuclei:tech"][0] == "planned"  # nuclei:products depends on nuclei:tech
    assert out["ffuf"] == ("skipped", NOT_IN_THIS_RUN)


def test_the_shards_of_one_check_are_the_same_check():
    assert check_family("nuclei:generic:2of5") == "nuclei:generic"
    assert check_family("nuclei:all:13of14") == "nuclei:all"
    assert check_family("ffuf:deep") == "ffuf:deep" and check_family("testssl") == "testssl"
    plan = _web_plan()
    out = _states(restrict_checks(plan, HOST, 443, [{"host": HOST, "check": "nuclei:generic:9of99"}]))
    shards = [c for c in out if c.startswith("nuclei:generic:")]
    assert shards and all(out[c][0] == "planned" for c in shards)


def test_a_tool_item_selects_every_check_of_that_tool_and_no_other():
    plan = _web_plan()
    out = _states(restrict_checks(plan, HOST, 443, [{"host": HOST, "tool": "nuclei"}]))
    wanted = {c.check_id for c in plan if c.state == "planned" and c.tool == "nuclei"} | {"katana"}  # nuclei:endpoints needs it
    assert {check_id for check_id, (state, _) in out.items() if state == "planned"} == wanted


@pytest.mark.parametrize("item", [
    {"host": "other.example.test", "check": "ffuf"},            # another host
    {"host": HOST, "port": 8443, "check": "ffuf"},              # another port
    {"host": HOST, "check": "ffuf:deep"},                       # a different check: not planned for `standard`
])
def test_negative_an_item_for_another_host_port_or_check_selects_nothing(item):
    plan = _web_plan()
    out = restrict_checks(plan, HOST, 443, [item])
    assert all(c.state != "planned" for c in out)


def test_host_names_match_without_case_or_a_trailing_dot():
    plan = _web_plan()
    out = _states(restrict_checks(plan, HOST, 443, [{"host": HOST.upper() + ".", "check": "testssl"}]))
    assert out["testssl"][0] == "planned"


def test_an_empty_list_selects_nothing_at_all():
    plan = _web_plan()
    assert all(c.state != "planned" for c in restrict_checks(plan, HOST, 443, []))
