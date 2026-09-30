"""TC-PIPE-003/004/005/016 (worker half): the deterministic planner, the
technology profile it reads and the service classes it plans for."""

from __future__ import annotations

import pathlib
import re

import pytest

from app import planner, surfaces, tech_profile
from app.planner import IndexInfo, Options, SurfaceInput, plan_surface, resolve_products, shard_count

REPO = pathlib.Path(__file__).resolve().parents[2]


def _ids(checks, state="planned"):
    return [c.check_id for c in checks if c.state == state]


def _web(profile=(), **over):
    return SurfaceInput(host="h.example", port=443, service_class="web", scheme="https", profile=tuple(profile), **over)


# --- REQ-PIPE-003: pure, reasoned, ordered ------------------------------------------

def test_req_pipe_003_the_same_inputs_give_the_same_plan():
    args = (_web(["nginx", "php"]), Options(crawling=True), IndexInfo())
    assert plan_surface(*args) == plan_surface(*args)


def test_req_pipe_003_every_check_names_its_reason():
    for surface in (_web(), _web(duplicate_of="a.example"), SurfaceInput("h", 80, "web_alias", "http", alias_of="h:443"),
                    SurfaceInput("h", 25, "tls_service", starttls="smtp"), SurfaceInput("h", 22, "service"),
                    SurfaceInput("h", 9, "unknown")):
        for check in plan_surface(surface, Options(crawling=True, screenshots=True, oob=True), IndexInfo()):
            assert check.reason.strip(), (surface.service_class, check.check_id)
            assert check.state in ("planned", "skipped")


def test_req_pipe_003_a_web_surface_runs_the_cheap_checks_first():
    ids = _ids(plan_surface(_web(), Options(crawling=True, screenshots=True), IndexInfo()))
    assert ids[:6] == ["wafw00f", "testssl", "header_findings", "ffuf", "screenshot", "katana"]
    assert ids[-1] == "nuclei:endpoints" or ids[-1] == "nuclei:takeover"
    assert ids.index("nuclei:tech") < ids.index("nuclei:products")


def test_req_pipe_003_only_fixed_typed_selections_are_planned():
    """The planner never produces free-form tool arguments: nuclei calls carry a
    group, a shard or product keys, nothing else."""
    for check in plan_surface(_web(["nginx"]), Options(oob=True, crawling=True), IndexInfo()):
        if check.tool == "nuclei" and check.args.get("mode") == "select":
            assert set(check.args) <= {"mode", "group", "shard", "products", "from_profile"}
            assert check.args["group"] in ("generic", "products", "all")
            for key in check.args.get("products", []):
                assert re.fullmatch(r"[a-z0-9][a-z0-9_.+-]{0,39}", key)


def test_negative_req_pipe_003_a_web_alias_gets_no_planned_check_and_names_its_target():
    checks = plan_surface(SurfaceInput("h.example", 80, "web_alias", "http", alias_of="h.example:443"), Options(crawling=True), IndexInfo())
    assert not _ids(checks)
    assert {c.reason for c in checks} == {"web_alias_of:h.example:443"}


def test_req_pipe_003_plain_http_is_never_planned_for_testssl():
    checks = plan_surface(SurfaceInput("h", 80, "web", "http"), Options(), IndexInfo())
    testssl = next(c for c in checks if c.check_id == "testssl")
    assert (testssl.state, testssl.reason) == ("skipped", "not_a_tls_service")


# --- REQ-PIPE-004: nuclei templates from evidence --------------------------------------

def test_req_pipe_004_the_standard_profile_runs_generic_shards_and_the_product_templates():
    checks = plan_surface(_web(["nextcloud", "nginx", "php"]), Options(), IndexInfo(generic=1980, total=5883))
    nuclei = _ids(checks)
    generic = [c for c in nuclei if c.startswith("nuclei:generic:")]
    assert generic == [f"nuclei:generic:{k}of5" for k in range(1, 6)]
    products = next(c for c in checks if c.check_id == "nuclei:products")
    assert products.args["products"] == ["nextcloud", "nginx", "php"]
    assert products.reason == "product:nextcloud,nginx,php"
    assert not [c for c in nuclei if c.startswith("nuclei:all:")], "the full set is the thorough profile"


def test_req_pipe_004_the_thorough_profile_runs_every_template_in_shards():
    checks = plan_surface(_web(["nginx"]), Options(scan_profile="thorough"), IndexInfo(generic=1980, total=5883))
    shards = [c for c in checks if c.check_id.startswith("nuclei:all:")]
    assert [c.check_id for c in shards] == [f"nuclei:all:{k}of15" for k in range(1, 16)]
    assert all(c.args == {"mode": "select", "group": "all", "shard": c.check_id.split(":")[2].replace("of", "/")} for c in shards)
    assert not [c for c in checks if c.check_id.startswith(("nuclei:generic:", "nuclei:products"))]
    assert {"nuclei:headless", "nuclei:takeover"} <= set(_ids(checks)), "the fixed passes run in both profiles"


def test_req_pipe_004_shards_hold_at_most_the_target_size():
    for total in (1, 399, 400, 401, 1980, 5883):
        n = shard_count(total)
        assert n * planner.SHARD_TARGET >= total > (n - 1) * planner.SHARD_TARGET or total <= planner.SHARD_TARGET
    assert shard_count(0) == 1


def test_req_pipe_004_an_empty_profile_selects_the_common_products_never_a_guess():
    keys, reason = resolve_products(())
    assert keys == list(planner.COMMON_PRODUCTS)
    assert reason == "no_product_identified:common_products"
    checks = plan_surface(_web(), Options(), IndexInfo())
    assert next(c for c in checks if c.check_id == "nuclei:products").args["products"] == list(planner.COMMON_PRODUCTS)


def test_negative_req_pipe_004_an_identified_profile_never_gets_the_fallback_list():
    keys, reason = resolve_products(("nginx@1.25.3", "php"))
    assert keys == ["nginx", "php"] and reason == "product:nginx,php"
    assert not set(planner.COMMON_PRODUCTS) - {"nginx", "php"} & set(keys)


def test_req_pipe_004_the_product_list_is_bounded():
    keys, _ = resolve_products([f"product{i}" for i in range(60)])
    assert len(keys) == planner.MAX_SELECT_PRODUCTS == 24


def test_req_pipe_004_the_planned_checks_keep_a_bounded_declared_budget():
    from app.tool_runner_client import RUNNER_MAX_BUDGET_S

    for check in plan_surface(_web(["nginx"]), Options(crawling=True, screenshots=True, oob=True), IndexInfo()):
        if check.state == "planned" and check.budget_s is not None:
            assert 0 < check.budget_s <= RUNNER_MAX_BUDGET_S


# --- REQ-PIPE-016: the common-product list is fixed and reviewable --------------------

def test_req_pipe_016_the_fallback_list_is_the_documented_one():
    assert planner.COMMON_PRODUCTS == (
        "wordpress", "drupal", "joomla", "apache", "nginx", "iis", "tomcat", "jenkins", "gitlab", "grafana",
        "confluence", "jira", "php", "spring",
    )


def test_req_pipe_016_code_and_design_document_agree():
    design = (REPO / "docs" / "design" / "scan-pipeline-architecture.md").read_text()
    requirement = (REPO / "docs" / "requirements" / "scan-pipeline.md").read_text()
    listed = ", ".join(planner.COMMON_PRODUCTS)
    flat = re.sub(r"\s+", " ", design)
    assert re.sub(r"\s+", " ", listed) in flat or all(p in flat for p in planner.COMMON_PRODUCTS)
    assert "wordpress, drupal, joomla, apache, nginx, iis, tomcat," in re.sub(r"\s+", " ", requirement)
    assert "jenkins, gitlab, grafana, confluence, jira, php, spring" in re.sub(r"\s+", " ", requirement)


# --- REQ-PIPE-005/015: profiles and switches -----------------------------------------

def test_req_pipe_005_the_profiles_are_standard_and_thorough_only():
    assert planner.SCAN_PROFILES == ("standard", "thorough")


def test_negative_req_pipe_005_neither_profile_turns_a_switch_on():
    for profile in planner.SCAN_PROFILES:
        checks = plan_surface(_web(), Options(scan_profile=profile), IndexInfo())
        skipped = {c.check_id: c.reason for c in checks if c.state == "skipped"}
        assert skipped["screenshot"] == "switch_off" and skipped["katana"] == "switch_off"
        assert all(skipped[f"nuclei:oob:{p}"] == "switch_off" for p in planner.NUCLEI_OOB_PARTS)


# --- non-web surfaces (REQ-PIPE-001/009) -----------------------------------------------

def test_req_pipe_009_a_tls_service_is_planned_for_testssl_with_its_starttls_protocol():
    (check,) = plan_surface(SurfaceInput("h", 587, "tls_service", starttls="smtp"), Options(), IndexInfo())
    assert (check.check_id, check.state, check.args) == ("testssl", "planned", {"starttls": "smtp"})
    (implicit,) = plan_surface(SurfaceInput("h", 993, "tls_service"), Options(), IndexInfo())
    assert implicit.args == {}


def test_negative_req_pipe_009_other_services_get_no_web_or_tls_check():
    for cls in ("service", "unknown"):
        (check,) = plan_surface(SurfaceInput("h", 22, cls), Options(crawling=True), IndexInfo())
        assert (check.state, check.reason) == ("skipped", "not_a_web_service")


# --- surface classification of open ports ----------------------------------------------

@pytest.mark.parametrize("port,name,expected", [
    (465, "smtps", ("tls_service", None)), (993, "imaps", ("tls_service", None)), (995, "pop3s", ("tls_service", None)),
    (636, "ldaps", ("tls_service", None)), (8443, "ssl", ("tls_service", None)),
    (25, "smtp", ("tls_service", "smtp")), (587, "submission", ("tls_service", "smtp")), (143, "imap", ("tls_service", "imap")),
    (110, "pop3", ("tls_service", "pop3")), (21, "ftp", ("tls_service", "ftp")), (5432, "postgresql", ("tls_service", "postgres")),
    (22, "ssh", ("service", None)), (3389, "ms-wbt-server", ("service", None)), (6379, "redis", ("service", None)),
    (9999, "unknown", ("unknown", None)), (9998, "tcpwrapped", ("unknown", None)), (9997, "", ("unknown", None)),
])
def test_req_pipe_001_open_ports_are_classified(port, name, expected):
    assert surfaces.classify_open_port(port, name) == expected


def test_req_pipe_001_an_unidentified_port_with_a_product_is_a_service():
    assert surfaces.classify_open_port(9999, "unknown", "Something 1.0") == ("service", None)


# --- REQ-PIPE-002: the technology profile ----------------------------------------------

def test_req_pipe_002_keys_are_normalized_and_versions_split():
    assert tech_profile.keys_for("Nextcloud") == ["nextcloud"]
    assert tech_profile.keys_for("PHP:8.2.7") == ["php@8.2.7"]
    assert tech_profile.keys_for("jQuery:3.6.0") == ["jquery@3.6.0"]
    assert tech_profile.keys_for("Apache httpd 2.4.57") == ["apache_httpd@2.4.57", "apache"]
    assert tech_profile.keys_for("Nginx") == ["nginx"]


def test_req_pipe_002_noise_and_empty_input_are_not_technologies():
    for raw in ("HSTS", "Ubuntu", "", None, "unknown", "tcpwrapped", " "):
        assert tech_profile.keys_for(raw) == [], raw


def test_req_pipe_002_the_profile_merges_nmap_httpx_and_the_server_header_without_duplicates():
    profile = tech_profile.build_profile(
        httpx_tech=["Nextcloud", "Nginx", "PHP", "HSTS"], webserver="nginx",
        nmap_products=[("nginx", "1.25.3")], extra=["nextcloud_server"],
    )
    assert profile == ["nginx@1.25.3", "nextcloud", "php", "nextcloud_server"]
    assert tech_profile.product_keys(profile) == ["nginx", "nextcloud", "php", "nextcloud_server"]


def test_req_pipe_002_an_empty_profile_stays_empty():
    assert tech_profile.build_profile() == []
    assert tech_profile.build_profile(httpx_tech=["HSTS"], webserver="") == []


def test_req_pipe_002_the_profile_is_bounded():
    assert len(tech_profile.build_profile(httpx_tech=[f"tech{i}" for i in range(80)])) == tech_profile.MAX_PROFILE_ENTRIES


def test_req_pipe_002_the_nuclei_technology_output_names_products():
    from app.nuclei_parse import parse_nuclei_tech

    out = "\n".join([
        '{"template-id":"nextcloud-detect","info":{"metadata":{"vendor":"nextcloud","product":"nextcloud_server"}}}',
        '{"template-id":"tech-detect","matcher-name":"php","info":{}}',
        '{"template-id":"nginx-version","info":{}}',
        "not json", '{"template-id":"x-panel","info":{}}',
    ])
    assert parse_nuclei_tech(out) == ["nextcloud_server", "nextcloud", "php", "nginx", "x"]
    assert parse_nuclei_tech("") == []


def test_the_profile_normalization_matches_the_template_indexs_own():
    import importlib.util

    spec = importlib.util.spec_from_file_location("nuclei_index_norm", REPO / "tool-runner" / "nuclei_index.py")
    index = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(index)
    for raw in ("Nextcloud Server", "nginx", "ASP.NET", "Apache_HTTP-Server", "  PHP  ", "C++ App"):
        assert tech_profile.normalize_key(raw) == index.normalize_key(raw), raw
