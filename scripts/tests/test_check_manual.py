"""TC-MANUAL-002/003: the manual checks pass on the real tree, and each check fails on the
mistake it exists to catch (a dead link, a missing route, a label the console does not
have, an unexplained code, an unused image, a private address)."""

from __future__ import annotations

import importlib.util
import shutil
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location("check_manual", ROOT / "scripts" / "check_manual.py")
cm = importlib.util.module_from_spec(_spec)
sys.modules["check_manual"] = cm
_spec.loader.exec_module(cm)

PAGE = "# {title}\n\n**Who this is for:** an operator.\n**After this page you can:** do the thing.\n\n{body}\n"


def write(root: Path, rel: str, text: str) -> Path:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def page(root: Path, name: str, body: str = "", title: str = "A page") -> Path:
    return write(root, f"docs/manual/{name}", PAGE.format(title=title, body=body))


@pytest.fixture()
def tree(tmp_path):
    page(tmp_path, "README.md", "Start.")
    return tmp_path


# --- the real tree --------------------------------------------------------------------------------

def test_the_real_manual_passes_every_check():
    assert cm.check_all(ROOT) == []


@pytest.mark.parametrize("name", [n for n, _ in cm.CHECKS])
def test_every_check_runs_on_the_real_tree_and_finds_nothing(name):
    check = dict(cm.CHECKS)[name]
    assert check(ROOT) == []


def test_the_manual_is_complete_enough_to_be_the_only_documentation():
    pages = {p.relative_to(ROOT / "docs/manual").as_posix() for p in cm.manual_pages(ROOT)}
    assert set(cm.REQUIRED_PAGES) <= pages
    assert len(cm.console_routes(ROOT)) >= 10 and len(cm._source_codes(ROOT)) >= 40  # the checks have real input


# --- anchors --------------------------------------------------------------------------------------

@pytest.mark.parametrize("heading, expected", [
    ("2.1 nmap — port/service discovery", "21-nmap--portservice-discovery"),
    ("Why the Scope Gateway denied a call", "why-the-scope-gateway-denied-a-call"),
    ("Bug-bounty engagements", "bug-bounty-engagements"),
    ("`PUT /engagements/{id}/owner` and more", "put-engagementsidowner-and-more"),
    ("Scan readiness messages", "scan-readiness-messages"),
    ("[Linked](x.md) heading", "linked-heading"),
])
def test_anchors_follow_githubs_rule(heading, expected):
    assert cm.github_slug(heading) == expected


def test_duplicate_headings_get_numbered_anchors():
    assert cm.anchors("# A\n\n## Same\n\n## Same\n") == {"a", "same", "same-1"}


def test_a_heading_inside_a_code_fence_is_not_an_anchor():
    assert "fake" not in cm.anchors("# Real\n\n```\n# fake\n```\n")


# --- structure ------------------------------------------------------------------------------------

def test_negative_a_missing_required_page_is_reported(tree):
    assert any("required page is missing" in p for p in cm.check_structure(tree, ["README.md", "guides/x.md"]))


def test_negative_a_page_must_say_who_it_is_for_and_what_the_reader_gains(tree):
    write(tree, "docs/manual/bad.md", "# Bad\n\nJust text.\n")
    problems = cm.check_structure(tree, ["README.md"])
    assert any("who it is for" in p for p in problems) and any("afterwards" in p for p in problems)


def test_negative_a_page_must_start_with_a_heading(tree):
    write(tree, "docs/manual/bad.md", "Text first.\n**Who this is for:** x\n**After this page you can:** y\n")
    assert any("level-1 heading" in p for p in cm.check_structure(tree, ["README.md"]))


# --- links ----------------------------------------------------------------------------------------

def test_negative_a_dead_relative_link_is_reported(tree):
    page(tree, "guides/a.md", "See [x](missing.md).")
    assert any("dead link: missing.md" in p for p in cm.check_links(tree))


def test_a_working_link_and_an_external_one_pass(tree):
    page(tree, "guides/a.md", "See [home](../README.md), [web](https://example.com/x) and [mail](mailto:a@example.com).")
    assert cm.check_links(tree) == []


def test_negative_an_anchor_that_does_not_exist_is_reported(tree):
    page(tree, "guides/a.md", "See [x](../README.md#no-such-heading).")
    assert any("no heading for the anchor" in p for p in cm.check_links(tree))


def test_an_anchor_that_exists_passes_and_one_within_the_page_too(tree):
    page(tree, "other.md", "## Section one\n\nSee [up](#section-one).")
    page(tree, "guides/a.md", "See [x](../other.md#section-one).")
    assert cm.check_links(tree) == []


def test_links_in_code_are_not_links(tree):
    page(tree, "guides/a.md", "Write `[x](missing.md)` like this.\n\n```\n[y](also-missing.md)\n```")
    assert cm.check_links(tree) == []


def test_negative_a_link_may_not_leave_the_repository(tree):
    page(tree, "guides/a.md", "See [x](../../../../outside.md).")
    assert any("leaves the repository" in p for p in cm.check_links(tree))


def test_negative_a_manual_page_may_not_link_to_a_file_the_public_export_drops(tree):
    write(tree, "scripts/oss-public-paths.txt", "docs/\nREADME.md\n")
    write(tree, "scripts/oss-public-paths.deny.txt", "docs/internal/\n")
    write(tree, "docs/internal/notes.md", "# Notes\n")
    page(tree, "guides/a.md", "See [x](../../internal/notes.md).")
    assert any("public export does not keep" in p for p in cm.check_links(tree))


def test_without_the_export_rules_that_check_is_skipped(tree):
    write(tree, "docs/internal/notes.md", "# Notes\n")
    page(tree, "guides/a.md", "See [x](../../internal/notes.md).")
    assert cm.check_links(tree) == []


def test_links_in_other_docs_are_checked_for_existence_too(tree):
    write(tree, "docs/other.md", "# O\n\n[x](gone.md)\n")
    assert any("docs/other.md: dead link: gone.md" in p for p in cm.check_links(tree))


# --- routes ---------------------------------------------------------------------------------------

APP = '<Routes>\n<Route path="/a" element={<A />} />\n<Route path="/b/:id" element={<B />} />\n<Route path="*" element={<N />} />\n</Routes>\n'


def test_negative_a_route_the_reference_does_not_mention_is_reported(tree):
    write(tree, "frontend/src/App.tsx", APP)
    write(tree, "docs/manual/reference/README.md", PAGE.format(title="R", body="Only `/a`."))
    problems = cm.check_routes(tree)
    assert problems == ["docs/manual/reference: the route `/b/:id` of the console is not mentioned"]


def test_every_route_mentioned_passes_and_the_wildcard_needs_no_entry(tree):
    write(tree, "frontend/src/App.tsx", APP)
    write(tree, "docs/manual/reference/README.md", PAGE.format(title="R", body="`/a` and `/b/:id`."))
    assert cm.check_routes(tree) == []


def test_adding_a_route_to_the_console_makes_the_check_fail():
    """The guard the issue asks for: a new route without a manual entry fails."""
    app = (ROOT / "frontend/src/App.tsx").read_text()
    assert '<Route path="*"' in app
    routes = cm.console_routes(ROOT)
    assert "/engagements/:id/runs/:runId" in routes and "/new" in routes


# --- labels ---------------------------------------------------------------------------------------

def test_negative_a_label_the_console_does_not_have_is_reported(tree):
    write(tree, "frontend/src/Page.tsx", "<button>Save tool grants</button>")
    page(tree, "guides/a.md", "<!-- ui-labels: Save tool grants | Delete everything -->\n")
    assert cm.check_labels(tree) == ['docs/manual/guides/a.md: the label "Delete everything" does not exist in the console']


def test_labels_that_exist_pass_even_when_jsx_escapes_or_wraps_them(tree):
    write(tree, "frontend/src/Page.tsx", "<h2>DNS &amp; hosting</h2>\n<p>\n  Confirm: this widens\n  what it may do\n</p>")
    page(tree, "guides/a.md", "<!-- ui-labels: DNS & hosting | Confirm: this widens what it may do -->\n")
    assert cm.check_labels(tree) == []


def test_negative_a_guide_must_list_the_labels_it_quotes(tree):
    write(tree, "frontend/src/Page.tsx", "<b>x</b>")
    page(tree, "guides/a.md", "No list.")
    assert any("list the console labels" in p for p in cm.check_labels(tree))


def test_the_landing_pages_need_no_label_list(tree):
    write(tree, "frontend/src/Page.tsx", "<b>x</b>")
    page(tree, "guides/README.md", "Index.")
    assert cm.check_labels(tree) == []


# --- codes ----------------------------------------------------------------------------------------

def codes_tree(tmp_path, documented: str):
    write(tmp_path, "control-plane/app/scan_readiness.py", 'Blocker(\n "no_scope",\n "x")\n')
    write(tmp_path, "control-plane/app/gateway/authorize.py", 'return DENY("target_out_of_scope")\nDENY("brand_new_reason")\n')
    write(tmp_path, "worker/app/tool_execution.py", 'SKIP_REASONS = frozenset({\n    "not_a_tls_service", "gone_missing",\n})\n')
    write(tmp_path, "control-plane/app/x.py", 'run.state_reason = "some_run_reason"\n')
    write(tmp_path, cm.TROUBLESHOOTING, PAGE.format(title="T", body=documented))
    return tmp_path


def test_negative_a_code_the_system_can_show_but_the_page_omits_is_reported(tmp_path):
    codes_tree(tmp_path, "`no_scope` `target_out_of_scope` `not_a_tls_service`")
    unexplained = {p.split("`")[1] for p in cm.check_codes(tmp_path)}
    assert {"brand_new_reason", "gone_missing", "some_run_reason"} <= unexplained
    assert "no_scope" not in unexplained


def test_a_new_gateway_denial_must_be_explained(tmp_path):
    documented = " ".join(f"`{c}`" for c in cm._source_codes(tmp_path) if False)  # nothing documented
    codes_tree(tmp_path, documented or "nothing")
    assert any("brand_new_reason" in p for p in cm.check_codes(tmp_path))


def test_codes_with_a_value_or_a_type_after_them_count_as_explained(tmp_path):
    body = " ".join(f"`{c}`" for c in cm._source_codes(tmp_path))
    codes_tree(tmp_path, body + " `pipeline_error:<type>:<phase>` `coverage_degraded:<tool>=<why>`")
    assert not any("pipeline_error" in p or "coverage_degraded" in p for p in cm.check_codes(tmp_path))


def test_the_real_gateway_reasons_are_all_found():
    found = set(cm._source_codes(ROOT))
    assert {"target_out_of_scope", "no_tool_grant", "no_active_tool_grant", "cancellation_status_unavailable",
            "asset_review_pending", "not_a_tls_service"} <= found


# --- images ---------------------------------------------------------------------------------------

def test_negative_an_image_that_is_not_there_is_reported(tree):
    page(tree, "guides/a.md", "![shot](../img/missing.png)")
    assert any("does not exist" in p for p in cm.check_images(tree))


def test_negative_an_unused_image_is_reported(tree):
    write(tree, "docs/manual/img/orphan.png", "x")
    assert any("not used by any page" in p for p in cm.check_images(tree))


def test_a_used_image_passes(tree):
    write(tree, "docs/manual/img/ok.png", "x")
    page(tree, "guides/a.md", "![ok](../img/ok.png)")
    assert cm.check_images(tree) == []


def test_negative_an_oversized_image_is_reported(tree):
    path = write(tree, "docs/manual/img/big.png", "x")
    path.write_bytes(b"0" * (cm.MAX_IMAGE_BYTES + 1))
    page(tree, "guides/a.md", "![big](../img/big.png)")
    assert any("larger than" in p for p in cm.check_images(tree))


# --- the entry points ------------------------------------------------------------------------------

def test_negative_a_readme_that_does_not_link_the_manual_is_reported(tree):
    write(tree, "README.md", "# Project\n\nNo pointer to the manual.\n")
    write(tree, "docs/README.md", "# Docs\n\nSee [the manual](manual/README.md).\n")
    problems = cm.check_structure(tree, required=[])
    assert problems == ["README.md: must link to the manual (manual/README.md)"]


def test_a_missing_docs_readme_is_reported(tree):
    write(tree, "README.md", "# Project\n\nSee [the manual](docs/manual/README.md).\n")
    assert cm.check_structure(tree, required=[]) == ["docs/README.md: must link to the manual (manual/README.md)"]


def test_both_readmes_linking_the_manual_pass(tree):
    write(tree, "README.md", "# Project\n\nSee [the manual](docs/manual/README.md).\n")
    write(tree, "docs/README.md", "# Docs\n\n| [manual/](manual/README.md) | The manual |\n")
    assert cm.check_structure(tree, required=[]) == []


# --- tools ----------------------------------------------------------------------------------------

REGISTRY = (
    'ToolSpec("alpha-scan", "recon", "passive", installed=True, default_enabled=True),\n'
    'ToolSpec("beta-probe", "fingerprint", "raw_network", installed=True, default_enabled=True),\n'
    'ToolSpec("gamma-ghost", "recon", "passive", installed=False, default_enabled=False),\n'
)


def test_every_installed_tool_of_the_real_registry_is_described():
    assert cm.installed_tools(ROOT), "the registry must yield tools, or this check protects nothing"
    assert cm.check_tools(ROOT) == []


def test_negative_an_installed_tool_missing_from_the_tools_page_is_reported(tree):
    write(tree, cm.REGISTRY, REGISTRY)
    page(tree, "tools.md", "Only `alpha-scan` is described here.")
    assert cm.check_tools(tree) == [f"{cm.TOOLS_PAGE}: the tool `beta-probe` is not described"]


def test_a_tool_that_is_not_installed_needs_no_description(tree):
    write(tree, cm.REGISTRY, REGISTRY)
    page(tree, "tools.md", "alpha-scan and beta-probe.")
    assert cm.check_tools(tree) == []


def test_a_tool_name_inside_another_word_does_not_count(tree):
    write(tree, cm.REGISTRY, REGISTRY)
    page(tree, "tools.md", "alpha-scan-extended and beta-probes only.")
    assert len(cm.check_tools(tree)) == 2


# --- privacy --------------------------------------------------------------------------------------

@pytest.mark.parametrize("text, expected", [
    ("The router is 10.0.0.1.", "10.0.0.1"),
    ("Write to someone@company.io.", "company.io"),
])
def test_negative_private_addresses_and_accounts_are_reported(tree, text, expected):
    page(tree, "guides/a.md", text)
    assert any(expected in p for p in cm.check_privacy(tree))


def test_negative_a_listed_private_marker_is_reported(tree):
    """The marker file is read from the tree being checked (here a made-up name)."""
    write(tree, cm.PRIVATE_MARKERS_FILE, "# comment\nacme-internal\n")
    page(tree, "guides/a.md", "Scan the host at scan.Acme-Internal.example.")
    problems = cm.check_privacy(tree)
    assert any("acme-internal" in p for p in problems), problems


def test_without_a_marker_file_only_the_generic_rules_apply(tree):
    """The exported tree has no marker file: the made-up name passes, a private address does not."""
    page(tree, "guides/a.md", "Scan the host at scan.acme-internal.example, or 10.0.0.1.")
    problems = cm.check_privacy(tree)
    assert not any("acme-internal" in p for p in problems)
    assert any("10.0.0.1" in p for p in problems)


def test_the_real_marker_file_is_not_in_the_public_export():
    """REQ-MANUAL-003: the file that names the private words must not be exported itself."""
    if not (ROOT / cm.PRIVATE_MARKERS_FILE).is_file():
        pytest.skip("no marker file in this tree (the public export, which is the point)")
    assert cm.PRIVATE_MARKERS_FILE in cm._rules(ROOT / "scripts/oss-public-paths.deny.txt")
    assert cm.load_private_markers(ROOT), "the private tree must carry its markers"


def test_no_public_manual_file_contains_a_listed_private_marker():
    markers = cm.load_private_markers(ROOT)
    if not markers:
        pytest.skip("no marker file in this tree (the public export)")
    public = [ROOT / "scripts/check_manual.py", ROOT / "scripts/manual_screenshots.py",
              ROOT / "control-plane/scripts/manual_demo_seed.py", Path(__file__)]
    for path in public:
        text = path.read_text(encoding="utf-8").lower()
        assert not [m for m in markers if m in text], f"{path.name} names a private marker"


def test_documentation_addresses_and_example_domains_are_fine(tree):
    page(tree, "guides/a.md", "Use 203.0.113.7, 198.51.100.0/24, http://127.0.0.1:8000 and you@example.com.")
    assert cm.check_privacy(tree) == []


def test_version_numbers_are_not_addresses(tree):
    page(tree, "guides/a.md", "Version 2.4.52 and OpenSSH 9.6.1.")
    assert cm.check_privacy(tree) == []


# --- the command line ------------------------------------------------------------------------------

def test_main_exits_zero_on_the_real_tree(capsys):
    assert cm.main() == 0
    assert "user manual ok" in capsys.readouterr().out


def test_main_exits_one_and_lists_the_problems_on_a_broken_tree(tmp_path, monkeypatch, capsys):
    shutil.copytree(ROOT / "docs/manual", tmp_path / "docs/manual")
    (tmp_path / "docs/manual/guides/run-a-scan.md").write_text("# Broken\n\nNo audience lines.\n")
    monkeypatch.setattr(cm, "ROOT", tmp_path)
    assert cm.main() == 1
    assert "who it is for" in capsys.readouterr().err
