"""Deterministic scan planner (REQ-PIPE-003, REQ-PIPE-004, REQ-PIPE-016).

`plan_surface` is a pure function of what the scan observed about one surface
(its service class and technology profile) and the engagement's options: the
same inputs give the same plan. Every check is either planned with a reason or
skipped with a reason, so the operator can read what will run and why - and
what will not.

The planner only chooses among fixed invocations the worker builds itself. It
never produces tool arguments beyond the small typed selections the Scope
Gateway validates, and a plan is never an authorization: every planned check is
still one gateway-authorized tool call when it executes.
"""

from __future__ import annotations

import dataclasses
import math

from app.tech_profile import product_keys
from app.tool_runner_client import (
    MAX_SELECT_PRODUCTS,
    NUCLEI_OOB_PARTS,
    check_budget_s,
)

# REQ-PIPE-016: web products whose product-bound templates run when a surface's
# profile is empty (nothing identified). Reviewed list, mirrored in
# docs/design/scan-pipeline-architecture.md; a test fails when they diverge.
COMMON_PRODUCTS = (
    "wordpress", "drupal", "joomla", "apache", "nginx", "iis", "tomcat", "jenkins", "gitlab", "grafana",
    "confluence", "jira", "php", "spring",
)

SCAN_PROFILES = ("standard", "thorough")
# REQ-PIPE-017: the thorough profile's deep content-discovery sweep.
DEEP_FFUF_CHECK_ID = "ffuf:deep"
DEEP_FFUF_WORDLIST = "raft-medium-dirs"
# Templates per nuclei call: small enough that a call's budget stays far below
# the runner maximum and a stopped call loses little.
SHARD_TARGET = 400
# Used only when the runner's index could not be read at planning time; the
# real count is re-resolved when the check executes.
FALLBACK_GENERIC_TEMPLATES = 1980
FALLBACK_ALL_TEMPLATES = 5883


@dataclasses.dataclass(frozen=True)
class IndexInfo:
    generic: int = FALLBACK_GENERIC_TEMPLATES
    total: int = FALLBACK_ALL_TEMPLATES
    known: bool = False


@dataclasses.dataclass(frozen=True)
class Options:
    crawling: bool = False
    screenshots: bool = False
    oob: bool = False
    oob_available: bool = True
    scan_profile: str = "standard"
    # Tools the campaign has switched off in its tool list: their checks are
    # planned as skipped. The gateway refuses them regardless; this only makes
    # the plan say so before anything runs.
    disabled_tools: frozenset[str] = frozenset()


@dataclasses.dataclass(frozen=True)
class SurfaceInput:
    host: str
    port: int
    service_class: str
    scheme: str | None = None
    profile: tuple[str, ...] = ()
    alias_of: str | None = None
    duplicate_of: str | None = None
    starttls: str | None = None

    @property
    def key(self) -> str:
        return f"{self.host}:{self.port}"


@dataclasses.dataclass(frozen=True)
class PlannedCheck:
    check_id: str
    tool: str
    state: str  # planned | skipped
    reason: str
    args: dict = dataclasses.field(default_factory=dict)
    depends_on: str | None = None
    budget_s: int | None = None


def shard_count(templates: int) -> int:
    return max(1, math.ceil(max(0, templates) / SHARD_TARGET))


def resolve_products(profile: tuple[str, ...] | list[str]) -> tuple[list[str], str]:
    """The product keys whose templates run, and why.

    A surface with an identified profile runs the templates bound to those
    products only; an empty profile (nothing identified) runs the fixed
    common-product list instead (REQ-PIPE-016), never a guess."""
    keys = product_keys(profile)[:MAX_SELECT_PRODUCTS]
    if keys:
        return keys, "product:" + ",".join(keys)
    return list(COMMON_PRODUCTS), "no_product_identified:common_products"


def _planned(check_id: str, tool: str, reason: str, args: dict | None = None, *, depends_on: str | None = None,
             budget_s: int | None = None) -> PlannedCheck:
    return PlannedCheck(check_id, tool, "planned", reason, dict(args or {}), depends_on, budget_s)


def _skipped(check_id: str, tool: str, reason: str) -> PlannedCheck:
    return PlannedCheck(check_id, tool, "skipped", reason)


def _nuclei_selection_checks(surface: SurfaceInput, options: Options, index: IndexInfo) -> list[PlannedCheck]:
    checks: list[PlannedCheck] = []
    if options.scan_profile == "thorough":
        n = shard_count(index.total)
        for k in range(1, n + 1):
            checks.append(_planned(
                f"nuclei:all:{k}of{n}", "nuclei", "thorough:every_template",
                {"mode": "select", "group": "all", "shard": f"{k}/{n}"},
            ))
        return checks
    n = shard_count(index.generic)
    for k in range(1, n + 1):
        checks.append(_planned(
            f"nuclei:generic:{k}of{n}", "nuclei", "generic_web",
            {"mode": "select", "group": "generic", "shard": f"{k}/{n}"},
        ))
    keys, reason = resolve_products(surface.profile)
    checks.append(_planned(
        "nuclei:products", "nuclei", reason,
        {"mode": "select", "group": "products", "products": keys, "from_profile": True},
        depends_on="nuclei:tech",
    ))
    return checks


def plan_surface(surface: SurfaceInput, options: Options, index: IndexInfo | None = None) -> list[PlannedCheck]:
    """The ordered checks of one surface (cheap first, so a run that is cut
    short still holds the inexpensive signal)."""
    checks = _plan_checks(surface, options, index or IndexInfo())
    if not options.disabled_tools:
        return checks
    return [
        _skipped(c.check_id, c.tool, "tool_disabled")
        if c.state == "planned" and c.tool in options.disabled_tools and c.check_id != "header_findings"
        else c
        for c in checks
    ]


def _plan_checks(surface: SurfaceInput, options: Options, index: IndexInfo) -> list[PlannedCheck]:
    cls = surface.service_class

    if cls == "web_alias":
        target = surface.alias_of or "another surface"
        skipped = [
            ("wafw00f", "wafw00f"), ("testssl", "testssl"), ("header_findings", "httpx"), ("ffuf", "ffuf"),
            ("screenshot", "screenshot"), ("katana", "katana"), ("nuclei", "nuclei"),
        ]
        if options.scan_profile == "thorough":
            skipped.insert(4, (DEEP_FFUF_CHECK_ID, "ffuf"))
        return [_skipped(cid, tool, f"web_alias_of:{target}") for cid, tool in skipped]

    if cls == "tls_service":
        return [_planned("testssl", "testssl", "tls_service", {"starttls": surface.starttls} if surface.starttls else {})]

    if cls != "web":
        return [_skipped("deep_checks", "-", "not_a_web_service")]

    dup = surface.duplicate_of
    dup_reason = f"duplicate_vhost_of:{dup}" if dup else None
    checks: list[PlannedCheck] = [_planned("wafw00f", "wafw00f", "web")]
    if surface.scheme == "https":
        checks.append(_planned("testssl", "testssl", "web_over_tls"))
    else:
        checks.append(_skipped("testssl", "testssl", "not_a_tls_service"))

    def deep(check_id: str, tool: str, reason: str, args: dict | None = None, *, enabled: bool = True,
             depends_on: str | None = None) -> None:
        if dup_reason:
            checks.append(_skipped(check_id, tool, dup_reason))
        elif not enabled:
            checks.append(_skipped(check_id, tool, "switch_off"))
        else:
            checks.append(_planned(check_id, tool, reason, args, depends_on=depends_on))

    deep("header_findings", "httpx", "web")
    deep("ffuf", "ffuf", "web", {"wordlist": "quickhits"})
    deep("screenshot", "screenshot", "switch_on", enabled=options.screenshots)
    deep("katana", "katana", "switch_on", enabled=options.crawling)
    if dup_reason:
        checks.append(_skipped("nuclei", "nuclei", dup_reason))
    else:
        checks.append(_planned("nuclei:tech", "nuclei", "technology_profile", {"mode": "tech"}))
        checks.extend(_nuclei_selection_checks(surface, options, index))
        checks.append(_planned("nuclei:headless", "nuclei", "web", {"mode": "headless"}))
        checks.append(_planned("nuclei:takeover", "nuclei", "web", {"mode": "takeover"}))
    if options.scan_profile == "thorough":
        # REQ-PIPE-017: the full-list sweep is a planned check with a budget
        # sized to its list (about 25 minutes), not an agent call that a 4-minute
        # cap cuts at ~15 %. After the cheap and the nuclei checks, so a run cut
        # short still holds their signal.
        deep(DEEP_FFUF_CHECK_ID, "ffuf", "thorough:deep_content_discovery", {"wordlist": DEEP_FFUF_WORDLIST})
    deep("nuclei:endpoints", "nuclei", "crawled_endpoints", {"mode": "endpoints"},
         enabled=options.crawling, depends_on="katana")
    for part in sorted(NUCLEI_OOB_PARTS):
        if options.oob and not options.oob_available and not dup_reason:
            checks.append(_skipped(f"nuclei:oob:{part}", "nuclei", "oob_unavailable"))
        else:
            deep(f"nuclei:oob:{part}", "nuclei", "switch_on", {"mode": "oob", "part": part}, enabled=options.oob)
    return [dataclasses.replace(c, budget_s=_declared_budget(c)) if c.state == "planned" else c for c in checks]


def _declared_budget(check: PlannedCheck) -> int | None:
    """The check's time budget where it is known at planning time. Selection
    calls get theirs from their template count when they execute."""
    if check.tool == "-" or check.check_id == "header_findings":
        return None
    if check.check_id.startswith("nuclei:") and check.args.get("mode") == "select":
        return None
    return check_budget_s(check.tool, check.args)


def plan_all(surfaces: list[SurfaceInput], options: Options, index: IndexInfo | None = None) -> dict[str, list[PlannedCheck]]:
    """surface key -> its checks, in the order the surfaces were given."""
    return {s.key: plan_surface(s, options, index) for s in surfaces}
