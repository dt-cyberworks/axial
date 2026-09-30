"""Styled customer report renderer (REQ-REPORT-005).

Separate from `app/pdf.py`: that writer's byte-for-byte determinism is
required for the authorization document's configuration checksum and stays
untouched. This module renders only the customer report, from the
`ReportModel` that `app/report_builder.py` already built and redacted - it
introduces no new data path, only a layout for facts that already went
through REQ-REPORT-002's redaction.

Compression is deliberately off (`pageCompression=0`): these documents are
small (well under a MB), and plain-text content streams keep a raw-bytes
credential search meaningful, matching how REQ-REPORT-002's negative test
already reasons about the previous, uncompressed writer's output.

Every dynamic string is escaped before it reaches a `Paragraph` - reportlab's
Paragraph text is a small XML dialect, and a finding title like
`Reflected XSS via <script> in ?q=` is exactly the kind of content this
renderer must display literally, not parse as markup.
"""

from __future__ import annotations

import io
from xml.sax.saxutils import escape as _esc

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import LETTER
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.pdfgen.canvas import Canvas
from reportlab.platypus import (
    BaseDocTemplate,
    Frame,
    KeepTogether,
    NextPageTemplate,
    PageBreak,
    PageTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)

from app.report_builder import (
    DEGRADED_WARNING,
    DIFF_NOTE,
    METHOD_LINES,
    RISK_RATING_EXPLANATION,
    SEVERITY_ORDER,
    ReportModel,
)

PAGE_WIDTH, PAGE_HEIGHT = LETTER
MARGIN = 20 * mm
CONTENT_WIDTH = PAGE_WIDTH - 2 * MARGIN

TEAL = colors.HexColor("#087f8c")
TEAL_DARK = colors.HexColor("#06636d")
INK = colors.HexColor("#17212b")
MUTED = colors.HexColor("#647280")
LINE = colors.HexColor("#d8e0e6")
SURFACE_2 = colors.HexColor("#eef3f6")
WHITE = colors.white

SEVERITY_COLOR = {
    "critical": colors.HexColor("#7a251f"),
    "high": colors.HexColor("#b8362d"),
    "medium": colors.HexColor("#946100"),
    "low": colors.HexColor("#2b67b1"),
    "info": colors.HexColor("#647280"),
}
RISK_LIGHT_COLOR = {
    "RED": colors.HexColor("#b8362d"),
    "AMBER": colors.HexColor("#946100"),
    "BLUE": colors.HexColor("#2b67b1"),
    "GREEN": colors.HexColor("#22784f"),
}


def _severity_color(severity: str) -> colors.Color:
    return SEVERITY_COLOR.get(str(severity).lower(), MUTED)


def _styles() -> dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()
    styles = {
        "CoverTitle": ParagraphStyle("CoverTitle", parent=base["Title"], fontName="Helvetica-Bold",
                                      fontSize=30, leading=36, textColor=TEAL, spaceAfter=10, alignment=TA_CENTER),
        "CoverSubtitle": ParagraphStyle("CoverSubtitle", parent=base["Normal"], fontName="Helvetica",
                                         fontSize=13, leading=17, textColor=MUTED, alignment=TA_CENTER, spaceAfter=28),
        "CoverEngagement": ParagraphStyle("CoverEngagement", parent=base["Normal"], fontName="Helvetica-Bold",
                                           fontSize=18, leading=23, textColor=INK, alignment=TA_CENTER, spaceAfter=18),
        "CoverNotice": ParagraphStyle("CoverNotice", parent=base["Normal"], fontName="Helvetica-Oblique",
                                       fontSize=9.5, textColor=MUTED, alignment=TA_CENTER, leading=13),
        "H1": ParagraphStyle("H1", parent=base["Heading1"], fontName="Helvetica-Bold", fontSize=16,
                              leading=20, textColor=TEAL_DARK, spaceBefore=14, spaceAfter=8),
        "H2": ParagraphStyle("H2", parent=base["Heading2"], fontName="Helvetica-Bold", fontSize=12,
                              leading=16, textColor=INK, spaceBefore=10, spaceAfter=6),
        "Body": ParagraphStyle("Body", parent=base["Normal"], fontName="Helvetica", fontSize=9.5,
                                textColor=INK, leading=13),
        "Muted": ParagraphStyle("Muted", parent=base["Normal"], fontName="Helvetica-Oblique", fontSize=8.5,
                                 textColor=MUTED, leading=12),
        "Bullet": ParagraphStyle("Bullet", parent=base["Normal"], fontName="Helvetica", fontSize=9.5,
                                  textColor=INK, leading=13, leftIndent=10, bulletIndent=0),
        "Cell": ParagraphStyle("Cell", parent=base["Normal"], fontName="Helvetica", fontSize=8.5,
                                textColor=INK, leading=11),
        "CellHead": ParagraphStyle("CellHead", parent=base["Normal"], fontName="Helvetica-Bold", fontSize=8.5,
                                    textColor=WHITE, leading=11),
        "Badge": ParagraphStyle("Badge", parent=base["Normal"], fontName="Helvetica-Bold", fontSize=8.5,
                                 textColor=WHITE, alignment=TA_CENTER, leading=11),
        "FindingTitle": ParagraphStyle("FindingTitle", parent=base["Normal"], fontName="Helvetica-Bold",
                                        fontSize=11, textColor=INK, leading=14),
        "Warning": ParagraphStyle("Warning", parent=base["Normal"], fontName="Helvetica-Bold", fontSize=9.5,
                                   textColor=colors.HexColor("#7a251f"), leading=13),
    }
    return styles


def _p(text: object, style: ParagraphStyle) -> Paragraph:
    return Paragraph(_esc(str(text)), style)


def _table(data: list[list], col_widths: list[float], style: TableStyle, repeat_header: bool = True) -> Table:
    table = Table(data, colWidths=col_widths, repeatRows=1 if repeat_header else 0)
    table.setStyle(style)
    return table


_HEADER_ROW_STYLE = [
    ("BACKGROUND", (0, 0), (-1, 0), TEAL),
    ("TEXTCOLOR", (0, 0), (-1, 0), WHITE),
    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
    ("FONTSIZE", (0, 0), (-1, -1), 8.5),
    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ("GRID", (0, 0), (-1, -1), 0.5, LINE),
    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [WHITE, SURFACE_2]),
    ("TOPPADDING", (0, 0), (-1, -1), 4),
    ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ("LEFTPADDING", (0, 0), (-1, -1), 5),
    ("RIGHTPADDING", (0, 0), (-1, -1), 5),
]


# --- cover page ------------------------------------------------------------

def _cover_flowables(model: ReportModel, styles: dict[str, ParagraphStyle]) -> list:
    meta_rows = [
        ["Generated", model.generated_at],
        ["Engagement ID", model.engagement_id],
        ["Report covers scan run", model.scan_run_id],
    ]
    meta_table = Table(
        [[_p(k, styles["Cell"]), _p(v, styles["Cell"])] for k, v in meta_rows],
        colWidths=[CONTENT_WIDTH * 0.35, CONTENT_WIDTH * 0.65],
    )
    meta_table.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
    ]))
    return [
        Spacer(1, 70 * mm),
        Paragraph("ASM-Konsole", styles["CoverTitle"]),
        Paragraph("Attack Surface Assessment Report", styles["CoverSubtitle"]),
        _p(model.engagement_title, styles["CoverEngagement"]),
        Spacer(1, 10 * mm),
        meta_table,
        Spacer(1, 20 * mm),
        Paragraph(
            "This report summarizes an authorized external attack surface assessment. "
            "It is confidential and intended for the engagement's authorized recipients.",
            styles["CoverNotice"],
        ),
    ]


# --- 1. executive summary ---------------------------------------------------

def _executive_summary_flowables(model: ReportModel, styles: dict[str, ParagraphStyle]) -> list:
    summary = model.executive_summary
    light_color = RISK_LIGHT_COLOR.get(summary.risk_light, MUTED)
    light_label = f"Overall risk: {summary.risk_light}" + (
        f"  (worst open finding: {summary.worst_severity.upper()})" if summary.worst_severity else "  (no open findings)"
    )
    light_badge = Table([[_p(light_label, styles["Badge"])]], colWidths=[CONTENT_WIDTH])
    light_badge.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), light_color),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
    ]))

    flowables: list = [
        Paragraph("1. Executive summary", styles["H1"]),
        light_badge,
        Spacer(1, 6),
        _p(f"Open findings: {summary.open_count}", styles["Body"]),
        _p(f"Trend vs. previous run: {summary.trend_line}", styles["Body"]),
        Spacer(1, 8),
        Paragraph("Top actions", styles["H2"]),
    ]
    if not summary.top_actions:
        flowables.append(_p("None. No open findings require action.", styles["Body"]))
    for index, action in enumerate(summary.top_actions, start=1):
        flowables.append(_p(f"{index}. {action}", styles["Bullet"]))
    if summary.coverage_note:
        flowables.append(Spacer(1, 8))
        flowables.append(Paragraph("Coverage of this run", styles["Warning"]))
        flowables.append(_p(summary.coverage_note, styles["Body"]))
    return flowables


# --- 2. risk overview --------------------------------------------------------

def _severity_bar(counts: dict[str, int], styles: dict[str, ParagraphStyle]) -> Table:
    total = sum(counts.values())
    if total == 0:
        bar = Table([[""]], colWidths=[CONTENT_WIDTH], rowHeights=[7 * mm])
        bar.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#22784f"))]))
        return bar
    widths = []
    cells = []
    for severity in SEVERITY_ORDER:
        count = counts.get(severity, 0)
        if count <= 0:
            continue
        widths.append(CONTENT_WIDTH * (count / total))
        cells.append("")
    bar = Table([cells], colWidths=widths, rowHeights=[7 * mm])
    style = [("LEFTPADDING", (0, 0), (-1, -1), 0), ("RIGHTPADDING", (0, 0), (-1, -1), 0)]
    col = 0
    for severity in SEVERITY_ORDER:
        if counts.get(severity, 0) <= 0:
            continue
        style.append(("BACKGROUND", (col, 0), (col, 0), _severity_color(severity)))
        col += 1
    bar.setStyle(TableStyle(style))
    return bar


def _risk_overview_flowables(model: ReportModel, styles: dict[str, ParagraphStyle]) -> list:
    overview = model.risk_overview
    header = [_p("Severity", styles["CellHead"]), _p("Open findings", styles["CellHead"])]
    rows = [header]
    for severity in SEVERITY_ORDER:
        rows.append([_p(severity.upper(), styles["Cell"]), _p(str(overview.counts.get(severity, 0)), styles["Cell"])])
    counts_table = _table(rows, [CONTENT_WIDTH * 0.7, CONTENT_WIDTH * 0.3], TableStyle(_HEADER_ROW_STYLE))

    flowables: list = [
        Paragraph("2. Risk overview", styles["H1"]),
        Paragraph("Open findings by severity", styles["H2"]),
        counts_table,
        Spacer(1, 6),
        _severity_bar(overview.counts, styles),
        Spacer(1, 10),
        _p(RISK_RATING_EXPLANATION, styles["Muted"]),
        Spacer(1, 10),
        Paragraph("Change vs. the previous run", styles["H2"]),
    ]

    if overview.diff_status == "no_run":
        flowables.append(_p("Not available: no completed scan run.", styles["Body"]))
        return flowables
    if overview.diff_status == "no_baseline":
        flowables.append(_p("Not available: this engagement has only one run, which is the baseline.", styles["Body"]))
        return flowables

    flowables.append(_p(f"Still present (unchanged): {overview.persisting_count}", styles["Body"]))
    flowables.append(_p(f"NEW in this run: {overview.new_total}", styles["Body"]))
    for item in overview.new_items:
        flowables.append(_p(item, styles["Bullet"]))
    if overview.new_total > len(overview.new_items):
        flowables.append(_p(f"... and {overview.new_total - len(overview.new_items)} more (see the console for the full list).", styles["Muted"]))

    flowables.append(_p(f"NO LONGER OBSERVED in this run: {overview.resolved_total}", styles["Body"]))
    for item in overview.resolved_items:
        flowables.append(_p(item, styles["Bullet"]))
    if overview.resolved_total > len(overview.resolved_items):
        flowables.append(_p(f"... and {overview.resolved_total - len(overview.resolved_items)} more (see the console for the full list).", styles["Muted"]))

    flowables.append(Spacer(1, 6))
    flowables.append(_p(DIFF_NOTE, styles["Muted"]))
    return flowables


# --- 3. detailed findings (findings-summary table + per-finding detail) ----

def _findings_summary_table(model: ReportModel, styles: dict[str, ParagraphStyle]) -> Table:
    header = [_p(h, styles["CellHead"]) for h in ("Severity", "Title", "Asset", "Status")]
    rows = [header]
    for finding in model.findings:
        rows.append([
            _p(finding.severity.upper(), styles["Cell"]),
            _p(finding.title, styles["Cell"]),
            _p(finding.location, styles["Cell"]),
            _p(finding.status, styles["Cell"]),
        ])
    table = _table(
        rows, [CONTENT_WIDTH * 0.12, CONTENT_WIDTH * 0.43, CONTENT_WIDTH * 0.30, CONTENT_WIDTH * 0.15],
        TableStyle(_HEADER_ROW_STYLE),
    )
    style = list(_HEADER_ROW_STYLE)
    for row_index, finding in enumerate(model.findings, start=1):
        style.append(("TEXTCOLOR", (0, row_index), (0, row_index), _severity_color(finding.severity)))
        style.append(("FONTNAME", (0, row_index), (0, row_index), "Helvetica-Bold"))
    table.setStyle(TableStyle(style))
    return table


def _finding_block(index: int, finding, styles: dict[str, ParagraphStyle]) -> KeepTogether:
    badge = Table([[_p(finding.severity.upper(), styles["Badge"])]], colWidths=[22 * mm])
    badge.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), _severity_color(finding.severity)),
        ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    title = _p(f"{index}. {finding.title}", styles["FindingTitle"])
    heading = Table([[badge, title]], colWidths=[24 * mm, CONTENT_WIDTH - 24 * mm])
    heading.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "MIDDLE"), ("LEFTPADDING", (1, 0), (1, 0), 8)]))

    parts: list = [heading, Spacer(1, 4)]
    parts.append(_p(f"Where: {finding.location}", styles["Body"]))
    parts.append(_p(
        f"Category: {finding.category}  |  Confidence: {finding.confidence}  |  "
        f"Risk score: {finding.risk_score}  |  Status: {finding.status}", styles["Body"],
    ))
    if finding.cve_line:
        parts.append(_p(f"CVE: {finding.cve_line}", styles["Body"]))
    parts.append(_p(f"First seen: {finding.first_seen}", styles["Body"]))
    if finding.inferred:
        parts.append(_p(
            "Note: inferred, not confirmed by a non-destructive proof. Treat as a lead to "
            "verify, not as an established fact.", styles["Muted"],
        ))

    if finding.explanation_paragraphs:
        parts.append(Paragraph("Explanation", styles["H2"]))
        for paragraph in finding.explanation_paragraphs:
            parts.append(_p(paragraph, styles["Body"]))
    elif finding.recommended_action:
        parts.append(_p(f"Recommended action: {finding.recommended_action}", styles["Body"]))

    if finding.evidence_items:
        parts.append(_p("Evidence (summary; credentials redacted):", styles["Body"]))
        for key, value in finding.evidence_items:
            parts.append(_p(f"- {key}: {value}", styles["Bullet"]))
    if finding.raw_ref:
        parts.append(_p(f"Full evidence reference: {finding.raw_ref}", styles["Muted"]))

    parts.append(Spacer(1, 10))
    return KeepTogether(parts)


def _triage_flowables(model: ReportModel, styles: dict[str, ParagraphStyle]) -> list:
    """REQ-TRIAGE-004: accepted risks stay visible with their justification;
    false positives are only counted."""
    flowables: list = []
    if model.accepted_risks:
        flowables.append(Paragraph("Accepted risks", styles["H2"]))
        flowables.append(_p(
            "These findings were reviewed and deliberately accepted. They are not counted as open "
            "findings above, but remain part of the assessed attack surface.", styles["Body"],
        ))
        header = [_p(h, styles["CellHead"]) for h in ("Severity", "Finding", "Asset", "Justification", "Accepted")]
        rows = [header] + [[
            _p(r.severity.upper(), styles["Cell"]), _p(r.title, styles["Cell"]), _p(r.location, styles["Cell"]),
            _p(r.justification, styles["Cell"]), _p(r.accepted_on, styles["Cell"]),
        ] for r in model.accepted_risks]
        flowables.append(_table(rows, [CONTENT_WIDTH * w for w in (0.10, 0.26, 0.22, 0.30, 0.12)],
                                TableStyle(_HEADER_ROW_STYLE)))
        flowables.append(Spacer(1, 8))
    if model.false_positive_count:
        noun = "finding was" if model.false_positive_count == 1 else "findings were"
        flowables.append(_p(
            f"{model.false_positive_count} {noun} reviewed and marked as false positive; "
            "they are not listed in this report.", styles["Muted"],
        ))
    return flowables


def _detailed_findings_flowables(model: ReportModel, styles: dict[str, ParagraphStyle]) -> list:
    flowables: list = [Paragraph("3. Detailed findings", styles["H1"])]
    if not model.findings:
        flowables.append(_p("No open findings.", styles["Body"]))
        flowables.extend(_triage_flowables(model, styles))
        return flowables

    flowables.append(Paragraph("Findings summary", styles["H2"]))
    flowables.append(_findings_summary_table(model, styles))
    flowables.append(Spacer(1, 10))
    flowables.append(Paragraph("Findings in detail", styles["H2"]))
    for index, finding in enumerate(model.findings, start=1):
        flowables.append(_finding_block(index, finding, styles))

    flowables.extend(_triage_flowables(model, styles))
    flowables.append(_p(
        "Raw requests and full tool output are deliberately not reproduced here. They remain "
        "in the platform's evidence store and audit trail, available on request.", styles["Muted"],
    ))
    return flowables


# --- 4. asset inventory ------------------------------------------------------

def _asset_inventory_flowables(model: ReportModel, styles: dict[str, ParagraphStyle]) -> list:
    inventory = model.asset_inventory
    flowables: list = [
        Paragraph("4. Asset inventory", styles["H1"]),
        _p(f"Discovered assets: {len(inventory.rows)}", styles["Body"]),
    ]
    if not inventory.rows:
        flowables.append(_p("None discovered.", styles["Body"]))
    else:
        header = [_p(h, styles["CellHead"]) for h in ("Asset", "Type", "Scope", "Via", "Services")]
        rows = [header]
        for asset in inventory.rows:
            scope_marker = "in scope" if asset.in_scope else "OUT OF SCOPE - not tested"
            rows.append([
                _p(asset.value, styles["Cell"]), _p(asset.asset_type, styles["Cell"]),
                _p(scope_marker, styles["Cell"]), _p(asset.discovered_via, styles["Cell"]),
                _p("; ".join(asset.service_lines) if asset.service_lines else "-", styles["Cell"]),
            ])
        flowables.append(_table(
            rows,
            [CONTENT_WIDTH * 0.22, CONTENT_WIDTH * 0.10, CONTENT_WIDTH * 0.18, CONTENT_WIDTH * 0.13, CONTENT_WIDTH * 0.37],
            TableStyle(_HEADER_ROW_STYLE),
        ))

    flowables.append(Spacer(1, 8))
    flowables.append(Paragraph("Third-party / shadow-IT hints", styles["H2"]))
    if not inventory.shadow_it:
        flowables.append(_p("None detected.", styles["Body"]))
    for entry in inventory.shadow_it:
        flowables.append(_p(entry, styles["Bullet"]))

    flowables.append(Spacer(1, 8))
    flowables.append(Paragraph("Certificate expiries", styles["H2"]))
    flowables.append(_p(inventory.cert_note, styles["Body"]))
    return flowables


# --- 5. methodology & scope ---------------------------------------------------

def _methodology_flowables(model: ReportModel, styles: dict[str, ParagraphStyle]) -> list:
    scope = model.methodology
    flowables: list = [Paragraph("5. Methodology & scope", styles["H1"]), Paragraph("Authorization", styles["H2"])]

    auth_rows = [
        ("Engagement", scope.engagement_label),
        ("Authorization source", scope.source),
        ("Authorized window", f"{scope.authorized_from} to {scope.authorized_until}"),
        ("Scope signed by", scope.scope_signed_by),
        ("Emergency contact", scope.emergency_contact),
        ("Autonomous agent testing", "authorized" if scope.ai_testing_allowed else "not authorized"),
    ]
    # scope_doc_sha256 is a 64-char unbroken hex string: rendered as its own
    # full-width paragraph below, not a table cell, so it never lands in a
    # column narrow enough to force a mid-hash line break.
    auth_table = Table(
        [[_p(k, styles["Cell"]), _p(v, styles["Cell"])] for k, v in auth_rows],
        colWidths=[CONTENT_WIDTH * 0.4, CONTENT_WIDTH * 0.6],
    )
    auth_table.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("GRID", (0, 0), (-1, -1), 0.5, LINE),
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [WHITE, SURFACE_2]),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING", (0, 0), (-1, -1), 5), ("RIGHTPADDING", (0, 0), (-1, -1), 5),
    ]))
    flowables.append(auth_table)
    flowables.append(Spacer(1, 6))
    flowables.append(_p("Authorization document reference (scope_doc_sha256)", styles["H2"]))
    flowables.append(_p(scope.scope_doc_sha256, styles["Body"]))

    flowables.append(Spacer(1, 8))
    flowables.append(Paragraph("What was in scope (tested)", styles["H2"]))
    if scope.allow_rows:
        header = [_p(h, styles["CellHead"]) for h in ("Type", "Value", "Ports", "Active/passive", "Authorization")]
        rows = [header]
        for row in scope.allow_rows:
            rows.append([
                _p(row.asset_type, styles["Cell"]), _p(row.value, styles["Cell"]), _p(row.ports, styles["Cell"]),
                _p(row.active, styles["Cell"]), _p(row.verified, styles["Cell"]),
            ])
        flowables.append(_table(
            rows,
            [CONTENT_WIDTH * 0.13, CONTENT_WIDTH * 0.30, CONTENT_WIDTH * 0.22, CONTENT_WIDTH * 0.17, CONTENT_WIDTH * 0.18],
            TableStyle(_HEADER_ROW_STYLE),
        ))
    else:
        flowables.append(_p("No allow-scope entries configured.", styles["Body"]))

    flowables.append(Spacer(1, 8))
    flowables.append(Paragraph("What was explicitly excluded (never tested)", styles["H2"]))
    if scope.deny_rows:
        header = [_p(h, styles["CellHead"]) for h in ("Type", "Value")]
        rows = [header] + [[_p(t, styles["Cell"]), _p(v, styles["Cell"])] for t, v in scope.deny_rows]
        flowables.append(_table(rows, [CONTENT_WIDTH * 0.3, CONTENT_WIDTH * 0.7], TableStyle(_HEADER_ROW_STYLE)))
    else:
        flowables.append(_p("No explicit exclusions configured.", styles["Body"]))

    flowables.append(Spacer(1, 8))
    flowables.append(Paragraph("Method", styles["H2"]))
    for line in METHOD_LINES:
        flowables.append(_p(line, styles["Bullet"]))

    flowables.append(Spacer(1, 8))
    flowables.append(Paragraph("Scan runs covered", styles["H2"]))
    if scope.no_runs:
        flowables.append(_p("No scan run has been executed for this engagement.", styles["Body"]))
    else:
        header = [_p(h, styles["CellHead"]) for h in ("Started at", "State", "Final phase", "Reason", "")]
        rows = [header]
        for run in scope.run_rows:
            marker = "<- this report" if run.is_report_run else ""
            rows.append([
                _p(run.started_at, styles["Cell"]), _p(run.state, styles["Cell"]), _p(run.phase, styles["Cell"]),
                _p(run.reason or "-", styles["Cell"]), _p(marker, styles["Cell"]),
            ])
        flowables.append(_table(
            rows,
            [CONTENT_WIDTH * 0.22, CONTENT_WIDTH * 0.13, CONTENT_WIDTH * 0.15, CONTENT_WIDTH * 0.35, CONTENT_WIDTH * 0.15],
            TableStyle(_HEADER_ROW_STYLE),
        ))
        if scope.runs_truncated:
            flowables.append(_p(f"... and {scope.runs_truncated} more (see the console for the full list).", styles["Muted"]))

    flowables.extend(_coverage_flowables(model, styles))

    if scope.degraded:
        flowables.append(Spacer(1, 10))
        flowables.append(Paragraph("IMPORTANT - reduced coverage", styles["Warning"]))
        flowables.append(_p(DEGRADED_WARNING, styles["Body"]))
    return flowables


def _coverage_flowables(model: ReportModel, styles: dict[str, ParagraphStyle]) -> list:
    """REQ-PIPE-011: per service, which checks ran completely, partially, failed
    or were skipped, and why."""
    coverage = model.coverage
    if coverage is None or not coverage.rows:
        return []
    depth = "thorough (every template on every web service)" if coverage.scan_depth == "thorough" else \
        "standard (checks chosen from what the scan found)"
    flowables: list = [
        Spacer(1, 8), Paragraph("Coverage of this run", styles["H2"]),
        _p(f"Scan depth: {depth}. Each row shows how many checks ran completely, stopped at their time budget "
           "(partial), failed, or were skipped on that service.", styles["Body"]),
    ]
    header = [_p(h, styles["CellHead"]) for h in ("Service", "Type", "Technologies", "Complete", "Partial", "Failed", "Skipped")]
    rows = [header]
    for row in coverage.rows:
        rows.append([
            _p(row.service, styles["Cell"]), _p(row.kind, styles["Cell"]), _p(row.technologies, styles["Cell"]),
            _p(str(row.complete), styles["Cell"]), _p(str(row.partial), styles["Cell"]),
            _p(str(row.failed), styles["Cell"]), _p(str(row.skipped), styles["Cell"]),
        ])
    flowables.append(_table(
        rows,
        [CONTENT_WIDTH * 0.24, CONTENT_WIDTH * 0.13, CONTENT_WIDTH * 0.23] + [CONTENT_WIDTH * 0.1] * 4,
        TableStyle(_HEADER_ROW_STYLE),
    ))
    notes = [(row.service, line) for row in coverage.rows for line in row.not_covered]
    if notes:
        flowables.append(Spacer(1, 6))
        flowables.append(Paragraph("Not fully covered", styles["H2"]))
        for service, line in notes[:60]:
            flowables.append(_p(f"{service} - {line}", styles["Bullet"]))
        if len(notes) > 60:
            flowables.append(_p(f"... and {len(notes) - 60} more (see the Plan tab of the run in the console).", styles["Muted"]))
    return flowables


# --- page furniture ----------------------------------------------------------

class _NumberedCanvas(Canvas):
    """Defers the footer's page-count to a second pass over buffered pages.

    Standard reportlab two-pass recipe: `showPage` snapshots canvas state
    instead of flushing it, `save` replays each snapshot once the total page
    count is known and draws the footer before the real `showPage`/`save`.
    """

    def __init__(self, *args, footer_label: str = "", **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states: list[dict] = []
        self._footer_label = footer_label

    def showPage(self) -> None:
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self) -> None:
        total_content_pages = len(self._saved_page_states) - 1
        for state in self._saved_page_states:
            self.__dict__.update(state)
            if self._pageNumber > 1:
                self._draw_footer(self._pageNumber - 1, total_content_pages)
            Canvas.showPage(self)
        Canvas.save(self)

    def _draw_footer(self, page_number: int, total_pages: int) -> None:
        self.saveState()
        self.setStrokeColor(LINE)
        self.setLineWidth(0.5)
        self.line(MARGIN, 15 * mm, PAGE_WIDTH - MARGIN, 15 * mm)
        self.setFont("Helvetica", 8)
        self.setFillColor(MUTED)
        self.drawString(MARGIN, 10 * mm, f"{self._footer_label}  |  CONFIDENTIAL")
        self.drawRightString(PAGE_WIDTH - MARGIN, 10 * mm, f"Page {page_number} of {total_pages}")
        self.restoreState()


def _header(canvas: Canvas, doc: BaseDocTemplate, label: str) -> None:
    canvas.saveState()
    canvas.setFont("Helvetica-Bold", 8)
    canvas.setFillColor(TEAL_DARK)
    canvas.drawString(MARGIN, PAGE_HEIGHT - 12 * mm, "ASM-Konsole")
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(MUTED)
    canvas.drawRightString(PAGE_WIDTH - MARGIN, PAGE_HEIGHT - 12 * mm, label)
    canvas.restoreState()


def render_report_pdf(model: ReportModel) -> bytes:
    """Render the customer report described by `model` to PDF bytes."""
    styles = _styles()
    buffer = io.BytesIO()

    doc = BaseDocTemplate(
        buffer, pagesize=LETTER, pageCompression=0,
        leftMargin=MARGIN, rightMargin=MARGIN, topMargin=MARGIN, bottomMargin=MARGIN,
        title=f"ASM Report - {model.engagement_title}",
    )

    cover_frame = Frame(MARGIN, MARGIN, CONTENT_WIDTH, PAGE_HEIGHT - 2 * MARGIN, id="cover")
    content_frame = Frame(
        MARGIN, MARGIN, CONTENT_WIDTH, PAGE_HEIGHT - 2 * MARGIN - 8 * mm, id="content",
    )
    header_label = model.engagement_title[:70]
    doc.addPageTemplates([
        PageTemplate(id="Cover", frames=[cover_frame]),
        PageTemplate(id="Content", frames=[content_frame], onPage=lambda c, d: _header(c, d, header_label)),
    ])

    story: list = list(_cover_flowables(model, styles))
    story.append(NextPageTemplate("Content"))
    story.append(PageBreak())
    for section in (
        _executive_summary_flowables(model, styles),
        _risk_overview_flowables(model, styles),
        _detailed_findings_flowables(model, styles),
        _asset_inventory_flowables(model, styles),
        _methodology_flowables(model, styles),
    ):
        story.extend(section)
        story.append(Spacer(1, 14))

    def _canvasmaker(*args, **kwargs):
        return _NumberedCanvas(*args, footer_label=model.engagement_title[:70], **kwargs)

    doc.build(story, canvasmaker=_canvasmaker)
    return buffer.getvalue()
