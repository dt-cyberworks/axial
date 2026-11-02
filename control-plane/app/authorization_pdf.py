"""The authorization letter as a styled PDF (REQ-AUTH-007, GitHub #62).

The document an operator sends to a customer for signature before activation. It used to be a plain-text dump
(`app/pdf.py`: one font, no headings, raw ISO timestamps, no page numbers). It now uses the same reportlab styles
and page furniture as the customer report (`app/pdf_report.py`), so the two customer-facing documents look like
they come from one product.

This module only lays out a document that `api/engagements.py` has already put into words. It changes no wording
of the guardrails or of the customer statement, and it never touches the configuration checksum: that is a hash of
`_authorization_config_payload()`, not of the PDF bytes, so a layout change cannot move it.

Every dynamic string goes through `_p`, which escapes it: a title like `A <b> & Co` is shown literally.
"""

from __future__ import annotations

import dataclasses
import datetime as dt
import io
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from reportlab.lib import colors
from reportlab.lib.pagesizes import LETTER
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import BaseDocTemplate, Frame, KeepTogether, PageTemplate, Spacer, Table, TableStyle

from app.pdf_report import (
    CONTENT_WIDTH,
    INK,
    LINE,
    MARGIN,
    MUTED,
    PAGE_HEIGHT,
    PRODUCT_NAME,
    TEAL,
    TEAL_DARK,
    WHITE,
    _header,
    _HEADER_ROW_STYLE,
    _NumberedCanvas,
    _p,
    _styles,
    _table,
)

DOCUMENT_TITLE = "Engagement Authorization Summary"

# The customer's words for the internal identifiers. An identifier that is not listed is shown in plain words
# (underscores removed), never as the raw string.
CATEGORY_LABEL = {
    "recon": "Reconnaissance", "fingerprint": "Fingerprinting", "vuln": "Vulnerability checks",
    "cred": "Credential checks", "exploit": "Exploit checks",
}
MODE_LABEL = {"passive": "Passive", "active": "Active"}
AUTH_METHOD_LABEL = {"operator_authorization_attestation": "Attested by the operator"}


def plain_words(identifier: str) -> str:
    return identifier.replace("_", " ").strip().capitalize()


def category_label(category: str) -> str:
    return CATEGORY_LABEL.get(category, plain_words(category))


def mode_label(mode: str) -> str:
    return MODE_LABEL.get(mode, plain_words(mode))


def authorization_label(attested: bool, method: str | None) -> str:
    if not attested:
        return "Not attested"
    if not method:
        return "Attested"
    return AUTH_METHOD_LABEL.get(method, f"Attested ({plain_words(method).lower()})")


# --------------------------------------------------------------------------------------------------- dates


def resolve_timezone(name: str | None) -> tuple[dt.tzinfo, str]:
    """The zone the dates are shown in: the one the browser reported, else UTC (stated in the document)."""
    if name:
        try:
            zone = ZoneInfo(name)
            return zone, name
        except (ZoneInfoNotFoundError, ValueError, OSError):
            pass
    return dt.timezone.utc, "UTC"


def format_instant(value: dt.datetime | None, zone: dt.tzinfo) -> str:
    """A date as the operator entered it. The console stores midnight (start) and 23:59:59.999 (end) of the
    chosen day, so those two are shown as a plain date; any other time keeps its minutes."""
    if value is None:
        return "not set"
    local = (value if value.tzinfo else value.replace(tzinfo=dt.timezone.utc)).astimezone(zone)
    day = f"{local.day} {local:%b %Y}"
    if (local.hour, local.minute) in ((0, 0), (23, 59)):
        return day
    return f"{day}, {local:%H:%M}"


def format_utc(value: dt.datetime | None) -> str:
    if value is None:
        return "not set"
    return (value if value.tzinfo else value.replace(tzinfo=dt.timezone.utc)).astimezone(dt.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


# --------------------------------------------------------------------------------------------------- model


@dataclasses.dataclass
class ScopeLine:
    rule: str  # "Allow" | "Deny"
    asset_type: str
    value: str
    checks: str
    authorization: str


@dataclasses.dataclass
class GrantLine:
    category: str
    mode: str
    manual_approval_default: str


@dataclasses.dataclass
class AuthorizationDocument:
    engagement_title: str
    engagement_id: str
    purpose: str
    checksum: str
    period_label: str  # "Test window" | "Authorized period"
    period_text: str
    time_note: str
    emergency_contact: str
    agent_text: str
    scope: list[ScopeLine]
    no_allow_text: str | None
    no_deny_text: str | None
    grants: list[GrantLine]
    no_grants_text: str | None
    discovery: list[tuple[str, str]]
    monitoring: list[str] | None
    manual_tools: list[str]
    no_manual_tools_text: str | None
    guardrails: list[str]
    customer_statement: str
    extra_facts: list[tuple[str, str]] = dataclasses.field(default_factory=list)
    test_accounts: list[str] | None = None   # REQ-TESTACCT-009


# --------------------------------------------------------------------------------------------------- layout


def _letter_styles() -> dict[str, ParagraphStyle]:
    styles = _styles()
    base = getSampleStyleSheet()
    # A heading never ends a page on its own: it stays with the table or paragraph that follows.
    styles["H1"].keepWithNext = 1
    styles["LetterBrand"] = ParagraphStyle(
        "LetterBrand", parent=base["Normal"], fontName="Helvetica-Bold", fontSize=11, leading=14,
        textColor=TEAL_DARK, spaceAfter=2,
    )
    styles["LetterTitle"] = ParagraphStyle(
        "LetterTitle", parent=base["Title"], fontName="Helvetica-Bold", fontSize=22, leading=27,
        textColor=INK, alignment=0, spaceAfter=4,
    )
    styles["LetterSubtitle"] = ParagraphStyle(
        "LetterSubtitle", parent=base["Normal"], fontName="Helvetica", fontSize=10.5, leading=14,
        textColor=MUTED, spaceAfter=10,
    )
    styles["Mono"] = ParagraphStyle(
        "Mono", parent=base["Normal"], fontName="Courier", fontSize=8, leading=10.5, textColor=INK,
    )
    styles["FactLabel"] = ParagraphStyle(
        "FactLabel", parent=base["Normal"], fontName="Helvetica-Bold", fontSize=9, leading=12, textColor=MUTED,
    )
    styles["SignHead"] = ParagraphStyle(
        "SignHead", parent=base["Normal"], fontName="Helvetica-Bold", fontSize=10, leading=13, textColor=INK,
    )
    styles["SignField"] = ParagraphStyle(
        "SignField", parent=base["Normal"], fontName="Helvetica", fontSize=8.5, leading=11, textColor=MUTED,
    )
    return styles


def _heading(text: str, styles: dict[str, ParagraphStyle]):
    return _p(text, styles["H1"])


def _bullets(items: list[str], styles: dict[str, ParagraphStyle]) -> list:
    out = []
    for item in items:
        paragraph = _p(item, styles["Bullet"])
        paragraph.bulletText = "•"
        out.append(paragraph)
    return out


def _facts_table(doc: AuthorizationDocument, styles: dict[str, ParagraphStyle]) -> Table:
    rows: list[list] = [
        [_p("Title", styles["FactLabel"]), _p(doc.engagement_title, styles["Body"])],
        [_p("Engagement ID", styles["FactLabel"]), _p(doc.engagement_id, styles["Body"])],
        [_p(doc.period_label, styles["FactLabel"]), _p(doc.period_text, styles["Body"])],
        [_p("Emergency contact", styles["FactLabel"]), _p(doc.emergency_contact, styles["Body"])],
        [_p("Vector Agent autonomous proposals", styles["FactLabel"]), _p(doc.agent_text, styles["Body"])],
    ]
    rows += [[_p(label, styles["FactLabel"]), _p(value, styles["Body"])] for label, value in doc.extra_facts]
    rows.append([_p("Configuration checksum (SHA-256)", styles["FactLabel"]), _p(doc.checksum, styles["Mono"])])
    table = Table(rows, colWidths=[132, CONTENT_WIDTH - 132])
    table.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("GRID", (0, 0), (-1, -1), 0.5, LINE),
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f3f6f8")),
        ("TOPPADDING", (0, 0), (-1, -1), 5), ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING", (0, 0), (-1, -1), 6), ("RIGHTPADDING", (0, 0), (-1, -1), 6),
    ]))
    return table


def _scope_table(lines: list[ScopeLine], styles: dict[str, ParagraphStyle]) -> Table:
    data = [[_p(h, styles["CellHead"]) for h in ("Rule", "Type", "Value", "Checks allowed", "Authorization")]]
    for line in lines:
        data.append([
            _p(line.rule, styles["Cell"]), _p(line.asset_type, styles["Cell"]), _p(line.value, styles["Cell"]),
            _p(line.checks, styles["Cell"]), _p(line.authorization, styles["Cell"]),
        ])
    return _table(data, [38, 52, 190, 100, CONTENT_WIDTH - 380], TableStyle(_HEADER_ROW_STYLE))


def _denied_table(lines: list[ScopeLine], styles: dict[str, ParagraphStyle]) -> Table:
    data = [[_p(h, styles["CellHead"]) for h in ("Rule", "Type", "Value")]]
    for line in lines:
        data.append([_p(line.rule, styles["Cell"]), _p(line.asset_type, styles["Cell"]), _p(line.value, styles["Cell"])])
    return _table(data, [38, 52, CONTENT_WIDTH - 90], TableStyle(_HEADER_ROW_STYLE))


def _grants_table(lines: list[GrantLine], styles: dict[str, ParagraphStyle]) -> Table:
    data = [[_p(h, styles["CellHead"]) for h in ("Category", "Mode", "Manual approval by default")]]
    for line in lines:
        data.append([_p(line.category, styles["Cell"]), _p(line.mode, styles["Cell"]), _p(line.manual_approval_default, styles["Cell"])])
    return _table(data, [180, 100, CONTENT_WIDTH - 280], TableStyle(_HEADER_ROW_STYLE))


def _pairs_table(pairs: list[tuple[str, str]], styles: dict[str, ParagraphStyle]) -> Table:
    data = [[_p("Capability", styles["CellHead"]), _p("State", styles["CellHead"])]]
    for label, state in pairs:
        data.append([_p(label, styles["Cell"]), _p(state, styles["Cell"])])
    return _table(data, [CONTENT_WIDTH - 110, 110], TableStyle(_HEADER_ROW_STYLE))


def _signature_block(styles: dict[str, ParagraphStyle]) -> Table:
    """Two columns, customer and provider, each with name, date and signature lines. Built as one table so it
    cannot be split by a page break between the two columns' fields."""
    gap = 24
    col = (CONTENT_WIDTH - gap) / 2
    data = [[_p("Customer representative", styles["SignHead"]), "", _p("Provider / operator representative", styles["SignHead"])]]
    for field in ("Name", "Date", "Signature"):
        data.append([_p(field, styles["SignField"]), "", _p(field, styles["SignField"])])
    table = Table(data, colWidths=[col, gap, col], rowHeights=[20, 38, 38, 46])
    style = [("VALIGN", (0, 0), (-1, 0), "BOTTOM"), ("VALIGN", (0, 1), (-1, -1), "TOP"),
             ("LEFTPADDING", (0, 0), (-1, -1), 0), ("RIGHTPADDING", (0, 0), (-1, -1), 0)]
    for row in (1, 2, 3):
        style += [("LINEBELOW", (0, row), (0, row), 0.7, INK), ("LINEBELOW", (2, row), (2, row), 0.7, INK)]
    table.setStyle(TableStyle(style))
    return table


def render_authorization_pdf(doc: AuthorizationDocument) -> bytes:
    styles = _letter_styles()
    buffer = io.BytesIO()
    pdf = BaseDocTemplate(
        buffer, pagesize=LETTER, pageCompression=0, invariant=1,
        leftMargin=MARGIN, rightMargin=MARGIN, topMargin=MARGIN, bottomMargin=MARGIN,
        title=f"{DOCUMENT_TITLE} - {doc.engagement_title}", author=PRODUCT_NAME,
    )
    # No inner padding, so headings, paragraphs and tables share one left edge.
    frame = Frame(MARGIN, MARGIN + 6 * mm, CONTENT_WIDTH, PAGE_HEIGHT - 2 * MARGIN - 14 * mm, id="letter",
                  leftPadding=0, rightPadding=0, topPadding=0, bottomPadding=0)
    header_label = f"{DOCUMENT_TITLE} · {doc.engagement_title[:60]}"
    pdf.addPageTemplates([PageTemplate(id="Letter", frames=[frame], onPage=lambda c, d: _header(c, d, header_label))])

    story: list = [
        _p(PRODUCT_NAME, styles["LetterBrand"]),
        _p(DOCUMENT_TITLE, styles["LetterTitle"]),
        _p("For review and signature by the customer before the engagement is activated", styles["LetterSubtitle"]),
        _p(doc.purpose, styles["Body"]),
        Spacer(1, 10),
        _facts_table(doc, styles),
        Spacer(1, 4),
        _p(doc.time_note, styles["Muted"]),
        _heading("Authorized scope", styles),
    ]
    allowed = [line for line in doc.scope if line.rule == "Allow"]
    denied = [line for line in doc.scope if line.rule == "Deny"]
    if allowed:
        story.append(_scope_table(allowed, styles))
    else:
        story.append(_p(doc.no_allow_text or "No allow-scope assets configured.", styles["Muted"]))
    story.append(_heading("Explicitly denied scope", styles))
    if denied:
        story.append(_denied_table(denied, styles))
    else:
        story.append(_p(doc.no_deny_text or "No explicit deny entries configured.", styles["Muted"]))

    story.append(_heading("Tool permissions", styles))
    if doc.grants:
        story.append(_grants_table(doc.grants, styles))
    else:
        story.append(_p(doc.no_grants_text or "No tool grants configured.", styles["Muted"]))

    story.append(_heading("Extended discovery", styles))
    story.append(_pairs_table(doc.discovery, styles))

    if doc.monitoring is not None:
        story.append(_heading("Unattended monitoring", styles))
        story += _bullets(doc.monitoring, styles)

    if doc.test_accounts:
        story.append(_heading("Test accounts", styles))
        story += _bullets(doc.test_accounts, styles)

    story.append(_heading("Tools requiring manual approval", styles))
    if doc.manual_tools:
        story += _bullets(doc.manual_tools, styles)
    else:
        story.append(_p(doc.no_manual_tools_text or "No concrete tools require manual approval.", styles["Muted"]))

    story.append(_heading("Guardrails", styles))
    story += _bullets(doc.guardrails, styles)

    story.append(KeepTogether([
        _heading("Customer authorization", styles),
        _p(doc.customer_statement, styles["Body"]),
        Spacer(1, 6),
        _signature_block(styles),
    ]))

    def _canvasmaker(*args, **kwargs):
        return _NumberedCanvas(*args, footer_label=f"Engagement {doc.engagement_id}", has_cover=False, **kwargs)

    pdf.build(story, canvasmaker=_canvasmaker)
    return buffer.getvalue()
