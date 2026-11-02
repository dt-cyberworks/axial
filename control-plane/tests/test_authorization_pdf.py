"""REQ-AUTH-007 / TC-AUTH-007 (GitHub #62): the authorization letter is a formatted document.

It carries the same words as before (the purpose, the guardrails, the monitoring statements and the customer
statement are the signed text) and the same configuration checksum; what changed is how it looks: headings,
tables, a header and a "Page x of y" footer on every page, the dates as the operator entered them, the customer's
words for internal identifiers, and a signature block that never splits across pages."""

from __future__ import annotations

import datetime as dt
import hashlib
import io
import json
import re
from types import SimpleNamespace as NS

import pytest
from pypdf import PdfReader

from app import authorization_pdf
from app.api import engagements as eng_api

ID = "019fa8b1-ea8f-7308-9464-0811b85fcc47"
PURPOSE = ("Purpose: This document summarizes the authorized external attack surface management engagement "
           "configuration for customer review and signature.")
GUARDRAILS = [
    "Every active tool call is authorized by the Scope Gateway before execution.",
    "Active checks are limited to allow-scope assets and the configured test window.",
    "Domain scope includes discovered subdomains unless explicitly denied.",
    "Default posture is non-destructive, bug-bounty-style validation with bounded tool budgets.",
    "Manual approval tools stop at the gateway until an operator approves the exact call.",
]
STATEMENT = ("By signing, the customer confirms that the scope, test window, emergency contact, and tool guardrails "
             "above are authorized for the engagement.")


def _eng(mode="monitoring", **kw):
    base = dict(
        id=ID, title="Sirkos Application", operating_mode=mode,
        # The console stores local midnight and 23:59:59.999 of the chosen days: 15 Oct 2026 to 15 Oct 2027 in Berlin.
        authorized_from=dt.datetime(2026, 10, 14, 22, 0, tzinfo=dt.timezone.utc),
        authorized_until=dt.datetime(2027, 10, 15, 21, 59, 59, 999000, tzinfo=dt.timezone.utc),
        emergency_contact="+49 170 0000000", ai_testing_allowed=False, subfinder_enabled=True, crawling_enabled=False,
        oob_enabled=False, screenshots_enabled=False, scan_profile="standard", new_asset_policy="hold",
        schedule_every_days=7, review_at=dt.datetime(2027, 10, 15, 21, 59, tzinfo=dt.timezone.utc),
    )
    base.update(kw)
    return NS(**base)


def _assets(extra=0):
    out = [
        NS(rule="allow", asset_type="domain", value="example.org", active_allowed=True, authorization_verified=True,
           authorization_method="operator_authorization_attestation"),
        NS(rule="allow", asset_type="domain", value="passive.example.com", active_allowed=False,
           authorization_verified=False, authorization_method=None),
        NS(rule="deny", asset_type="wildcard", value="*.cloud.example.org", active_allowed=False,
           authorization_verified=False, authorization_method=None),
    ]
    out += [NS(rule="allow", asset_type="domain", value=f"host-{i:03d}.example.com", active_allowed=True,
               authorization_verified=True, authorization_method="operator_authorization_attestation") for i in range(extra)]
    return out


GRANTS = [NS(tool_category=c, mode=m, requires_manual_approval=a)
          for c, m, a in (("recon", "passive", False), ("fingerprint", "active", False), ("vuln", "active", True))]
POLICIES = [NS(tool_name="nuclei", requires_manual_approval=True, enabled=None)]
CAPS = [{"id": "public_discovery", "label": "Public-source discovery", "enabled": True}]


def _pdf(mode="monitoring", extra=0, tz="Europe/Berlin", eng=None, assets=None):
    eng = eng or _eng(mode)
    return eng_api._authorization_pdf(
        eng, assets if assets is not None else _assets(extra), GRANTS, POLICIES,
        CAPS if mode == "monitoring" else None, ["hooks.example.org"] if mode == "monitoring" else None, tz)


def _pages(raw: bytes) -> list[str]:
    return [page.extract_text() or "" for page in PdfReader(io.BytesIO(raw)).pages]


def _flat(raw: bytes) -> str:
    return re.sub(r"\s+", " ", " ".join(_pages(raw)))


# --- layout --------------------------------------------------------------------------------------------


def test_every_page_has_a_header_and_a_page_x_of_y_footer():
    pages = _pages(_pdf(extra=40))
    assert len(pages) >= 3
    for index, text in enumerate(pages, start=1):
        assert "Engagement Authorization Summary" in text and "Sirkos Application" in text, f"header on page {index}"
        assert f"Page {index} of {len(pages)}" in text, f"footer on page {index}"
        assert "CONFIDENTIAL" in text and ID in text


def test_headings_are_visibly_distinct_from_body_text():
    seen: dict[str, tuple[str, float]] = {}

    def visitor(text, cm, tm, font_dict, font_size):
        if text.strip():
            seen.setdefault(text.strip(), (str(font_dict.get("/BaseFont")), round(float(font_size), 1)))

    for page in PdfReader(io.BytesIO(_pdf())).pages:
        page.extract_text(visitor_text=visitor)
    for heading in ("Authorized scope", "Tool permissions", "Guardrails", "Customer authorization"):
        font, size = seen[heading]
        assert "Bold" in font and size >= 16, f"{heading}: {font} {size}"
    font, size = seen["Engagement Authorization Summary"]
    assert "Bold" in font and size >= 20
    body_font, body_size = seen[GUARDRAILS[0]]
    assert "Bold" not in body_font and body_size < 11
    checksum_font = next(v for k, v in seen.items() if re.fullmatch(r"[0-9a-f]{64}", k))
    assert "Courier" in checksum_font[0], "the checksum has its own monospaced row"


def test_scope_permissions_and_facts_are_tables():
    text = _flat(_pdf())
    assert "Authorized scope Rule Type Value Checks allowed Authorization Allow domain example.org Active checks allowed Attested by the operator" in text
    assert "Allow domain passive.example.com Passive only Not attested" in text
    assert "Explicitly denied scope Rule Type Value Deny wildcard *.cloud.example.org" in text
    assert "Tool permissions Category Mode Manual approval by default" in text
    assert "Fingerprinting Active No" in text and "Vulnerability checks Active Yes" in text
    assert "Capability State Passive subdomain discovery with subfinder Enabled" in text


def test_an_empty_scope_says_so_under_its_own_heading():
    text = _flat(_pdf(assets=[]))
    assert "Authorized scope No allow-scope assets configured." in text
    assert "Explicitly denied scope No explicit deny entries configured." in text


@pytest.mark.parametrize("extra", [0, 20, 80])
def test_the_signature_block_is_whole_and_on_the_last_page_with_1_20_and_80_scope_rows(extra):
    pages = _pages(_pdf(extra=extra))
    holder = [i for i, text in enumerate(pages) if "Customer authorization" in text]
    assert len(holder) == 1
    page = pages[holder[0]]
    for needle in (STATEMENT[:40], "Customer representative", "Provider / operator representative"):
        assert needle in page
    assert page.count("Signature") == 2 and page.count("Name") >= 2 and page.count("Date") >= 2


def test_negative_the_signature_block_never_splits_at_any_page_boundary():
    """The sweep covers every scope-row count across the page boundaries, so wherever the signature block
    would have fallen across a page break, one count catches it."""
    for extra in range(0, 130, 2):
        pages = _pages(_pdf(extra=extra))
        holder = [i for i, text in enumerate(pages) if "Customer authorization" in text]
        assert len(holder) == 1, extra
        page = pages[holder[0]]
        assert "Customer representative" in page and "Provider / operator representative" in page and page.count("Signature") == 2, \
            f"the signature block is split with {extra} extra scope rows"
        assert holder[0] == len(pages) - 1, f"something follows the signature block with {extra} extra scope rows"


# --- content -------------------------------------------------------------------------------------------


def test_the_period_is_shown_as_entered_with_its_time_zone_and_no_raw_timestamps():
    text = _flat(_pdf(tz="Europe/Berlin"))
    assert "Authorized period 15 Oct 2026 to 15 Oct 2027 (Europe/Berlin)" in text
    assert "Dates are shown in Europe/Berlin" in text
    for raw in ("+00:00", ".999000", "21:59:59", "T22:00"):
        assert raw not in text
    # the exact stored instants stay stated, once, in the note
    assert "2026-10-14 22:00 UTC to 2027-10-15 21:59 UTC" in text


def test_without_a_time_zone_the_dates_are_utc_and_say_so():
    for tz in (None, "", "Not/A_Zone"):
        text = _flat(_pdf(tz=tz))
        assert "(UTC)" in text and "Dates are shown in UTC" in text, tz
        assert "14 Oct 2026, 22:00 to 15 Oct 2027, 21:59 (UTC)" in text


def test_an_assessment_says_test_window_a_standing_monitor_says_authorized_period():
    assert "Test window" in _flat(_pdf(mode="assessment")) and "Authorized period" not in _flat(_pdf(mode="assessment"))
    assert "Authorized period" in _flat(_pdf(mode="monitoring")) and "Test window" not in _flat(_pdf(mode="monitoring")).split("above are authorized")[0]


def test_no_internal_identifier_appears_in_the_document():
    text = _flat(_pdf(extra=3))
    for identifier in ("operator_authorization_attestation", "fingerprint / active", "recon / passive",
                       "vuln / active", "active_allowed", "requires_manual_approval"):
        assert identifier not in text, identifier


def test_the_signed_wording_is_unchanged():
    text = _flat(_pdf())
    for sentence in [PURPOSE, STATEMENT, *GUARDRAILS,
                     "This engagement runs without a person watching. Runs are started by a person or by a schedule, "
                     "and nothing waits for a person's decision during a run.",
                     "Calls that would need a person's approval are not made; they are listed as suggestions.",
                     "Credential testing and exploitation are not part of monitoring.",
                     "held until acknowledged (not tested before)"]:
        assert sentence in text, sentence


def test_the_unattended_section_exists_only_for_a_monitor_and_has_no_orphaned_fragment():
    monitor = _flat(_pdf(mode="monitoring"))
    assert "Unattended monitoring" in monitor and "Automatic runs: every 7 days" in monitor
    assert "Authorization review date: 15 Oct 2027" in monitor
    assert "Alerts go to: hooks.example.org" in monitor
    assert "Unattended monitoring" not in _flat(_pdf(mode="assessment"))
    # the old hard-wrapped bullet left "schedule," on a line of its own
    assert not re.search(r"(?m)^\s*schedule,\s*$", "\n".join(_pages(_pdf(mode="monitoring"))))


def test_negative_dynamic_text_is_shown_literally_not_parsed_as_markup():
    eng = _eng(title="A <b>bold</b> & <i>Co</i>")
    text = _flat(_pdf(eng=eng))
    assert "A <b>bold</b> & <i>Co</i>" in text


# --- checksum and determinism ----------------------------------------------------------------------------


def test_the_checksum_is_the_hash_of_the_configuration_not_of_the_layout():
    eng, assets = _eng(), _assets(2)
    payload = eng_api._authorization_config_payload(eng, assets, GRANTS, POLICIES, CAPS, ["hooks.example.org"])
    expected = hashlib.sha256(json.dumps(payload, sort_keys=True, default=str).encode("utf-8")).hexdigest()
    printed = re.search(r"\(SHA-256\)\s*([0-9a-f]{64})", _flat(_pdf(extra=2)))
    assert printed and printed.group(1) == expected


def test_the_checksum_does_not_depend_on_the_time_zone_the_dates_are_shown_in():
    grab = lambda raw: re.search(r"([0-9a-f]{64})", _flat(raw)).group(1)  # noqa: E731
    assert grab(_pdf(tz="Europe/Berlin")) == grab(_pdf(tz="America/New_York")) == grab(_pdf(tz=None))


def test_a_change_after_signing_changes_the_checksum():
    grab = lambda raw: re.search(r"([0-9a-f]{64})", _flat(raw)).group(1)  # noqa: E731
    assert grab(_pdf()) != grab(_pdf(eng=_eng(scan_profile="thorough")))


def test_the_output_is_reproducible_byte_for_byte():
    assert _pdf() == _pdf()


# --- helpers -------------------------------------------------------------------------------------------


def test_dates_are_formatted_as_entered_and_other_times_keep_their_minutes():
    berlin, _ = authorization_pdf.resolve_timezone("Europe/Berlin")
    f = authorization_pdf.format_instant
    assert f(dt.datetime(2026, 10, 14, 22, 0, tzinfo=dt.timezone.utc), berlin) == "15 Oct 2026"
    assert f(dt.datetime(2027, 10, 15, 21, 59, 59, 999000, tzinfo=dt.timezone.utc), berlin) == "15 Oct 2027"
    assert f(dt.datetime(2026, 10, 15, 9, 30, tzinfo=dt.timezone.utc), berlin) == "15 Oct 2026, 11:30"
    assert f(None, berlin) == "not set"


def test_an_unknown_identifier_is_shown_in_plain_words_never_raw():
    assert authorization_pdf.category_label("some_new_category") == "Some new category"
    assert authorization_pdf.authorization_label(True, "some_new_method") == "Attested (some new method)"
    assert authorization_pdf.authorization_label(True, None) == "Attested"
    assert authorization_pdf.authorization_label(False, "operator_authorization_attestation") == "Not attested"


# --- REQ-TESTACCT-009 (GitHub #89): the test accounts the signer authorizes -------------------------------------------------

ACCOUNTS = [{"label": "shop-user", "role": "user", "kind": "login_form", "username": "alice", "hosts": ["shop.example.com", "www.example.com"],
             "attested_by": "Johannes", "attested_at": "2026-11-01T09:00:00+00:00"}]
SECRET = "-".join(["S3cret", "Pass", "word", "4711"])


def _pdf_with(accounts, mode="monitoring"):
    eng = _eng(mode)
    return eng_api._authorization_pdf(
        eng, _assets(), GRANTS, POLICIES, CAPS if mode == "monitoring" else None,
        ["hooks.example.org"] if mode == "monitoring" else None, "Europe/Berlin", accounts)


def test_the_document_lists_each_account_with_its_hosts_and_who_attested_it():
    text = _flat(_pdf_with(ACCOUNTS))
    assert "Test accounts" in text
    assert "shop-user (role user, login form, username alice): valid on shop.example.com, www.example.com only. Attested by Johannes on 2026-11-01." in text
    assert "sent to the language-model provider with every request of a run" in text


def test_negative_the_document_never_contains_the_secret():
    assert SECRET not in _flat(_pdf_with(ACCOUNTS))


def test_a_monitors_document_carries_the_login_consent_wording_and_an_assessments_does_not():
    assert "Login consent: The scanner will sign in with these accounts on exactly these hosts, on each scheduled run" in _flat(_pdf_with(ACCOUNTS))
    assert "Login consent" not in _flat(_pdf_with(ACCOUNTS, mode="assessment"))


def test_an_account_with_no_host_says_so():
    text = _flat(_pdf_with([{**ACCOUNTS[0], "hosts": []}]))
    assert "valid on no host (it cannot be used anywhere) only" in text


def test_a_document_without_accounts_is_unchanged_and_keeps_its_checksum():
    assert "Test accounts" not in _flat(_pdf_with(None))
    plain = eng_api._authorization_document(_eng(), _assets(), GRANTS, POLICIES, CAPS, ["hooks.example.org"], "Europe/Berlin")
    with_none = eng_api._authorization_document(_eng(), _assets(), GRANTS, POLICIES, CAPS, ["hooks.example.org"], "Europe/Berlin", None)
    assert plain.checksum == with_none.checksum


def test_negative_adding_changing_or_removing_an_account_after_signing_changes_the_checksum():
    def checksum(accounts):
        return eng_api._authorization_document(_eng(), _assets(), GRANTS, POLICIES, CAPS, ["hooks.example.org"], "Europe/Berlin", accounts).checksum

    base = checksum(None)
    added = checksum(ACCOUNTS)
    assert added != base
    assert checksum([{**ACCOUNTS[0], "hosts": ["shop.example.com"]}]) != added, "a host removed"
    assert checksum([{**ACCOUNTS[0], "role": "admin"}]) != added, "a role changed"
    assert checksum(ACCOUNTS) == added, "the same accounts, the same checksum"
    assert checksum(None) == base, "removing it again gives back the old checksum"
