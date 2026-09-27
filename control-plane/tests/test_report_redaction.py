"""REQ-REPORT-002: credentials must never reach a generated customer report.

The report is the one artifact deliberately produced to leave the platform, and
its inputs (finding evidence, and a Lens explanation generated from that same
evidence) are exactly where a credential would be if one were captured. These
are the load-bearing tests for that requirement.
"""

from app.report_redaction import (
    MAX_VALUE_CHARS,
    REDACTED,
    is_sensitive_key,
    redact_prose,
    redact_value,
    safe_evidence_items,
)

BEARER = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.s3cr3tS1gnatureV4lue"
COOKIE = "PHPSESSID=9c8b7a6d5e4f3a2b1c0d9e8f7a6b5c4d"
API_KEY = "sk-live-7f3a9c2e5b8d1f4a6c0e2b7d9f1a3c5e"
PASSWORD = "Hunter2!SuperSecret"


# --- key-based redaction -------------------------------------------------

def test_credential_named_keys_are_detected_case_insensitively():
    for name in ("password", "PASSWORD", "user_password", "apiKey", "X-Auth-Token",
                 "session_id", "client_secret", "private_key", "Cookie"):
        assert is_sensitive_key(name), name


def test_non_credential_keys_are_not_redacted():
    for name in ("status_code", "url", "method", "response_length", "title"):
        assert not is_sensitive_key(name)


def test_sensitive_value_is_replaced_but_the_key_name_survives():
    items = safe_evidence_items({"password": PASSWORD, "status_code": 200})
    assert ("password", REDACTED) in items
    # The non-credential field in the same blob stays fully readable.
    assert ("status_code", "200") in items


def test_negative_no_credential_value_survives_evidence_rendering():
    evidence = {
        "authorization": f"Bearer {BEARER}",
        "cookie": COOKIE,
        "x-api-key": API_KEY,
        "password": PASSWORD,
        "url": "https://target.example/login",
    }
    rendered = " ".join(f"{k}={v}" for k, v in safe_evidence_items(evidence))
    for secret in (BEARER, COOKIE, API_KEY, PASSWORD):
        assert secret not in rendered, f"leaked: {secret}"
    assert "https://target.example/login" in rendered


# --- prose redaction (no key to match on) --------------------------------

def test_bearer_and_basic_tokens_are_redacted_in_prose():
    out = redact_prose(f"The request sent Authorization: Bearer {BEARER} to the API.")
    assert BEARER not in out
    assert "Bearer" in out and REDACTED in out


def test_cookie_values_are_redacted_in_prose():
    out = redact_prose(f"The response set Cookie: {COOKIE} for the session.")
    assert COOKIE not in out


def test_api_key_assignments_are_redacted_in_prose():
    for text in (f"X-Api-Key: {API_KEY}", f"api_key={API_KEY}", f'password="{PASSWORD}"'):
        out = redact_prose(text)
        assert API_KEY not in out and PASSWORD not in out, text


def test_jwts_are_redacted_wherever_they_appear():
    out = redact_prose(f"Observed token {BEARER} in the body.")
    assert BEARER not in out


def test_prose_without_credentials_is_left_readable():
    text = "The endpoint /admin returned HTTP 200 without authentication, exposing user records."
    assert redact_prose(text) == text


# --- bounding and structure ----------------------------------------------

def test_long_values_are_truncated_to_the_documented_bound():
    rendered = redact_value("body", "A" * (MAX_VALUE_CHARS * 3))
    assert len(rendered) <= MAX_VALUE_CHARS + 1  # + the ellipsis


def test_nested_evidence_is_skipped_entirely_not_flattened():
    """Nested structures ARE the raw request/response captures the report is
    specified to keep out (Kap. 6.2). Flattening them would smuggle that
    content back in one key at a time."""
    evidence = {
        "raw_response": {"headers": {"set-cookie": COOKIE}, "body": PASSWORD},
        "request_chain": [f"Authorization: Bearer {BEARER}"],
        "status_code": 401,
    }
    items = safe_evidence_items(evidence)
    assert items == [("status_code", "401")]
    rendered = " ".join(f"{k}={v}" for k, v in items)
    for secret in (BEARER, COOKIE, PASSWORD):
        assert secret not in rendered


def test_lens_agent_block_is_not_rendered_as_an_evidence_field():
    # It is rendered separately as prose (and redacted there).
    items = safe_evidence_items({"lens_agent": {"explanation": "x"}, "url": "https://a.test"})
    assert [k for k, _ in items] == ["url"]


def test_evidence_item_count_is_bounded():
    evidence = {f"field_{i}": i for i in range(50)}
    assert len(safe_evidence_items(evidence, limit=8)) == 8


def test_newlines_never_break_a_rendered_evidence_line():
    assert "\n" not in redact_value("note", "line one\nline two\rline three")
