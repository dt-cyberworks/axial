"""TC-AUDIT-004: credentials must never reach the audit trail.

These are the load-bearing tests of REQ-AUDIT-003/004. The capture feature
writes tool invocations into durable, hash-chained audit storage that cannot
be rewritten afterwards - so a redaction gap is not a cosmetic bug, it is a
permanently recorded credential.

The negative tests deliberately assert against the SECRET VALUES directly
(`assert token not in rendered`) rather than against an expected-output
template. A template assertion can be "fixed" by updating the template when a
regression changes the output; asserting the secret's absence cannot.
"""

from __future__ import annotations

from app import command_redaction as cr
from app import tool_runner_client as trc

# Referenced through `trc.` at call time, not bound at import time - see the
# note in test_tool_invocation_audit.py (test_runner_auth_header.py reloads
# this module, which would leave import-time bindings stale).


# --- Header redaction (REQ-AUDIT-004) --------------------------------------

def test_sensitive_header_value_is_redacted_but_name_survives():
    """The whole point: the operator still sees THAT an Authorization header
    was sent, without the token being stored."""
    out = cr.redact_headers({"Authorization": "Bearer sk-live-abc123"})
    assert out == {"Authorization": cr.REDACTED}


def test_header_matching_is_case_insensitive():
    """HTTP header names are case-insensitive and the agent composes these
    freely - AUTHORIZATION must redact exactly like Authorization."""
    for name in ("Authorization", "authorization", "AUTHORIZATION", "AuThOrIzAtIoN"):
        out = cr.redact_headers({name: "Bearer secret-token"})
        assert out[name] == cr.REDACTED, f"{name} was not redacted"


def test_every_documented_sensitive_header_is_redacted():
    for name in cr.SENSITIVE_HEADERS:
        out = cr.redact_headers({name: "the-secret-value"})
        assert out[name] == cr.REDACTED, f"{name} leaked"


def test_non_sensitive_headers_are_never_redacted():
    """Over-redaction would defeat the transparency this feature exists for."""
    out = cr.redact_headers({"Accept": "application/json", "User-Agent": "asm-scanner/1.0"})
    assert out == {"Accept": "application/json", "User-Agent": "asm-scanner/1.0"}


def test_session_cookie_is_redacted():
    """Cookies are merged in automatically by session_state.apply_to_headers,
    so the agent never explicitly asks for this one - it must still redact."""
    out = cr.redact_headers({"Cookie": "PHPSESSID=abc123def456; role=admin"})
    assert out["Cookie"] == cr.REDACTED


# --- Body redaction (REQ-AUDIT-004) ----------------------------------------

def test_form_body_redacts_password_but_keeps_other_fields_readable():
    out = cr.redact_body("username=alice&password=hunter2&next=/dashboard")
    assert "hunter2" not in out
    assert "username=alice" in out
    assert "next=/dashboard" in out


def test_json_body_redacts_credential_fields_only():
    out = cr.redact_body('{"username": "alice", "password": "hunter2"}')
    assert "hunter2" not in out
    assert "alice" in out


def test_xss_marker_in_a_body_stays_fully_readable():
    """The agent's own prompt tells it to send inert XSS markers. Blanking the
    whole body to be 'safe' would destroy the evidence this feature records."""
    marker = 'zz9<b>\'"marker'
    out = cr.redact_body(f"comment={marker}")
    assert marker in out


def test_body_field_name_variants_are_caught():
    for field in ("password", "passwd", "pwd", "api_key", "apikey", "token", "secret",
                  "user_password", "authToken"):
        out = cr.redact_body(f"{field}=SUPERSECRET")
        assert "SUPERSECRET" not in out, f"{field} leaked"


def test_non_string_body_is_passed_through_untouched():
    assert cr.redact_body(None) is None
    assert cr.redact_body(b"raw") == b"raw"


# --- redact_args does not mutate the caller's args -------------------------

def test_redact_args_does_not_mutate_the_original():
    """The ORIGINAL args must still drive real execution - if redaction
    mutated them in place, the scanner would send '<redacted>' as a real
    credential and every authenticated check would silently break."""
    args = {"headers": {"Authorization": "Bearer real-token"}, "body": "password=hunter2"}
    redacted = cr.redact_args(args)
    assert args["headers"]["Authorization"] == "Bearer real-token"
    assert args["body"] == "password=hunter2"
    assert redacted["headers"]["Authorization"] == cr.REDACTED


# --- End-to-end through the REAL command builder (the negative test) -------

def test_negative_no_credential_survives_into_the_rendered_invocation():
    """THE required R3 negative test (TC-AUDIT-004).

    A realistic authenticated http_request: bearer token, auto-merged session
    cookie, API key, and a login password body. None of those values may
    appear anywhere in what reaches the audit payload.
    """
    bearer = "sk-live-9f8e7d6c5b4a3210"
    cookie = "PHPSESSID=deadbeefcafe1234"
    api_key = "AKIA1234567890ABCDEF"
    password = "correct-horse-battery-staple"

    args = {
        "method": "POST",
        "path": "/login",
        "headers": {
            "Authorization": f"Bearer {bearer}",
            "Cookie": cookie,
            "X-Api-Key": api_key,
            "Accept": "text/html",
        },
        "body": f"username=alice&password={password}",
    }

    rendered = trc._audit_invocation(trc._http_request_command, "target.example.com", args)

    for secret in (bearer, cookie, api_key, password):
        assert secret not in rendered, f"SECRET LEAKED INTO AUDIT: {secret}"

    # ...while the invocation is still genuinely useful for transparency.
    assert "curl" in rendered
    assert "/login" in rendered
    assert "Authorization" in rendered  # the NAME survives
    assert "Accept" in rendered
    assert "username=alice" in rendered


def test_redacted_invocation_is_structurally_identical_to_the_executed_one():
    """Same builder, same flags/order/target - only secret values differ. This
    is what makes the logged command trustworthy as evidence of what ran."""
    args = {"method": "GET", "path": "/x", "headers": {"Authorization": "Bearer s3cr3t"}}
    real = trc._http_request_command("target.example.com", args)
    logged = trc._audit_invocation(trc._http_request_command, "target.example.com", args)

    assert real.replace("Bearer s3cr3t", cr.REDACTED) == logged


def test_secret_containing_shell_metacharacters_is_still_redacted():
    """A quoting edge case must not be able to leak a value - which is exactly
    why redaction happens on structured args, before any shell quoting."""
    nasty = "'; cat /etc/passwd #"
    args = {"method": "GET", "path": "/", "headers": {"Authorization": nasty}}
    rendered = trc._audit_invocation(trc._http_request_command, "target.example.com", args)
    assert nasty not in rendered
    assert "/etc/passwd" not in rendered


# --- Response redaction (REQ-AUDIT-006/007) ---------------------------------
# Found live on int 2026-08-10: real Nextcloud/DVWA session cookie values were
# sitting unredacted in the hash-chained audit trail via the http_request
# observation path - the request side (above) was already solved, the
# response side was not.

def test_set_cookie_header_value_is_redacted_but_name_and_position_survive():
    raw = "HTTP/1.1 200 OK\nSet-Cookie: PHPSESSID=deadbeefcafe1234; Path=/\nContent-Type: text/html\n\n<html>hi</html>"
    out = cr.redact_http_response(raw)
    assert "deadbeefcafe1234" not in out
    assert "Set-Cookie:" in out
    assert "Content-Type: text/html" in out
    assert "<html>hi</html>" in out


def test_multiple_set_cookie_headers_are_each_redacted_independently():
    """A real login response often sets more than one cookie - each header
    line must be checked on its own, not collapsed into a dict that would
    silently drop all but the last one."""
    raw = (
        "HTTP/1.1 200 OK\n"
        "Set-Cookie: session=aaaaaaaaaaaaaaaa; Path=/\n"
        "Set-Cookie: csrf_secret=bbbbbbbbbbbbbbbb; Path=/\n"
        "\n"
        "body"
    )
    out = cr.redact_http_response(raw)
    assert "aaaaaaaaaaaaaaaa" not in out
    assert "bbbbbbbbbbbbbbbb" not in out
    assert out.count("Set-Cookie:") == 2


def test_crlf_response_is_handled_like_the_real_curl_output():
    """curl -i emits CRLF line endings, not bare \\n."""
    raw = "HTTP/1.1 200 OK\r\nSet-Cookie: sid=realsecretvalue\r\n\r\nbody text"
    out = cr.redact_http_response(raw)
    assert "realsecretvalue" not in out
    assert "body text" in out


def test_json_response_body_redacts_credential_fields_only():
    raw = 'HTTP/1.1 200 OK\nContent-Type: application/json\n\n{"user": "alice", "session_token": "s3cr3t-value"}'
    out = cr.redact_http_response(raw)
    assert "s3cr3t-value" not in out
    assert "alice" in out


def test_negative_a_response_truncated_mid_header_still_redacts_the_cookie():
    """THE required R3 negative test for the response side (TC-AUDIT-007).

    The runner caps the response at 16 KB (`head -c 16384`), which can cut
    mid-header before any blank line separating headers from body ever
    appears. Bailing out unredacted because no boundary was found would ship
    a live session cookie."""
    full = "HTTP/1.1 200 OK\nSet-Cookie: PHPSESSID=deadbeefcafe1234abcdef; Path=/; HttpOnly"
    truncated = full[:48]  # cuts partway through the cookie's value
    assert "deadbeef" in truncated  # sanity: the secret fragment IS present pre-redaction
    out = cr.redact_http_response(truncated)
    assert "deadbeef" not in out
    assert "cafe1234abcdef" not in out


def test_negative_login_response_cookie_and_json_password_never_survive():
    """A realistic authenticated login response: Set-Cookie session plus a
    JSON body echoing a password field back. Neither value may appear
    anywhere in what reaches the audit payload or the LLM's own context."""
    session = "9c9ecb61c44cb62b7d9d83bd30ceb70c"
    password = "correct-horse-battery-staple"
    raw = (
        "HTTP/1.1 200 OK\n"
        f"Set-Cookie: ocqycf4p1g88={session}; Path=/; HttpOnly\n"
        "Content-Type: application/json\n"
        "\n"
        f'{{"status": "ok", "password": "{password}"}}'
    )
    out = cr.redact_http_response(raw)
    for secret in (session, password):
        assert secret not in out, f"SECRET LEAKED INTO AUDIT: {secret}"
    assert "HTTP/1.1 200 OK" in out
    assert "status" in out
    assert '"ok"' in out


def test_non_sensitive_response_headers_and_body_markup_are_untouched():
    raw = (
        "HTTP/1.1 200 OK\n"
        "Content-Type: text/html\n"
        "Server: nginx\n"
        "\n"
        "<script>alert('zz9xss')</script>"
    )
    out = cr.redact_http_response(raw)
    assert out == raw


def test_empty_response_passes_through():
    assert cr.redact_http_response("") == ""


def test_headers_only_response_with_no_body_boundary_is_still_redacted():
    """A response cut before the blank line ever appears (headers-only
    capture) must not fall back to returning the raw, unredacted text."""
    raw = "HTTP/1.1 200 OK\nSet-Cookie: sid=liveleakvalue123"
    out = cr.redact_http_response(raw)
    assert "liveleakvalue123" not in out


# --- CONNECT-tunnel-wrapped responses (found live on int 2026-08-11) -------
# curl -i through the egress proxy's CONNECT tunnel for an HTTPS target
# captures TWO status-line blocks: "HTTP/1.1 200 Connection Established"
# (the tunnel handshake) then a blank line then the REAL response. The first
# version of redact_http_response only handled one block, so everything
# after the tunnel handshake's blank line - including the real response's
# Set-Cookie headers - fell into "body" and was never scanned. A real
# pentest-ground.com (DVWA) PHPSESSID reached int's audit trail this exact
# way; this is the regression test pinning the fix.

def test_negative_a_connect_tunnel_wrapped_login_response_never_leaks_the_session_cookie():
    """THE regression test for the live 2026-08-11 leak - reproduces the
    exact shape the runner actually produces for an HTTPS target through the
    proxy, not the single-block shape the original tests assumed."""
    session = "4e1f46c15d61a8e2894fce99b9b5e65b"
    raw = (
        "HTTP/1.1 200 Connection Established\n"
        "\n"
        "HTTP/1.1 200 OK\n"
        "Server: nginx/1.31.3\n"
        "Content-Type: text/html;charset=utf-8\n"
        "Set-Cookie: security=low; path=/\n"
        f"Set-Cookie: PHPSESSID={session}; expires=Wed, 12 Aug 2026 08:58:17 GMT; Max-Age=86400; path=/\n"
        "\n"
        "<html><body>Welcome to DVWA</body></html>"
    )
    out = cr.redact_http_response(raw)
    assert session not in out, f"SECRET LEAKED INTO AUDIT: {session}"
    # The tunnel handshake line, the real status line, and non-sensitive
    # headers all survive. Both Set-Cookie lines are redacted unconditionally
    # (name-kept/value-dropped, same as REQ-AUDIT-004) - not only the one that
    # happens to look secret; a filter that tried to guess "does this value
    # look sensitive" would be exactly the kind of gap this feature exists to
    # avoid.
    assert "HTTP/1.1 200 Connection Established" in out
    assert "HTTP/1.1 200 OK" in out
    assert "Server: nginx/1.31.3" in out
    assert "security=low" not in out
    assert out.count("Set-Cookie:") == 2
    assert "<html><body>Welcome to DVWA</body></html>" in out


def test_a_connect_tunnel_response_with_no_headers_of_its_own_passes_through():
    """The common case: the tunneled response sets no sensitive headers at
    all - nothing should be altered beyond the redaction pass being a no-op."""
    raw = "HTTP/1.1 200 Connection Established\n\nHTTP/1.1 404 Not Found\nContent-Type: text/html\n\n<h1>404</h1>"
    out = cr.redact_http_response(raw)
    assert out == raw


def test_a_response_truncated_mid_header_inside_the_second_tunneled_block_still_redacts():
    """Truncation can land mid-header in the SECOND block too, after the
    first (tunnel handshake) block was already fully parsed."""
    full = (
        "HTTP/1.1 200 Connection Established\n\n"
        "HTTP/1.1 200 OK\nSet-Cookie: PHPSESSID=deadbeefcafe1234abcdef; Path=/"
    )
    truncated = full[:88]
    assert "deadbeef" in truncated  # sanity: fragment present pre-redaction
    out = cr.redact_http_response(truncated)
    assert "deadbeef" not in out
    assert "HTTP/1.1 200 Connection Established" in out
