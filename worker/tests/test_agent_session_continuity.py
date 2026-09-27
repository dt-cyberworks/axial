"""REQ-AGENT-022 / TC-AGENT-022: run-scoped HTTP session continuity.

R3 requirement - the cross-host isolation tests below are mandatory. Holding a
customer's authenticated session and replaying it to the wrong host would be a
genuine security incident, not merely a bug, so that invariant is tested in
both directions rather than assumed.

Motivation (docs/benchmarking/benchmark-design.md §14): DVWA's four curated
vulnerabilities all sit behind a login form. With no way to carry a session,
the scanner reached none of them - 100% of that suite's false negatives.
"""

from __future__ import annotations

import pytest

from app import session_state
from app.tasks import agent

EID = "22222222-2222-2222-2222-222222222222"


# --- Set-Cookie extraction -------------------------------------------------

def test_extracts_cookies_from_a_real_response_head():
    raw = (
        "HTTP/1.1 302 Found\r\n"
        "Date: Mon, 03 Aug 2026 12:00:00 GMT\r\n"
        "Set-Cookie: PHPSESSID=abc123def; path=/; HttpOnly\r\n"
        "Set-Cookie: security=low; path=/\r\n"
        "Location: index.php\r\n\r\n"
    )
    assert session_state.extract_cookies(raw) == {"PHPSESSID": "abc123def", "security": "low"}


def test_extraction_is_case_insensitive_and_survives_lf_only():
    raw = "HTTP/1.1 200 OK\nset-cookie: session=xyz; Path=/\n\n"
    assert session_state.extract_cookies(raw) == {"session": "xyz"}


def test_no_set_cookie_yields_nothing():
    assert session_state.extract_cookies("HTTP/1.1 200 OK\r\n\r\nbody") == {}
    assert session_state.extract_cookies("") == {}


def test_cookie_attributes_are_dropped_including_domain():
    """Domain is the one attribute that could widen replay beyond the issuing
    host. It must never be stored, let alone honoured."""
    raw = "HTTP/1.1 200 OK\r\nSet-Cookie: sid=v1; Domain=.example.com; Secure; HttpOnly\r\n\r\n"
    jar = session_state.extract_cookies(raw)
    assert jar == {"sid": "v1"}
    assert "Domain" not in str(jar) and "example.com" not in str(jar)


def test_absurdly_long_cookie_value_is_skipped():
    raw = f"HTTP/1.1 200 OK\r\nSet-Cookie: big={'x' * 5000}; path=/\r\n\r\n"
    assert session_state.extract_cookies(raw) == {}


# --- Jar mechanics ---------------------------------------------------------

def test_later_set_cookie_wins_so_a_relogin_rotates_the_session():
    merged = session_state.merge_cookies({"sid": "old"}, {"sid": "new"})
    assert merged == {"sid": "new"}


def test_jar_is_bounded():
    fresh = {f"c{i}": "v" for i in range(50)}
    merged = session_state.merge_cookies({}, fresh)
    assert len(merged) <= session_state.MAX_COOKIES_PER_HOST


def test_cookie_header_is_rfc_shaped_and_length_capped():
    assert session_state.cookie_header({"a": "1", "b": "2"}) == "a=1; b=2"
    assert session_state.cookie_header({}) is None
    # Over the cap -> no header at all rather than a truncated, corrupt one
    # (a mangled Cookie is worse than none, and would also risk tripping the
    # gateway's own 1024-byte header-value limit).
    assert session_state.cookie_header({"k": "x" * 2000}) is None


def test_apply_to_headers_adds_the_cookie():
    assert session_state.apply_to_headers({}, {"sid": "v"}) == {"Cookie": "sid=v"}


def test_an_explicit_agent_cookie_header_is_never_overwritten():
    """The model may be deliberately testing a forged/absent/downgraded session.
    Silently replacing it would corrupt the test AND hide that from the
    operator."""
    for name in ("Cookie", "cookie", "COOKIE"):
        out = session_state.apply_to_headers({name: "chosen=byagent"}, {"sid": "fromjar"})
        assert out == {name: "chosen=byagent"}


def test_empty_jar_leaves_headers_untouched():
    assert session_state.apply_to_headers({"X-Test": "1"}, {}) == {"X-Test": "1"}


# --- Cross-host isolation (mandatory R3 negative tests) --------------------

def _ctx():
    return agent.SimpleContext(scan_run_id="11111111-1111-1111-1111-111111111111")


@pytest.fixture(autouse=True)
def _no_audit(monkeypatch):
    monkeypatch.setattr(agent.client, "agent_event", lambda *a, **k: None)


def test_a_session_from_host_a_is_never_attached_to_host_b():
    """THE load-bearing security invariant of this feature."""
    ctx = _ctx()
    agent._capture_session(ctx, "victim.example", "HTTP/1.1 200 OK\r\nSet-Cookie: sid=SECRET\r\n\r\n", EID)

    assert ctx.cookies_by_host["victim.example"] == {"primary": {"sid": "SECRET"}}
    # Another in-scope host in the SAME run must get nothing.
    assert session_state.apply_to_headers({}, ctx.cookies_by_host.get("other.example", {}).get("primary", {})) == {}


def test_each_host_keeps_its_own_independent_session():
    ctx = _ctx()
    agent._capture_session(ctx, "a.example", "HTTP/1.1 200 OK\r\nSet-Cookie: sid=AAA\r\n\r\n", EID)
    agent._capture_session(ctx, "b.example", "HTTP/1.1 200 OK\r\nSet-Cookie: sid=BBB\r\n\r\n", EID)

    assert ctx.cookies_by_host["a.example"] == {"primary": {"sid": "AAA"}}
    assert ctx.cookies_by_host["b.example"] == {"primary": {"sid": "BBB"}}


def test_the_jar_does_not_survive_into_another_run():
    """The jar lives on the per-run context object; a new run starts empty.
    Nothing is persisted, so there is no path for it to leak across runs or
    engagements."""
    first = _ctx()
    agent._capture_session(first, "host.example", "HTTP/1.1 200 OK\r\nSet-Cookie: sid=v\r\n\r\n", EID)
    assert first.cookies_by_host

    assert _ctx().cookies_by_host == {}


def test_capturing_a_response_without_cookies_changes_nothing():
    ctx = _ctx()
    agent._capture_session(ctx, "host.example", "HTTP/1.1 200 OK\r\n\r\nplain body", EID)
    assert ctx.cookies_by_host == {}


def test_session_capture_audits_names_but_never_values(monkeypatch):
    """A session id is exactly as sensitive as the credential that produced it."""
    events = []
    monkeypatch.setattr(agent.client, "agent_event",
                        lambda eid, **kw: events.append(kw))
    ctx = _ctx()
    agent._capture_session(ctx, "host.example",
                           "HTTP/1.1 200 OK\r\nSet-Cookie: PHPSESSID=SUPERSECRETVALUE\r\n\r\n", EID)

    assert events, "establishing a session must be auditable"
    blob = str(events)
    assert "PHPSESSID" in blob
    assert "SUPERSECRETVALUE" not in blob
