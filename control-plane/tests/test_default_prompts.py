"""REQ-AGENT-016/019/020: the default agent prompt must guide the agent toward
non-destructive, generic (not target-specific) structural checks for
categories no deterministic tool can reliably express, all via `http_request`
(curl) without a browser: CSRF (missing anti-CSRF token), the three XSS
classes (reflected marker-reflection, DOM source->sink read, stored
persist-and-redisplay), other injection (SQLi/LFI/etc. read-only probes),
insecure challenge-response controls (client-side-exposed secret), and weak
session IDs (multi-sample entropy/rotation check, never guessing or hijacking
a real session)."""

from __future__ import annotations

from app.default_prompts import DEFAULT_AGENT_PROMPT


def test_prompt_covers_csrf_via_non_destructive_structural_check():
    assert "CSRF" in DEFAULT_AGENT_PROMPT
    assert "anti-CSRF token" in DEFAULT_AGENT_PROMPT
    assert "Never submit the form yourself" in DEFAULT_AGENT_PROMPT


def test_prompt_tells_the_agent_to_test_xss_itself_not_defer_to_a_scanner():
    # REQ-AGENT-020: the agent owns XSS detection via http_request; nuclei
    # cannot discover the vulnerable parameters, so deferring to it (the old
    # wording) is why XSS was non-deterministic. The prompt must NOT tell the
    # agent to let nuclei do the structured injection detection.
    assert "let `nuclei`'s injection-tagged templates do the structured detection" not in DEFAULT_AGENT_PROMPT
    assert "YOU test this yourself" in DEFAULT_AGENT_PROMPT


def test_prompt_covers_reflected_xss_via_marker_reflection_read_only():
    assert "Reflected XSS" in DEFAULT_AGENT_PROMPT
    assert "UNESCAPED" in DEFAULT_AGENT_PROMPT
    assert "no browser needed" in DEFAULT_AGENT_PROMPT


def test_prompt_covers_dom_xss_by_reading_js_not_executing_it():
    assert "DOM-based XSS" in DEFAULT_AGENT_PROMPT
    assert "source→sink" in DEFAULT_AGENT_PROMPT
    assert "document.write" in DEFAULT_AGENT_PROMPT
    # Explicitly a read/structural check, never browser execution.
    assert "you never need a real browser" in DEFAULT_AGENT_PROMPT


def test_prompt_covers_stored_xss_via_inert_marker_not_live_payload():
    assert "not a live script payload" in DEFAULT_AGENT_PROMPT
    assert "requires operator approval" in DEFAULT_AGENT_PROMPT


def test_prompt_covers_insecure_challenge_response_controls():
    assert "CAPTCHA" in DEFAULT_AGENT_PROMPT
    assert "bypassable challenge-response controls" in DEFAULT_AGENT_PROMPT
    assert "client-side JS" in DEFAULT_AGENT_PROMPT


def test_prompt_covers_weak_session_ids_without_hijacking():
    assert "weak-session-ID finding" in DEFAULT_AGENT_PROMPT
    assert "never attempt to guess, reuse, or hijack" in DEFAULT_AGENT_PROMPT
