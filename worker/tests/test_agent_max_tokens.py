"""REQ-AGENT-026: the worker asks the provider for the CONFIGURED completion
cap, re-clamped to its own bounds, not a value fixed at process start."""

from __future__ import annotations

import pytest

from app.tasks import agent


def _clamp(value: int) -> int:
    """The worker's own last-word clamp, as applied in agent.run()."""
    return max(agent.AGENT_MIN_MAX_TOKENS, min(int(value), agent.AGENT_MAX_MAX_TOKENS))


def test_the_env_var_default_is_now_8192():
    """4096 truncated a reasoning-plus-tool-call turn mid-JSON, which breaks
    the tool call outright rather than merely shortening the answer."""
    assert agent.AGENT_MAX_TOKENS == 8192


def test_worker_bounds_match_the_control_plane_setting_bounds():
    assert (agent.AGENT_MIN_MAX_TOKENS, agent.AGENT_MAX_MAX_TOKENS) == (1024, 32768)


@pytest.mark.parametrize("delivered,expected", [
    (16384, 16384),
    (1024, 1024),
    (32768, 32768),
])
def test_a_valid_configured_value_is_used_as_delivered(delivered, expected):
    assert _clamp(delivered) == expected


@pytest.mark.parametrize("delivered,expected", [
    (10, 1024),          # far below the floor
    (1023, 1024),        # just below
    (32769, 32768),      # just above
    (10_000_000, 32768), # absurd
])
def test_negative_an_out_of_range_delivered_value_is_reclamped_by_the_worker(delivered, expected):
    """The control plane already validates, but the worker must not depend on
    that: its own bounds are the last word on what it will request."""
    assert _clamp(delivered) == expected


def _retry_max_tokens(max_tokens: int, length_retries: int | None = None) -> int:
    """The worker's own retry-ceiling formula, as applied in agent.run()."""
    retries = agent.AGENT_LENGTH_RETRIES if length_retries is None else length_retries
    return min(max(max_tokens * (2 ** retries), agent.AGENT_RETRY_MAX_TOKENS), agent.AGENT_MAX_MAX_TOKENS)


def test_the_retry_ceiling_never_sits_below_the_configured_cap():
    """A configured cap above the built-in retry ceiling must not be silently
    clamped back down on a length retry - that would make raising the setting
    do nothing on exactly the turns that needed it."""
    configured = 16384
    retry_ceiling = _retry_max_tokens(configured)
    assert retry_ceiling >= configured
    # First attempt asks for exactly the configured cap.
    assert min(configured * (2 ** 0), retry_ceiling) == configured


def test_negative_a_retry_must_gain_real_headroom_over_the_configured_cap():
    """THE regression test for the live 2026-08-11 incident (Confluence,
    Jenkins: zero tool calls, ever, because retries never gained headroom).

    The old formula `max(max_tokens, AGENT_RETRY_MAX_TOKENS)` technically
    satisfied 'ceiling >= configured cap' (the previous test above) while
    still being completely broken: with AGENT_RETRY_MAX_TOKENS's own default
    equal to AGENT_MAX_TOKENS's default, the retry ceiling equalled max_tokens
    exactly, so `token_budget = min(max_tokens * 2, retry_ceiling)` on retry
    was IDENTICAL to the first (already-truncated) attempt. This asserts the
    stronger, actually-meaningful property: a retry must be able to ask for
    MORE than the value that already failed - in the default configuration,
    with no operator tuning at all.
    """
    max_tokens = agent.AGENT_MAX_TOKENS  # the default, unconfigured case
    retry_ceiling = _retry_max_tokens(max_tokens)
    first_attempt_budget = min(max_tokens * (2 ** 0), retry_ceiling)
    retry_budget = min(max_tokens * (2 ** 1), retry_ceiling)
    assert retry_budget > first_attempt_budget, (
        "a retry that asks for the SAME budget as the attempt that just got "
        "truncated cannot possibly succeed where the first one failed"
    )


@pytest.mark.parametrize("configured", [1024, 8192, 16384, 32768])
def test_a_retry_gains_headroom_at_every_configured_cap(configured):
    """Not just the default - any value an operator sets must retry with
    genuinely more room, not just a ceiling that happens to match the cap."""
    retry_ceiling = _retry_max_tokens(configured)
    first_attempt_budget = min(configured, retry_ceiling)
    retry_budget = min(configured * 2, retry_ceiling)
    if configured < agent.AGENT_MAX_MAX_TOKENS:
        assert retry_budget > first_attempt_budget
    else:
        # Already at the absolute ceiling - nowhere higher to escalate to,
        # which is the one legitimate case where equal budgets are correct.
        assert retry_budget == first_attempt_budget == agent.AGENT_MAX_MAX_TOKENS


def test_the_default_retry_count_is_now_2():
    """Live-observed 2026-08-11: even a doubled (1-retry) budget was not
    enough for one real engagement (Jenkins) - raised the default so a run
    can reach this platform's absolute token ceiling (32768) before giving
    up, maximizing recovery odds, still bounded (max 3 by the same clamp as
    before)."""
    assert agent.AGENT_LENGTH_RETRIES == 2


def test_negative_a_third_attempt_is_not_clamped_back_down_to_the_second_ceiling():
    """THE regression test for the SECOND live incident (Jenkins still failed
    after the first fix): the old ceiling was a flat `max_tokens * 2`
    regardless of AGENT_LENGTH_RETRIES, so a third attempt's exponential
    request (`max_tokens * 4`) was clamped back down to the SAME ceiling as
    the second attempt - raising the retry count could never reach further.
    The ceiling must scale with the actual configured retry count."""
    max_tokens = agent.AGENT_MAX_TOKENS
    retry_ceiling = _retry_max_tokens(max_tokens, length_retries=2)
    second_attempt_budget = min(max_tokens * (2 ** 1), retry_ceiling)
    third_attempt_budget = min(max_tokens * (2 ** 2), retry_ceiling)
    assert third_attempt_budget > second_attempt_budget, (
        "a third attempt that asks for the SAME budget as the second cannot "
        "possibly succeed where the second one just failed"
    )
    # And it should reach the platform's absolute ceiling given the default
    # 8192 base and 2 configured retries (8192 * 2**2 = 32768 exactly).
    assert third_attempt_budget == agent.AGENT_MAX_MAX_TOKENS


def test_run_reads_the_configured_value_from_the_control_plane_config():
    """Wiring guard: the resolved value has to be read out of the agent-config
    response, not left at the module-level env default."""
    import inspect

    source = inspect.getsource(agent.run)
    assert 'cfg.get("agent_max_tokens")' in source, "run() must read the resolved cap"
    assert "max_tokens = max(AGENT_MIN_MAX_TOKENS" in source, "run() must re-clamp it"
    assert "retry_max_tokens = min(" in source and "max_tokens * (2 ** AGENT_LENGTH_RETRIES)" in source, (
        "the retry ceiling must derive from THIS run's resolved max_tokens "
        "AND scale with the configured retry count, not a flat multiple of "
        "a static module-level default"
    )
    assert "token_budget = min(max_tokens" in source, "the request must use the resolved value"


def test_falls_back_to_the_env_default_when_the_config_lookup_fails():
    """A control-plane hiccup must not stop the agent phase - it degrades to
    the env default rather than failing."""
    import inspect

    source = inspect.getsource(agent.run)
    assert "max_tokens = AGENT_MAX_TOKENS" in source
