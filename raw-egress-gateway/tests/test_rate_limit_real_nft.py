"""GitHub issue #37: the mocked-runner tests in test_gateway.py prove
NftPolicyManager GENERATES the intended nftables script; this proves that
script is actually valid, real nftables syntax, and that the flush-chain-
and-rebuild pattern genuinely updates a slot's live rate - not assumed.

Runs against the real `nft` binary inside a running raw-egress-gateway
container (which has the CAP_NET_ADMIN this needs; the bare test host does
not). Uses a throwaway table name (never `asm_raw`, the real gateway's own
table) so this can never interfere with a live lease. Skipped, not failed,
when no such container is reachable - mirrors
scripts/tests/test_production_exposure.py's own docker-availability skip."""

from __future__ import annotations

import shutil
import subprocess

import pytest

from app import gateway as gateway_module
from app.gateway import NftPolicyManager

TEST_TABLE = "asm_raw_test_issue37"


def _raw_egress_container() -> str | None:
    if shutil.which("docker") is None:
        return None
    try:
        result = subprocess.run(
            ["docker", "ps", "--filter", "name=raw-egress-gateway", "--format", "{{.Names}}"],
            capture_output=True, text=True, timeout=10,
        )
    except Exception:  # noqa: BLE001
        return None
    names = [n for n in result.stdout.splitlines() if n.strip()]
    if not names:
        return None
    container = names[0]
    try:
        probe = subprocess.run(
            ["docker", "exec", container, "nft", "--version"],
            capture_output=True, text=True, timeout=10,
        )
    except Exception:  # noqa: BLE001
        return None
    return container if probe.returncode == 0 else None


def _docker_nft_runner(container: str):
    def run(script: str, check: bool) -> None:
        result = subprocess.run(
            ["docker", "exec", "-i", container, "nft", "-f", "-"],
            input=script, capture_output=True, text=True, timeout=15,
        )
        if check and result.returncode != 0:
            raise AssertionError(f"real nft rejected the generated script:\n{result.stderr}\n---script---\n{script}")
    return run


def _nft_list(container: str) -> str:
    result = subprocess.run(
        ["docker", "exec", container, "nft", "list", "table", "inet", TEST_TABLE],
        capture_output=True, text=True, timeout=10,
    )
    return result.stdout


@pytest.fixture
def real_policy(monkeypatch):
    container = _raw_egress_container()
    if container is None:
        pytest.skip("no running raw-egress-gateway container with a working nft binary available")
    monkeypatch.setattr(gateway_module, "TABLE", TEST_TABLE)
    policy = NftPolicyManager(_docker_nft_runner(container), proxy_addresses=["172.30.0.8"], proxy_port=3128, num_slots=2)
    try:
        yield policy, container
    finally:
        subprocess.run(
            ["docker", "exec", container, "nft", "delete", "table", "inet", TEST_TABLE],
            capture_output=True, text=True, timeout=10,
        )


def test_initialize_produces_syntactically_valid_nftables(real_policy):
    policy, container = real_policy
    policy.initialize()  # raises AssertionError (via the runner above) if nft rejects it
    listing = _nft_list(container)
    assert "chain slot_0" in listing
    assert "chain slot_1" in listing


def test_apply_installs_a_real_kernel_enforced_rate_limit(real_policy):
    policy, container = real_policy
    policy.initialize()
    policy.apply(0, "192.0.2.10", [(443, 443)], 60, "tcp", 5)
    listing = _nft_list(container)
    assert "limit rate 5/second" in listing


def test_reapplying_with_a_different_rate_actually_updates_the_live_kernel_rule(real_policy):
    """The specific scenario a manual investigation found nftables refuses
    for a NAMED limit object still referenced by a rule ("Resource busy") -
    proves the flush-chain-and-rebuild design sidesteps that entirely."""
    policy, container = real_policy
    policy.initialize()
    policy.apply(0, "192.0.2.10", [(443, 443)], 60, "tcp", 5)
    assert "limit rate 5/second" in _nft_list(container)

    policy.apply(0, "192.0.2.10", [(443, 443)], 60, "tcp", 800)
    listing = _nft_list(container)
    assert "limit rate 800/second" in listing
    assert "limit rate 5/second" not in listing


def test_clear_removes_the_rate_limited_rule(real_policy):
    policy, container = real_policy
    policy.initialize()
    policy.apply(0, "192.0.2.10", [(443, 443)], 60, "tcp", 300)
    policy.clear(0)
    listing = _nft_list(container)
    assert "limit rate" not in listing


def test_two_slots_get_independent_rate_limits_simultaneously(real_policy):
    policy, container = real_policy
    policy.initialize()
    policy.apply(0, "192.0.2.10", [(443, 443)], 60, "tcp", 5)
    policy.apply(1, "203.0.113.5", [(8080, 8080)], 60, "tcp", 900)
    listing = _nft_list(container)
    assert "limit rate 5/second" in listing
    assert "limit rate 900/second" in listing
