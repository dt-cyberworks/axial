"""REQ-EGRESS-014: the compose installation requires the signed run identity by default.

With the identity on, two engagements that cover the same host can both be active. The three settings have to be on or off
TOGETHER: a worker that presents no identity to a proxy that requires one is refused on every request, so a file that
disagrees with itself ships a scanner that scans nothing. The process default of each component stays off, so something
started without the compose file keeps its old behavior."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
COMPOSE = (ROOT / "docker-compose.yml").read_text()
SETTING = re.compile(r"^\s+(EGRESS_REQUIRE_TOKEN|EGRESS_RUN_TOKENS):\s*\$\{\1:-([^}]*)\}\s*$", re.MULTILINE)


def _defaults() -> list[tuple[str, str]]:
    return SETTING.findall(COMPOSE)


def test_the_compose_file_requires_the_identity_by_default():
    found = _defaults()
    assert sorted(name for name, _ in found) == ["EGRESS_REQUIRE_TOKEN", "EGRESS_REQUIRE_TOKEN", "EGRESS_RUN_TOKENS"], found
    assert all(value == "true" for _, value in found), found


def test_negative_the_three_defaults_are_always_the_same_value():
    """The pairing: never a worker without identity next to a proxy that requires one, or the reverse."""
    assert len({value for _, value in _defaults()}) == 1


def test_env_example_turns_both_on_and_explains_the_pairing():
    text = (ROOT / ".env.example").read_text()
    assert re.search(r"^EGRESS_RUN_TOKENS=true$", text, re.MULTILINE)
    assert re.search(r"^EGRESS_REQUIRE_TOKEN=true$", text, re.MULTILINE)
    assert "must stay on while" in text


def test_negative_the_production_overlay_does_not_undo_it():
    overlay = (ROOT / "docker-compose.prod.yml").read_text()
    assert not re.search(r"EGRESS_(REQUIRE_TOKEN|RUN_TOKENS)\s*:", overlay), "the overlay must inherit the default"
    # ...and it still insists on a real secret rather than the development placeholder.
    assert "EGRESS_RUN_TOKEN_SECRET: ${EGRESS_RUN_TOKEN_SECRET:?" in overlay


def test_negative_the_process_defaults_stay_off():
    """A component started without the compose file keeps its old behavior; only the installation turns the identity on."""
    proxy = (ROOT / "egress-proxy/app/proxy.py").read_text()
    worker = (ROOT / "worker/app/tool_runner_client.py").read_text()
    config = (ROOT / "control-plane/app/config.py").read_text()
    assert re.search(r'os\.environ\.get\("EGRESS_REQUIRE_TOKEN", "false"\)', proxy)
    assert re.search(r'os\.environ\.get\("EGRESS_RUN_TOKENS", "false"\)', worker)
    assert re.search(r"egress_require_token\b[^\n]*(False|\"false\")", config, re.IGNORECASE)


def test_the_install_documents_say_what_changed_and_the_way_back():
    install = (ROOT / "INSTALL.md").read_text()
    assert "scan identity is on by default" in install and "set both to `false`" in install
    # docs/deployment.md is instance-specific and is not part of the public export. In the private checkout (the requirements pipeline is
    # there) it must exist and say so; in the exported tree only the public INSTALL.md is checked.
    if (ROOT / "scripts/requirements_pipeline.py").exists():
        assert "must be set alike" in (ROOT / "docs/deployment.md").read_text()
