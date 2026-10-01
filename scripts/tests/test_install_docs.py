"""REQ-INSTALL-001/006/007/008: the install guide cannot drift away from the tree again.

On 2026-10-01 the published guide told readers to run `make lab-test` (the lab is not
in the public export), to copy `.env.example` (leaving an encryption key empty so
nobody could log in), and to type a production settings block that was missing four
required settings. None of that was caught because nothing compared the guide to the
tree. These tests do, and they run in the PUBLIC tree too (the staged-tree verifier
runs scripts/tests there), which is the tree that matters.

Standard library only (plus PyYAML for the workflow, skipped if absent)."""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
INSTALL = (ROOT / "INSTALL.md").read_text(encoding="utf-8")
MAKEFILE = (ROOT / "Makefile").read_text(encoding="utf-8")
README = (ROOT / "README.md").read_text(encoding="utf-8")
QUICKSTART = (ROOT / "docs" / "manual" / "quickstart.md").read_text(encoding="utf-8")

# Tokens that mean "the guide points at something the public tree does not have".
STALE_TOKENS = ("lab-test", "lab-up", "lab-verify", "make uat", "reference-scan", "lab/", "uat/", "benchmark/",
                "minio/minio", "MINIO_", "miniodata:", "9001")


def _make_targets(text: str) -> set[str]:
    return set(re.findall(r"^([a-zA-Z_][a-zA-Z0-9_-]*):", text, flags=re.M)) - {"help"} | {"help"}


def _code_blocks(text: str) -> list[str]:
    return re.findall(r"```(?:bash|sh|shell)?\n(.*?)```", text, flags=re.S)


def _make_commands(text: str) -> set[str]:
    """Targets named by `make X` in code - fenced blocks and inline code, not English prose."""
    found: set[str] = set()
    for block in _code_blocks(text):
        found |= set(re.findall(r"^\s*(?:[A-Z_]+=\S+\s+)*make ([a-z][a-z0-9-]+)", block, flags=re.M))
    found |= set(re.findall(r"`(?:[A-Z_]+=\S+\s+)*make ([a-z][a-z0-9-]+)[^`]*`", text))
    return found


# --------------------------------------------------------------------------
# REQ-INSTALL-006: no instruction that cannot work in the public tree
# --------------------------------------------------------------------------

def test_negative_every_make_target_the_guides_mention_exists_in_the_public_makefile():
    targets = _make_targets(MAKEFILE)
    for name, text in (("INSTALL.md", INSTALL), ("README.md", README), ("docs/manual/quickstart.md", QUICKSTART)):
        mentioned = _make_commands(text)
        assert mentioned, f"{name} was expected to name at least one make target"
        missing = sorted(mentioned - targets)
        assert not missing, f"{name} tells the reader to run make target(s) the public Makefile lacks: {missing}"


def test_negative_the_public_makefile_refers_to_no_private_harness():
    """The private targets live in Makefile.private, which the export omits."""
    for token in ("lab/", "uat/", "benchmark/"):
        assert token not in MAKEFILE, f"Makefile refers to {token} - move that target to Makefile.private"
    assert "\n-include Makefile.private" in MAKEFILE, "the optional include of the private targets is missing"


def test_makefile_private_exists_only_where_its_harnesses_do():
    private = ROOT / "Makefile.private"
    if private.exists():          # the private checkout
        assert (ROOT / "lab").exists() or (ROOT / "uat").exists()
    else:                         # the public tree: nothing left that needs them
        assert not (ROOT / "lab").exists() and not (ROOT / "uat").exists()


def test_makefile_private_is_excluded_from_the_public_export():
    deny = (ROOT / "scripts" / "oss-public-paths.deny.txt")
    allow = (ROOT / "scripts" / "oss-public-paths.txt")
    if not deny.exists():         # the public tree ships neither list
        pytest.skip("export rules are not part of the public tree")
    assert "Makefile.private" in deny.read_text().splitlines()
    assert "Makefile.private" not in allow.read_text().splitlines()


def test_negative_every_script_and_path_a_make_recipe_runs_exists():
    """A target whose script is missing fails with 'No such file' - what `make lab-test` did."""
    problems = []
    for target, recipe in re.findall(r"^([a-zA-Z_][a-zA-Z0-9_-]*):.*\n((?:\t.*\n?)+)", MAKEFILE, flags=re.M):
        for path in re.findall(r"(?<![\w./-])((?:scripts|control-plane|frontend|docs)/[A-Za-z0-9_./-]+\.(?:py|sh))", recipe):
            # A recipe may run the file inside the control-plane container, where it sits under /app.
            if not ((ROOT / path).exists() or (ROOT / "control-plane" / path).exists()):
                problems.append(f"make {target}: {path}")
    assert not problems, problems


def test_negative_the_guides_name_no_removed_or_private_thing():
    # The install guide itself must not name any of them outside the upgrade notes, which
    # legitimately mention the old variables and volume once.
    upgrade = INSTALL.split("#### From v0.3.0 to v0.3.1")[1].split("### Stop or restart safely")[0]
    outside_upgrade = INSTALL.replace(upgrade, "")
    found = [token for token in STALE_TOKENS if token in outside_upgrade]
    assert not found, f"INSTALL.md mentions {found} outside its upgrade notes"
    # README and the manual quickstart are checked for commands and settings only: the README's
    # project-structure table legitimately lists `lab/` as "not yet in the public release".
    commands = ("lab-test", "lab-up", "lab-verify", "make uat", "reference-scan", "minio/minio", "MINIO_", "cp .env.example")
    for name, text in (("README.md", README), ("docs/manual/quickstart.md", QUICKSTART)):
        found = [token for token in commands if token in text]
        assert not found, f"{name} mentions {found}"


def test_every_relative_link_and_code_path_in_the_install_guide_exists():
    missing = []
    for target in re.findall(r"\]\(([^)#\s]+)(?:#[^)]*)?\)", INSTALL):
        if re.match(r"^[a-z]+:", target):
            continue
        if not (ROOT / target).exists():
            missing.append(target)
    for path in re.findall(r"`((?:scripts|docs|deployment)/[A-Za-z0-9_./<>-]+)`", INSTALL):
        if "<" in path:
            continue
        if not (ROOT / path.rstrip("/")).exists():
            missing.append(path)
    assert not missing, f"INSTALL.md points at paths the tree lacks: {sorted(set(missing))}"


def test_scope_check_runs_only_files_that_exist():
    recipe = re.search(r"^scope-check:.*\n((?:\t.*\n?)+)", MAKEFILE, flags=re.M).group(1)
    for path in re.findall(r"tests/(test_[a-z_]+\.py)", recipe):
        assert (ROOT / "control-plane" / "tests" / path).exists(), path
    assert "docker compose run --rm --no-deps" in recipe, "scope-check must not start the stack"


# --------------------------------------------------------------------------
# REQ-INSTALL-007: the guide is complete for a reader who starts from nothing
# --------------------------------------------------------------------------

def test_the_guide_lists_every_prerequisite_its_commands_need():
    software = INSTALL.split("### Software")[1].split("### Get the source")[0]
    for tool in ("Git", "GNU Make", "Docker Engine", "Compose v2", "curl", "Python 3", "Node.js 20"):
        assert tool in software, f"prerequisite {tool!r} is not listed"
    for command in ("git --version", "make --version", "curl --version", "python3 --version"):
        assert command in software


def test_the_guide_clones_a_real_url_not_a_placeholder():
    assert "<repository-url>" not in INSTALL
    assert "git clone https://github.com/dt-cyberworks/axial.git" in INSTALL


def test_negative_the_guides_no_longer_copy_the_env_example_by_hand():
    """That step is what left the encryption key empty (REQ-INSTALL-003)."""
    for name, text in (("INSTALL.md", INSTALL), ("README.md", README), ("quickstart", QUICKSTART)):
        assert "cp .env.example .env" not in text, f"{name} still tells the reader to copy .env.example"
    assert "make env" in INSTALL and "make up" in INSTALL


def test_the_local_section_ends_with_the_first_administrator_and_the_manual():
    local = INSTALL.split("## 3. Local evaluation")[1].split("## 4. Single-host production")[0]
    assert "make bootstrap-admin" in local
    assert "docs/manual/quickstart.md" in local
    assert "make scope-check" in local


def test_production_uses_the_generator_and_documents_the_ip_address_pitfall():
    production = INSTALL.split("## 4. Single-host production")[1].split("## 5. Operations")[0]
    assert "python3 scripts/gen_production_env.py --domain" in production
    assert "sends no server name" in production.replace("send no server name", "sends no server name") \
        or "no server name" in production
    assert "bare IP address" in production
    # The hand-typed secrets block is gone: it had drifted behind the production gate.
    assert "<database-password>" not in production and "openssl rand" not in production


def test_the_guide_documents_the_v0_3_0_upgrade():
    assert "#### From v0.3.0 to v0.3.1" in INSTALL
    section = INSTALL.split("#### From v0.3.0 to v0.3.1")[1].split("### Stop or restart safely")[0]
    # Migration 0038 (#47) runs automatically and can refuse to run: an upgrader must be told.
    for needle in ("SeaweedFS", "nothing to migrate", "make env", "S3_ENDPOINT", "http://seaweedfs:8333",
                   "Migration `0038`", "no active administrator", "changes nothing"):
        assert needle in section, needle


def test_the_documented_production_start_command_matches_the_smoke_test():
    """The smoke test is only meaningful if it runs the guide's commands."""
    smoke = (ROOT / "scripts" / "install_smoke.sh").read_text()
    for needle in ("docker-compose.yml -f docker-compose.prod.yml", "config --quiet", "bootstrap_admin.py", "make bootstrap-admin",
                   "make scope-check", "make up", "make env", "gen_production_env.py --domain"):
        assert needle in smoke or needle.replace(" -f ", "\" -f \"") in smoke or "PROD_FILES" in smoke, needle
    assert "docker compose \"${PROD_FILES[@]}\"" in smoke and "-f docker-compose.prod.yml" in smoke
    for command in ("config --quiet", "scripts/bootstrap_admin.py", "--profile production"):
        assert command in INSTALL


# --------------------------------------------------------------------------
# REQ-INSTALL-001/008: the smoke script and the release workflow
# --------------------------------------------------------------------------

def test_the_smoke_script_stops_the_console_it_started_and_only_that_one():
    """Killing the `npm` PID left Vite holding :5173, so a SECOND run on the same host failed
    (found on the clean VM). The console is stopped by this run's unique work-copy path."""
    source = (ROOT / "scripts" / "install_smoke.sh").read_text()
    assert 'pkill -f "$WORK/frontend/node_modules"' in source
    assert source.count("stop_console") >= 3        # defined, used after the check, and in the exit trap
    assert "pkill -f vite" not in source and "pkill vite" not in source and "killall" not in source


def test_the_smoke_scripts_are_valid_and_executable():
    script = ROOT / "scripts" / "install_smoke.sh"
    assert script.stat().st_mode & 0o111, "install_smoke.sh must be executable"
    assert subprocess.run(["bash", "-n", str(script)], capture_output=True).returncode == 0
    for helper in ("smoke_first_login.py", "smoke_object_store.py", "init_dev_env.py"):
        compile((ROOT / "scripts" / helper).read_text(), helper, "exec")


def test_the_smoke_script_waits_for_the_backend_not_just_for_the_page_the_proxy_serves():
    """The proxy answers with the console HTML by itself, so a served page proves nothing about the
    API behind it; asserting the 401 once, seconds after `up`, was a race (found on the clean VM)."""
    source = (ROOT / "scripts" / "install_smoke.sh").read_text()
    assert 'wait_for "the API behind the proxy' in source
    assert source.index('wait_for "the API behind the proxy') < source.index("INSTALL.md 4: the first administrator")
    assert 'wait_for "the control-plane /health"' in source                 # the local stage waits for the backend too


def test_the_smoke_script_cannot_touch_a_stack_it_did_not_create():
    source = (ROOT / "scripts" / "install_smoke.sh").read_text()
    assert 'COMPOSE_PROJECT_NAME="axial-smoke-$$"' in source and 'ASM_NETWORK_PREFIX="axial_smoke_$$"' in source
    assert "mktemp -d" in source and "--exclude=./.env" in source       # works on a copy, never on the caller's .env
    assert "port $port is already in use" in source                     # refuses instead of fighting for a port
    assert "COMPOSE_PROJECT_NAME" in source and "label=com.docker.compose.project=$COMPOSE_PROJECT_NAME" in source


def test_the_smoke_script_contains_its_negative_checks():
    source = (ROOT / "scripts" / "install_smoke.sh").read_text()
    assert "admin@example.test" in source and "cannot be used" in source          # REQ-INSTALL-005
    assert "FAIL  start TOTP enrollment -> 503" in source                          # REQ-INSTALL-004
    assert "grep -v '^OOB_TOKEN='" in source                                       # the 2026-10-01 production failure
    assert "smoke_object_store.py" in source                                       # REQ-INSTALL-002


def test_the_release_workflow_exists_and_runs_the_smoke_on_every_release_path():
    yaml = pytest.importorskip("yaml")
    workflow = ROOT / ".github" / "workflows" / "install-smoke.yml"
    assert workflow.exists(), "the install smoke workflow must ship"
    parsed = yaml.safe_load(workflow.read_text())
    triggers = parsed.get("on") or parsed.get(True)
    assert "pull_request" in triggers and triggers["push"]["tags"] == ["v*"] and "workflow_dispatch" in triggers
    job = parsed["jobs"]["install-smoke"]
    # Release pull requests (release/*) are gated; ordinary PRs are left to CI.
    assert "startsWith(github.head_ref, 'release/')" in job["if"]
    assert job["runs-on"].startswith("ubuntu-")
    steps = " ".join(str(step.get("run", "")) for step in job["steps"])
    assert "scripts/install_smoke.sh local" in steps and "scripts/install_smoke.sh production" in steps
    assert parsed["permissions"] == {"contents": "read"}, "the job needs no write access"


def test_the_workflow_is_part_of_the_public_export():
    allow = ROOT / "scripts" / "oss-public-paths.txt"
    if not allow.exists():
        pytest.skip("export rules are not part of the public tree")
    rules = allow.read_text().splitlines()
    assert ".github/" in rules and "scripts/" in rules
