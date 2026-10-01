"""REQ-INSTALL-003: `make env` (scripts/init_dev_env.py) creates or completes the
local-evaluation .env without ever shipping a key, overwriting a value, or
touching a production file.

The defect it exists for (found 2026-10-01 on a clean VM): `.env.example` ships
MFA_ENCRYPTION_KEY empty on purpose, the install guide said the defaults
suffice, so the stack came up healthy and nobody could ever finish MFA
enrollment. Standard library only - the same constraint the script has."""

from __future__ import annotations

import base64
import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "init_dev_env.py"
sys.path.insert(0, str(ROOT / "scripts"))

import init_dev_env  # noqa: E402

EXAMPLE = """\
# comment kept as is
ENVIRONMENT=development
S3_ACCESS_KEY=asm-dev-access
MFA_ENCRYPTION_KEY=
# another comment
SETTINGS_ENCRYPTION_KEY=
LLM_API_KEY=
"""


def _run(tmp_path: Path, env_text: str | None, example: str = EXAMPLE) -> tuple[subprocess.CompletedProcess, Path]:
    example_path = tmp_path / ".env.example"
    example_path.write_text(example)
    env_path = tmp_path / ".env"
    if env_text is not None:
        env_path.write_text(env_text)
    result = subprocess.run(
        [sys.executable, str(SCRIPT), "--env-file", str(env_path), "--example", str(example_path)],
        capture_output=True, text=True, timeout=30,
    )
    return result, env_path


def _values(path: Path) -> dict[str, str]:
    out = {}
    for line in path.read_text().splitlines():
        if "=" in line and not line.startswith("#"):
            key, value = line.split("=", 1)
            out[key] = value
    return out


def _is_fernet_key(value: str) -> bool:
    try:
        return len(base64.urlsafe_b64decode(value.encode())) == 32
    except Exception:  # noqa: BLE001
        return False


def test_a_missing_env_file_is_created_from_the_example_with_both_keys(tmp_path):
    result, env_path = _run(tmp_path, None)
    assert result.returncode == 0, result.stderr
    values = _values(env_path)
    assert _is_fernet_key(values["MFA_ENCRYPTION_KEY"]) and _is_fernet_key(values["SETTINGS_ENCRYPTION_KEY"])
    # Everything else is the example, byte for byte (comments included).
    text = env_path.read_text()
    assert "# comment kept as is\n" in text and "# another comment\n" in text
    assert values["S3_ACCESS_KEY"] == "asm-dev-access" and values["LLM_API_KEY"] == ""


def test_the_two_keys_are_different_so_one_leak_does_not_expose_the_other(tmp_path):
    _, env_path = _run(tmp_path, None)
    values = _values(env_path)
    assert values["MFA_ENCRYPTION_KEY"] != values["SETTINGS_ENCRYPTION_KEY"]


def test_the_created_file_is_private_to_its_owner(tmp_path):
    _, env_path = _run(tmp_path, None)
    assert stat.S_IMODE(env_path.stat().st_mode) == 0o600


def test_the_keys_and_values_are_never_printed(tmp_path):
    result, env_path = _run(tmp_path, None)
    for value in (_values(env_path)["MFA_ENCRYPTION_KEY"], _values(env_path)["SETTINGS_ENCRYPTION_KEY"]):
        assert value not in result.stdout + result.stderr
    assert "MFA_ENCRYPTION_KEY" in result.stdout  # it does say WHICH keys it generated


def test_negative_a_second_run_changes_nothing(tmp_path):
    _, env_path = _run(tmp_path, None)
    before = env_path.read_text()
    result, _ = _run(tmp_path, before)
    assert result.returncode == 0
    assert env_path.read_text() == before
    assert "nothing to do" in result.stdout


def test_negative_a_value_that_is_already_set_is_never_changed(tmp_path):
    existing = "ENVIRONMENT=development\nMFA_ENCRYPTION_KEY=my-own-key-value\nSETTINGS_ENCRYPTION_KEY=\nCUSTOM=1\n"
    result, env_path = _run(tmp_path, existing)
    assert result.returncode == 0
    values = _values(env_path)
    assert values["MFA_ENCRYPTION_KEY"] == "my-own-key-value"      # kept, even though it is not a valid key
    assert _is_fernet_key(values["SETTINGS_ENCRYPTION_KEY"])         # the empty one was filled
    assert values["CUSTOM"] == "1"


def test_an_env_file_from_v0_3_0_with_the_empty_keys_is_repaired(tmp_path):
    """Upgrade path: someone who already ran `cp .env.example .env` (the v0.3.0 guide)."""
    result, env_path = _run(tmp_path, EXAMPLE)
    assert result.returncode == 0
    values = _values(env_path)
    assert _is_fernet_key(values["MFA_ENCRYPTION_KEY"]) and _is_fernet_key(values["SETTINGS_ENCRYPTION_KEY"])


@pytest.mark.parametrize("empty", ['MFA_ENCRYPTION_KEY=""', "MFA_ENCRYPTION_KEY=''", "MFA_ENCRYPTION_KEY=   "])
def test_quoted_or_blank_values_count_as_empty(tmp_path, empty):
    _, env_path = _run(tmp_path, f"ENVIRONMENT=development\n{empty}\n")
    assert _is_fernet_key(_values(env_path)["MFA_ENCRYPTION_KEY"])


def test_a_key_line_that_is_missing_altogether_is_appended(tmp_path):
    _, env_path = _run(tmp_path, "ENVIRONMENT=development\n")
    values = _values(env_path)
    assert _is_fernet_key(values["MFA_ENCRYPTION_KEY"]) and _is_fernet_key(values["SETTINGS_ENCRYPTION_KEY"])


@pytest.mark.parametrize("production_line", ["ENVIRONMENT=production", 'ENVIRONMENT="production"', "ENVIRONMENT=Production"])
def test_negative_a_production_env_file_is_never_modified(tmp_path, production_line):
    """An empty key in production must stay an error (the gate refuses to start); it must
    not be papered over by a development helper."""
    text = f"{production_line}\nMFA_ENCRYPTION_KEY=\nSETTINGS_ENCRYPTION_KEY=\n"
    result, env_path = _run(tmp_path, text)
    assert result.returncode == 0
    assert env_path.read_text() == text
    assert "untouched" in result.stdout


def test_negative_without_an_env_file_and_without_an_example_it_fails_clearly(tmp_path):
    result = subprocess.run(
        [sys.executable, str(SCRIPT), "--env-file", str(tmp_path / ".env"), "--example", str(tmp_path / "nope")],
        capture_output=True, text=True, timeout=30,
    )
    assert result.returncode == 1 and "missing" in result.stderr


def test_the_real_env_example_ships_no_key(tmp_path):
    """REQ-IAM-004 invariant behind all of this: no encryption key is ever committed."""
    values = _values(ROOT / ".env.example")
    assert values["MFA_ENCRYPTION_KEY"] == "" and values["SETTINGS_ENCRYPTION_KEY"] == ""
    assert values["ENVIRONMENT"] == "development"


def test_the_real_env_example_produces_a_complete_development_env(tmp_path):
    result = subprocess.run(
        [sys.executable, str(SCRIPT), "--env-file", str(tmp_path / ".env"), "--example", str(ROOT / ".env.example")],
        capture_output=True, text=True, timeout=30,
    )
    assert result.returncode == 0, result.stderr
    values = _values(tmp_path / ".env")
    assert _is_fernet_key(values["MFA_ENCRYPTION_KEY"]) and _is_fernet_key(values["SETTINGS_ENCRYPTION_KEY"])


def test_generated_keys_have_fernet_shape():
    key = init_dev_env.fernet_key()
    assert len(key) == 44 and _is_fernet_key(key)
    assert init_dev_env.fernet_key() != key  # random each time


def test_the_script_needs_only_the_standard_library():
    """The documented prerequisites contain no Python packages."""
    source = SCRIPT.read_text()
    stdlib_only = {"argparse", "base64", "os", "re", "stat", "sys", "pathlib", "__future__"}
    imported = {line.split()[1].split(".")[0] for line in source.splitlines() if line.startswith(("import ", "from "))}
    assert imported <= stdlib_only, imported - stdlib_only


def test_make_up_runs_env_first():
    makefile = (ROOT / "Makefile").read_text()
    assert "\nup: env" in makefile and "python3 scripts/init_dev_env.py" in makefile
    assert os.access(SCRIPT, os.R_OK)
