"""TC-EGRESS-004: the check that runs the real nuclei through the real proxy code.

It needs Docker and local images, so these tests drive it with a fake `docker` and prove what the
check decides: a template the proxy slows down fails it, a template that is slow on its own does
not, an environment problem is never read as a verdict, and the throwaway environment is always
removed. The real run is the check itself (`make verify-tunnel-handshake`)."""

from __future__ import annotations

import argparse
import importlib.util
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location("verify_tunnel_handshake", ROOT / "scripts" / "verify_tunnel_handshake.py")
vth = importlib.util.module_from_spec(_spec)
sys.modules["verify_tunnel_handshake"] = vth
_spec.loader.exec_module(vth)

T1 = "/opt/nuclei-templates/http/misconfiguration/proxy/metadata-google.yaml"
T2 = "/opt/nuclei-templates/http/cves/2022/CVE-2022-22536.yaml"


class FakeDocker:
    """Records every docker call and answers the way a healthy installation does."""

    def __init__(self, *, missing_image: str | None = None, template_output: str | None = None, fail_run: bool = False):
        self.calls: list[list[str]] = []
        self.missing_image = missing_image
        self.template_output = f"{{\"templates\": 2}}\n{T1}\n{T2}\n" if template_output is None else template_output
        self.fail_run = fail_run

    def __call__(self, cmd, **kwargs):
        self.calls.append(cmd)
        args = cmd[1:]
        if args[:2] == ["image", "inspect"]:
            return subprocess.CompletedProcess(cmd, 1 if args[2] == self.missing_image else 0, "", "")
        if args[:1] == ["run"] and "--entrypoint" in args and "sh" in args and "nuclei_index.py" in args[-1]:
            return subprocess.CompletedProcess(cmd, 0, self.template_output, "")
        if args[:2] == ["network", "create"] and self.fail_run:
            raise subprocess.CalledProcessError(1, cmd, "", "boom")
        return subprocess.CompletedProcess(cmd, 0, "", "")

    def where(self, *words) -> list[list[str]]:
        return [c for c in self.calls if all(w in c for w in words)]


def _args(tmp_path: Path, **over) -> argparse.Namespace:
    app = tmp_path / "app"
    app.mkdir(exist_ok=True)
    (app / "proxy.py").write_text("# stand-in")
    base = dict(tool_runner="runner:test", proxy_image="proxy:test", proxy_app_dir=str(app), margin=15.0)
    base.update(over)
    return argparse.Namespace(**base)


@pytest.fixture(autouse=True)
def _no_waiting(monkeypatch):
    monkeypatch.setattr(vth, "SETTLE_SECONDS", 0)


# --- what the check decides -------------------------------------------------------

def test_a_template_the_proxy_slows_down_by_a_minute_is_stalled():
    assert vth.evaluate({T1: 0.5, T2: 0.5}, {T1: 60.6, T2: 0.8}, 15.0) == [T1]


def test_a_template_that_is_slow_on_its_own_is_not_blamed_on_the_proxy():
    """Some smuggling checks wait for the server by design (24 s with no proxy at all)."""
    assert vth.evaluate({T1: 24.0}, {T1: 24.6}, 15.0) == []


def test_the_margin_is_a_limit_not_a_target():
    assert vth.evaluate({T1: 1.0}, {T1: 16.0}, 15.0) == []
    assert vth.evaluate({T1: 1.0}, {T1: 16.5}, 15.0) == [T1]


def test_the_known_stall_is_far_above_the_default_margin():
    """The stall is 60 s per request; a margin near it would stop catching it."""
    assert vth.DEFAULT_MARGIN_SECONDS * 3 < 60


def test_template_list_keeps_only_template_paths_and_ignores_the_index_summary():
    out = f'{{"templates": 3}}\n{T2}\n\n{T1}\n{T1}\nnot a path\n/opt/other/file.txt\n'
    assert vth.parse_template_list(out) == sorted({T1, T2})


# --- an environment problem is not a verdict --------------------------------------

@pytest.mark.parametrize("missing", ["runner:test", "proxy:test", "caddy:2-alpine"])
def test_negative_a_missing_image_means_the_check_cannot_run(tmp_path, missing):
    with pytest.raises(vth.CheckCannotRun, match="not present locally"):
        vth.verify(_args(tmp_path), run=FakeDocker(missing_image=missing))


def test_negative_docker_not_installed_means_the_check_cannot_run(tmp_path):
    def no_docker(*_a, **_k):
        raise FileNotFoundError("docker")

    with pytest.raises(vth.CheckCannotRun, match="docker is not usable"):
        vth.verify(_args(tmp_path), run=no_docker)


def test_negative_an_image_without_any_raw_request_template_cannot_pass_by_checking_nothing(tmp_path):
    with pytest.raises(vth.CheckCannotRun, match="nothing to check"):
        vth.verify(_args(tmp_path), run=FakeDocker(template_output='{"templates": 0}\n'))


def test_negative_a_proxy_directory_that_is_not_the_proxy_cannot_be_checked(tmp_path):
    args = _args(tmp_path)
    (Path(args.proxy_app_dir) / "proxy.py").unlink()
    with pytest.raises(vth.CheckCannotRun, match="not an egress-proxy app directory"):
        vth.verify(args, run=FakeDocker())


def test_main_exits_2_when_the_check_cannot_run(monkeypatch, capsys):
    def cannot(_args, **_k):
        raise vth.CheckCannotRun("no docker")

    monkeypatch.setattr(vth, "verify", cannot)
    assert vth.main([]) == 2
    assert "cannot run: no docker" in capsys.readouterr().err


# --- the verdicts end to end (timing replaced, docker faked) ----------------------

def _times(monkeypatch, direct: dict, proxied: dict):
    monkeypatch.setattr(vth, "time_template",
                        lambda network, runner, template, *, via_proxy, run=None, clock=None:
                        (proxied if via_proxy else direct)[template])


def test_verify_passes_when_the_proxy_adds_nothing(tmp_path, monkeypatch, capsys):
    _times(monkeypatch, {T1: 0.5, T2: 24.0}, {T1: 0.7, T2: 24.4})
    assert vth.verify(_args(tmp_path), run=FakeDocker()) == 0
    assert "PASS" in capsys.readouterr().out


def test_negative_verify_fails_when_the_proxy_stalls_a_template(tmp_path, monkeypatch, capsys):
    _times(monkeypatch, {T1: 0.5, T2: 0.5}, {T1: 60.7, T2: 0.6})
    assert vth.verify(_args(tmp_path), run=FakeDocker()) == 1
    out = capsys.readouterr().out
    assert "STALLED" in out and "metadata-google.yaml" in out and "FAIL" in out


# --- the throwaway environment ----------------------------------------------------

def test_the_environment_is_internal_read_only_and_always_removed(tmp_path, monkeypatch):
    _times(monkeypatch, {T1: 0.5, T2: 0.5}, {T1: 0.6, T2: 0.6})
    fake = FakeDocker()
    vth.verify(_args(tmp_path), run=fake)
    (create,) = fake.where("network", "create")
    assert "--internal" in create, "the target network must have no route to the internet"
    (proxy_start,) = fake.where("--entrypoint", "python", "proxy:test")
    mounts = [proxy_start[i + 1] for i, a in enumerate(proxy_start) if a == "-v"]
    assert all(m.endswith(":ro") for m in mounts), mounts
    removed = [c[3] for c in fake.where("rm", "-f")]
    assert len(removed) == 2 and all(name.startswith("tunnel-check-") for name in removed)
    assert len(fake.where("network", "rm")) == 1


def test_the_environment_is_removed_even_when_a_measurement_fails(tmp_path, monkeypatch):
    def boom(*_a, **_k):
        raise RuntimeError("nuclei crashed")

    monkeypatch.setattr(vth, "time_template", boom)
    fake = FakeDocker()
    with pytest.raises(RuntimeError):
        vth.verify(_args(tmp_path), run=fake)
    assert len(fake.where("rm", "-f")) == 2
    assert len(fake.where("network", "rm")) == 1


def test_a_directory_is_mounted_over_the_images_code_and_image_mode_mounts_nothing():
    assert vth.app_mount("/work/egress-proxy/app") == ["-v", "/work/egress-proxy/app:/app/app:ro"]
    assert vth.app_mount("image") == []


def test_image_mode_judges_the_built_image_and_needs_no_app_directory(tmp_path, monkeypatch):
    _times(monkeypatch, {T1: 0.5, T2: 0.5}, {T1: 0.6, T2: 0.6})
    fake = FakeDocker()
    args = _args(tmp_path, proxy_app_dir="image")
    assert vth.verify(args, run=fake) == 0
    (proxy_start,) = fake.where("--entrypoint", "python", "proxy:test")
    mounts = [proxy_start[i + 1] for i, a in enumerate(proxy_start) if a == "-v"]
    assert len(mounts) == 1 and mounts[0].endswith("/app/harness.py:ro"), mounts  # only the harness, no code over the image


def test_a_failed_setup_is_reported_as_cannot_run_and_still_cleans_up(tmp_path):
    fake = FakeDocker(fail_run=True)
    with pytest.raises(vth.CheckCannotRun, match="throwaway environment"):
        vth.verify(_args(tmp_path), run=fake)
    assert len(fake.where("network", "rm")) == 1


# --- the check is wired in and says what it is for --------------------------------

def test_the_make_target_exists_and_names_the_script():
    makefile = ROOT / "Makefile.private"
    if not makefile.exists():
        pytest.skip("public tree: Makefile.private (the private targets) is not exported")
    text = makefile.read_text(encoding="utf-8")
    assert "verify-tunnel-handshake:" in text
    assert "scripts/verify_tunnel_handshake.py" in text


def test_the_production_flags_the_check_mirrors_still_exist_in_the_worker():
    """The per-request timeout, the single retry and no interactsh are what the worker passes; if the
    worker's invocation changes, this check must be revisited, not silently drift."""
    source = (ROOT / "worker" / "app" / "tool_runner_client.py").read_text(encoding="utf-8")
    for flag in ("-timeout 8", "-retries 1", "-no-interactsh", "-rate-limit"):
        assert flag in source, flag
        assert flag in vth.NUCLEI_FLAGS, flag


def test_ci_runs_the_egress_proxy_tests_so_the_connect_reply_guards_are_not_only_local():
    """Until 2026-10-02 no workflow ran egress-proxy/tests at all. The reply guards live there, so a CI
    that does not run them would let the stall come back unnoticed."""
    workflow = ROOT / ".github" / "workflows" / "ci.yml"
    if not workflow.exists():
        pytest.skip("no CI workflow in this tree")
    lines = workflow.read_text(encoding="utf-8").splitlines()
    steps = [i for i, line in enumerate(lines) if line.strip() == "working-directory: egress-proxy"]
    assert steps, "ci.yml has no step that works in egress-proxy"
    assert any("python -m pytest tests" in " ".join(lines[i:i + 6]) for i in steps), \
        "the egress-proxy step does not run the tests"
