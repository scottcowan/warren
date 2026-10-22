"""`warren doctor` — synchronous diagnostic (Plan 05b-06)."""

from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
import typer
from typer.testing import CliRunner


def _write_local_config(tmp_path: Path) -> Path:
    cfg = tmp_path / "config.toml"
    cfg.write_text(
        f'[defaults]\nmode = "local"\nprojects_dir = "{(tmp_path / "projects").as_posix()}"\n'
        '\n[runtime]\ntype = "seatbelt"\n'
    )
    cfg.chmod(0o600)
    return cfg


@pytest.fixture()
def runner() -> CliRunner:
    return CliRunner()


def test_doctor_runs_and_exits_zero(tmp_path, runner, monkeypatch):
    from warren_cli import main as cli_main

    cfg_path = _write_local_config(tmp_path)
    monkeypatch.setattr(cli_main, "CONFIG_PATH", cfg_path)
    result = runner.invoke(cli_main.app, ["doctor", "--config", str(cfg_path)])
    assert result.exit_code == 0, result.output


def test_doctor_lists_runtime_availability(tmp_path, runner, monkeypatch):
    from warren_cli import main as cli_main

    cfg_path = _write_local_config(tmp_path)
    result = runner.invoke(cli_main.app, ["doctor", "--config", str(cfg_path)])
    out = result.output
    assert "Seatbelt" in out
    assert "Bubblewrap" in out
    assert "nsjail" in out
    assert "Docker" in out


def test_doctor_reports_recommended(tmp_path, runner, monkeypatch):
    from warren_cli import main as cli_main
    import warren_cli.commands.doctor as doctor_mod

    cfg_path = _write_local_config(tmp_path)

    class _Fake:
        seatbelt = True
        bwrap = False
        nsjail = False
        docker = False
        ecs = False
        recommended = "seatbelt"
        docker_host = None
        note = ""
        windows_build = None
        mxc = False
        mxc_status = "n/a"
        mxc_reason = ""

    monkeypatch.setattr(doctor_mod, "detect", lambda: _Fake())
    result = runner.invoke(cli_main.app, ["doctor", "--config", str(cfg_path)])
    assert "recommended" in result.output.lower()
    assert "seatbelt" in result.output


def test_doctor_shows_windows_note_and_pipe(tmp_path, runner, monkeypatch):
    from warren_cli import main as cli_main
    import warren_cli.commands.doctor as doctor_mod
    from warren_common.runtime_detect import RuntimeAvailability

    cfg_path = _write_local_config(tmp_path)
    avail = RuntimeAvailability(
        seatbelt=False, bwrap=False, nsjail=False, docker=True, ecs=False,
        recommended="docker", docker_host="npipe:////./pipe/docker_engine",
        note="",
    )
    monkeypatch.setattr(doctor_mod, "detect", lambda: avail)
    result = runner.invoke(cli_main.app, ["doctor", "--config", str(cfg_path)])
    assert "npipe:////./pipe/docker_engine" in result.output

    none = RuntimeAvailability(
        seatbelt=False, bwrap=False, nsjail=False, docker=False, ecs=False,
        recommended="none", note="use WSL2",
    )
    monkeypatch.setattr(doctor_mod, "detect", lambda: none)
    result = runner.invoke(cli_main.app, ["doctor", "--config", str(cfg_path)])
    assert "note: use WSL2" in result.output


def test_doctor_reports_mxc_on_windows(tmp_path, runner, monkeypatch):
    from warren_cli import main as cli_main
    import json as _json
    import warren_cli.commands.doctor as doctor_mod
    from warren_common.runtime_detect import RuntimeAvailability

    cfg_path = _write_local_config(tmp_path)
    avail = RuntimeAvailability(
        seatbelt=False, bwrap=False, nsjail=False, docker=False, ecs=False,
        recommended="none", mxc=False, mxc_status="unknown",
        mxc_reason="PSEC exports present", windows_build="26100.9278",
    )
    monkeypatch.setattr(doctor_mod, "detect", lambda: avail)
    result = runner.invoke(cli_main.app, ["doctor", "--config", str(cfg_path)])
    assert "MXC (Windows 26100.9278, report only): unknown (PSEC exports present)" in result.output

    result = runner.invoke(cli_main.app, ["doctor", "--config", str(cfg_path), "--json"])
    rt = _json.loads(result.output)["runtimes"]
    assert (rt["mxc"], rt["mxc_status"], rt["windows_build"]) == (False, "unknown", "26100.9278")
    assert rt["recommended"] == "none"


def test_doctor_hides_mxc_off_windows(tmp_path, runner, monkeypatch):
    from warren_cli import main as cli_main

    cfg_path = _write_local_config(tmp_path)
    result = runner.invoke(cli_main.app, ["doctor", "--config", str(cfg_path)])
    if sys.platform != "win32":
        assert "MXC" not in result.output


def test_help_never_detects_or_probes(runner, monkeypatch):
    from warren_cli import main as cli_main
    import warren_common.runtime_detect as det_mod
    import warren_common.winsupport as ws

    monkeypatch.setattr(det_mod, "detect", lambda: pytest.fail("detect on --help"))
    monkeypatch.setattr(ws, "probe_mxc", lambda: pytest.fail("MXC probe on --help"))
    result = runner.invoke(cli_main.app, ["--help"])
    assert result.exit_code == 0, result.output


def test_doctor_resolves_configured_images(tmp_path, runner, monkeypatch):
    from warren_cli import main as cli_main

    cfg = tmp_path / "config.toml"
    cfg.write_text(
        f'[defaults]\nmode = "local"\nprojects_dir = "{(tmp_path / "projects").as_posix()}"\n'
        '\n[runtime]\ntype = "seatbelt"\n'
        '\n[images]\n"ghcr.io/scottcowan/warren-docker-base:latest" = "docker.io/mirror/base:pinned"\n'
    )
    cfg.chmod(0o600)
    result = runner.invoke(cli_main.app, ["doctor", "--config", str(cfg)])
    assert result.exit_code == 0
    assert "ghcr.io/scottcowan/warren-docker-base:latest" in result.output
    assert "docker.io/mirror/base:pinned" in result.output


def test_doctor_aws_missing_is_best_effort(tmp_path, runner, monkeypatch):
    from warren_cli import main as cli_main
    import warren_cli.commands.doctor as doctor_mod

    cfg_path = _write_local_config(tmp_path)

    def _boom(*a, **kw):
        raise FileNotFoundError("no aws")

    monkeypatch.setattr(doctor_mod.subprocess, "run", _boom)
    result = runner.invoke(cli_main.app, ["doctor", "--config", str(cfg_path)])
    assert result.exit_code == 0
    assert "AWS" in result.output or "aws" in result.output


def test_doctor_remotes_online(tmp_path, runner, monkeypatch):
    """doctor() shows 'Remotes:' with online + runtime status when /healthz succeeds."""
    from warren_cli import main as cli_main
    import warren_cli.commands.doctor as doctor_mod

    cfg_path = tmp_path / "config.toml"
    cfg_path.write_text(
        f'[defaults]\nmode = "local"\nprojects_dir = "{(tmp_path / "projects").as_posix()}"\n'
        '\n[runtime]\ntype = "seatbelt"\n'
        '\n[remotes.node2]\nurl = "http://node2.local:8420"\n'
    )
    cfg_path.chmod(0o600)

    hz_data = {"runtime": {"type": "podman", "reachable": True}, "workspaces": {"running": 2, "total": 3}}

    async def _fake_check_remotes(cfg, out=typer.echo):
        typer.echo("\nRemotes:")
        typer.echo("  node2: online  podman ✓  2 running / 3 total")

    import typer as typer_mod
    monkeypatch.setattr(doctor_mod, "_check_remotes", _fake_check_remotes)

    result = runner.invoke(cli_main.app, ["doctor", "--config", str(cfg_path)])
    assert result.exit_code == 0, result.output
    assert "Remotes:" in result.output
    assert "online" in result.output
    assert "podman" in result.output
    assert "2 running / 3 total" in result.output


def test_doctor_remotes_offline(tmp_path, runner, monkeypatch):
    """doctor() shows 'Remotes:' with offline when /healthz raises."""
    from warren_cli import main as cli_main
    import warren_cli.commands.doctor as doctor_mod

    cfg_path = tmp_path / "config.toml"
    cfg_path.write_text(
        f'[defaults]\nmode = "local"\nprojects_dir = "{(tmp_path / "projects").as_posix()}"\n'
        '\n[runtime]\ntype = "seatbelt"\n'
        '\n[remotes.node2]\nurl = "http://node2.local:8420"\n'
    )
    cfg_path.chmod(0o600)

    async def _fake_check_remotes(cfg, out=typer.echo):
        typer.echo("\nRemotes:")
        typer.echo("  node2: offline")

    import typer as typer_mod
    monkeypatch.setattr(doctor_mod, "_check_remotes", _fake_check_remotes)

    result = runner.invoke(cli_main.app, ["doctor", "--config", str(cfg_path)])
    assert result.exit_code == 0, result.output
    assert "Remotes:" in result.output
    assert "offline" in result.output


def test_doctor_remotes_not_configured(tmp_path, runner, monkeypatch):
    """doctor() shows '(not configured)' when no remotes in config."""
    from warren_cli import main as cli_main
    import warren_cli.commands.doctor as doctor_mod

    cfg_path = _write_local_config(tmp_path)

    async def _fake_check_remotes(cfg, out=typer.echo):
        typer.echo("\nRemotes:")
        typer.echo("  (not configured)")

    import typer as typer_mod
    monkeypatch.setattr(doctor_mod, "_check_remotes", _fake_check_remotes)

    result = runner.invoke(cli_main.app, ["doctor", "--config", str(cfg_path)])
    assert result.exit_code == 0, result.output
    assert "Remotes:" in result.output
    assert "(not configured)" in result.output


def test_doctor_json_outputs_structured_report(tmp_path, runner, monkeypatch):
    """`--json` emits one parseable JSON object mirroring the text report,
    instead of the human-readable sections -- no stray prose lines mixed in."""
    from warren_cli import main as cli_main
    import json as _json

    cfg_path = _write_local_config(tmp_path)
    result = runner.invoke(cli_main.app, ["doctor", "--config", str(cfg_path), "--json"])
    assert result.exit_code == 0, result.output

    report = _json.loads(result.output)
    assert "runtimes" in report
    assert "seatbelt" in report["runtimes"]
    assert "images" in report
    assert "ghcr.io/scottcowan/warren-docker-base:latest" in report["images"]
    assert "remotes" in report


def test_doctor_ecs_section(tmp_path, monkeypatch, capsys):
    """doctor ECS section reports aws CLI status without raising.

    Case 1: aws CLI absent — prints ECS Runtime section without raising.
    Case 2: aws CLI present, creds valid, no server_id/ecs_cluster — skips optional checks.
    """
    import shutil as shutil_mod
    import subprocess as subprocess_mod
    import warren_cli.commands.doctor as doctor_mod
    from warren_cli.commands.doctor import _check_ecs
    from types import SimpleNamespace

    # Case 1: aws CLI absent
    monkeypatch.setattr(shutil_mod, "which", lambda name: None)
    # Should not raise even with aws CLI missing
    _check_ecs(None)
    captured = capsys.readouterr()
    assert "ECS Runtime:" in captured.out

    # Case 2: aws CLI present, subprocess returns success (creds ok), no server_id/ecs_cluster
    monkeypatch.setattr(shutil_mod, "which", lambda name: "/usr/local/bin/" + name)

    class _FakeResult:
        returncode = 0

    monkeypatch.setattr(subprocess_mod, "run", lambda *a, **kw: _FakeResult())

    # Mock boto3 to avoid real AWS calls
    class _FakeSsm:
        def describe_parameters(self, **kwargs):
            return {}

    class _FakeEcs:
        def describe_clusters(self, **kwargs):
            return {"clusters": [{"configuration": {"executeCommandConfiguration": {"logging": "ENABLED"}}}]}

    class _FakeBoto3:
        @staticmethod
        def client(service):
            if service == "ssm":
                return _FakeSsm()
            return _FakeEcs()

    import sys
    monkeypatch.setitem(sys.modules, "boto3", _FakeBoto3)

    # Pass cfg=None so server_id and ecs_cluster are None → SSM and cluster checks skipped
    _check_ecs(None)
    captured = capsys.readouterr()
    assert "ECS Runtime:" in captured.out
    # When server_id is None, SSM check should say skipped
    assert "skipped" in captured.out


# --- AI6: harness minimum versions ------------------------------------------


def _fake_harness_env(monkeypatch, stdout):
    import shutil as shutil_mod
    import warren_cli.commands.doctor as doctor_mod

    monkeypatch.setattr(shutil_mod, "which", lambda name: f"/usr/bin/{name}" if stdout is not None else None)
    monkeypatch.setattr(
        doctor_mod.subprocess, "run", lambda *a, **kw: SimpleNamespace(returncode=0, stdout=stdout or "")
    )
    monkeypatch.setattr(doctor_mod, "_HARNESS_MIN_VERSIONS", {"claude": "2.1.0"})
    return doctor_mod


def test_harness_below_minimum_warns(monkeypatch):
    lines: list[str] = []
    doctor_mod = _fake_harness_env(monkeypatch, "2.0.99 (Claude Code)\n")
    res = doctor_mod._check_harnesses(out=lines.append)
    assert res["claude"] == {"minimum": "2.1.0", "version": "2.0.99", "ok": False}
    assert any("below minimum 2.1.0" in line for line in lines)


def test_harness_at_or_above_minimum_ok(monkeypatch):
    doctor_mod = _fake_harness_env(monkeypatch, "2.1.10 (Claude Code)\n")
    res = doctor_mod._check_harnesses(out=lambda _l: None)
    assert res["claude"]["ok"] is True  # 2.1.10 >= 2.1.0 numerically


def test_harness_missing_or_unparseable_is_not_an_error(monkeypatch):
    lines: list[str] = []
    doctor_mod = _fake_harness_env(monkeypatch, None)
    assert doctor_mod._check_harnesses(out=lines.append)["claude"]["ok"] is None
    assert any("not installed" in line for line in lines)
    doctor_mod = _fake_harness_env(monkeypatch, "garbage")
    assert doctor_mod._check_harnesses(out=lambda _l: None)["claude"]["ok"] is None
