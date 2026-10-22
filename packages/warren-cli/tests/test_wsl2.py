"""AC2: WSL2 wiring in the CLI — doctor, connect, provision, get_runtime.

/proc files and mount tables are faked, so these run on any OS; tests that
rely on POSIX paths are marked. HOME is a per-test tmp dir (conftest)."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
import typer
from typer.testing import CliRunner

from warren_cli import dispatch as d
from warren_common import wsl
from warren_common.runtime_detect import RuntimeAvailability

from test_dispatch import _RecordingRuntime

posix_only = pytest.mark.skipif(sys.platform == "win32", reason="POSIX mount paths")


def _cfg(tmp_path: Path) -> Path:
    cfg = tmp_path / "config.toml"
    cfg.write_text(
        f'[defaults]\nmode = "local"\nprojects_dir = "{(tmp_path / "projects").as_posix()}"\n'
        '\n[runtime]\ntype = "bwrap"\n'
    )
    cfg.chmod(0o600)
    return cfg


def _avail(**kw) -> RuntimeAvailability:
    base = dict(
        seatbelt=False, bwrap=True, nsjail=False, docker=False, ecs=False,
        recommended="bubblewrap", bwrap_path="/usr/bin/bwrap",
    )
    base.update(kw)
    return RuntimeAvailability(**base)


def _fake_mounts(tmp_path: Path, monkeypatch, drvfs_point: str) -> None:
    table = tmp_path / "mounts"
    table.write_text(
        "/dev/sdc / ext4 rw 0 0\n"
        f"C:\\134 {drvfs_point} 9p rw,noatime,aname=drvfs;path=C:\\;uid=1000 0 0\n"
    )
    monkeypatch.setattr(wsl, "PROC_MOUNTS", str(table))


# --- doctor -----------------------------------------------------------------


def test_doctor_prints_apparmor_fix(tmp_path, monkeypatch):
    from warren_cli import main as cli_main
    import warren_cli.commands.doctor as doctor_mod

    monkeypatch.setattr(doctor_mod, "detect", lambda: _avail(wsl_version=2, apparmor_userns_restricted=True))
    monkeypatch.setattr(
        wsl, "probe_bwrap",
        lambda _p: wsl.BwrapProbe(False, "bwrap: setting up uid map: Permission denied", wsl.APPARMOR_USERNS_FIX),
    )
    result = CliRunner().invoke(cli_main.app, ["doctor", "--config", str(_cfg(tmp_path))])
    assert result.exit_code == 0, result.output
    assert "WSL: 2" in result.output
    assert "bwrap-userns-restrict" in result.output
    assert "apparmor_parser -r" in result.output


def test_doctor_reports_wsl1(tmp_path, monkeypatch):
    from warren_cli import main as cli_main
    import warren_cli.commands.doctor as doctor_mod

    monkeypatch.setattr(
        doctor_mod, "detect",
        lambda: _avail(bwrap=False, bwrap_path=None, recommended="none", wsl_version=1, note=wsl.WSL1_REFUSAL),
    )
    result = CliRunner().invoke(cli_main.app, ["doctor", "--config", str(_cfg(tmp_path))])
    assert result.exit_code == 0
    assert "WSL: 1" in result.output and "no Linux namespaces" in result.output


@posix_only
def test_doctor_flags_drvfs_home(tmp_path, monkeypatch):
    from warren_cli import main as cli_main
    import warren_cli.commands.doctor as doctor_mod

    _fake_mounts(tmp_path, monkeypatch, str(Path.home()))
    monkeypatch.setattr(doctor_mod, "detect", lambda: _avail(wsl_version=2))
    result = CliRunner().invoke(cli_main.app, ["doctor", "--config", str(_cfg(tmp_path)), "--json"])
    report = json.loads(result.output)
    drvfs = report["linux_sandbox"]["drvfs"]
    assert any(m.startswith("warren home ") for m in drvfs)
    assert report["linux_sandbox"]["bwrap_probe"]["ok"] is True


# --- connect ------------------------------------------------------------------


@posix_only
def test_bwrap_connect_prints_apparmor_fix_instead_of_raw_error(monkeypatch, capsys):
    monkeypatch.setattr(
        wsl, "probe_bwrap",
        lambda _p: wsl.BwrapProbe(False, "bwrap: setting up uid map: Permission denied", wsl.APPARMOR_USERNS_FIX),
    )
    handed_off = []
    monkeypatch.setattr(d, "_hand_off", lambda *a, **kw: handed_off.append(a))
    with pytest.raises(typer.Exit) as ei:
        d._connect_via_execvp({
            "runtime_type": "bwrap",
            "bwrap_path": "/usr/bin/bwrap",
            "bwrap_args": ["--", "bash"],
            "app": "bash",
            "workspace_id": "ws",
        })
    assert ei.value.exit_code == 1
    assert not handed_off
    assert "bwrap-userns-restrict" in capsys.readouterr().err


def test_unclassified_probe_failure_falls_through(monkeypatch):
    monkeypatch.setattr(wsl, "probe_bwrap", lambda _p: wsl.BwrapProbe(False, "weird", None))
    d._check_bwrap_before_hand_off("/usr/bin/bwrap")  # no raise


# --- provision: drvfs refusal ------------------------------------------------


def _project(projects_dir: Path) -> None:
    projects_dir.mkdir(exist_ok=True)
    (projects_dir / "proj.yaml").write_text(
        "name: proj\ndescription: t\nrepo: git@example:proj.git\n"
        "bare_path: /tmp/proj/.git-store\ndocker_image: ghcr.io/x/base:latest\n"
        "templates:\n  t:\n    app: bash\n"
    )


@posix_only
@pytest.mark.parametrize("runtime_type", ["bwrap", "nsjail", "seatbelt"])
def test_provision_refuses_state_on_drvfs(tmp_path, monkeypatch, capsys, runtime_type):
    projects_dir = tmp_path / "projects"
    _project(projects_dir)
    _fake_mounts(tmp_path, monkeypatch, str(Path.home()))
    rt = _RecordingRuntime()
    cfg = SimpleNamespace(runtime=SimpleNamespace(type=runtime_type), images={})
    with pytest.raises(typer.Exit):
        d.provision_local("proj", "t", projects_dir, runtime=rt, cfg=cfg)
    assert rt.captured_spec is None
    err = capsys.readouterr().err
    assert "refusing: warren home" in err and "Linux filesystem" in err


@posix_only
def test_provision_allows_linux_filesystem(tmp_path, monkeypatch):
    projects_dir = tmp_path / "projects"
    _project(projects_dir)
    _fake_mounts(tmp_path, monkeypatch, "/mnt/c")
    rt = _RecordingRuntime()
    cfg = SimpleNamespace(runtime=SimpleNamespace(type="bwrap"), images={})
    d.provision_local("proj", "t", projects_dir, runtime=rt, cfg=cfg)
    assert rt.captured_spec is not None


def test_check_local_paths_not_on_drvfs_unreadable_table(tmp_path, monkeypatch):
    monkeypatch.setattr(wsl, "PROC_MOUNTS", str(tmp_path / "missing"))
    d.check_local_paths_not_on_drvfs({"x": tmp_path})


# --- get_runtime: WSL1 ---------------------------------------------------------


@pytest.mark.parametrize("rt_type", ["bwrap", "nsjail"])
def test_get_runtime_refuses_namespaces_on_wsl1(monkeypatch, capsys, rt_type):
    monkeypatch.setattr(wsl, "wsl_version", lambda: 1)
    with pytest.raises(typer.Exit):
        d.get_runtime(SimpleNamespace(runtime=SimpleNamespace(type=rt_type)))
    assert "WSL1" in capsys.readouterr().err
