"""`warren init` runtime prompt (Plan 05b-06)."""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner


@pytest.fixture()
def runner() -> CliRunner:
    return CliRunner()


def test_init_local_mode_persists_runtime_choice(tmp_path, runner, monkeypatch):
    from warren_cli import main as cli_main
    import warren_cli.main as cli_main_mod

    cfg_path = tmp_path / "config.toml"
    projects_dir = tmp_path / "projects"
    monkeypatch.setattr(cli_main_mod, "PROJECTS_DIR", projects_dir)

    # Answer prompts: mode=local, runtime=bwrap
    result = runner.invoke(
        cli_main.app,
        ["init", "--config", str(cfg_path)],
        input="local\nbwrap\n",
    )
    assert result.exit_code == 0, result.output
    text = cfg_path.read_text()
    assert '[runtime]' in text
    assert 'type = "bwrap"' in text


def test_init_recommends_detected_default(tmp_path, runner, monkeypatch):
    from warren_cli import main as cli_main
    import warren_cli.main as cli_main_mod

    cfg_path = tmp_path / "config.toml"
    projects_dir = tmp_path / "projects"
    monkeypatch.setattr(cli_main_mod, "PROJECTS_DIR", projects_dir)

    class _Fake:
        seatbelt = True
        bwrap = False
        nsjail = False
        docker = False
        recommended = "seatbelt"
        docker_host = None
        note = ""
        windows_build = None
        mxc = False
        mxc_status = "n/a"
        mxc_reason = ""

    # Patch the detect symbol imported in main.
    import warren_common.runtime_detect as det_mod
    monkeypatch.setattr(det_mod, "detect", lambda: _Fake())

    # Only answer mode=local, then accept the default runtime.
    result = runner.invoke(
        cli_main.app,
        ["init", "--config", str(cfg_path)],
        input="local\n\n",
    )
    assert result.exit_code == 0, result.output
    text = cfg_path.read_text()
    assert 'type = "seatbelt"' in text


def test_init_server_mode_still_works(tmp_path, runner, monkeypatch):
    from warren_cli import main as cli_main
    import warren_cli.main as cli_main_mod

    cfg_path = tmp_path / "config.toml"
    projects_dir = tmp_path / "projects"
    monkeypatch.setattr(cli_main_mod, "PROJECTS_DIR", projects_dir)

    # server mode: url, token, name — runtime prompt must NOT appear.
    result = runner.invoke(
        cli_main.app,
        ["init", "--config", str(cfg_path)],
        input="server\nhttp://x.example:8420\ntok123\nnode2\n",
    )
    assert result.exit_code == 0, result.output
    text = cfg_path.read_text()
    assert 'mode = "server"' in text
    assert 'auth_token = "tok123"' in text
