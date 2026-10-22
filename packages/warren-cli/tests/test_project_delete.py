"""`warren project delete` — remove a local project file, or the caller's own
user-scoped project on a remote warren-server (DELETE /projects/{name})."""

from __future__ import annotations

from pathlib import Path

import httpx
import pytest
import respx
from typer.testing import CliRunner

from warren_cli.main import app

runner = CliRunner()


@pytest.fixture
def cfg_file(tmp_path: Path) -> Path:
    path = tmp_path / "config.toml"
    path.write_text(
        """
[defaults]
mode = "local"

[remotes.node2]
url = "http://test.local"
"""
    )
    return path


@pytest.fixture
def projects_dir(tmp_path: Path) -> Path:
    d = tmp_path / "projects"
    d.mkdir()
    return d


def test_delete_local_project_with_yes_skips_prompt(monkeypatch, projects_dir):
    monkeypatch.setattr("warren_cli.main.PROJECTS_DIR", projects_dir)
    (projects_dir / "dotmusic.yaml").write_text("name: dotmusic\n")

    result = runner.invoke(app, ["project", "delete", "dotmusic", "--yes"])

    assert result.exit_code == 0, result.output
    assert not (projects_dir / "dotmusic.yaml").exists()


def test_delete_local_project_requires_confirmation(monkeypatch, projects_dir):
    monkeypatch.setattr("warren_cli.main.PROJECTS_DIR", projects_dir)
    (projects_dir / "dotmusic.yaml").write_text("name: dotmusic\n")

    result = runner.invoke(app, ["project", "delete", "dotmusic"], input="n\n")

    assert result.exit_code == 0, result.output
    assert (projects_dir / "dotmusic.yaml").exists()


def test_delete_local_project_confirmed_interactively(monkeypatch, projects_dir):
    monkeypatch.setattr("warren_cli.main.PROJECTS_DIR", projects_dir)
    (projects_dir / "dotmusic.yaml").write_text("name: dotmusic\n")

    result = runner.invoke(app, ["project", "delete", "dotmusic"], input="y\n")

    assert result.exit_code == 0, result.output
    assert not (projects_dir / "dotmusic.yaml").exists()


def test_delete_local_project_not_found(monkeypatch, projects_dir):
    monkeypatch.setattr("warren_cli.main.PROJECTS_DIR", projects_dir)

    result = runner.invoke(app, ["project", "delete", "nope", "--yes"])

    assert result.exit_code == 1


@respx.mock
def test_delete_remote_project_calls_server(monkeypatch, cfg_file, projects_dir):
    monkeypatch.setattr("warren_cli.main.PROJECTS_DIR", projects_dir)
    route = respx.delete("http://test.local/projects/dotmusic").mock(
        return_value=httpx.Response(204)
    )

    result = runner.invoke(
        app,
        ["project", "delete", "dotmusic", "--server", "node2", "--yes", "--config", str(cfg_file)],
    )

    assert result.exit_code == 0, result.output
    assert route.called


@respx.mock
def test_delete_remote_project_404_reports_failure(monkeypatch, cfg_file, projects_dir):
    monkeypatch.setattr("warren_cli.main.PROJECTS_DIR", projects_dir)
    respx.delete("http://test.local/projects/dotmusic").mock(return_value=httpx.Response(404))

    result = runner.invoke(
        app,
        ["project", "delete", "dotmusic", "--server", "node2", "--yes", "--config", str(cfg_file)],
    )

    assert result.exit_code == 1


@respx.mock
def test_delete_remote_project_requires_confirmation(monkeypatch, cfg_file, projects_dir):
    monkeypatch.setattr("warren_cli.main.PROJECTS_DIR", projects_dir)
    route = respx.delete("http://test.local/projects/dotmusic").mock(
        return_value=httpx.Response(204)
    )

    result = runner.invoke(
        app,
        ["project", "delete", "dotmusic", "--server", "node2", "--config", str(cfg_file)],
        input="n\n",
    )

    assert result.exit_code == 0, result.output
    assert not route.called
