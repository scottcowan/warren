"""`warren project clone --server` — pull a server project down for local-mode use."""

from __future__ import annotations

from pathlib import Path

import httpx
import pytest
import respx
import yaml
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


_EFFECTIVE = {
    "name": "dotmusic",
    "docker_image": "ghcr.io/example/dev:latest",
    "folders": [],
    "templates": {
        "vps-aws": {
            "secrets": [{"name": "GRAFANA_PASSWORD"}, {"name": "ATLASSIAN_API_TOKEN"}],
        }
    },
}


@respx.mock
def test_clone_writes_effective_project_locally(monkeypatch, cfg_file, projects_dir):
    monkeypatch.setattr("warren_cli.main.PROJECTS_DIR", projects_dir)
    respx.get("http://test.local/projects/dotmusic").mock(
        return_value=httpx.Response(200, json={
            "name": "dotmusic",
            "server_wide_yaml": "name: dotmusic\n",
            "server_wide_version": "abc",
            "user_scoped_yaml": None,
            "effective": _EFFECTIVE,
        })
    )

    result = runner.invoke(
        app, ["project", "clone", "dotmusic", "--server", "node2", "--config", str(cfg_file)]
    )

    assert result.exit_code == 0, result.output
    written = projects_dir / "dotmusic.yaml"
    assert written.exists()
    loaded = yaml.safe_load(written.read_text())
    assert loaded["name"] == "dotmusic"
    assert "vps-aws" in loaded["templates"]
    # Mentions declared secret names so the new teammate knows what to add locally.
    assert "GRAFANA_PASSWORD" in result.output
    assert "ATLASSIAN_API_TOKEN" in result.output


@respx.mock
def test_clone_404_reports_project_not_found(monkeypatch, cfg_file, projects_dir):
    monkeypatch.setattr("warren_cli.main.PROJECTS_DIR", projects_dir)
    respx.get("http://test.local/projects/nope").mock(return_value=httpx.Response(404))

    result = runner.invoke(
        app, ["project", "clone", "nope", "--server", "node2", "--config", str(cfg_file)]
    )

    assert result.exit_code == 1
    assert not (projects_dir / "nope.yaml").exists()


@respx.mock
def test_clone_refuses_to_overwrite_without_force(monkeypatch, cfg_file, projects_dir):
    monkeypatch.setattr("warren_cli.main.PROJECTS_DIR", projects_dir)
    (projects_dir / "dotmusic.yaml").write_text("name: dotmusic\nalready: here\n")

    result = runner.invoke(
        app, ["project", "clone", "dotmusic", "--server", "node2", "--config", str(cfg_file)]
    )

    assert result.exit_code == 1
    assert "already" in (projects_dir / "dotmusic.yaml").read_text()


@respx.mock
def test_clone_force_overwrites_existing_local_project(monkeypatch, cfg_file, projects_dir):
    monkeypatch.setattr("warren_cli.main.PROJECTS_DIR", projects_dir)
    (projects_dir / "dotmusic.yaml").write_text("name: dotmusic\nstale: true\n")
    respx.get("http://test.local/projects/dotmusic").mock(
        return_value=httpx.Response(200, json={
            "name": "dotmusic",
            "server_wide_yaml": "name: dotmusic\n",
            "server_wide_version": "abc",
            "user_scoped_yaml": None,
            "effective": _EFFECTIVE,
        })
    )

    result = runner.invoke(
        app,
        ["project", "clone", "dotmusic", "--server", "node2", "--force", "--config", str(cfg_file)],
    )

    assert result.exit_code == 0, result.output
    loaded = yaml.safe_load((projects_dir / "dotmusic.yaml").read_text())
    assert "stale" not in loaded
