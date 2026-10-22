"""`warren project list --json` / `warren project show --json` -- UX-4: the
local, file-based `project` commands used to have no --json at all, unlike
the server-backed `warren projects`."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner


@pytest.fixture()
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture()
def projects_dir(tmp_path: Path, monkeypatch) -> Path:
    import warren_cli.main as cli_main_mod

    d = tmp_path / "projects"
    d.mkdir()
    monkeypatch.setattr(cli_main_mod, "PROJECTS_DIR", d)
    return d


def _write_project(projects_dir: Path, name: str) -> None:
    (projects_dir / f"{name}.yaml").write_text(
        f"""\
name: {name}
description: "A test project"
repo: https://example.com/{name}.git
bare_path: {projects_dir}/{name}/.git-store
templates:
  observe:
    description: Browse code
    app: zsh
"""
    )


def test_project_list_json_empty(projects_dir: Path, runner):
    from warren_cli.main import app

    result = runner.invoke(app, ["project", "list", "--json"])
    assert result.exit_code == 0, result.output
    assert json.loads(result.output) == []


def test_project_list_json(projects_dir: Path, runner):
    from warren_cli.main import app

    _write_project(projects_dir, "demo")
    result = runner.invoke(app, ["project", "list", "--json"])
    assert result.exit_code == 0, result.output
    body = json.loads(result.output)
    assert body == [{"name": "demo", "description": "A test project"}]


def test_project_show_json(projects_dir: Path, runner):
    from warren_cli.main import app

    _write_project(projects_dir, "demo")
    result = runner.invoke(app, ["project", "show", "demo", "--json"])
    assert result.exit_code == 0, result.output
    body = json.loads(result.output)
    assert body["name"] == "demo"
    assert body["description"] == "A test project"
    assert body["templates"] == [{"path": "observe", "description": "Browse code"}]
