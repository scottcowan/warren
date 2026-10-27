"""Wave 0 RED tests for `warren secrets add|list|delete` (Plan 03/04 will turn GREEN)."""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest
from typer.testing import CliRunner

from warren_cli.main import app

runner = CliRunner()


@pytest.fixture
def cli_projects_dir(tmp_path: Path, monkeypatch) -> Path:
    d = tmp_path / "projects"
    d.mkdir(mode=0o700)
    (d / "proj").mkdir()
    monkeypatch.setattr("warren_cli.main.PROJECTS_DIR", d)
    return d


def test_add_no_value_flag():
    result = runner.invoke(app, ["secrets", "add", "--help"])
    assert result.exit_code == 0
    assert "--value" not in result.stdout


def test_add_prompts_and_appends(cli_projects_dir: Path):
    result = runner.invoke(
        app,
        ["secrets", "add", "GITHUB_TOKEN", "--project", "proj"],
        input="hunter2\nhunter2\n",
    )
    assert result.exit_code == 0, result.stdout
    secrets_file = cli_projects_dir / "proj" / "secrets.env"
    assert secrets_file.exists()
    if os.name != "nt":
        mode = stat.S_IMODE(secrets_file.stat().st_mode)
        assert mode == 0o600
    contents = secrets_file.read_text()
    assert "GITHUB_TOKEN=hunter2" in contents
    assert "hunter2" not in result.stdout


def test_list_shows_names_only(cli_projects_dir: Path):
    secrets_file = cli_projects_dir / "proj" / "secrets.env"
    secrets_file.write_text("FOO=bar\nBAZ=qux\n")
    secrets_file.chmod(0o600)
    result = runner.invoke(app, ["secrets", "list", "--project", "proj"])
    assert result.exit_code == 0, result.stdout
    assert "FOO" in result.stdout
    assert "BAZ" in result.stdout
    assert "bar" not in result.stdout
    assert "qux" not in result.stdout


def test_list_json(cli_projects_dir: Path):
    import json

    secrets_file = cli_projects_dir / "proj" / "secrets.env"
    secrets_file.write_text("FOO=bar\nBAZ=qux\n")
    secrets_file.chmod(0o600)
    result = runner.invoke(app, ["secrets", "list", "--project", "proj", "--json"])
    assert result.exit_code == 0, result.stdout
    names = json.loads(result.stdout)
    assert sorted(names) == ["BAZ", "FOO"]


def test_delete_removes_named_line(cli_projects_dir: Path):
    secrets_file = cli_projects_dir / "proj" / "secrets.env"
    secrets_file.write_text("FOO=bar\nBAZ=qux\nZAP=zop\n")
    secrets_file.chmod(0o600)
    result = runner.invoke(app, ["secrets", "delete", "FOO", "--project", "proj"])
    assert result.exit_code == 0, result.stdout
    contents = secrets_file.read_text()
    assert "FOO=" not in contents
    assert "BAZ=qux" in contents
    assert "ZAP=zop" in contents


def _remote_config(tmp_path: Path) -> Path:
    p = tmp_path / "config.toml"
    p.write_text('[remotes.r1]\nurl = "http://r1.local:8420"\nauth_token = "tok"\n')
    return p


def test_rotate_local_replaces_existing_value(cli_projects_dir: Path):
    secrets_file = cli_projects_dir / "proj" / "secrets.env"
    secrets_file.write_text("FOO=old\n")
    secrets_file.chmod(0o600)
    result = runner.invoke(
        app, ["secrets", "rotate", "FOO", "--project", "proj"], input="new\nnew\n"
    )
    assert result.exit_code == 0, result.output
    assert "FOO=new" in secrets_file.read_text()
    assert "new" not in result.stdout.replace("New value", "")


def test_rotate_local_unknown_secret_errors(cli_projects_dir: Path):
    result = runner.invoke(app, ["secrets", "rotate", "NOPE", "--project", "proj"])
    assert result.exit_code == 1


def test_rotate_requires_exactly_one_target():
    assert runner.invoke(app, ["secrets", "rotate", "FOO"]).exit_code == 1


def test_rotate_server_posts_new_value(tmp_path: Path):
    import json

    import httpx
    import respx

    with respx.mock(base_url="http://r1.local:8420") as m:
        route = m.post("/secrets/FOO/rotate").mock(return_value=httpx.Response(204))
        result = runner.invoke(
            app,
            ["secrets", "rotate", "FOO", "--server", "r1", "--config", str(_remote_config(tmp_path))],
            input="s3cret\ns3cret\n",
        )
    assert result.exit_code == 0, result.output
    assert json.loads(route.calls.last.request.content) == {"value": "s3cret"}

def test_rotate_server_reencrypt_only_sends_no_value(tmp_path: Path):
    import httpx
    import respx

    with respx.mock(base_url="http://r1.local:8420") as m:
        route = m.post("/secrets/FOO/rotate").mock(return_value=httpx.Response(204))
        result = runner.invoke(
            app,
            ["secrets", "rotate", "FOO", "--server", "r1", "--reencrypt-only",
             "--config", str(_remote_config(tmp_path))],
        )
    assert result.exit_code == 0, result.output
    assert route.calls.last.request.content in (b"", b"null")
    assert "re-encrypted" in result.output


def test_rotate_server_missing_secret_errors(tmp_path: Path):
    import httpx
    import respx

    with respx.mock(base_url="http://r1.local:8420") as m:
        m.post("/secrets/FOO/rotate").mock(return_value=httpx.Response(404))
        result = runner.invoke(
            app,
            ["secrets", "rotate", "FOO", "--server", "r1", "--reencrypt-only",
             "--config", str(_remote_config(tmp_path))],
        )
    assert result.exit_code == 1
