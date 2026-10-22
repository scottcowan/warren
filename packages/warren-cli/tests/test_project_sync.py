"""`warren project sync --server` / `warren project promote` — ownership flows."""

from __future__ import annotations

from pathlib import Path

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


def _write_demo_project(projects_dir: Path) -> Path:
    path = projects_dir / "demo.yaml"
    path.write_text("name: demo\ntemplates:\n  observe: {}\n")
    return path


@respx.mock
def test_sync_server_wide_no_existing_project_pushes_directly(monkeypatch, cfg_file, projects_dir):
    monkeypatch.setattr("warren_cli.main.PROJECTS_DIR", projects_dir)
    _write_demo_project(projects_dir)

    import httpx

    respx.get("http://test.local/projects/demo").mock(return_value=httpx.Response(404))
    put_route = respx.put("http://test.local/projects/demo").mock(
        return_value=httpx.Response(204)
    )

    result = runner.invoke(
        app,
        [
            "project", "sync", "demo",
            "--server", "node2",
            "--server-wide",
            "--config", str(cfg_file),
        ],
    )

    assert result.exit_code == 0, result.output
    assert put_route.call_count == 1
    assert put_route.calls[0].request.url.params["server_wide"] == "true"


@respx.mock
def test_sync_prompts_to_use_existing_server_wide_template(monkeypatch, cfg_file, tmp_path):
    """Creation-time guard: syncing a name that already exists server-wide
    (and the caller has no override yet) must prompt instead of silently
    creating a shadowing user-scoped copy."""
    home = tmp_path / "home"
    projects_dir = home / ".warren" / "projects"
    projects_dir.mkdir(parents=True)
    monkeypatch.setattr("warren_cli.main.PROJECTS_DIR", projects_dir)
    _write_demo_project(projects_dir)

    import httpx

    respx.get("http://test.local/projects/demo").mock(
        return_value=httpx.Response(
            200,
            json={
                "name": "demo",
                "server_wide_yaml": "name: demo\ntemplates: {}\n",
                "server_wide_version": "abc123",
                "user_scoped_yaml": None,
                "effective": {"name": "demo", "templates": {}},
            },
        )
    )
    put_route = respx.put("http://test.local/projects/demo").mock(
        return_value=httpx.Response(204)
    )

    result = runner.invoke(
        app,
        ["project", "sync", "demo", "--server", "node2", "--config", str(cfg_file)],
        input="y\n",
    )

    assert "already exists" in result.output
    assert put_route.call_count == 0


@respx.mock
def test_promote_no_user_scoped_project_errors(cfg_file):
    import httpx

    respx.get("http://test.local/projects/demo").mock(
        return_value=httpx.Response(404)
    )

    result = runner.invoke(
        app,
        ["project", "promote", "demo", "--server", "node2", "--config", str(cfg_file)],
    )

    assert result.exit_code != 0
    assert "no user-scoped" in result.output.lower()


@respx.mock
def test_promote_fresh_publish_needs_no_confirmation(cfg_file):
    """No existing server-wide version to diff against — promotion is a
    straight publish, no prompt."""
    import httpx

    respx.get("http://test.local/projects/demo").mock(
        return_value=httpx.Response(
            200,
            json={
                "name": "demo",
                "server_wide_yaml": None,
                "server_wide_version": None,
                "user_scoped_yaml": "name: demo\ntemplates: {}\n",
                "effective": {"name": "demo", "templates": {}},
            },
        )
    )
    put_route = respx.put("http://test.local/projects/demo").mock(
        return_value=httpx.Response(204)
    )

    result = runner.invoke(
        app,
        ["project", "promote", "demo", "--server", "node2", "--config", str(cfg_file)],
    )

    assert result.exit_code == 0
    assert put_route.call_count == 1
    assert put_route.calls[0].request.url.params["server_wide"] == "true"
    assert "expected_version" not in put_route.calls[0].request.url.params


@respx.mock
def test_promote_shows_diff_and_requires_confirmation(cfg_file):
    import httpx

    respx.get("http://test.local/projects/demo").mock(
        return_value=httpx.Response(
            200,
            json={
                "name": "demo",
                "server_wide_yaml": "name: demo\ndescription: old\ntemplates: {}\n",
                "server_wide_version": "abc123",
                "user_scoped_yaml": "name: demo\ndescription: new\ntemplates: {}\n",
                "effective": {"name": "demo", "templates": {}},
            },
        )
    )
    put_route = respx.put("http://test.local/projects/demo").mock(
        return_value=httpx.Response(204)
    )

    result = runner.invoke(
        app,
        ["project", "promote", "demo", "--server", "node2", "--config", str(cfg_file)],
        input="y\n",
    )

    assert "Diff" in result.output
    assert put_route.call_count == 1
    assert put_route.calls[0].request.url.params["expected_version"] == "abc123"


@respx.mock
def test_promote_declined_diff_does_not_push(cfg_file):
    import httpx

    respx.get("http://test.local/projects/demo").mock(
        return_value=httpx.Response(
            200,
            json={
                "name": "demo",
                "server_wide_yaml": "name: demo\ndescription: old\ntemplates: {}\n",
                "server_wide_version": "abc123",
                "user_scoped_yaml": "name: demo\ndescription: new\ntemplates: {}\n",
                "effective": {"name": "demo", "templates": {}},
            },
        )
    )
    put_route = respx.put("http://test.local/projects/demo").mock(
        return_value=httpx.Response(204)
    )

    result = runner.invoke(
        app,
        ["project", "promote", "demo", "--server", "node2", "--config", str(cfg_file)],
        input="n\n",
    )

    assert put_route.call_count == 0
    assert "cancelled" in result.output.lower()


def _write_demo_project_with_secret_ref(projects_dir: Path) -> Path:
    path = projects_dir / "demo.yaml"
    path.write_text(
        "name: demo\n"
        "secrets:\n"
        "  - name: API_KEY\n"
        "templates:\n"
        "  observe: {}\n"
    )
    return path


def _write_local_secret(projects_dir: Path, name: str, value: str) -> None:
    secret_dir = projects_dir / "demo"
    secret_dir.mkdir(parents=True, exist_ok=True)
    (secret_dir / "secrets.env").write_text(f"{name}={value}\n")


@respx.mock
def test_sync_prompts_before_pushing_secrets_and_declines(monkeypatch, cfg_file, projects_dir):
    monkeypatch.setattr("warren_cli.main.PROJECTS_DIR", projects_dir)
    _write_demo_project_with_secret_ref(projects_dir)
    _write_local_secret(projects_dir, "API_KEY", "sk-local-value")

    import httpx

    respx.get("http://test.local/projects/demo").mock(return_value=httpx.Response(404))
    respx.put("http://test.local/projects/demo").mock(return_value=httpx.Response(204))
    secrets_route = respx.put("http://test.local/secrets").mock(return_value=httpx.Response(204))

    result = runner.invoke(
        app,
        ["project", "sync", "demo", "--server", "node2", "--server-wide", "--config", str(cfg_file)],
        input="n\n",
    )

    assert result.exit_code == 0, result.output
    assert "Push 1 local secret" in result.output
    assert secrets_route.call_count == 0


@respx.mock
def test_sync_pushes_declared_secrets_on_confirm(monkeypatch, cfg_file, projects_dir):
    monkeypatch.setattr("warren_cli.main.PROJECTS_DIR", projects_dir)
    _write_demo_project_with_secret_ref(projects_dir)
    _write_local_secret(projects_dir, "API_KEY", "sk-local-value")

    import httpx

    respx.get("http://test.local/projects/demo").mock(return_value=httpx.Response(404))
    respx.put("http://test.local/projects/demo").mock(return_value=httpx.Response(204))
    secrets_route = respx.put("http://test.local/secrets").mock(return_value=httpx.Response(204))

    result = runner.invoke(
        app,
        ["project", "sync", "demo", "--server", "node2", "--server-wide", "--config", str(cfg_file)],
        input="y\n",
    )

    assert result.exit_code == 0, result.output
    assert secrets_route.call_count == 1
    import json as _json

    body = _json.loads(secrets_route.calls[0].request.content)
    assert body == {"name": "API_KEY", "value": "sk-local-value"}


@respx.mock
def test_sync_skips_local_secrets_not_declared_by_any_template(monkeypatch, cfg_file, projects_dir):
    monkeypatch.setattr("warren_cli.main.PROJECTS_DIR", projects_dir)
    _write_demo_project(projects_dir)  # no secrets: declared at all
    _write_local_secret(projects_dir, "UNDECLARED", "value")

    import httpx

    respx.get("http://test.local/projects/demo").mock(return_value=httpx.Response(404))
    respx.put("http://test.local/projects/demo").mock(return_value=httpx.Response(204))
    secrets_route = respx.put("http://test.local/secrets").mock(return_value=httpx.Response(204))

    result = runner.invoke(
        app,
        ["project", "sync", "demo", "--server", "node2", "--server-wide", "--config", str(cfg_file)],
    )

    assert result.exit_code == 0, result.output
    assert secrets_route.call_count == 0
    assert "not declared by any template, skipped" in result.output
