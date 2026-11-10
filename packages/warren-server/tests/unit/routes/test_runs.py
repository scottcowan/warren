"""Headless run routes (routes/runs.py): starting a run, and who may read which run."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from warren.auth.models import User
from warren.registry import runs
from warren.registry.store import open_db
from warren.routes import runs as runs_routes
from warren_common.errors import ImageUnavailable

from .test_workspaces import _fake_workspace, _lifespan_patches, env_defaults  # noqa: F401
from .test_workspaces import _make_fake_registry as _base_fake_registry

NOW = datetime(2026, 11, 1, tzinfo=UTC)
USERS = {
    "alice": User(user_id="u-alice", username="alice", is_admin=False, created_at=NOW),
    "bob": User(user_id="u-bob", username="bob", is_admin=False, created_at=NOW),
    "root": User(user_id="u-root", username="root", is_admin=True, created_at=NOW),
}


# --- authz, on a minimal app with a stand-in auth middleware -------------------------


@pytest.fixture
async def authz(sqlite_path):
    db = await open_db(sqlite_path)
    store = runs.RunStore(db)
    application = FastAPI()
    application.include_router(runs_routes.router)

    @application.middleware("http")
    async def _user(request: Request, call_next):
        request.state.user = USERS.get(request.headers.get("x-user", ""))
        request.state.workspace_scope = request.headers.get("x-scope")
        return await call_next(request)

    workspaces: dict[str, SimpleNamespace] = {}
    application.state.run_store = store
    application.state.registry = SimpleNamespace(
        store=SimpleNamespace(get=AsyncMock(side_effect=lambda wid: workspaces.get(wid)))
    )
    for run_id, owner in (("run-a", "u-alice"), ("run-b", "u-bob")):
        await store.create(run_id=run_id, owner_id=owner, project="p", template="t", timeout_seconds=60)
        workspaces[run_id] = SimpleNamespace(status="running")
    await store.finish("run-a", status="succeeded", result={"schema": runs.SCHEMA, "status": "succeeded", "exit_code": 0})
    yield TestClient(application), store, workspaces
    await db.close()


def _get(client, path, user, **headers):
    return client.get(path, headers={"x-user": user, **headers})


def test_owner_reads_status_and_result(authz):
    client, _, _ = authz
    status = _get(client, "/runs/run-a", "alice")
    assert status.status_code == 200
    assert status.json()["status"] == "succeeded" and status.json()["exit_code"] == 0
    result = _get(client, "/runs/run-a/result", "alice")
    assert result.json() == {"schema": runs.SCHEMA, "status": "succeeded", "exit_code": 0}


def test_other_users_are_denied(authz):
    client, _, _ = authz
    # Another owner's run is indistinguishable from a missing one (no existence oracle).
    other = _get(client, "/runs/run-a", "bob")
    missing = _get(client, "/runs/nope", "bob")
    assert other.status_code == missing.status_code == 404
    assert other.json() == missing.json()
    assert _get(client, "/runs/run-a/result", "bob").status_code == 404
    assert _get(client, "/runs/run-a", "").status_code == 401


def test_admin_reads_every_run(authz):
    client, _, _ = authz
    assert _get(client, "/runs/run-a/result", "root").status_code == 200
    assert _get(client, "/runs/run-b", "root").json()["status"] == "running"
    assert {r["run_id"] for r in _get(client, "/runs?all=true", "root").json()} == {"run-a", "run-b"}


def test_list_is_scoped_to_the_caller(authz):
    client, _, _ = authz
    assert [r["run_id"] for r in _get(client, "/runs", "alice").json()] == ["run-a"]
    assert _get(client, "/runs", "root").json() == []
    assert _get(client, "/runs?all=true", "alice").status_code == 403


def test_workspace_scoped_tokens_are_refused(authz):
    client, _, _ = authz
    assert _get(client, "/runs/run-a", "alice", **{"x-scope": "run-a"}).status_code == 403
    assert _get(client, "/runs", "alice", **{"x-scope": "run-a"}).status_code == 403


def test_running_result_is_a_short_view(authz):
    client, _, _ = authz
    body = _get(client, "/runs/run-b/result", "bob").json()
    assert body["status"] == "running" and body["ended_at"] is None and body["timeout_seconds"] == 60


def test_a_run_whose_workspace_went_away_is_failed(authz):
    client, store, workspaces = authz
    workspaces["run-b"].status = "destroyed"
    body = _get(client, "/runs/run-b/result", "bob").json()
    assert body["status"] == "failed"
    assert "destroyed before the run completed" in body["error"]
    workspaces.pop("run-b")
    assert _get(client, "/runs/run-b", "bob").json()["status"] == "failed"


# --- POST /runs through the real app -------------------------------------------------


@pytest.fixture
def claude_project():
    from warren_common.models import ProjectConfig

    cfg = ProjectConfig.model_validate({
        "name": "demo",
        "docker_image": "ghcr.io/scottcowan/warren-base:latest",
        "templates": {"fix": {"app": "claude --dangerously-skip-permissions", "seed_prompt": "ignored"},
                      "observe": {}},
    })
    with patch("warren_common.loader.ProjectLoader.load_effective", return_value=cfg):
        yield


def _make_fake_registry():
    registry = _base_fake_registry()
    registry.store.get = AsyncMock(
        side_effect=lambda wid: _fake_workspace(status="running").model_copy(update={"workspace_id": wid})
    )
    return registry


def test_start_run_provisions_a_headless_single_turn_workspace(env_defaults, auth_headers, claude_project):  # noqa: F811
    from warren.app import app

    fake_registry = _make_fake_registry()
    with _lifespan_patches(fake_registry):
        with TestClient(app, headers=auth_headers) as client:
            app.state.registry = fake_registry
            resp = client.post("/runs", json={
                "project": "demo", "template": "fix", "prompt": "add a --verbose flag", "timeout_seconds": 600,
            })
            assert resp.status_code == 202, resp.text
            body = resp.json()
            run_id = body["run_id"]
            again = client.get(f"/runs/{run_id}")
            listed = client.get("/runs").json()

    assert body["status"] == "running" and body["timeout_seconds"] == 600
    workspace_id, spec = fake_registry._do_provision.call_args.args
    assert workspace_id == run_id
    assert spec.mode == "single-turn" and spec.seed_prompt is None
    assert "-p --output-format json 'add a --verbose flag' < /dev/null" in spec.app
    assert json.loads(fake_registry.store.insert.call_args.kwargs["spec_json"])["app"] == spec.app
    assert again.status_code == 200 and again.json()["status"] == "running"
    assert [r["run_id"] for r in listed] == [run_id]


def test_provision_failure_fails_the_run(env_defaults, auth_headers, claude_project):  # noqa: F811
    from warren.app import app

    fake_registry = _make_fake_registry()
    fake_registry._do_provision = AsyncMock(side_effect=ImageUnavailable("no such image"))
    with _lifespan_patches(fake_registry):
        with TestClient(app, headers=auth_headers) as client:
            app.state.registry = fake_registry
            resp = client.post("/runs", json={"project": "demo", "template": "fix", "prompt": "x"})
            listed = client.get("/runs").json()
            result = client.get(f"/runs/{listed[0]['run_id']}/result").json()
    assert resp.status_code == 422
    assert listed[0]["status"] == "failed"
    assert result["error"].startswith("provision failed (image_unavailable)")


def test_run_validation(env_defaults, auth_headers, claude_project, monkeypatch):  # noqa: F811
    from warren.app import app

    monkeypatch.setenv("WARREN_RUN_MAX_TIMEOUT_SECONDS", "100")
    fake_registry = _make_fake_registry()
    with _lifespan_patches(fake_registry):
        with TestClient(app, headers=auth_headers) as client:
            app.state.registry = fake_registry
            bash = client.post("/runs", json={"project": "demo", "template": "observe", "prompt": "x"})
            too_long = client.post("/runs", json={"project": "demo", "template": "fix", "prompt": "x", "timeout_seconds": 101})
            empty = client.post("/runs", json={"project": "demo", "template": "fix", "prompt": ""})
            interactive = client.post("/workspaces", json={"project": "demo", "template": "fix", "prompt": "x"})
    assert bash.status_code == 422 and bash.json()["detail"]["error"] == "single_turn_requires_app"
    assert too_long.status_code == 422 and too_long.json()["detail"]["error"] == "timeout_too_long"
    assert empty.status_code == 422
    assert interactive.status_code == 422
    fake_registry._do_provision.assert_not_called()


def test_ecs_prompt_size_limit():
    from fastapi import HTTPException
    from warren.routes.workspaces import _MAX_ECS_PROMPT_BYTES, _headless_app

    settings = SimpleNamespace(runtime_type="ecs")
    assert "claude" in _headless_app("claude", "x" * _MAX_ECS_PROMPT_BYTES, settings)
    with pytest.raises(HTTPException) as exc:
        _headless_app("claude", "x" * (_MAX_ECS_PROMPT_BYTES + 1), settings)
    assert exc.value.detail["error"] == "prompt_too_large"
    assert _headless_app("claude", "x" * (_MAX_ECS_PROMPT_BYTES + 1), SimpleNamespace(runtime_type="podman"))


@pytest.mark.parametrize("status", ["running", "destroyed"])
def test_auth_middleware_never_lets_a_workspace_token_reach_runs(status):
    from warren.auth.models import WorkspaceToken
    from warren.auth.workspace_tokens import scoped_request_allowed

    token = WorkspaceToken(
        token_id="t", workspace_id="run-a", user_id="u-alice", created_at=NOW, expires_at=NOW,
        workspace_status=status,
    )
    for method, path in (("GET", "/runs"), ("GET", "/runs/run-a"), ("GET", "/runs/run-a/result"), ("POST", "/runs")):
        assert not scoped_request_allowed(method, path, token)
