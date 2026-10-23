"""Workspace route tests — WS-01..WS-04."""

from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from tests.conftest import TEST_BOOTSTRAP_TOKEN
from warren.app import app
from warren.registry.models import Workspace


def _fake_workspace(status: str = "provisioning", owner_id: str | None = None) -> Workspace:
    """Return a minimal valid Workspace for mock responses."""
    return Workspace(
        workspace_id="ws-test",
        project="demo",
        intent="observe",
        image="ghcr.io/scottcowan/warren-base:latest",
        root_path="",
        status=status,  # type: ignore[arg-type]
        server_instance="test-server",
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
        owner_id=owner_id,
    )


def _bootstrap_user_id(client) -> str:
    """Resolve the real bootstrap-admin user_id via the admin API (same pattern as
    test_workspace_connect.py) so ownership-gated routes can be exercised as the owner."""
    resp = client.get("/admin/users")
    return resp.json()[0]["user_id"]


def _make_fake_registry(**overrides) -> MagicMock:
    """Return a MagicMock registry with all async methods pre-configured."""
    r = MagicMock()
    r.server_id = "test-server"
    r.reconcile_from_disk = AsyncMock()
    r.provision = AsyncMock()
    r._do_provision = AsyncMock()
    r.destroy = AsyncMock()
    r.store = MagicMock()
    r.store.insert = AsyncMock()
    r.store.get = AsyncMock(return_value=_fake_workspace())
    r.store.list_all = AsyncMock(return_value=[])
    r.store.list_non_terminal = AsyncMock(return_value=[])
    for k, v in overrides.items():
        setattr(r, k, v)
    return r


@contextmanager
def _lifespan_patches(fake_registry):
    """Mock lifespan dependencies so TestClient can start without a real Podman socket."""
    with (
        patch("warren.app.WorkspaceRegistry", return_value=fake_registry),
        patch("warren.app.PodmanRuntime"),
    ):
        yield


@pytest.fixture
def env_defaults(monkeypatch, tmp_path):
    monkeypatch.setenv("WARREN_SECRET_KEY", "x" * 32)
    monkeypatch.setenv("WARREN_BOOTSTRAP_TOKEN", TEST_BOOTSTRAP_TOKEN)
    monkeypatch.setenv("WARREN_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("WARREN_PODMAN_SOCKET", str(tmp_path / "podman.sock"))
    monkeypatch.setenv("WARREN_SERVER_ID", "test-server")
    monkeypatch.setenv("WARREN_PROJECTS_DIR", str(tmp_path / "projects"))
    monkeypatch.setenv("WARREN_DRY_RUN_SKIP_PREFLIGHT", "1")
    monkeypatch.setenv("WARREN_REAPER_ENABLED", "0")
    yield
    # Clean up app.state to prevent test pollution of the module-level app singleton
    app.state._state.clear()


@pytest.fixture(autouse=True)
def _fake_project():
    """Provide a real-enough project config for every test in this module.

    Issue #9 made `_resolve_image` fail closed (404) when the project can't
    be loaded — correct behavior, but it means any test that provisions a
    workspace now needs a project that actually resolves, where previously
    the old fail-open fallback silently papered over there being no real
    project file on disk at all.
    """
    from warren_common.models import ProjectConfig

    project_cfg = ProjectConfig.model_validate(
        {
            "name": "demo",
            "docker_image": "ghcr.io/scottcowan/warren-base:latest",
            "templates": {"observe": {}},
        }
    )
    with patch("warren_common.loader.ProjectLoader.load_effective", return_value=project_cfg):
        yield


def test_provision_returns_202(env_defaults, auth_headers):
    fake_registry = _make_fake_registry()
    with _lifespan_patches(fake_registry):
        with TestClient(app, headers=auth_headers) as client:
            app.state.registry = fake_registry
            resp = client.post("/workspaces", json={"project": "demo", "template": "observe"})
    assert resp.status_code == 202


def test_provision_rejects_at_max_workspaces(env_defaults, monkeypatch, auth_headers):
    """Regression for issue #9: max_workspaces was declared in config but never
    enforced — a request at capacity must be rejected before provisioning."""
    monkeypatch.setenv("WARREN_MAX_WORKSPACES", "2")
    fake_registry = _make_fake_registry()
    fake_registry.store.list_non_terminal = AsyncMock(
        return_value=[_fake_workspace(status="running"), _fake_workspace(status="provisioning")]
    )
    with _lifespan_patches(fake_registry):
        with TestClient(app, headers=auth_headers) as client:
            app.state.registry = fake_registry
            resp = client.post("/workspaces", json={"project": "demo", "template": "observe"})
    assert resp.status_code == 503
    assert resp.json()["detail"]["error"] == "capacity_exhausted"
    fake_registry.store.insert.assert_not_called()


def test_provision_rejects_at_max_workspaces_per_user(env_defaults, monkeypatch, auth_headers):
    """Regression for issue #11: max_workspaces was a server-wide cap only — one
    owner at their per-user limit must be rejected even with server capacity free."""
    monkeypatch.setenv("WARREN_MAX_WORKSPACES_PER_USER", "1")
    fake_registry = _make_fake_registry()
    with _lifespan_patches(fake_registry):
        with TestClient(app, headers=auth_headers) as client:
            app.state.registry = fake_registry
            owner_id = _bootstrap_user_id(client)
            fake_registry.store.list_non_terminal = AsyncMock(
                return_value=[_fake_workspace(status="running", owner_id=owner_id)]
            )
            resp = client.post("/workspaces", json={"project": "demo", "template": "observe"})
    assert resp.status_code == 503
    assert resp.json()["detail"]["error"] == "capacity_exhausted"
    fake_registry.store.insert.assert_not_called()


def test_provision_allowed_when_only_other_users_near_server_cap(
    env_defaults, monkeypatch, auth_headers
):
    """Other users' non-terminal workspaces count toward the server-wide cap but
    must not count against this caller's own per-user limit."""
    monkeypatch.setenv("WARREN_MAX_WORKSPACES_PER_USER", "1")
    monkeypatch.setenv("WARREN_MAX_WORKSPACES", "10")
    fake_registry = _make_fake_registry()
    fake_registry.store.list_non_terminal = AsyncMock(
        return_value=[
            _fake_workspace(status="running", owner_id="some-other-user-id"),
            _fake_workspace(status="provisioning", owner_id="some-other-user-id"),
        ]
    )
    with _lifespan_patches(fake_registry):
        with TestClient(app, headers=auth_headers) as client:
            app.state.registry = fake_registry
            resp = client.post("/workspaces", json={"project": "demo", "template": "observe"})
    assert resp.status_code == 202


def test_provision_rejects_path_traversal_project_name(env_defaults, auth_headers):
    """Regression for issue #9: an unvalidated project name could point
    project_path outside projects_dir via "../" segments."""
    fake_registry = _make_fake_registry()
    with _lifespan_patches(fake_registry):
        with TestClient(app, headers=auth_headers) as client:
            app.state.registry = fake_registry
            resp = client.post(
                "/workspaces",
                json={"project": "../../../../etc/passwd", "template": "observe"},
            )
    assert resp.status_code == 422
    assert resp.json()["detail"]["error"] == "invalid_project_name"


def test_provision_missing_project_fails_closed_404(env_defaults, auth_headers):
    """Regression for issue #9: a missing project must reject the request
    (404), not silently fall back to the default image before intent
    enforcement ever ran."""
    from warren_common.errors import ProjectNotFoundError

    fake_registry = _make_fake_registry()
    with (
        patch(
            "warren_common.loader.ProjectLoader.load_effective",
            side_effect=ProjectNotFoundError("no such project"),
        ),
        _lifespan_patches(fake_registry),
    ):
        with TestClient(app, headers=auth_headers) as client:
            app.state.registry = fake_registry
            resp = client.post(
                "/workspaces", json={"project": "nonexistent", "template": "observe"}
            )
    assert resp.status_code == 404
    assert resp.json()["detail"]["error"] == "project_not_found"
    fake_registry.store.insert.assert_not_called()


def test_provision_missing_project_response_never_leaks_host_path(env_defaults, auth_headers):
    """Audit #46: ProjectNotFoundError's own message embeds the absolute host path it
    looked for -- that text must never reach the client, only the project name."""
    from warren_common.errors import ProjectNotFoundError

    fake_registry = _make_fake_registry()
    with (
        patch(
            "warren_common.loader.ProjectLoader.load_effective",
            side_effect=ProjectNotFoundError(
                "project file not found: /var/lib/warren/projects/nonexistent.yaml"
            ),
        ),
        _lifespan_patches(fake_registry),
    ):
        with TestClient(app, headers=auth_headers) as client:
            app.state.registry = fake_registry
            resp = client.post(
                "/workspaces", json={"project": "nonexistent", "template": "observe"}
            )
    assert resp.status_code == 404
    assert "/var/lib/warren" not in resp.text


def test_provision_invalid_project_config_response_never_leaks_exception_text(env_defaults, auth_headers):
    """Audit #46: a malformed-YAML/schema-validation failure used to echo str(exc)
    straight to the client, which can embed host paths or raw YAML content."""
    fake_registry = _make_fake_registry()
    with (
        patch(
            "warren_common.loader.ProjectLoader.load_effective",
            side_effect=ValueError("while parsing /var/lib/warren/projects/demo.yaml: bad indent"),
        ),
        _lifespan_patches(fake_registry),
    ):
        with TestClient(app, headers=auth_headers) as client:
            app.state.registry = fake_registry
            resp = client.post("/workspaces", json={"project": "demo", "template": "observe"})
    assert resp.status_code == 422
    assert resp.json()["detail"]["error"] == "project_invalid"
    assert "/var/lib/warren" not in resp.text
    assert "bad indent" not in resp.text


def test_provision_image_unavailable(env_defaults, auth_headers):
    from warren_common.errors import ImageUnavailable

    fake_registry = _make_fake_registry(
        _do_provision=AsyncMock(side_effect=ImageUnavailable("img")),
    )
    with _lifespan_patches(fake_registry):
        with TestClient(app, headers=auth_headers) as client:
            app.state.registry = fake_registry
            resp = client.post("/workspaces", json={"project": "demo", "template": "observe"})
    assert resp.status_code == 422
    assert "image_unavailable" in resp.json().get("detail", {}).get("error", "")


def test_provision_capacity_exhausted(env_defaults, auth_headers):
    from warren_common.errors import CapacityExhausted

    fake_registry = _make_fake_registry(
        _do_provision=AsyncMock(side_effect=CapacityExhausted()),
    )
    with _lifespan_patches(fake_registry):
        with TestClient(app, headers=auth_headers) as client:
            app.state.registry = fake_registry
            resp = client.post("/workspaces", json={"project": "demo", "template": "observe"})
    assert resp.status_code == 503
    assert "capacity_exhausted" in resp.json().get("detail", {}).get("error", "")


def test_list_all_workspaces(env_defaults, auth_headers):
    fake_registry = _make_fake_registry()
    fake_registry.store.list_all = AsyncMock(return_value=[])
    with _lifespan_patches(fake_registry):
        with TestClient(app, headers=auth_headers) as client:
            app.state.registry = fake_registry
            resp = client.get("/workspaces")
    assert resp.status_code == 200
    assert resp.json() == []


def test_status_route(env_defaults, auth_headers):
    fake_registry = _make_fake_registry()
    with _lifespan_patches(fake_registry):
        with TestClient(app, headers=auth_headers) as client:
            app.state.registry = fake_registry
            owner_id = _bootstrap_user_id(client)
            fake_registry.store.get = AsyncMock(
                return_value=_fake_workspace(status="running", owner_id=owner_id)
            )
            resp = client.get("/workspaces/test-id/status")
    assert resp.status_code == 200
    assert resp.json()["status"] == "running"


def test_status_route_non_owner_returns_403(env_defaults, auth_headers):
    """D-11: status is owner-only, same as connect/git-pull (regression for issue #3)."""
    fake_registry = _make_fake_registry()
    fake_registry.store.get = AsyncMock(
        return_value=_fake_workspace(status="running", owner_id="some-other-user-id")
    )
    with _lifespan_patches(fake_registry):
        with TestClient(app, headers=auth_headers) as client:
            app.state.registry = fake_registry
            resp = client.get("/workspaces/test-id/status")
    assert resp.status_code == 403


def test_delete_idempotent(env_defaults, auth_headers):
    fake_registry = _make_fake_registry()
    with _lifespan_patches(fake_registry):
        with TestClient(app, headers=auth_headers) as client:
            app.state.registry = fake_registry
            owner_id = _bootstrap_user_id(client)
            fake_registry.store.get = AsyncMock(
                return_value=_fake_workspace(owner_id=owner_id)
            )
            resp = client.delete("/workspaces/test-id")
            assert resp.status_code == 204
            resp2 = client.delete("/workspaces/test-id")
            assert resp2.status_code == 204


def test_delete_non_owner_returns_403_and_does_not_destroy(env_defaults, auth_headers):
    """D-11: delete is owner-only (regression for issue #3 — any authenticated
    user could previously destroy any workspace)."""
    fake_registry = _make_fake_registry()
    fake_registry.store.get = AsyncMock(
        return_value=_fake_workspace(owner_id="some-other-user-id")
    )
    with _lifespan_patches(fake_registry):
        with TestClient(app, headers=auth_headers) as client:
            app.state.registry = fake_registry
            resp = client.delete("/workspaces/test-id")
    assert resp.status_code == 403
    fake_registry.destroy.assert_not_called()


def test_delete_missing_workspace_still_204(env_defaults, auth_headers):
    """A workspace that doesn't exist at all remains a no-op 204 (idempotent
    delete), distinct from an existing-but-not-yours 403."""
    fake_registry = _make_fake_registry()
    fake_registry.store.get = AsyncMock(return_value=None)
    with _lifespan_patches(fake_registry):
        with TestClient(app, headers=auth_headers) as client:
            app.state.registry = fake_registry
            resp = client.delete("/workspaces/test-id")
    assert resp.status_code == 204


def test_list_workspaces_filters_to_owner(env_defaults, auth_headers):
    """D-11: list only returns the caller's own workspaces (regression for issue #3)."""
    fake_registry = _make_fake_registry()
    with _lifespan_patches(fake_registry):
        with TestClient(app, headers=auth_headers) as client:
            app.state.registry = fake_registry
            owner_id = _bootstrap_user_id(client)
            mine = _fake_workspace(owner_id=owner_id)
            mine = mine.model_copy(update={"workspace_id": "mine"})
            theirs = _fake_workspace(owner_id="some-other-user-id")
            theirs = theirs.model_copy(update={"workspace_id": "theirs"})
            fake_registry.store.list_all = AsyncMock(return_value=[mine, theirs])
            resp = client.get("/workspaces")
    assert resp.status_code == 200
    ids = [w["workspace_id"] for w in resp.json()]
    assert ids == ["mine"]


def test_provision_records_owner_id(env_defaults, auth_headers):
    """D-11: POST /workspaces stamps owner_id with the authenticated caller's user_id."""
    fake_registry = _make_fake_registry()
    with _lifespan_patches(fake_registry):
        with TestClient(app, headers=auth_headers) as client:
            app.state.registry = fake_registry
            # Resolve the bootstrap admin's real user_id via the admin API (same token).
            admin_resp = client.get("/admin/users")
            bootstrap_user_id = admin_resp.json()[0]["user_id"]

            resp = client.post("/workspaces", json={"project": "demo", "template": "observe"})
    assert resp.status_code == 202
    assert fake_registry.store.insert.call_args.kwargs["owner_id"] == bootstrap_user_id
    assert "owner_id" in resp.json()  # response model (Workspace) carries owner_id


def test_provision_ignores_client_supplied_owner_id(env_defaults, auth_headers):
    """AI1: the owner_id that becomes the ECS task's warren.owner_id tag is derived on
    the server; a body field of the same name never reaches the spec or the row."""
    fake_registry = _make_fake_registry()
    with _lifespan_patches(fake_registry):
        with TestClient(app, headers=auth_headers) as client:
            app.state.registry = fake_registry
            bootstrap_user_id = _bootstrap_user_id(client)
            resp = client.post(
                "/workspaces",
                json={"project": "demo", "template": "observe", "owner_id": "attacker"},
            )
    assert resp.status_code == 202
    _, spec = fake_registry._do_provision.call_args.args
    assert spec.owner_id == bootstrap_user_id
    assert fake_registry.store.insert.call_args.kwargs["owner_id"] == bootstrap_user_id


def test_provision_single_turn_requires_an_app(env_defaults, auth_headers):
    """AH2: a bash template never exits on its own, so single-turn is refused."""
    fake_registry = _make_fake_registry()
    with _lifespan_patches(fake_registry):
        with TestClient(app, headers=auth_headers) as client:
            app.state.registry = fake_registry
            resp = client.post(
                "/workspaces", json={"project": "demo", "template": "observe", "mode": "single-turn"}
            )
    assert resp.status_code == 422
    assert resp.json()["detail"]["error"] == "single_turn_requires_app"
    fake_registry._do_provision.assert_not_called()


def test_provision_single_turn_mode_reaches_spec_and_spec_json(env_defaults, auth_headers):
    import json

    from warren_common.models import ProjectConfig

    cfg = ProjectConfig.model_validate(
        {
            "name": "demo",
            "docker_image": "ghcr.io/scottcowan/warren-base:latest",
            "templates": {"agent": {"app": "claude -p 'fix the bug'"}},
        }
    )
    fake_registry = _make_fake_registry()
    with patch("warren_common.loader.ProjectLoader.load_effective", return_value=cfg):
        with _lifespan_patches(fake_registry):
            with TestClient(app, headers=auth_headers) as client:
                app.state.registry = fake_registry
                resp = client.post(
                    "/workspaces", json={"project": "demo", "template": "agent", "mode": "single-turn"}
                )
                bad = client.post(
                    "/workspaces", json={"project": "demo", "template": "agent", "mode": "forever"}
                )
    assert resp.status_code == 202
    _, spec = fake_registry._do_provision.call_args.args
    assert spec.mode == "single-turn"
    assert json.loads(fake_registry.store.insert.call_args.kwargs["spec_json"])["mode"] == "single-turn"
    assert bad.status_code == 422


def test_provision_agent_workspace_carries_its_launch_spec(env_defaults, auth_headers):
    """AG2b/AM3: kind: agent persists the supervisor launch spec; the list view shows
    the ACP port `warren tunnel` defaults to; single-turn stays an `app` feature."""
    import json

    from warren_common.models import ProjectConfig

    from warren.registry.models import WorkspaceView

    cfg = ProjectConfig.model_validate({
        "name": "demo",
        "templates": {"bot": {"kind": "agent", "harness": "opencode", "agent": {"port": 9100}}},
    })
    fake_registry = _make_fake_registry()
    with patch("warren_common.loader.ProjectLoader.load_effective", return_value=cfg):
        with _lifespan_patches(fake_registry):
            with TestClient(app, headers=auth_headers) as client:
                app.state.registry = fake_registry
                resp = client.post("/workspaces", json={"project": "demo", "template": "bot"})
                single = client.post(
                    "/workspaces", json={"project": "demo", "template": "bot", "mode": "single-turn"}
                )
    assert resp.status_code == 202
    _, spec = fake_registry._do_provision.call_args.args
    assert spec.agent["harness"] == "opencode" and spec.agent["port"] == 9100
    assert "opencode" in spec.harnesses
    spec_json = fake_registry.store.insert.call_args.kwargs["spec_json"]
    assert json.loads(spec_json)["agent"] == spec.agent
    from datetime import datetime, timezone
    from types import SimpleNamespace

    now = datetime.now(timezone.utc)
    ws = SimpleNamespace(
        workspace_id="w", project="demo", intent="bot", image="i", container_id=None, status="running",
        server_instance="s", created_at=now, updated_at=now, ssh_port=None, owner_id="u",
        idle_ttl_seconds=None, spec_json=spec_json,
    )
    view = WorkspaceView.from_workspace(ws)
    assert (view.agent_harness, view.acp_port) == ("opencode", 9100)
    assert single.status_code == 422
    assert single.json()["detail"]["error"] == "single_turn_not_for_agents"


def test_provision_without_token_returns_401(env_defaults):
    fake_registry = _make_fake_registry()
    with _lifespan_patches(fake_registry):
        with TestClient(app) as client:
            app.state.registry = fake_registry
            resp = client.post("/workspaces", json={"project": "demo", "template": "observe"})
    assert resp.status_code == 401


def test_provision_threads_template_app_into_spec(env_defaults, auth_headers):
    """The resolved template's `app` field must reach WorkspaceSpec.app -- it was
    never threaded through at all, so every workspace silently ran the
    WorkspaceSpec default (bash) regardless of what the template declared."""
    from warren_common.models import ProjectConfig

    project_cfg = ProjectConfig.model_validate(
        {
            "name": "demo",
            "docker_image": "ghcr.io/scottcowan/warren-base:latest",
            "templates": {"observe": {"app": "claude"}},
        }
    )

    fake_registry = _make_fake_registry()
    with _lifespan_patches(fake_registry):
        with patch("warren_common.loader.ProjectLoader.load_effective", return_value=project_cfg):
            with TestClient(app, headers=auth_headers) as client:
                app.state.registry = fake_registry
                resp = client.post("/workspaces", json={"project": "demo", "template": "observe"})
                assert resp.status_code == 202

    _, spec = fake_registry._do_provision.call_args.args
    assert spec.app == "claude"


def test_provision_threads_template_idle_ttl_seconds_into_spec_and_row(env_defaults, auth_headers):
    """ProjectConfig.idle_ttl_seconds must reach both WorkspaceSpec.idle_ttl_seconds
    (for parity with app/efs_retention_days) and the stored row via store.insert
    (what the idle reaper actually reads per-workspace) -- an unattended ops
    workspace needs a longer grace period than the operator's global TTL."""
    from warren_common.models import ProjectConfig

    project_cfg = ProjectConfig.model_validate(
        {
            "name": "demo",
            "docker_image": "ghcr.io/scottcowan/warren-base:latest",
            "templates": {"observe": {"idle_ttl_seconds": 1800.0}},
        }
    )

    fake_registry = _make_fake_registry()
    with _lifespan_patches(fake_registry):
        with patch("warren_common.loader.ProjectLoader.load_effective", return_value=project_cfg):
            with TestClient(app, headers=auth_headers) as client:
                app.state.registry = fake_registry
                resp = client.post("/workspaces", json={"project": "demo", "template": "observe"})
                assert resp.status_code == 202

    _, spec = fake_registry._do_provision.call_args.args
    assert spec.idle_ttl_seconds == 1800.0
    assert fake_registry.store.insert.call_args.kwargs["idle_ttl_seconds"] == 1800.0


def test_provision_without_template_idle_ttl_seconds_defaults_to_none(env_defaults, auth_headers):
    fake_registry = _make_fake_registry()
    with _lifespan_patches(fake_registry):
        with TestClient(app, headers=auth_headers) as client:
            app.state.registry = fake_registry
            resp = client.post("/workspaces", json={"project": "demo", "template": "observe"})
            assert resp.status_code == 202

    _, spec = fake_registry._do_provision.call_args.args
    assert spec.idle_ttl_seconds is None
    assert fake_registry.store.insert.call_args.kwargs["idle_ttl_seconds"] is None


def test_provision_threads_template_ecs_cpu_memory_and_docker_networks_into_spec(
    env_defaults, monkeypatch, auth_headers
):
    """Issue #23: ecs_cpu/ecs_memory/docker_networks from the resolved template
    were silently dropped -- every workspace got whatever default ecs_cpu/
    ecs_memory is on `settings` (runtime/ecs.py's own fallback) and no
    docker_networks attachment, regardless of what the template declared.

    R24 added an allow-list gate on docker_networks (see
    test_provision_* allow-list tests below) -- `my-net` must be on
    WARREN_ALLOWED_DOCKER_NETWORKS here for it to still survive into the spec;
    this test is about the threading, not the allow-list itself.
    """
    monkeypatch.setenv("WARREN_ALLOWED_DOCKER_NETWORKS", "my-net")
    from warren_common.models import ProjectConfig

    project_cfg = ProjectConfig.model_validate(
        {
            "name": "demo",
            "docker_image": "ghcr.io/scottcowan/warren-base:latest",
            "templates": {
                "observe": {
                    "ecs_cpu": "1024",
                    "ecs_memory": "2048",
                    "docker_networks": ["my-net"],
                }
            },
        }
    )

    fake_registry = _make_fake_registry()
    with _lifespan_patches(fake_registry):
        with patch("warren_common.loader.ProjectLoader.load_effective", return_value=project_cfg):
            with TestClient(app, headers=auth_headers) as client:
                app.state.registry = fake_registry
                resp = client.post("/workspaces", json={"project": "demo", "template": "observe"})
                assert resp.status_code == 202

    _, spec = fake_registry._do_provision.call_args.args
    assert spec.ecs_cpu == "1024"
    assert spec.ecs_memory == "2048"
    assert spec.docker_networks == ["my-net"]


def test_provision_drops_docker_network_not_in_allow_list_or_server_wide_file(
    env_defaults, auth_headers
):
    """R24: a user-scoped project's docker_networks entry naming a network not
    declared in the server-wide project file and not in
    WARREN_ALLOWED_DOCKER_NETWORKS must be dropped, not attached -- without this,
    any authenticated non-admin user (no admin check on the project-write path,
    routes/projects.py) could attach a workspace to ANY host podman/docker
    network, including ones giving access to other workspaces' traffic."""
    from warren_common.models import ProjectConfig

    project_cfg = ProjectConfig.model_validate(
        {
            "name": "demo",
            "docker_image": "ghcr.io/scottcowan/warren-base:latest",
            "templates": {"observe": {"docker_networks": ["host-internal-net"]}},
        }
    )

    fake_registry = _make_fake_registry()
    with _lifespan_patches(fake_registry):
        with patch("warren_common.loader.ProjectLoader.load_effective", return_value=project_cfg):
            with TestClient(app, headers=auth_headers) as client:
                app.state.registry = fake_registry
                resp = client.post("/workspaces", json={"project": "demo", "template": "observe"})
                assert resp.status_code == 202

    _, spec = fake_registry._do_provision.call_args.args
    assert spec.docker_networks == []


def test_provision_allows_docker_network_declared_in_server_wide_project_file(
    env_defaults, auth_headers, tmp_path
):
    """R24: a network declared in the server-wide (admin-managed) project file is
    unrestricted, same trust tier as the existing local-path exception -- no
    allow-list entry needed."""
    projects_dir = tmp_path / "projects"
    projects_dir.mkdir(parents=True, exist_ok=True)
    (projects_dir / "demo.yaml").write_text(
        """\
name: demo
docker_image: ghcr.io/scottcowan/warren-base:latest
templates:
  observe:
    docker_networks:
      - admin-net
"""
    )

    from warren_common.models import ProjectConfig

    project_cfg = ProjectConfig.model_validate(
        {
            "name": "demo",
            "docker_image": "ghcr.io/scottcowan/warren-base:latest",
            "templates": {"observe": {"docker_networks": ["admin-net"]}},
        }
    )

    fake_registry = _make_fake_registry()
    with _lifespan_patches(fake_registry):
        with patch("warren_common.loader.ProjectLoader.load_effective", return_value=project_cfg):
            with TestClient(app, headers=auth_headers) as client:
                app.state.registry = fake_registry
                resp = client.post("/workspaces", json={"project": "demo", "template": "observe"})
                assert resp.status_code == 202

    _, spec = fake_registry._do_provision.call_args.args
    assert spec.docker_networks == ["admin-net"]


def _provision_template(auth_headers, template: dict):
    from warren_common.models import ProjectConfig

    project_cfg = ProjectConfig.model_validate({"name": "demo", "templates": {"observe": template}})
    fake_registry = _make_fake_registry()
    with _lifespan_patches(fake_registry):
        with patch("warren_common.loader.ProjectLoader.load_effective", return_value=project_cfg):
            with TestClient(app, headers=auth_headers) as client:
                app.state.registry = fake_registry
                resp = client.post("/workspaces", json={"project": "demo", "template": "observe"})
    return resp, fake_registry


def test_provision_threads_selected_harnesses_into_spec(env_defaults, auth_headers):
    resp, fake_registry = _provision_template(auth_headers, {"app": "claude", "harnesses": ["codex"]})
    assert resp.status_code == 202
    _, spec = fake_registry._do_provision.call_args.args
    assert spec.harnesses == ["claude", "codex"]


@pytest.mark.parametrize(
    "template",
    [{"allow_vendor_cloud": False, "harnesses": ["cursor-agent"]}, {"harnesses": ["custom"]}],
)
def test_provision_rejects_invalid_harness_selection(env_defaults, auth_headers, template):
    resp, fake_registry = _provision_template(auth_headers, template)
    assert resp.status_code == 422
    assert resp.json()["detail"]["error"] == "invalid_template"
    fake_registry._do_provision.assert_not_called()


@pytest.mark.parametrize(
    "template",
    [{"app": "claude", "model_access": "bedrock"}, {"app": "claude", "env": {"CLAUDE_CODE_USE_BEDROCK": "1"}}],
)
def test_provision_bedrock_mode_threads_into_spec(env_defaults, auth_headers, template):
    resp, fake_registry = _provision_template(auth_headers, template)
    assert resp.status_code == 202
    _, spec = fake_registry._do_provision.call_args.args
    assert spec.model_access == "bedrock"
    assert spec.template_env["CLAUDE_CODE_USE_BEDROCK"] == "1"


def test_provision_bedrock_rejects_claude_oauth_token_secret(env_defaults, auth_headers):
    resp, fake_registry = _provision_template(
        auth_headers, {"app": "claude", "model_access": "bedrock", "secrets": [{"name": "CLAUDE_CODE_OAUTH_TOKEN"}]}
    )
    assert resp.status_code == 422
    fake_registry._do_provision.assert_not_called()


def test_provision_drops_image_not_sanctioned_falls_back_to_default(env_defaults, auth_headers):
    """Z12: a user-scoped template's docker_image naming an arbitrary registry
    image -- not the model's own default, not declared in any server-wide
    file, not on WARREN_ALLOWED_IMAGES -- must fall back to the default, same
    class as R24 (docker_networks). Without this, any authenticated
    non-admin user (no admin check on the project-write path,
    routes/projects.py) could point workspaces at any image they control."""
    from warren_common.models import ProjectConfig

    project_cfg = ProjectConfig.model_validate(
        {
            "name": "demo",
            "templates": {"observe": {"docker_image": "attacker.example.com/evil:latest"}},
        }
    )

    fake_registry = _make_fake_registry()
    with _lifespan_patches(fake_registry):
        with patch("warren_common.loader.ProjectLoader.load_effective", return_value=project_cfg):
            with TestClient(app, headers=auth_headers) as client:
                app.state.registry = fake_registry
                resp = client.post("/workspaces", json={"project": "demo", "template": "observe"})
                assert resp.status_code == 202

    _, spec = fake_registry._do_provision.call_args.args
    assert spec.image == ProjectConfig.model_fields["docker_image"].default


def test_provision_allows_image_declared_in_server_wide_project_file(
    env_defaults, auth_headers, tmp_path
):
    """Z12: an image declared in the server-wide (admin-managed) project file
    is unrestricted, same trust tier as the local-path/docker_networks
    exceptions -- no allow-list entry needed."""
    projects_dir = tmp_path / "projects"
    projects_dir.mkdir(parents=True, exist_ok=True)
    (projects_dir / "demo.yaml").write_text(
        """\
name: demo
templates:
  observe:
    docker_image: registry.example.com/admin-approved:latest
"""
    )

    from warren_common.models import ProjectConfig

    project_cfg = ProjectConfig.model_validate(
        {
            "name": "demo",
            "templates": {
                "observe": {"docker_image": "registry.example.com/admin-approved:latest"}
            },
        }
    )

    fake_registry = _make_fake_registry()
    with _lifespan_patches(fake_registry):
        with patch("warren_common.loader.ProjectLoader.load_effective", return_value=project_cfg):
            with TestClient(app, headers=auth_headers) as client:
                app.state.registry = fake_registry
                resp = client.post("/workspaces", json={"project": "demo", "template": "observe"})
                assert resp.status_code == 202

    _, spec = fake_registry._do_provision.call_args.args
    assert spec.image == "registry.example.com/admin-approved:latest"


def test_provision_allows_image_on_allowed_images_setting(
    env_defaults, monkeypatch, auth_headers
):
    """Z12: WARREN_ALLOWED_IMAGES is a deployment-wide escape hatch, same shape
    as WARREN_ALLOWED_DOCKER_NETWORKS -- no server-wide file needed when the
    operator has explicitly allow-listed the image."""
    monkeypatch.setenv("WARREN_ALLOWED_IMAGES", "registry.example.com/also-fine:latest")
    from warren_common.models import ProjectConfig

    project_cfg = ProjectConfig.model_validate(
        {
            "name": "demo",
            "templates": {"observe": {"docker_image": "registry.example.com/also-fine:latest"}},
        }
    )

    fake_registry = _make_fake_registry()
    with _lifespan_patches(fake_registry):
        with patch("warren_common.loader.ProjectLoader.load_effective", return_value=project_cfg):
            with TestClient(app, headers=auth_headers) as client:
                app.state.registry = fake_registry
                resp = client.post("/workspaces", json={"project": "demo", "template": "observe"})
                assert resp.status_code == 202

    _, spec = fake_registry._do_provision.call_args.args
    assert spec.image == "registry.example.com/also-fine:latest"


def test_provision_with_no_template_resolved_has_empty_docker_networks(env_defaults, auth_headers):
    """R24: the allow-list/server-wide check must not blow up when there's no
    resolved template config at all (template_cfg is None, e.g. no project file
    on disk at all) -- docker_networks stays the pre-existing empty-list default,
    and provisioning doesn't 500."""
    fake_registry = _make_fake_registry()
    with _lifespan_patches(fake_registry):
        with TestClient(app, headers=auth_headers) as client:
            app.state.registry = fake_registry
            resp = client.post("/workspaces", json={"project": "demo", "template": "observe"})
    assert resp.status_code == 202
    _, spec = fake_registry._do_provision.call_args.args
    assert spec.docker_networks == []


def test_provision_without_template_ecs_overrides_leaves_spec_fields_none(
    env_defaults, auth_headers
):
    fake_registry = _make_fake_registry()
    with _lifespan_patches(fake_registry):
        with TestClient(app, headers=auth_headers) as client:
            app.state.registry = fake_registry
            resp = client.post("/workspaces", json={"project": "demo", "template": "observe"})
            assert resp.status_code == 202

    _, spec = fake_registry._do_provision.call_args.args
    assert spec.ecs_cpu is None
    assert spec.ecs_memory is None
    assert spec.docker_networks == []


def test_provision_threads_template_ssh_aws_scope_into_spec(env_defaults, auth_headers, monkeypatch):
    """Audit R11: ssh/aws/scope from the resolved template were silently
    dropped on the floor here too -- never threaded onto WorkspaceSpec at
    all, so a template declaring e.g. an `ssh.keys` block provisioned a
    workspace with no sign any of these fields were ever resolved."""
    from warren_common.models import ProjectConfig

    monkeypatch.setenv("SSH_AUTH_SOCK", "/tmp/fake-agent.sock")

    project_cfg = ProjectConfig.model_validate(
        {
            "name": "demo",
            "docker_image": "ghcr.io/scottcowan/warren-base:latest",
            "templates": {
                "observe": {
                    "ssh": {"keys": ["/home/op/.ssh/id_deploy"], "agent": True},
                    "aws": {"profile": "prod"},
                    "scope": {"paths": ["/workspace"]},
                }
            },
        }
    )

    fake_registry = _make_fake_registry()
    with _lifespan_patches(fake_registry):
        with patch("warren_common.loader.ProjectLoader.load_effective", return_value=project_cfg):
            with TestClient(app, headers=auth_headers) as client:
                app.state.registry = fake_registry
                resp = client.post("/workspaces", json={"project": "demo", "template": "observe"})
                assert resp.status_code == 202

    _, spec = fake_registry._do_provision.call_args.args
    assert spec.ssh_key_paths == ["/home/op/.ssh/id_deploy"]
    assert spec.ssh_agent_sock == "/tmp/fake-agent.sock"
    assert spec.aws is not None
    assert spec.aws.profile == "prod"
    assert spec.scope is not None
    assert spec.scope.paths == ["/workspace"]


def test_provision_without_template_ssh_block_sets_no_agent_sock(env_defaults, auth_headers, monkeypatch):
    """A template with no `ssh` block (or ssh.agent=False) must never forward
    SSH_AUTH_SOCK into the workspace -- opt-in only, not ambient."""
    monkeypatch.setenv("SSH_AUTH_SOCK", "/tmp/fake-agent.sock")

    fake_registry = _make_fake_registry()
    with _lifespan_patches(fake_registry):
        with TestClient(app, headers=auth_headers) as client:
            app.state.registry = fake_registry
            resp = client.post("/workspaces", json={"project": "demo", "template": "observe"})
            assert resp.status_code == 202

    _, spec = fake_registry._do_provision.call_args.args
    assert spec.ssh_key_paths == []
    assert spec.ssh_agent_sock is None
    assert spec.aws is None
    assert spec.scope is None


def test_provision_strips_local_path_folder_not_in_server_wide_file(env_defaults, auth_headers):
    """Audit Y1/V2: a `local-path` folder in the (merged) effective config
    that isn't backed by anything in the actual on-disk server-wide project
    file must be stripped at provision time -- the write-time 422 in
    routes/projects.py alone doesn't cover a user-scoped file that already
    held one before that check existed, or that reached disk some other
    way. No server-wide file exists at all in this test, so nothing can be
    sanctioned."""
    from warren_common.models import ProjectConfig

    project_cfg = ProjectConfig.model_validate(
        {
            "name": "demo",
            "docker_image": "ghcr.io/scottcowan/warren-base:latest",
            "templates": {
                "observe": {
                    "folders": [
                        {"name": "wiki", "type": "local-path", "mount": "wiki", "path": "/etc"},
                    ],
                }
            },
        }
    )

    fake_registry = _make_fake_registry()
    with _lifespan_patches(fake_registry):
        with patch("warren_common.loader.ProjectLoader.load_effective", return_value=project_cfg):
            with TestClient(app, headers=auth_headers) as client:
                app.state.registry = fake_registry
                resp = client.post("/workspaces", json={"project": "demo", "template": "observe"})
                assert resp.status_code == 202

    _, spec = fake_registry._do_provision.call_args.args
    assert spec.folders == []


def test_provision_keeps_local_path_folder_declared_in_server_wide_file(env_defaults, auth_headers, tmp_path):
    """The companion case: a `local-path` folder that IS present in the
    real on-disk server-wide file is still honored -- the re-validation
    must not break the legitimate admin-sanctioned path."""
    projects_dir = tmp_path / "projects"
    projects_dir.mkdir(parents=True, exist_ok=True)
    (projects_dir / "demo.yaml").write_text(
        """\
name: demo
docker_image: ghcr.io/scottcowan/warren-base:latest
templates:
  observe:
    folders:
      - name: wiki
        type: local-path
        mount: wiki
        path: /etc
"""
    )

    from warren_common.models import ProjectConfig

    project_cfg = ProjectConfig.model_validate(
        {
            "name": "demo",
            "docker_image": "ghcr.io/scottcowan/warren-base:latest",
            "templates": {
                "observe": {
                    "folders": [
                        {"name": "wiki", "type": "local-path", "mount": "wiki", "path": "/etc"},
                    ],
                }
            },
        }
    )

    fake_registry = _make_fake_registry()
    with _lifespan_patches(fake_registry):
        with patch("warren_common.loader.ProjectLoader.load_effective", return_value=project_cfg):
            with TestClient(app, headers=auth_headers) as client:
                app.state.registry = fake_registry
                resp = client.post("/workspaces", json={"project": "demo", "template": "observe"})
                assert resp.status_code == 202

    _, spec = fake_registry._do_provision.call_args.args
    assert len(spec.folders) == 1
    assert spec.folders[0].name == "wiki"


def test_provision_injects_owners_local_secrets_into_spec_env(env_defaults, auth_headers):
    """warren.secrets: a secret the caller previously PUT, named in the resolved
    template's `secrets` allow-list, gets decrypted and merged into
    WorkspaceSpec.env — podman/docker path only (runtime_type defaults to
    "podman" in these tests)."""
    from warren_common.models import ProjectConfig

    project_cfg = ProjectConfig.model_validate(
        {
            "name": "demo",
            "docker_image": "ghcr.io/scottcowan/warren-base:latest",
            "templates": {"observe": {"secrets": [{"name": "API_KEY"}]}},
        }
    )

    fake_registry = _make_fake_registry()
    with _lifespan_patches(fake_registry):
        with patch("warren_common.loader.ProjectLoader.load_effective", return_value=project_cfg):
            with TestClient(app, headers=auth_headers) as client:
                app.state.registry = fake_registry

                put_resp = client.put("/secrets", json={"name": "API_KEY", "value": "sk-abc"})
                assert put_resp.status_code == 204

                resp = client.post("/workspaces", json={"project": "demo", "template": "observe"})
                assert resp.status_code == 202

    fake_registry._do_provision.assert_called_once()
    _, spec = fake_registry._do_provision.call_args.args
    assert spec.env == {"API_KEY": "sk-abc"}
    assert spec.secret_names == ["API_KEY"]


def test_provision_does_not_leak_another_users_secrets(env_defaults, auth_headers):
    """Our caller's template declares API_KEY by name, same as mallory's secret
    name -- but mallory's value must never appear, since resolution is scoped
    to the caller's own owner_id regardless of what name is declared."""
    from warren_common.models import ProjectConfig

    project_cfg = ProjectConfig.model_validate(
        {
            "name": "demo",
            "docker_image": "ghcr.io/scottcowan/warren-base:latest",
            "templates": {"observe": {"secrets": [{"name": "API_KEY"}]}},
        }
    )

    fake_registry = _make_fake_registry()
    with _lifespan_patches(fake_registry):
        with patch("warren_common.loader.ProjectLoader.load_effective", return_value=project_cfg):
            with TestClient(app, headers=auth_headers) as client:
                app.state.registry = fake_registry

                other_token_resp = client.post("/admin/users", json={"username": "mallory", "is_admin": False})
                other_headers = {"Authorization": f"Bearer {other_token_resp.json()['token']['token']}"}
                client.put(
                    "/secrets",
                    json={"name": "API_KEY", "value": "mallorys-secret"},
                    headers=other_headers,
                )

                resp = client.post("/workspaces", json={"project": "demo", "template": "observe"})
                assert resp.status_code == 202

    _, spec = fake_registry._do_provision.call_args.args
    assert spec.env == {}


def test_provision_on_ecs_without_aws_identity_header_401s(env_defaults, monkeypatch, auth_headers):
    """ECS deployments resolve secret ownership from the caller's verified AWS
    identity (warren.auth.deps.resolve_owner_id) -- provisioning must fail
    closed without it, the same as a direct PUT /secrets call."""
    monkeypatch.setenv("WARREN_RUNTIME_TYPE", "ecs")
    fake_registry = _make_fake_registry()
    fake_runtime = MagicMock()

    with (
        patch("warren.app.WorkspaceRegistry", return_value=fake_registry),
        patch("warren.runtime.ecs.ECSRuntime", return_value=fake_runtime),
    ):
        with TestClient(app, headers=auth_headers) as client:
            resp = client.post("/workspaces", json={"project": "demo", "template": "observe"})
    assert resp.status_code == 401
    assert resp.json()["detail"]["error"] == "aws_identity_required"


def test_provision_on_ecs_uses_aws_identity_as_spec_owner_id(env_defaults, monkeypatch, auth_headers):
    monkeypatch.setenv("WARREN_RUNTIME_TYPE", "ecs")
    fake_registry = _make_fake_registry()
    fake_runtime = MagicMock()
    aws_headers = {"X-AWS-STS-Signed-Request": '{"url": "https://sts.amazonaws.com/"}'}
    derived_owner_id = "deadbeef" * 4  # SSM-safe hex, as derive_owner_id would return

    with (
        patch("warren.app.WorkspaceRegistry", return_value=fake_registry),
        patch("warren.runtime.ecs.ECSRuntime", return_value=fake_runtime),
        patch(
            "warren.auth.aws_identity.verify_signed_caller_identity",
            AsyncMock(return_value=derived_owner_id),
        ),
    ):
        with TestClient(app, headers={**auth_headers, **aws_headers}) as client:
            app.state.registry = fake_registry
            resp = client.post("/workspaces", json={"project": "demo", "template": "observe"})
    assert resp.status_code == 202

    _, spec = fake_registry._do_provision.call_args.args
    assert spec.owner_id == derived_owner_id
    # ECS never goes through the local Fernet store -- no decrypted values pass
    # through this process for that runtime.
    assert spec.env == {}


def test_provision_rate_limited_after_threshold(env_defaults, auth_headers):
    """Audit #46: nothing throttled repeated POST /workspaces -- a per-user sliding
    window must reject requests past the threshold with 429."""
    from warren.routes.workspaces import _CREATE_WORKSPACE_MAX, _create_workspace_limiter

    fake_registry = _make_fake_registry()
    with _lifespan_patches(fake_registry):
        with TestClient(app, headers=auth_headers) as client:
            app.state.registry = fake_registry
            user_id = _bootstrap_user_id(client)
            _create_workspace_limiter._events.pop(user_id, None)  # isolate from other tests

            for _ in range(_CREATE_WORKSPACE_MAX):
                resp = client.post("/workspaces", json={"project": "demo", "template": "observe"})
                assert resp.status_code == 202

            resp = client.post("/workspaces", json={"project": "demo", "template": "observe"})
            assert resp.status_code == 429
            assert resp.json()["detail"]["error"] == "rate_limited"


def test_provision_rejects_aws_sso_mode(env_defaults, auth_headers):
    """AK3: server runtimes never get the host SSO token cache."""
    from warren_common.models import ProjectConfig

    project_cfg = ProjectConfig.model_validate(
        {
            "name": "demo",
            "docker_image": "ghcr.io/scottcowan/warren-base:latest",
            "templates": {"observe": {"aws": {"mode": "sso", "profile": "prod"}}},
        }
    )
    fake_registry = _make_fake_registry()
    with _lifespan_patches(fake_registry):
        with patch("warren_common.loader.ProjectLoader.load_effective", return_value=project_cfg):
            with TestClient(app, headers=auth_headers) as client:
                app.state.registry = fake_registry
                resp = client.post("/workspaces", json={"project": "demo", "template": "observe"})
    assert resp.status_code == 422
    assert "only allowed for local runtimes" in resp.json()["detail"]["detail"]
    fake_registry._do_provision.assert_not_called()


def test_provision_refuses_git_crypt_key_as_workspace_secret(env_defaults, auth_headers):
    """AK2: the git-crypt key goes only to materialization, never into the workspace."""
    from warren_common.models import ProjectConfig

    project_cfg = ProjectConfig.model_validate(
        {
            "name": "demo",
            "docker_image": "ghcr.io/scottcowan/warren-base:latest",
            "templates": {"observe": {"secrets": [{"name": "GIT_CRYPT_KEY"}]}},
        }
    )
    fake_registry = _make_fake_registry()
    with _lifespan_patches(fake_registry):
        with patch("warren_common.loader.ProjectLoader.load_effective", return_value=project_cfg):
            with TestClient(app, headers=auth_headers) as client:
                app.state.registry = fake_registry
                resp = client.post("/workspaces", json={"project": "demo", "template": "observe"})
    assert resp.status_code == 422
    assert resp.json()["detail"]["error"] == "template_denied"
    fake_registry._do_provision.assert_not_called()


def test_provision_threads_template_env_into_spec_and_spec_json(env_defaults, auth_headers):
    import json

    from warren_common.models import ProjectConfig

    project_cfg = ProjectConfig.model_validate(
        {
            "name": "demo",
            "docker_image": "ghcr.io/scottcowan/warren-base:latest",
            "env": {"LOG_LEVEL": "info"},
            "templates": {"observe": {"env": {"OLLAMA_HOST": "http://gpu:11434"}}},
        }
    )

    fake_registry = _make_fake_registry()
    with _lifespan_patches(fake_registry):
        with patch("warren_common.loader.ProjectLoader.load_effective", return_value=project_cfg):
            with TestClient(app, headers=auth_headers) as client:
                app.state.registry = fake_registry
                resp = client.post("/workspaces", json={"project": "demo", "template": "observe"})
                assert resp.status_code == 202

    _, spec = fake_registry._do_provision.call_args.args
    expected = {"LOG_LEVEL": "info", "OLLAMA_HOST": "http://gpu:11434"}
    assert spec.template_env == expected
    persisted = json.loads(fake_registry.store.insert.call_args.kwargs["spec_json"])
    assert persisted["template_env"] == expected


def test_provision_persists_template_idle_destroy_seconds(env_defaults, auth_headers):
    import json

    from warren_common.models import ProjectConfig

    project_cfg = ProjectConfig.model_validate(
        {"name": "demo", "templates": {"observe": {"idle_destroy_seconds": 86400.0}}}
    )
    fake_registry = _make_fake_registry()
    with _lifespan_patches(fake_registry):
        with patch("warren_common.loader.ProjectLoader.load_effective", return_value=project_cfg):
            with TestClient(app, headers=auth_headers) as client:
                app.state.registry = fake_registry
                resp = client.post("/workspaces", json={"project": "demo", "template": "observe"})
                assert resp.status_code == 202

    _, spec = fake_registry._do_provision.call_args.args
    assert spec.idle_destroy_seconds == 86400.0
    persisted = json.loads(fake_registry.store.insert.call_args.kwargs["spec_json"])
    assert persisted["idle_destroy_seconds"] == 86400.0


_SENSITIVE_SPEC_JSON = (
    '{"app": "claude", "secret_names": ["ANTHROPIC_API_KEY"], '
    '"folders": [{"name": "wiki", "type": "local-path", "mount": "refs/wiki", "path": "/srv/private/wiki"}], '
    '"template_env": {"INTERNAL_URL": "http://10.0.0.5"}, "ssh_key_paths": ["/home/op/.ssh/id_ed25519"]}'
)


def _assert_no_spec_leak(body: dict) -> None:
    import json

    text = json.dumps(body)
    for leaked in ("ANTHROPIC_API_KEY", "/srv/private/wiki", "refs/wiki", "10.0.0.5", "id_ed25519", "/w/root"):
        assert leaked not in text
    assert body["app"] == "claude"
    assert json.loads(body["spec_json"]) == {"app": "claude"}


def test_list_workspaces_returns_only_app_from_spec_json(env_defaults, auth_headers):
    fake_registry = _make_fake_registry()
    with _lifespan_patches(fake_registry):
        with TestClient(app, headers=auth_headers) as client:
            app.state.registry = fake_registry
            mine = _fake_workspace(owner_id=_bootstrap_user_id(client)).model_copy(
                update={"spec_json": _SENSITIVE_SPEC_JSON, "root_path": "/w/root"}
            )
            fake_registry.store.list_all = AsyncMock(return_value=[mine])
            resp = client.get("/workspaces")
    assert resp.status_code == 200
    [body] = resp.json()
    _assert_no_spec_leak(body)
    assert body["workspace_id"] == "ws-test"
    assert "root_path" not in body


def test_provision_response_returns_only_app_from_spec_json(env_defaults, auth_headers):
    fake_registry = _make_fake_registry()
    fake_registry.store.get = AsyncMock(
        return_value=_fake_workspace().model_copy(update={"spec_json": _SENSITIVE_SPEC_JSON})
    )
    with _lifespan_patches(fake_registry):
        with TestClient(app, headers=auth_headers) as client:
            app.state.registry = fake_registry
            resp = client.post("/workspaces", json={"project": "demo", "template": "observe"})
    assert resp.status_code == 202
    _assert_no_spec_leak(resp.json())


def test_concurrent_provisions_never_exceed_per_user_cap(env_defaults, monkeypatch, auth_headers):
    """Finding 11: list-then-insert let concurrent POST /workspaces all pass the cap check."""
    from concurrent.futures import ThreadPoolExecutor

    monkeypatch.setenv("WARREN_MAX_WORKSPACES_PER_USER", "2")
    fake_registry = _make_fake_registry()

    def _wrap_real_store(**kwargs):
        fake_registry.store = kwargs["store"]
        return fake_registry

    with (
        patch("warren.app.WorkspaceRegistry", side_effect=_wrap_real_store),
        patch("warren.app.PodmanRuntime"),
    ):
        with TestClient(app, headers=auth_headers) as client:
            with ThreadPoolExecutor(max_workers=6) as pool:
                responses = list(
                    pool.map(
                        lambda _: client.post("/workspaces", json={"project": "demo", "template": "observe"}),
                        range(6),
                    )
                )
            rows = client.portal.call(fake_registry.store.list_non_terminal)
    codes = [r.status_code for r in responses]
    assert codes.count(202) == 2
    assert codes.count(503) == 4
    assert len(rows) == 2
