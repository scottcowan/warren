"""Project route tests — PJ-02."""

from __future__ import annotations

from contextlib import contextmanager
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import yaml
from fastapi.testclient import TestClient

from tests.conftest import TEST_BOOTSTRAP_TOKEN
from warren.app import app
from warren.routes.projects import _sha256


def _make_fake_registry() -> MagicMock:
    """Return a MagicMock registry with async methods for lifespan compat."""
    r = MagicMock()
    r.server_id = "test-server"
    r.reconcile_from_disk = AsyncMock()
    r.provision = AsyncMock()
    r._do_provision = AsyncMock()
    r.destroy = AsyncMock()
    r.store = MagicMock()
    r.store.insert = AsyncMock()
    r.store.get = AsyncMock(return_value=None)
    r.store.list_all = AsyncMock(return_value=[])
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


def test_list_projects_empty(tmp_path, env_defaults, monkeypatch, auth_headers):
    projects_dir = tmp_path / "projects"
    projects_dir.mkdir(exist_ok=True)
    monkeypatch.setenv("WARREN_PROJECTS_DIR", str(projects_dir))
    fake_registry = _make_fake_registry()
    with _lifespan_patches(fake_registry):
        with TestClient(app, headers=auth_headers) as client:
            resp = client.get("/projects")
    assert resp.status_code == 200
    assert resp.json() == []


def test_put_project_invalid_name_rejected(tmp_path, env_defaults, auth_headers):
    fake_registry = _make_fake_registry()
    with _lifespan_patches(fake_registry):
        with TestClient(app, headers=auth_headers) as client:
            resp = client.put("/projects/../etc/passwd", content=b"name: x")
    assert resp.status_code in (400, 404, 422)


def test_put_project_invalid_yaml_returns_422(tmp_path, env_defaults, monkeypatch, auth_headers):
    projects_dir = tmp_path / "projects"
    projects_dir.mkdir(exist_ok=True)
    monkeypatch.setenv("WARREN_PROJECTS_DIR", str(projects_dir))
    fake_registry = _make_fake_registry()
    with _lifespan_patches(fake_registry):
        with TestClient(app, headers=auth_headers) as client:
            resp = client.put("/projects/demo", content=b": invalid: yaml: {{{{")
    assert resp.status_code == 422


def test_put_project_invalid_yaml_response_never_leaks_tempfile_path(
    tmp_path, env_defaults, monkeypatch, auth_headers
):
    """Audit #46: _write_project_file used to echo str(exc) straight to the client --
    the validation failure's own exception text can embed the tempfile's absolute host
    path (ProjectLoader.load raises ProjectNotFoundError naming it, among others)."""
    projects_dir = tmp_path / "projects"
    projects_dir.mkdir(exist_ok=True)
    monkeypatch.setenv("WARREN_PROJECTS_DIR", str(projects_dir))
    fake_registry = _make_fake_registry()
    with _lifespan_patches(fake_registry):
        with TestClient(app, headers=auth_headers) as client:
            resp = client.put("/projects/demo", content=b": invalid: yaml: {{{{")
    assert resp.status_code == 422
    assert str(tmp_path) not in resp.text
    assert resp.json()["detail"] == "project configuration is invalid"


def test_put_project_valid_yaml_succeeds(tmp_path, env_defaults, monkeypatch, auth_headers):
    """Regression for the request.body() fix: a legitimate YAML upload must
    actually succeed — previously bytes=Body(...) forced JSON parsing first,
    so no valid YAML PUT ever worked at all, admin or not."""
    projects_dir = tmp_path / "projects"
    projects_dir.mkdir(exist_ok=True)
    monkeypatch.setenv("WARREN_PROJECTS_DIR", str(projects_dir))
    fake_registry = _make_fake_registry()
    valid_yaml = yaml.dump(
        {
            "name": "demo",
            "description": "t",
            "docker_image": "ghcr.io/x/base:latest",
            "templates": {"observe": {"permission": "readonly", "app": "bash"}},
        }
    ).encode()

    with _lifespan_patches(fake_registry):
        with TestClient(app, headers=auth_headers) as client:
            resp = client.put("/projects/demo?server_wide=true", content=valid_yaml)

    assert resp.status_code == 204
    assert (projects_dir / "demo.yaml").read_bytes() == valid_yaml


def test_put_project_non_admin_returns_403(tmp_path, env_defaults, monkeypatch, auth_headers):
    """Regression for issue #10: a non-admin authenticated user must not be
    able to overwrite shared project config."""
    projects_dir = tmp_path / "projects"
    projects_dir.mkdir(exist_ok=True)
    monkeypatch.setenv("WARREN_PROJECTS_DIR", str(projects_dir))
    fake_registry = _make_fake_registry()
    valid_yaml = yaml.dump(
        {
            "name": "demo",
            "description": "t",
            "docker_image": "ghcr.io/x/base:latest",
            "templates": {"observe": {"permission": "readonly", "app": "bash"}},
        }
    ).encode()

    with _lifespan_patches(fake_registry):
        with TestClient(app, headers=auth_headers) as client:
            create_resp = client.post(
                "/admin/users", json={"username": "carol", "is_admin": False}
            )
            assert create_resp.status_code == 201
            minted_token = create_resp.json()["token"]["token"]

            resp = client.put(
                "/projects/demo?server_wide=true",
                content=valid_yaml,
                headers={"Authorization": f"Bearer {minted_token}"},
            )
    assert resp.status_code == 403
    assert not (projects_dir / "demo.yaml").exists()


def test_put_project_bad_update_does_not_destroy_existing_valid_project(
    tmp_path, env_defaults, monkeypatch, auth_headers
):
    """Regression for issue #10: a rejected update must not delete a
    previously-valid project — the old flow wrote directly to the real file
    then deleted it on validation failure, destroying whatever was there."""
    projects_dir = tmp_path / "projects"
    projects_dir.mkdir(exist_ok=True)
    monkeypatch.setenv("WARREN_PROJECTS_DIR", str(projects_dir))
    original = yaml.dump(
        {
            "name": "demo",
            "description": "original",
            "docker_image": "ghcr.io/x/base:latest",
            "templates": {"observe": {"permission": "readonly", "app": "bash"}},
        }
    ).encode()
    (projects_dir / "demo.yaml").write_bytes(original)

    fake_registry = _make_fake_registry()
    with _lifespan_patches(fake_registry):
        with TestClient(app, headers=auth_headers) as client:
            resp = client.put(
                f"/projects/demo?server_wide=true&expected_version={_sha256(original)}",
                content=b": invalid: yaml: {{{{",
            )

    assert resp.status_code == 422
    assert (projects_dir / "demo.yaml").read_bytes() == original


def test_put_project_default_writes_user_scoped_not_shared(
    tmp_path, env_defaults, monkeypatch, auth_headers
):
    """A plain PUT (no server_wide) must write the caller's own user-scoped
    file, never the shared one — any authenticated user can do this, admin
    or not, since it only ever touches their own override."""
    projects_dir = tmp_path / "projects"
    projects_dir.mkdir(exist_ok=True)
    monkeypatch.setenv("WARREN_PROJECTS_DIR", str(projects_dir))
    fake_registry = _make_fake_registry()
    valid_yaml = yaml.dump(
        {
            "name": "demo",
            "description": "t",
            "docker_image": "ghcr.io/x/base:latest",
            "templates": {"observe": {"permission": "readonly", "app": "bash"}},
        }
    ).encode()

    with _lifespan_patches(fake_registry):
        with TestClient(app, headers=auth_headers) as client:
            admin_resp = client.get("/admin/users")
            user_id = admin_resp.json()[0]["user_id"]
            resp = client.put("/projects/demo", content=valid_yaml)

    assert resp.status_code == 204
    assert not (projects_dir / "demo.yaml").exists()
    assert (projects_dir / "users" / user_id / "demo.yaml").read_bytes() == valid_yaml


def test_put_project_non_admin_can_write_own_user_scoped_project(
    tmp_path, env_defaults, monkeypatch, auth_headers
):
    """Unlike server_wide writes, a non-admin writing their own user-scoped
    project is not a privilege-escalation path — it must succeed."""
    projects_dir = tmp_path / "projects"
    projects_dir.mkdir(exist_ok=True)
    monkeypatch.setenv("WARREN_PROJECTS_DIR", str(projects_dir))
    fake_registry = _make_fake_registry()
    valid_yaml = yaml.dump(
        {
            "name": "demo",
            "description": "t",
            "docker_image": "ghcr.io/x/base:latest",
            "templates": {"observe": {"permission": "readonly", "app": "bash"}},
        }
    ).encode()

    with _lifespan_patches(fake_registry):
        with TestClient(app, headers=auth_headers) as client:
            create_resp = client.post(
                "/admin/users", json={"username": "carol", "is_admin": False}
            )
            carol_id = create_resp.json()["user"]["user_id"]
            minted_token = create_resp.json()["token"]["token"]

            resp = client.put(
                "/projects/demo",
                content=valid_yaml,
                headers={"Authorization": f"Bearer {minted_token}"},
            )

    assert resp.status_code == 204
    assert (projects_dir / "users" / carol_id / "demo.yaml").read_bytes() == valid_yaml


def test_put_project_user_scoped_local_path_folder_rejected(
    tmp_path, env_defaults, monkeypatch, auth_headers
):
    """Audit T1: a user-scoped project declaring a `local-path` folder must be
    rejected — it bind-mounts an arbitrary host path (e.g. `/`, the podman
    socket, warren's own data dir) into the workspace, read-write unless
    `readonly`, with no admin check on who can write a user-scoped project."""
    projects_dir = tmp_path / "projects"
    projects_dir.mkdir(exist_ok=True)
    monkeypatch.setenv("WARREN_PROJECTS_DIR", str(projects_dir))
    fake_registry = _make_fake_registry()
    malicious_yaml = yaml.dump(
        {
            "name": "demo",
            "description": "t",
            "docker_image": "ghcr.io/x/base:latest",
            "folders": [
                {"name": "pwn", "type": "local-path", "mount": "pwn", "path": "/"},
            ],
            "templates": {"observe": {}},
        }
    ).encode()

    with _lifespan_patches(fake_registry):
        with TestClient(app, headers=auth_headers) as client:
            create_resp = client.post(
                "/admin/users", json={"username": "carol", "is_admin": False}
            )
            carol_id = create_resp.json()["user"]["user_id"]
            minted_token = create_resp.json()["token"]["token"]

            resp = client.put(
                "/projects/demo",
                content=malicious_yaml,
                headers={"Authorization": f"Bearer {minted_token}"},
            )

    assert resp.status_code == 422
    assert resp.json()["detail"]["error"] == "local_path_not_allowed_user_scoped"
    assert not (projects_dir / "users" / carol_id / "demo.yaml").exists()


def test_put_project_user_scoped_nested_template_local_path_folder_rejected(
    tmp_path, env_defaults, monkeypatch, auth_headers
):
    """The same rejection must apply when `local-path` is declared on a
    nested `templates.*` node, not just the root `folders` list — template
    merge treats `folders` as an ordinary override field at any depth, not
    something confined to the root."""
    projects_dir = tmp_path / "projects"
    projects_dir.mkdir(exist_ok=True)
    monkeypatch.setenv("WARREN_PROJECTS_DIR", str(projects_dir))
    fake_registry = _make_fake_registry()
    malicious_yaml = yaml.dump(
        {
            "name": "demo",
            "description": "t",
            "docker_image": "ghcr.io/x/base:latest",
            "templates": {
                "observe": {
                    "folders": [
                        {
                            "name": "pwn",
                            "type": "local-path",
                            "mount": "pwn",
                            "path": "/run/podman/podman.sock",
                        }
                    ],
                }
            },
        }
    ).encode()

    with _lifespan_patches(fake_registry):
        with TestClient(app, headers=auth_headers) as client:
            create_resp = client.post(
                "/admin/users", json={"username": "carol", "is_admin": False}
            )
            minted_token = create_resp.json()["token"]["token"]

            resp = client.put(
                "/projects/demo",
                content=malicious_yaml,
                headers={"Authorization": f"Bearer {minted_token}"},
            )

    assert resp.status_code == 422
    assert resp.json()["detail"]["error"] == "local_path_not_allowed_user_scoped"


def test_put_project_server_wide_local_path_folder_allowed(
    tmp_path, env_defaults, monkeypatch, auth_headers
):
    """An admin-written server-wide project is the trusted path -- local-path
    must still work there (admin is already a trusted role)."""
    projects_dir = tmp_path / "projects"
    projects_dir.mkdir(exist_ok=True)
    monkeypatch.setenv("WARREN_PROJECTS_DIR", str(projects_dir))
    fake_registry = _make_fake_registry()
    valid_yaml = yaml.dump(
        {
            "name": "demo",
            "description": "t",
            "docker_image": "ghcr.io/x/base:latest",
            "folders": [
                {
                    "name": "vault",
                    "type": "local-path",
                    "mount": "vault",
                    "path": "/srv/obsidian-vault",
                    "readonly": True,
                }
            ],
            "templates": {"observe": {}},
        }
    ).encode()

    with _lifespan_patches(fake_registry):
        with TestClient(app, headers=auth_headers) as client:
            resp = client.put("/projects/demo?server_wide=true", content=valid_yaml)

    assert resp.status_code == 204
    assert (projects_dir / "demo.yaml").read_bytes() == valid_yaml


def test_put_project_rejected_when_no_templates(
    tmp_path, env_defaults, monkeypatch, auth_headers
):
    """A project that parses cleanly but has zero templates (e.g. an outdated
    `intents:`/`base_image:` schema, silently dropped by ProjectConfig's
    `extra="ignore"`) is never actually provisionable -- resolve_template()
    always requires at least one named template segment. Reject it at write
    time instead of letting it land silently and fail later at provision."""
    projects_dir = tmp_path / "projects"
    projects_dir.mkdir(exist_ok=True)
    monkeypatch.setenv("WARREN_PROJECTS_DIR", str(projects_dir))
    fake_registry = _make_fake_registry()
    stale_schema_yaml = yaml.dump(
        {
            "name": "uat-test",
            "base_image": "localhost/warren-workspace-base:latest",
            "intents": {"default": {"description": "UAT test intent"}},
        }
    ).encode()

    with _lifespan_patches(fake_registry):
        with TestClient(app, headers=auth_headers) as client:
            resp = client.put(
                "/projects/uat-test?server_wide=true", content=stale_schema_yaml
            )

    assert resp.status_code == 422
    assert resp.json()["detail"]["error"] == "no_templates"
    assert not (projects_dir / "uat-test.yaml").exists()


def test_put_project_server_wide_conflict_returns_409(
    tmp_path, env_defaults, monkeypatch, auth_headers
):
    """A server-wide write against a stale expected_version must be rejected,
    not silently clobber whatever another admin last published."""
    projects_dir = tmp_path / "projects"
    projects_dir.mkdir(exist_ok=True)
    monkeypatch.setenv("WARREN_PROJECTS_DIR", str(projects_dir))
    existing = yaml.dump({"name": "demo", "templates": {"observe": {}}}).encode()
    (projects_dir / "demo.yaml").write_bytes(existing)

    new_yaml = yaml.dump({"name": "demo", "description": "v2", "templates": {"observe": {}}}).encode()
    fake_registry = _make_fake_registry()
    with _lifespan_patches(fake_registry):
        with TestClient(app, headers=auth_headers) as client:
            resp = client.put(
                "/projects/demo?server_wide=true&expected_version=stale-hash",
                content=new_yaml,
            )

    assert resp.status_code == 409
    assert resp.json()["detail"]["error"] == "version_conflict"
    assert (projects_dir / "demo.yaml").read_bytes() == existing


def test_put_project_server_wide_new_project_needs_no_expected_version(
    tmp_path, env_defaults, monkeypatch, auth_headers
):
    """A brand-new server-wide project (nothing to conflict with yet) must
    not require expected_version."""
    projects_dir = tmp_path / "projects"
    projects_dir.mkdir(exist_ok=True)
    monkeypatch.setenv("WARREN_PROJECTS_DIR", str(projects_dir))
    valid_yaml = yaml.dump({"name": "demo", "templates": {"observe": {}}}).encode()
    fake_registry = _make_fake_registry()
    with _lifespan_patches(fake_registry):
        with TestClient(app, headers=auth_headers) as client:
            resp = client.put("/projects/demo?server_wide=true", content=valid_yaml)

    assert resp.status_code == 204
    assert (projects_dir / "demo.yaml").read_bytes() == valid_yaml


def test_get_project_detail_returns_both_halves_and_effective(
    tmp_path, env_defaults, monkeypatch, auth_headers
):
    projects_dir = tmp_path / "projects"
    projects_dir.mkdir(exist_ok=True)
    monkeypatch.setenv("WARREN_PROJECTS_DIR", str(projects_dir))
    server_wide = yaml.dump(
        {"name": "demo", "templates": {"observe": {"permission": "readonly"}}}
    ).encode()
    (projects_dir / "demo.yaml").write_bytes(server_wide)

    fake_registry = _make_fake_registry()
    with _lifespan_patches(fake_registry):
        with TestClient(app, headers=auth_headers) as client:
            admin_resp = client.get("/admin/users")
            user_id = admin_resp.json()[0]["user_id"]
            user_dir = projects_dir / "users" / user_id
            user_dir.mkdir(parents=True)
            user_yaml = yaml.dump(
                {"name": "demo", "templates": {"claude": {"app": "claude"}}}
            ).encode()
            (user_dir / "demo.yaml").write_bytes(user_yaml)

            resp = client.get("/projects/demo")

    assert resp.status_code == 200
    body = resp.json()
    assert body["server_wide_yaml"] == server_wide.decode()
    assert body["user_scoped_yaml"] == user_yaml.decode()
    assert set(body["effective"]["templates"]) == {"observe", "claude"}


def test_get_project_detail_404_when_neither_exists(env_defaults, auth_headers):
    fake_registry = _make_fake_registry()
    with _lifespan_patches(fake_registry):
        with TestClient(app, headers=auth_headers) as client:
            resp = client.get("/projects/nonexistent")
    assert resp.status_code == 404


def test_delete_project_removes_own_user_scoped_project(
    tmp_path, env_defaults, monkeypatch, auth_headers
):
    projects_dir = tmp_path / "projects"
    projects_dir.mkdir(exist_ok=True)
    monkeypatch.setenv("WARREN_PROJECTS_DIR", str(projects_dir))
    fake_registry = _make_fake_registry()
    with _lifespan_patches(fake_registry):
        with TestClient(app, headers=auth_headers) as client:
            admin_resp = client.get("/admin/users")
            user_id = admin_resp.json()[0]["user_id"]
            user_dir = projects_dir / "users" / user_id
            user_dir.mkdir(parents=True)
            (user_dir / "demo.yaml").write_bytes(
                yaml.dump({"name": "demo", "templates": {"observe": {}}}).encode()
            )

            resp = client.delete("/projects/demo")

    assert resp.status_code == 204
    assert not (user_dir / "demo.yaml").exists()


def test_delete_project_404_when_caller_has_none(tmp_path, env_defaults, monkeypatch, auth_headers):
    projects_dir = tmp_path / "projects"
    projects_dir.mkdir(exist_ok=True)
    monkeypatch.setenv("WARREN_PROJECTS_DIR", str(projects_dir))
    fake_registry = _make_fake_registry()
    with _lifespan_patches(fake_registry):
        with TestClient(app, headers=auth_headers) as client:
            resp = client.delete("/projects/nonexistent")

    assert resp.status_code == 404


def test_delete_project_cannot_remove_server_wide_project(
    tmp_path, env_defaults, monkeypatch, auth_headers
):
    """A user-scoped delete must never touch the shared server-wide project,
    even when the caller has no user-scoped override of their own -- only
    the caller's own `users/{user_id}/demo.yaml` is a valid delete target,
    never `demo.yaml` itself."""
    projects_dir = tmp_path / "projects"
    projects_dir.mkdir(exist_ok=True)
    monkeypatch.setenv("WARREN_PROJECTS_DIR", str(projects_dir))
    (projects_dir / "demo.yaml").write_bytes(
        yaml.dump({"name": "demo", "templates": {"observe": {}}}).encode()
    )

    fake_registry = _make_fake_registry()
    with _lifespan_patches(fake_registry):
        with TestClient(app, headers=auth_headers) as client:
            resp = client.delete("/projects/demo")

    assert resp.status_code == 404
    assert (projects_dir / "demo.yaml").exists()


def test_delete_project_cannot_remove_another_users_project(
    tmp_path, env_defaults, monkeypatch, auth_headers
):
    """One user's DELETE must never remove a different user's own-scoped
    project of the same name."""
    projects_dir = tmp_path / "projects"
    projects_dir.mkdir(exist_ok=True)
    monkeypatch.setenv("WARREN_PROJECTS_DIR", str(projects_dir))
    fake_registry = _make_fake_registry()
    with _lifespan_patches(fake_registry):
        with TestClient(app, headers=auth_headers) as client:
            create_resp = client.post(
                "/admin/users", json={"username": "carol", "is_admin": False}
            )
            carol_id = create_resp.json()["user"]["user_id"]
            carol_dir = projects_dir / "users" / carol_id
            carol_dir.mkdir(parents=True)
            (carol_dir / "demo.yaml").write_bytes(
                yaml.dump({"name": "demo", "templates": {"observe": {}}}).encode()
            )

            resp = client.delete("/projects/demo")

    assert resp.status_code == 404
    assert (carol_dir / "demo.yaml").exists()


def test_delete_project_invalid_name_rejected(env_defaults, auth_headers):
    fake_registry = _make_fake_registry()
    with _lifespan_patches(fake_registry):
        with TestClient(app, headers=auth_headers) as client:
            resp = client.delete("/projects/../etc/passwd")
    assert resp.status_code in (400, 404, 422)


def test_list_projects_marks_scope(tmp_path, env_defaults, monkeypatch, auth_headers):
    projects_dir = tmp_path / "projects"
    projects_dir.mkdir(exist_ok=True)
    monkeypatch.setenv("WARREN_PROJECTS_DIR", str(projects_dir))
    (projects_dir / "shared.yaml").write_bytes(
        yaml.dump({"name": "shared", "templates": {"observe": {}}}).encode()
    )

    fake_registry = _make_fake_registry()
    with _lifespan_patches(fake_registry):
        with TestClient(app, headers=auth_headers) as client:
            admin_resp = client.get("/admin/users")
            user_id = admin_resp.json()[0]["user_id"]
            user_dir = projects_dir / "users" / user_id
            user_dir.mkdir(parents=True)
            (user_dir / "mine.yaml").write_bytes(
                yaml.dump({"name": "mine", "templates": {"observe": {}}}).encode()
            )

            resp = client.get("/projects")

    assert resp.status_code == 200
    by_name = {p["name"]: p for p in resp.json()}
    assert by_name["shared"]["_scope"] == "server_wide"
    assert by_name["mine"]["_scope"] == "user_scoped"
