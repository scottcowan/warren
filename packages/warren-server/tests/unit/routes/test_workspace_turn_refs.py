"""HIST-05/09/10: GET /workspaces/{id}/refs, POST /workspaces/{id}/branch and
session.json on connect, against real git clones on disk."""

from __future__ import annotations

import json
import os
import subprocess
import uuid
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from tests.conftest import TEST_BOOTSTRAP_TOKEN
from warren.app import app
from warren.git.manager import GitManager
from warren.registry.registry import WorkspaceRegistry
from warren.registry.store import WorkspaceStore
from warren_common.models import ProjectConfig
from warren_common.runtime.fake import FakeRuntime

_ADMIN = {"Authorization": f"Bearer {TEST_BOOTSTRAP_TOKEN}"}
_IDENT = ["-c", "user.email=t@t", "-c", "user.name=t"]
_FOLDER = {"name": "app", "type": "git-clone", "url": "https://example.invalid/app.git", "mount": "app"}
_PROJECT = ProjectConfig.model_validate(
    {"name": "demo", "templates": {"observe": {"folders": [_FOLDER]}, "hotfix": {"folders": [_FOLDER]}, "bare": {"folders": []}}}
)
_FORMAT = {"version": "1", "tool": "git-turn", "ref_pattern": "refs/git-turn/sessions/{id}/turn-{N}"}


def _git(*args: str, input: str | None = None) -> str:
    return subprocess.run(
        ["git", *args], input=input, text=True, capture_output=True, check=True
    ).stdout.strip()


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
    app.state._state.clear()


@pytest.fixture
def upstream(tmp_path: Path) -> Path:
    src = tmp_path / "upstream"
    _git("init", "-q", "-b", "main", str(src))
    (src / "a.txt").write_text("one\n")
    _git("-C", str(src), "add", "a.txt")
    _git("-C", str(src), *_IDENT, "commit", "-qm", "one")
    return src


def _turn(repo: Path, session: str, n: int) -> str:
    """A git-turn two-tree snapshot of the worktree, including untracked files."""
    env = {**os.environ, "GIT_INDEX_FILE": str(repo / ".git" / "turn-index")}
    subprocess.run(["git", "-C", str(repo), "add", "-A"], env=env, check=True)
    tree = subprocess.run(
        ["git", "-C", str(repo), "write-tree"], env=env, check=True, capture_output=True, text=True
    ).stdout.strip()
    sha = _git("-C", str(repo), *_IDENT, "commit-tree", tree, "-p", "HEAD", "-m", f"turn {n}")
    _git("-C", str(repo), "update-ref", f"refs/git-turn/sessions/{session}/turn-{n}", sha)
    return sha


@contextmanager
def _client(tmp_path: Path, upstream: Path):
    gm = GitManager(worktree_root=tmp_path / "worktrees")

    async def clone_into(dest, url, **_kw):
        if not (dest / ".git").exists():
            _git("clone", "-q", str(upstream), str(dest))
        return dest

    gm.clone_into = clone_into
    registry = WorkspaceRegistry(
        runtime=FakeRuntime("test-server"), store=MagicMock(), server_id="test-server", git_manager=gm
    )
    registry.reconcile_from_disk = AsyncMock()
    with (
        patch("warren.app.WorkspaceRegistry", return_value=registry),
        patch("warren.app.PodmanRuntime"),
        patch("warren_common.loader.ProjectLoader.load_effective", return_value=_PROJECT),
        TestClient(app, headers=_ADMIN) as client,
    ):
        app.state.registry = registry
        registry.store = WorkspaceStore(app.state.db)
        owner = client.get("/admin/users").json()[0]["user_id"]
        for ws_id, ws_owner in (("ws-src", owner), ("ws-other", "someone-else")):
            client.portal.call(
                lambda ws_id=ws_id, ws_owner=ws_owner: registry.store.insert(
                    workspace_id=ws_id, project="demo", intent="observe", image="img",
                    root_path="", server_instance="test-server", status="running",
                    owner_id=ws_owner, spec_json=json.dumps({"folders": [_FOLDER]}),
                )
            )
        src = gm.folder_worktree_path("ws-src", "app")
        src.parent.mkdir(parents=True)
        _git("clone", "-q", str(upstream), str(src))
        blob = _git("-C", str(src), "hash-object", "-w", "--stdin", input=json.dumps(_FORMAT))
        _git("-C", str(src), "update-ref", "refs/git-turn/format", blob)
        yield client, registry, src


def test_refs_lists_turn_refs(env_defaults, tmp_path, upstream):
    with _client(tmp_path, upstream) as (client, _, src):
        sha = _turn(src, "abc", 1)
        resp = client.get("/workspaces/ws-src/refs", params={"repo": "app", "prefix": "refs/git-turn/sessions/"})
        assert resp.status_code == 200, resp.text
        assert resp.json() == [{"ref": "refs/git-turn/sessions/abc/turn-1", "sha": sha}]

        default = client.get("/workspaces/ws-src/refs", params={"repo": "app"}).json()
        assert {r["ref"] for r in default} == {"refs/git-turn/format", "refs/git-turn/sessions/abc/turn-1"}


def test_refs_errors(env_defaults, tmp_path, upstream):
    with _client(tmp_path, upstream) as (client, _, _src):
        assert client.get("/workspaces/ws-other/refs", params={"repo": "app"}).status_code == 403
        assert client.get("/workspaces/nope/refs").status_code == 404
        assert client.get("/workspaces/ws-src/refs").status_code == 404  # no root clone
        bad = client.get("/workspaces/ws-src/refs", params={"repo": "app", "prefix": "--all"})
        assert bad.status_code == 422


def test_refs_unavailable_without_server_clone(env_defaults, tmp_path, upstream):
    with _client(tmp_path, upstream) as (client, registry, _src):
        registry.git_manager = None
        resp = client.get("/workspaces/ws-src/refs", params={"repo": "app"})
        assert resp.status_code == 409


def test_branch_from_turn_provisions_snapshot(env_defaults, tmp_path, upstream):
    with _client(tmp_path, upstream) as (client, registry, src):
        (src / "a.txt").write_text("mid-edit\n")
        (src / "new.txt").write_text("untracked\n")
        turn = _turn(src, "abc", 2)
        session = str(uuid.uuid4())

        resp = client.post("/workspaces/ws-src/branch", json={
            "from_ref": "refs/git-turn/sessions/abc/turn-2", "intent": "hotfix",
            "repo": "app", "new_session_id": session,
        })
        assert resp.status_code == 202, resp.text
        body = resp.json()
        assert body["snapshot_model"] == "two-tree-dangling-commit"
        assert body["source_commit"] == turn
        assert body["parent_workspace_id"] == "ws-src"
        assert body["workspace"]["status"] == "running"
        assert body["workspace"]["intent"] == "hotfix"

        new_id = body["workspace"]["workspace_id"]
        dest = registry.git_manager.folder_worktree_path(new_id, "app")
        assert (dest / "a.txt").read_text() == "mid-edit\n"
        assert (dest / "new.txt").read_text() == "untracked\n"
        assert _git("-C", str(dest), "symbolic-ref", "--short", "HEAD") == body["branch"]
        _git("-C", str(dest), "fsck", "--connectivity-only")
        session_file = json.loads((dest / ".git" / "git-turn" / "session.json").read_text())
        assert session_file == {
            "session_id": session, "workspace_id": new_id, "turn_n": 0, "refs_namespace": "refs/git-turn",
        }


def test_branch_errors(env_defaults, tmp_path, upstream):
    with _client(tmp_path, upstream) as (client, _, _src):
        def post(ws="ws-src", **body):
            return client.post(f"/workspaces/{ws}/branch", json={"repo": "app", **body})

        assert post(from_ref="refs/git-turn/sessions/none/turn-1").status_code == 404
        assert post(from_ref="HEAD").status_code == 422
        assert post(from_ref="refs/git-turn/format").status_code == 422
        assert post(ws="ws-other", from_ref="refs/heads/main").status_code == 403
        assert post(from_ref="refs/heads/main", new_session_id="../x").status_code == 422


def test_branch_fails_when_template_lacks_target_repo(env_defaults, tmp_path, upstream):
    with _client(tmp_path, upstream) as (client, _, src):
        _turn(src, "abc", 1)
        resp = client.post("/workspaces/ws-src/branch", json={
            "from_ref": "refs/git-turn/sessions/abc/turn-1", "intent": "bare", "repo": "app",
        })
        assert resp.status_code == 202
        assert resp.json()["workspace"]["status"] == "failed"


def test_branch_denied_to_workspace_token(env_defaults, tmp_path, upstream):
    with _client(tmp_path, upstream) as (client, _, src):
        _turn(src, "abc", 1)
        token = client.post("/workspaces/ws-src/tokens", json={}).json()["token"]
        hdr = {"Authorization": f"Bearer {token}"}
        refs = client.get("/workspaces/ws-src/refs", params={"repo": "app"}, headers=hdr)
        assert refs.status_code == 200
        branch = client.post(
            "/workspaces/ws-src/branch",
            json={"from_ref": "refs/git-turn/sessions/abc/turn-1", "repo": "app"},
            headers=hdr,
        )
        assert branch.status_code == 403


def test_ensure_running_writes_session_json(env_defaults, tmp_path, upstream):
    with _client(tmp_path, upstream) as (client, registry, src):
        registry.ensure_running = AsyncMock(return_value=MagicMock(runtime_id="ctr-1"))
        resp = client.post("/workspaces/ws-src/ensure_running")
        assert resp.status_code == 200, resp.text
        session_id = resp.json()["session_id"]
        data = json.loads((src / ".git" / "git-turn" / "session.json").read_text())
        assert data == {
            "session_id": session_id, "workspace_id": "ws-src", "turn_n": 0, "refs_namespace": "refs/git-turn",
        }


def test_session_json_skips_symlinked_git_dir(env_defaults, tmp_path, upstream):
    with _client(tmp_path, upstream) as (client, registry, src):
        outside = tmp_path / "outside"
        outside.mkdir()
        real = src / ".git"
        real.rename(tmp_path / "moved-git")
        real.symlink_to(outside)
        registry.ensure_running = AsyncMock(return_value=MagicMock(runtime_id="ctr-1"))
        resp = client.post("/workspaces/ws-src/ensure_running")
        assert resp.status_code == 200
        assert resp.json()["session_id"] is None
        assert list(outside.iterdir()) == []
