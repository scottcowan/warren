"""SD-02, SD-03: GET /files and GET /files/{path} endpoints."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from warren_sidecar.app import app


def test_files_returns_list(env_defaults, auth_headers):
    with TestClient(app) as client:
        response = client.get("/files", headers=auth_headers)
    assert response.status_code == 200
    assert isinstance(response.json(), list)


def test_files_excludes_git_dir(env_defaults, auth_headers):
    with TestClient(app) as client:
        response = client.get("/files", headers=auth_headers)
    entries = response.json()
    assert all(".git" not in str(e) for e in entries)


def test_files_excludes_node_modules(env_defaults, auth_headers):
    with TestClient(app) as client:
        response = client.get("/files", headers=auth_headers)
    entries = response.json()
    assert all("node_modules" not in str(e) for e in entries)


def test_files_excludes_env_files(env_defaults, auth_headers):
    with TestClient(app) as client:
        response = client.get("/files", headers=auth_headers)
    entries = response.json()
    names = [e.get("name", str(e)) if isinstance(e, dict) else str(e) for e in entries]
    assert all(not n.startswith(".env") for n in names)


def test_files_excludes_gitignored(env_defaults, auth_headers, monkeypatch, tmp_path):
    """Files matching .gitignore patterns must be absent from listing."""
    (tmp_path / ".gitignore").write_text("*.secret\n")
    (tmp_path / "hidden.secret").write_text("data")
    monkeypatch.setenv("WARREN_WORKTREE_PATHS", str(tmp_path))
    with TestClient(app) as client:
        response = client.get("/files", headers=auth_headers)
    names = [
        e.get("name", str(e)) if isinstance(e, dict) else str(e)
        for e in response.json()
    ]
    assert all(not n.endswith(".secret") for n in names)


def test_files_requires_auth_header(env_defaults):
    with TestClient(app) as client:
        response = client.get("/files")
    assert response.status_code == 401


def test_files_rejects_wrong_token(env_defaults):
    with TestClient(app) as client:
        response = client.get("/files", headers={"X-Warren-Sidecar-Token": "wrong"})
    assert response.status_code == 401


def test_file_get_returns_content(env_defaults, auth_headers, monkeypatch, tmp_path):
    target = tmp_path / "hello.txt"
    target.write_text("hello world")
    monkeypatch.setenv("WARREN_WORKTREE_PATHS", str(tmp_path))
    with TestClient(app) as client:
        response = client.get("/files/hello.txt", headers=auth_headers)
    assert response.status_code == 200
    assert "hello world" in response.text


def test_file_get_over_1mib_returns_413(env_defaults, auth_headers, monkeypatch, tmp_path):
    """Files larger than 1 MiB must return 413 Request Entity Too Large."""
    large = tmp_path / "big.bin"
    large.write_bytes(b"x" * (1_048_576 + 1))
    monkeypatch.setenv("WARREN_WORKTREE_PATHS", str(tmp_path))
    with TestClient(app) as client:
        response = client.get("/files/big.bin", headers=auth_headers)
    assert response.status_code == 413


def test_file_get_absolute_path_never_escapes_root(env_defaults, auth_headers, monkeypatch, tmp_path):
    """An absolute-looking request path (e.g. /proc/1/environ) must never
    reach outside the workspace root (audit #47) — it is always joined onto
    root, so it 404s rather than ever resolving to a real host file."""
    monkeypatch.setenv("WARREN_WORKTREE_PATHS", str(tmp_path))
    with TestClient(app) as client:
        response = client.get("/files//proc/1/environ", headers=auth_headers)
    assert response.status_code == 404


def test_resolve_under_root_rejects_dotdot_traversal(tmp_path):
    from fastapi import HTTPException

    from warren_sidecar.routes.files import _resolve_under_root

    with pytest.raises(HTTPException) as ei:
        _resolve_under_root("../etc/passwd", tmp_path)
    assert ei.value.status_code == 400


def test_resolve_under_root_joins_absolute_path_onto_root(tmp_path):
    """An absolute request path is joined onto root (audit #47), never served as-is."""
    from warren_sidecar.routes.files import _resolve_under_root

    resolved = _resolve_under_root("/proc/1/environ", tmp_path)
    assert resolved == (tmp_path / "proc/1/environ").resolve()


def test_resolve_under_root_treats_requests_as_relative_to_root(tmp_path):
    """A caller-supplied path is always joined onto root, never trusted as an
    absolute filesystem path — including when it happens to start with
    root's own path components."""
    from warren_sidecar.routes.files import _resolve_under_root

    resolved = _resolve_under_root("hello.txt", tmp_path)
    assert resolved == (tmp_path / "hello.txt").resolve()
