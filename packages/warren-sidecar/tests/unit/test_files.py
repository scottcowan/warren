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


def test_request_parts_rejects_dotdot_traversal():
    from warren_sidecar.files import PathDenied, request_parts

    for bad in ("../etc/passwd", "a/../../etc", "./x", ""):
        with pytest.raises(PathDenied):
            request_parts(bad)


def test_request_parts_joins_absolute_path_onto_root():
    """An absolute request path is joined onto root (audit #47), never served as-is."""
    from warren_sidecar.files import request_parts

    assert request_parts("/proc/1/environ") == ("proc", "1", "environ")
    assert request_parts("hello.txt") == ("hello.txt",)


def test_dotdot_request_is_rejected(env_defaults, auth_headers, monkeypatch, tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    (tmp_path / "outside.txt").write_text("TOPSECRET")
    monkeypatch.setenv("WARREN_WORKTREE_PATHS", str(root))
    with TestClient(app) as client:
        response = client.get("/files/sub/%2E%2E/%2E%2E/outside.txt", headers=auth_headers)
    assert response.status_code in (400, 404)
    assert "TOPSECRET" not in response.text


@pytest.mark.parametrize(
    "rel",
    [".env", "config/.env.local", ".git/config", "node_modules/pkg/index.js", "hidden.secret", "build/out.txt"],
)
def test_excluded_file_is_not_readable_directly(env_defaults, auth_headers, monkeypatch, tmp_path, rel):
    (tmp_path / ".gitignore").write_text("*.secret\nbuild/\n")
    target = tmp_path / rel
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("TOPSECRET")
    monkeypatch.setenv("WARREN_WORKTREE_PATHS", str(tmp_path))
    with TestClient(app) as client:
        listed = [e["path"] for e in client.get("/files", headers=auth_headers).json()]
        response = client.get(f"/files/{rel}", headers=auth_headers)
    assert rel not in listed
    assert response.status_code == 404
    assert "TOPSECRET" not in response.text


def _escape_layout(tmp_path):
    root = tmp_path / "root"
    outside = tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    (outside / "secret.txt").write_text("TOPSECRET")
    (outside / "nested").mkdir()
    (outside / "nested" / "deep.txt").write_text("TOPSECRET")
    (root / "ok.txt").write_text("fine")
    (root / "link.txt").symlink_to(outside / "secret.txt")
    (root / "linkdir").symlink_to(outside, target_is_directory=True)
    return root


def test_file_symlink_escaping_root_is_refused(env_defaults, auth_headers, monkeypatch, tmp_path):
    root = _escape_layout(tmp_path)
    monkeypatch.setenv("WARREN_WORKTREE_PATHS", str(root))
    with TestClient(app) as client:
        response = client.get("/files/link.txt", headers=auth_headers)
    assert response.status_code == 400
    assert "TOPSECRET" not in response.text


def test_directory_symlink_escaping_root_is_refused(env_defaults, auth_headers, monkeypatch, tmp_path):
    root = _escape_layout(tmp_path)
    monkeypatch.setenv("WARREN_WORKTREE_PATHS", str(root))
    with TestClient(app) as client:
        response = client.get("/files/linkdir/secret.txt", headers=auth_headers)
        nested = client.get("/files/linkdir/nested/deep.txt", headers=auth_headers)
    assert response.status_code == 400
    assert nested.status_code == 400
    assert "TOPSECRET" not in response.text + nested.text


def test_symlink_inside_root_is_also_not_followed(env_defaults, auth_headers, monkeypatch, tmp_path):
    root = _escape_layout(tmp_path)
    (root / "alias.txt").symlink_to(root / "ok.txt")
    monkeypatch.setenv("WARREN_WORKTREE_PATHS", str(root))
    with TestClient(app) as client:
        assert client.get("/files/ok.txt", headers=auth_headers).text == "fine"
        assert client.get("/files/alias.txt", headers=auth_headers).status_code == 400


def test_component_swapped_for_symlink_after_listing_is_refused(
    env_defaults, auth_headers, monkeypatch, tmp_path
):
    """The race: a directory that was real when listed is a symlink when read."""
    root = _escape_layout(tmp_path)
    (root / "sub").mkdir()
    (root / "sub" / "secret.txt").write_text("fine")
    monkeypatch.setenv("WARREN_WORKTREE_PATHS", str(root))
    with TestClient(app) as client:
        assert "sub/secret.txt" in {e["path"] for e in client.get("/files", headers=auth_headers).json()}
        (root / "sub" / "secret.txt").unlink()
        (root / "sub").rmdir()
        (root / "sub").symlink_to(tmp_path / "outside", target_is_directory=True)
        response = client.get("/files/sub/secret.txt", headers=auth_headers)
    assert response.status_code == 400
    assert "TOPSECRET" not in response.text


def test_walker_does_not_descend_symlinked_dirs(tmp_path):
    from warren_sidecar.files import walk_tree

    root = _escape_layout(tmp_path)
    (root / "real").mkdir()
    (root / "real" / "a.txt").write_text("a")
    paths = {e["path"] for e in walk_tree(root)}
    assert paths == {"ok.txt", "real", "real/a.txt"}


def test_walker_does_not_follow_symlink_loop(tmp_path):
    from warren_sidecar.files import walk_tree

    (tmp_path / "d").mkdir()
    (tmp_path / "d" / "loop").symlink_to(tmp_path, target_is_directory=True)
    assert {e["path"] for e in walk_tree(tmp_path)} == {"d"}


def test_gitignore_symlink_is_not_read(tmp_path):
    from warren_sidecar.files import walk_tree

    (tmp_path / "outside").write_text("*.txt\n")
    root = tmp_path / "root"
    root.mkdir()
    (root / ".gitignore").symlink_to(tmp_path / "outside")
    (root / "keep.txt").write_text("x")
    assert "keep.txt" in {e["path"] for e in walk_tree(root)}
