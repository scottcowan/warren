"""Issue #10: server-side git clone must not accept an arbitrary scheme, and
the GitHub App installation token must never be sent to a host other than
the one it was minted for.

Unlike test_manager.py, this module does NOT patch `_validate_clone_url` --
it exercises the real, unpatched scheme allow-list, and bypasses it only
inline, within the handful of tests that need a local `file://` fixture repo
to reach the credential-pinning logic underneath it.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from git import Repo
from warren.git.manager import GitError, GitManager, _validate_clone_url


@pytest.fixture
def source_repo(tmp_path: Path) -> Path:
    src = tmp_path / "source"
    src.mkdir()
    repo = Repo.init(src, initial_branch="main")
    (src / "file.txt").write_text("hello")
    repo.index.add(["file.txt"])
    repo.index.commit("initial commit")
    return src


@pytest.fixture
def worktree_root(tmp_path: Path) -> Path:
    root = tmp_path / "worktrees"
    root.mkdir()
    return root


def _file_url(path: Path) -> str:
    return f"file://{path}"


@pytest.mark.parametrize(
    "repo_url",
    [
        "file:///etc/some/repo",
        "git://example.com/org/repo.git",
        "ext::sh -c touch /tmp/pwned",
        "/absolute/local/path.git",
        "relative/local/path.git",
        "http://example.com/org/repo.git",
    ],
)
def test_validate_clone_url_rejects_disallowed_schemes(repo_url):
    with pytest.raises(GitError, match="unsupported clone url scheme"):
        _validate_clone_url(repo_url)


@pytest.mark.parametrize(
    "repo_url",
    [
        "https://github.com/scottcowan/warren.git",
        "git@github.com:scottcowan/warren.git",
        "ssh://git@bitbucket.org/dotmusic/whmcs.git",
    ],
)
def test_validate_clone_url_allows_https_and_ssh(repo_url):
    _validate_clone_url(repo_url)  # must not raise


async def test_clone_rejects_file_url_by_default(worktree_root, tmp_path):
    """No monkeypatch here -- the real, shipped validation must reject a
    file:// URL before any clone attempt, and must leave nothing on disk."""
    mgr = GitManager(worktree_root)

    with pytest.raises(GitError, match="unsupported clone url scheme"):
        await mgr.clone("ws-file-rejected", f"file://{tmp_path}/source")

    assert not (worktree_root / "ws-file-rejected").exists()


async def test_clone_rejects_bare_local_path_by_default(worktree_root, source_repo):
    mgr = GitManager(worktree_root)

    with pytest.raises(GitError, match="unsupported clone url scheme"):
        await mgr.clone("ws-bare-path-rejected", str(source_repo))

    assert not (worktree_root / "ws-bare-path-rejected").exists()


async def test_clone_never_sends_installation_token_to_mismatched_host(
    worktree_root, source_repo, monkeypatch
):
    """The GitHub App token belongs to `credential_host` only -- a project's
    own `url` naming a different host must clone (if it can, uncredentialed)
    without that token ever being requested."""
    import warren.git.manager as manager_module

    monkeypatch.setattr(manager_module, "_validate_clone_url", lambda repo_url: None)
    monkeypatch.setattr(manager_module, "_GIT_ALLOW_PROTOCOL_ENV", {})

    creds = SimpleNamespace(token=AsyncMock(return_value="server-token"), credential_host="github.com")
    mgr = GitManager(worktree_root, credentials=creds)

    path = await mgr.clone("ws-host-mismatch", _file_url(source_repo))

    creds.token.assert_not_awaited()
    assert (path / "file.txt").read_text() == "hello"


async def test_pull_never_sends_installation_token_to_mismatched_origin_host(
    worktree_root, source_repo, monkeypatch
):
    import warren.git.manager as manager_module

    monkeypatch.setattr(manager_module, "_validate_clone_url", lambda repo_url: None)
    monkeypatch.setattr(manager_module, "_GIT_ALLOW_PROTOCOL_ENV", {})

    mgr_no_creds = GitManager(worktree_root)
    await mgr_no_creds.clone("ws-pull-host-mismatch", _file_url(source_repo))

    (source_repo / "file2.txt").write_text("second file")
    upstream = Repo(source_repo)
    upstream.index.add(["file2.txt"])
    upstream.index.commit("second commit")

    creds = SimpleNamespace(token=AsyncMock(return_value="server-token"), credential_host="github.com")
    mgr_with_creds = GitManager(worktree_root, credentials=creds)

    await mgr_with_creds.pull("ws-pull-host-mismatch")

    creds.token.assert_not_awaited()


def test_clone_sync_sets_git_allow_protocol_env(monkeypatch, worktree_root):
    """Defense in depth alongside `_validate_clone_url`: git itself is told,
    via GIT_ALLOW_PROTOCOL, to refuse any transport but https/ssh."""
    from unittest.mock import MagicMock

    import warren.git.manager as manager_module

    captured_env: dict = {}

    def _fake_clone_from(url, path, env=None, **kwargs):
        captured_env.update(env or {})
        return MagicMock(git=MagicMock())

    monkeypatch.setattr(manager_module.Repo, "clone_from", staticmethod(_fake_clone_from))

    mgr = GitManager(worktree_root)
    mgr._clone_sync("https://github.com/o/r.git", worktree_root / "ws-env", None, None)

    assert captured_env["GIT_ALLOW_PROTOCOL"] == "https:ssh"
