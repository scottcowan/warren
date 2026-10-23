"""GitManager clone/pull unit tests (Phase 4 Plan 06, LIFE-03).

All behaviors from 04-06-PLAN.md Task 1 are covered against a local file-URL source
repository built fresh per test in `tmp_path` -- no network or GitHub access required.
Credential-bearing clones use a stub credentials object (AsyncMock `token()`, and a
`clone_url()` that mirrors the real `GitHubAppCredentials.clone_url()` urlsplit/urlunsplit
logic) so the resulting `file://x-access-token:<token>@<path>` URL is a real, clonable
local git URL -- this lets the "never persisted" assertions read the actual `.git/config`
file on disk rather than mocking git internals.
"""

from __future__ import annotations

import os
import subprocess
import tempfile
import time
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock
from urllib.parse import urlsplit, urlunsplit

import pytest
from git import GitCommandError, Repo

import warren.git.manager as manager_module
from warren.git.manager import (
    GitError,
    GitManager,
    GitPullError,
    _sanitize,
    _url_with_askpass_username,
)
from warren.git.github_app import GitHubAuthError


def _stub_clone_url(repo_url: str, token: str) -> str:
    """Mirror GitHubAppCredentials.clone_url()'s urlsplit/urlunsplit shape exactly."""
    parsed = urlsplit(repo_url)
    netloc = f"x-access-token:{token}@{parsed.netloc}"
    return urlunsplit((parsed.scheme, netloc, parsed.path, parsed.query, parsed.fragment))


def _make_credentials(
    token: str = "secret-installation-token", credential_host: str | None = None
) -> SimpleNamespace:
    # credential_host=None matches urlsplit("file://...").hostname (no netloc),
    # which is what every local fixture repo in this module uses -- the real
    # GitHubAppCredentials.credential_host (git/test_github_app.py) is always a
    # real hostname, never None, so this default never matches a URL outside
    # these file:// fixtures.
    return SimpleNamespace(
        token=AsyncMock(return_value=token),
        clone_url=_stub_clone_url,
        credential_host=credential_host,
    )


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


@pytest.fixture(autouse=True)
def _allow_file_urls(monkeypatch):
    """This module clones from local `file://` fixture repos for every test, to
    avoid any real network dependency -- production code (issue #10) allows
    only https/ssh clone URLs. Bypass that check here so the pre-existing
    functional tests keep exercising real git clone/pull behavior against a
    local repo; the scheme allow-list itself is covered on its own merits in
    test_git_url_security.py, unpatched.
    """
    import warren.git.manager as manager_module

    monkeypatch.setattr(manager_module, "_validate_clone_url", lambda repo_url: None)
    # Git itself also refuses the `file` transport once GIT_ALLOW_PROTOCOL is
    # set (the git-level half of issue #10's defense in depth) -- these local
    # fixture repos need that relaxed for the same reason as the line above.
    monkeypatch.setattr(manager_module, "_GIT_ALLOW_PROTOCOL_ENV", {})


async def test_clone_creates_worktree_and_returns_path(worktree_root, source_repo):
    mgr = GitManager(worktree_root)
    path = await mgr.clone("ws-1", _file_url(source_repo))

    assert path == worktree_root / "ws-1"
    assert (path / "file.txt").read_text() == "hello"
    assert (path / ".git").exists()


async def test_clone_idempotent_on_existing_worktree(worktree_root, source_repo):
    mgr = GitManager(worktree_root)
    path = await mgr.clone("ws-2", _file_url(source_repo))

    # Simulate local, uncommitted work that a re-clone must never destroy.
    (path / "local_only.txt").write_text("keep me")

    path2 = await mgr.clone("ws-2", _file_url(source_repo))

    assert path2 == path
    assert (path / "local_only.txt").read_text() == "keep me"


async def test_clone_with_ref_checks_out_ref(worktree_root, source_repo):
    repo = Repo(source_repo)
    repo.git.checkout("-b", "feature")
    (source_repo / "feature.txt").write_text("feature file")
    repo.index.add(["feature.txt"])
    feature_commit = repo.index.commit("feature commit")
    repo.git.checkout("main")

    mgr = GitManager(worktree_root)
    path = await mgr.clone("ws-3", _file_url(source_repo), ref="feature")

    assert (path / "feature.txt").exists()
    cloned = Repo(path)
    assert cloned.head.commit.hexsha == feature_commit.hexsha


async def test_clone_private_repo_requests_token_and_uses_credentialed_url(
    worktree_root, source_repo
):
    creds = _make_credentials(token="tok-abc123")
    mgr = GitManager(worktree_root, credentials=creds)

    path = await mgr.clone("ws-4", _file_url(source_repo))

    creds.token.assert_awaited_once()
    assert (path / "file.txt").read_text() == "hello"


async def test_clone_with_pat_clones_without_any_github_app_credentials(
    worktree_root, source_repo
):
    """GITHUB_PAT -- a plain personal access token -- is the simpler,
    caller-supplied alternative to a GitHub App installation: no
    `self.credentials` needed at all."""
    mgr = GitManager(worktree_root)  # no credentials configured

    path = await mgr.clone("ws-pat", _file_url(source_repo), pat="ghp_faketoken")

    assert (path / "file.txt").read_text() == "hello"


async def test_clone_pat_takes_priority_over_github_app_credentials(
    worktree_root, source_repo
):
    """When both a caller-supplied pat and self.credentials could apply to the
    same HTTPS clone, pat wins -- it's the caller's own explicit secret, not
    warren-server's own app-wide fallback."""
    creds = _make_credentials(token="should-not-be-used")
    mgr = GitManager(worktree_root, credentials=creds)

    await mgr.clone("ws-pat-priority", _file_url(source_repo), pat="ghp_faketoken")

    creds.token.assert_not_awaited()


async def test_clone_never_persists_token_in_git_config(worktree_root, source_repo):
    """Issue #11: the ACTUAL TOKEN must never touch .git/config (or any file,
    or argv) — that's the security property. The fixed, non-secret
    "x-access-token" USERNAME marker is expected to persist permanently in
    the origin URL now (see _url_with_askpass_username's docstring): it
    identifies the auth scheme, not a credential, and leaving it there is
    what lets a later pull() reuse the same origin URL without ever
    rewriting .git/config again (removing the old "concurrent pulls" race
    entirely, not just narrowing its window)."""
    creds = _make_credentials(token="tok-should-not-leak")
    mgr = GitManager(worktree_root, credentials=creds)

    path = await mgr.clone("ws-5", _file_url(source_repo))

    config_text = (path / ".git" / "config").read_text()
    assert "tok-should-not-leak" not in config_text
    cloned = Repo(path)
    origin_url = next(iter(cloned.remotes.origin.urls))
    assert origin_url == _url_with_askpass_username(_file_url(source_repo))


async def test_pull_returns_new_head_sha(worktree_root, source_repo):
    mgr = GitManager(worktree_root)
    path = await mgr.clone("ws-6", _file_url(source_repo))

    # Advance the upstream source repo past the cloned HEAD.
    (source_repo / "file2.txt").write_text("second file")
    upstream = Repo(source_repo)
    upstream.index.add(["file2.txt"])
    new_commit = upstream.index.commit("second commit")

    sha = await mgr.pull("ws-6")

    assert sha == new_commit.hexsha
    assert (path / "file2.txt").exists()


async def test_pull_missing_worktree_raises_git_pull_error(worktree_root):
    mgr = GitManager(worktree_root)

    with pytest.raises(GitPullError):
        await mgr.pull("never-cloned")


async def test_clone_failure_raises_git_error_not_raw_exception(worktree_root, tmp_path):
    mgr = GitManager(worktree_root)
    nonexistent = tmp_path / "does-not-exist"

    with pytest.raises(GitError) as exc_info:
        await mgr.clone("ws-7", _file_url(nonexistent))

    assert not isinstance(exc_info.value, GitCommandError)


async def test_clone_timeout_raises_git_error_not_hang(worktree_root, monkeypatch):
    """A clone that never returns (e.g. a credential helper blocking on its
    own network call with no attached terminal to prompt on) must raise
    GitError within the bounded timeout, not hang the caller forever --
    real failure observed 2026-10-13: a stuck unauthenticated clone blocked
    an entire multi-folder provision for minutes."""
    import warren.git.manager as manager_module

    monkeypatch.setattr(manager_module, "_CLONE_TIMEOUT_S", 0.05)

    def _hang(*args, **kwargs):
        import time

        time.sleep(10)

    monkeypatch.setattr(GitManager, "_clone_sync", _hang)

    mgr = GitManager(worktree_root)
    with pytest.raises(GitError, match="timed out"):
        await mgr.clone("ws-timeout", "https://example.invalid/org/repo.git")


async def test_pull_failure_raises_git_pull_error_not_raw_exception(
    worktree_root, source_repo
):
    mgr = GitManager(worktree_root)
    path = await mgr.clone("ws-8", _file_url(source_repo))

    # Corrupt the remote so fetch fails at the git layer, not at the
    # missing-worktree check.
    cloned = Repo(path)
    with cloned.config_writer() as cw:
        cw.set_value('remote "origin"', "url", str(worktree_root / "nonexistent-upstream"))

    with pytest.raises(GitPullError) as exc_info:
        await mgr.pull("ws-8")

    assert not isinstance(exc_info.value, GitCommandError)


def test_sanitize_scrubs_token_from_realistic_git_command_error_message():
    raw = (
        "Cmd('git') failed due to: exit code(128)\n"
        "  cmdline: git fetch https://x-access-token:ghs_liveTokenValue123@github.com/o/r.git\n"
        "  stderr: 'fatal: Authentication failed for "
        "'https://x-access-token:ghs_liveTokenValue123@github.com/o/r.git/''"
    )
    cleaned = _sanitize(raw)

    assert "ghs_liveTokenValue123" not in cleaned
    assert "x-access-token:***@" in cleaned


def test_askpass_env_script_echoes_token_and_is_cleaned_up():
    """Issue #11: the GIT_ASKPASS script must actually supply the token when
    invoked, be owner-only (0700), and be removed once the context exits —
    it must never linger on disk after the git operation it was created for."""
    import os
    import stat
    import subprocess

    from warren.git.manager import _askpass_env

    with _askpass_env("tok-xyz") as env:
        script_path = env["GIT_ASKPASS"]
        assert os.path.exists(script_path)
        mode = stat.S_IMODE(os.stat(script_path).st_mode)
        assert mode == stat.S_IRWXU  # 0700, owner rwx only

        result = subprocess.run(
            [script_path],
            env={**os.environ, "WARREN_GIT_ASKPASS_TOKEN": "tok-xyz"},
            capture_output=True,
            text=True,
        )
        assert result.stdout.strip() == "tok-xyz"

    assert not os.path.exists(script_path)


async def test_pull_preserves_uncommitted_local_changes_on_clean_fast_forward(
    worktree_root, source_repo
):
    """Regression for issue #11: pull() must not use `reset --hard` — an
    uncommitted local edit to a file the upstream commit doesn't touch must
    survive a clean fast-forward pull, not be silently discarded."""
    mgr = GitManager(worktree_root)
    path = await mgr.clone("ws-9", _file_url(source_repo))

    (path / "local_uncommitted.txt").write_text("my local work")

    (source_repo / "upstream_only.txt").write_text("upstream change")
    upstream = Repo(source_repo)
    upstream.index.add(["upstream_only.txt"])
    upstream.index.commit("upstream commit")

    await mgr.pull("ws-9")

    assert (path / "local_uncommitted.txt").read_text() == "my local work"
    assert (path / "upstream_only.txt").exists()


async def test_pull_raises_instead_of_discarding_diverged_local_commit(
    worktree_root, source_repo
):
    """Regression for issue #11: when the worktree has a local commit the
    upstream doesn't have, a fast-forward is impossible — pull() must raise
    (GitPullError), not silently reset --hard and destroy that commit."""
    mgr = GitManager(worktree_root)
    path = await mgr.clone("ws-10", _file_url(source_repo))

    cloned = Repo(path)
    (path / "local_commit.txt").write_text("local work")
    cloned.index.add(["local_commit.txt"])
    local_commit = cloned.index.commit("local commit that diverges from upstream")

    (source_repo / "upstream_only.txt").write_text("upstream change")
    upstream = Repo(source_repo)
    upstream.index.add(["upstream_only.txt"])
    upstream.index.commit("upstream commit")

    with pytest.raises(GitPullError):
        await mgr.pull("ws-10")

    # The local commit must still be there — not blown away by reset --hard.
    assert cloned.head.commit.hexsha == local_commit.hexsha
    assert (path / "local_commit.txt").read_text() == "local work"


def test_workspace_id_path_traversal_rejected(worktree_root):
    mgr = GitManager(worktree_root)

    with pytest.raises(GitError):
        mgr.worktree_path("../escape")

    # Confirm nothing was written outside worktree_root.
    assert not (worktree_root.parent / "escape").exists()


@pytest.mark.parametrize(
    "repo_url,expected",
    [
        ("git@bitbucket.org:dotmusic/whmcs.git", True),
        ("git@github.com:scottcowan/warren.git", True),
        ("ssh://git@bitbucket.org/dotmusic/whmcs.git", True),
        ("https://github.com/scottcowan/warren.git", False),
        ("https://x-access-token:tok@github.com/o/r.git", False),
        ("file:///tmp/some/repo", False),
    ],
)
def test_is_ssh_url_classifies_transport(repo_url, expected):
    from warren.git.manager import _is_ssh_url

    assert _is_ssh_url(repo_url) is expected


def test_ssh_key_env_writes_0600_key_file_and_is_cleaned_up():
    """The SSH analog of _askpass_env: the key must land in a private,
    owner-only (0600) temp file referenced by GIT_SSH_COMMAND, and that file
    must be gone once the context exits — it must never linger on disk."""
    import os
    import stat

    from warren.git.manager import _ssh_key_env

    key_text = "-----BEGIN OPENSSH PRIVATE KEY-----\nFAKEKEYDATA\n-----END OPENSSH PRIVATE KEY-----"
    known_hosts_path = Path(tempfile.mkdtemp(prefix="warren-test-known-hosts-")) / "known_hosts"

    with _ssh_key_env(key_text, known_hosts_path) as env:
        ssh_command = env["GIT_SSH_COMMAND"]
        assert "IdentitiesOnly=yes" in ssh_command
        assert "StrictHostKeyChecking=accept-new" in ssh_command
        assert f"UserKnownHostsFile={known_hosts_path}" in ssh_command

        key_path = ssh_command.split("-i ", 1)[1].split(" ", 1)[0]
        assert os.path.exists(key_path)
        mode = stat.S_IMODE(os.stat(key_path).st_mode)
        assert mode == stat.S_IRUSR | stat.S_IWUSR  # 0600, owner read/write only
        assert Path(key_path).read_text().strip() == key_text

    assert not os.path.exists(key_path)


def test_clone_sync_uses_ssh_key_env_for_ssh_remote(monkeypatch, worktree_root):
    """GitManager._clone_sync routes an SSH remote + ssh_key through
    _ssh_key_env, never through _askpass_env — the two transports are
    mutually exclusive per URL."""
    from unittest.mock import MagicMock

    import warren.git.manager as manager_module

    captured_env: dict = {}

    def _fake_clone_from(url, path, env=None, **kwargs):
        captured_env.update(env or {})
        return MagicMock(git=MagicMock())

    monkeypatch.setattr(manager_module.Repo, "clone_from", staticmethod(_fake_clone_from))

    mgr = GitManager(worktree_root)
    mgr._clone_sync(
        "git@bitbucket.org:dotmusic/whmcs.git",
        worktree_root / "ws-ssh",
        None,
        None,
        ssh_key="fake-key-contents",
    )

    assert "GIT_SSH_COMMAND" in captured_env
    assert "GIT_ASKPASS" not in captured_env


def test_clone_sync_ignores_ssh_key_for_https_remote(monkeypatch, worktree_root):
    """An ssh_key passed alongside an HTTPS repo_url is simply unused — HTTPS
    auth goes through self.credentials/_askpass_env instead, never SSH."""
    from unittest.mock import MagicMock

    import warren.git.manager as manager_module

    captured_env: dict = {}

    def _fake_clone_from(url, path, env=None, **kwargs):
        captured_env.update(env or {})
        return MagicMock(git=MagicMock())

    monkeypatch.setattr(manager_module.Repo, "clone_from", staticmethod(_fake_clone_from))

    mgr = GitManager(worktree_root)
    # clone()'s own logic (not exercised here) is what decides ssh_key gets
    # passed as None for an HTTPS url in the first place (use_ssh_key check);
    # _clone_sync itself has no opinion, so pass None here to match that contract.
    mgr._clone_sync(
        "https://github.com/scottcowan/warren.git",
        worktree_root / "ws-https",
        None,
        None,
        ssh_key=None,
    )

    # Still disables terminal prompts even with no credential at all, so a
    # missing credential helper fails fast instead of hanging (2026-10-13).
    from warren_common.safe_git import safe_git_env

    assert captured_env == {"GIT_TERMINAL_PROMPT": "0", **safe_git_env(isolated=True)}


async def test_clone_passes_ssh_key_through_only_for_ssh_repo_url(monkeypatch, worktree_root):
    """End-to-end through the async clone() wrapper: an ssh_key is threaded
    to _clone_sync for an SSH repo_url (use_ssh_key's _is_ssh_url check)."""
    from unittest.mock import MagicMock

    import warren.git.manager as manager_module

    mgr = GitManager(worktree_root)
    mgr._clone_sync = MagicMock()

    async def _fake_to_thread(fn, *args, **kwargs):
        return fn(*args, **kwargs)

    monkeypatch.setattr(manager_module.asyncio, "to_thread", _fake_to_thread)

    await mgr.clone("ws-ssh-e2e", "git@bitbucket.org:dotmusic/whmcs.git", ssh_key="the-key")

    call_args = mgr._clone_sync.call_args.args
    assert call_args[4] == "the-key"  # ssh_key positional arg


async def test_clone_drops_ssh_key_for_https_repo_url(monkeypatch, worktree_root):
    """The same ssh_key passed alongside an HTTPS repo_url never reaches
    _clone_sync — it would be meaningless there and must never leak into an
    askpass flow."""
    from unittest.mock import MagicMock

    import warren.git.manager as manager_module

    mgr = GitManager(worktree_root)
    mgr._clone_sync = MagicMock()

    async def _fake_to_thread(fn, *args, **kwargs):
        return fn(*args, **kwargs)

    monkeypatch.setattr(manager_module.asyncio, "to_thread", _fake_to_thread)

    await mgr.clone("ws-https-e2e", "https://github.com/scottcowan/warren.git", ssh_key="the-key")

    call_args = mgr._clone_sync.call_args.args
    assert call_args[4] is None  # ssh_key dropped — not an SSH remote


def _plant_hostile(repo_path: Path, tmp_path: Path) -> Path:
    """Simulate a workspace planting every exec-capable key in its clone's
    config (plus hooks and attributes naming the planted drivers)."""
    marker = tmp_path / "pwned"
    script = tmp_path / "evil.sh"
    script.write_text(f'#!/bin/sh\necho "$0 $*" >> {marker}\nexit 1\n')
    script.chmod(0o755)
    hook = repo_path / ".git" / "hooks" / "post-merge"
    hook.parent.mkdir(parents=True, exist_ok=True)
    hook.write_text(f"#!/bin/sh\ntouch {marker}\n")
    hook.chmod(0o755)
    cfg = str(repo_path / ".git" / "config")
    for key, value in {
        "filter.evil.smudge": str(script),
        "filter.evil.clean": str(script),
        "filter.evil.process": str(script),
        "core.sshCommand": str(script),
        "credential.helper": f"!{script}",
        "remote.origin.uploadpack": str(script),
        "diff.external": str(script),
        "diff.evil.textconv": str(script),
        "core.pager": str(script),
        "core.fsmonitor": str(script),
    }.items():
        subprocess.run(["git", "config", "--file", cfg, key, value], check=True)
    (repo_path / ".gitattributes").write_text("* filter=evil diff=evil\n")
    return marker


def _advance_upstream(source_repo: Path) -> str:
    (source_repo / "file.txt").write_text("changed")
    (source_repo / "file2.txt").write_text("second file")
    upstream = Repo(source_repo)
    upstream.index.add(["file.txt", "file2.txt"])
    return upstream.index.commit("second commit").hexsha


async def test_plain_git_pull_runs_planted_config_baseline(worktree_root, source_repo, tmp_path):
    mgr = GitManager(worktree_root)
    path = await mgr.clone("ws-base", _file_url(source_repo))
    marker = _plant_hostile(path, tmp_path)
    _advance_upstream(source_repo)
    subprocess.run(["git", "-C", str(path), "pull", "--ff-only"], capture_output=True, timeout=30)
    assert marker.exists()


async def test_pull_ignores_workspace_planted_config(worktree_root, source_repo, tmp_path):
    """BB7/BB12: host-side fetch + fast-forward never reads the clone's config."""
    mgr = GitManager(worktree_root)
    path = await mgr.clone("ws-hooks", _file_url(source_repo))
    marker = _plant_hostile(path, tmp_path)
    new_sha = _advance_upstream(source_repo)

    sha = await mgr.pull("ws-hooks")

    assert sha == new_sha
    assert (path / "file2.txt").read_text() == "second file"
    assert not marker.exists()
    # The planted config itself is left alone; host git just never reads it.
    assert "evil" in (path / ".git" / "config").read_text()


async def test_reclone_check_ignores_workspace_planted_config(worktree_root, source_repo, tmp_path):
    mgr = GitManager(worktree_root)
    path = await mgr.clone("ws-verify", _file_url(source_repo))
    marker = _plant_hostile(path, tmp_path)

    assert await mgr.clone("ws-verify", _file_url(source_repo)) == path
    assert not marker.exists()


async def test_clone_with_ref_checkout_ignores_planted_attributes(
    worktree_root, source_repo, tmp_path, monkeypatch
):
    """The post-clone `checkout <ref>` runs through the shadow git dir too."""
    first = Repo(source_repo).head.commit.hexsha
    _advance_upstream(source_repo)
    planted: list[Path] = []
    orig = GitManager._checkout_ref

    def plant_then_checkout(self, path, clone_url, ref):
        planted.append(_plant_hostile(path, tmp_path))
        orig(self, path, clone_url, ref)

    monkeypatch.setattr(GitManager, "_checkout_ref", plant_then_checkout)
    path = await GitManager(worktree_root).clone("ws-ref", _file_url(source_repo), ref=first)
    assert Repo(path).head.commit.hexsha == first
    assert not planted[0].exists()


def _has_object(git_dir: Path, sha: str, objects: Path | None = None) -> bool:
    env = {**os.environ, "GIT_OBJECT_DIRECTORY": str(objects)} if objects else None
    return subprocess.run(
        ["git", f"--git-dir={git_dir}", "cat-file", "-e", sha], capture_output=True, env=env
    ).returncode == 0


async def test_pull_objects_swapped_mid_fetch_never_touch_other_store(
    worktree_root, source_repo, monkeypatch
):
    """A workspace swapping `.git/objects` for a symlink to another
    workspace's store while host git runs can't redirect git's reads or
    writes there: git only ever sees warren's linked copy."""
    mgr = GitManager(worktree_root)
    a = await mgr.clone("ws-a", _file_url(source_repo))
    b = await mgr.clone("ws-b", _file_url(source_repo))
    new_sha = _advance_upstream(source_repo)
    moved = a / ".git" / "objects-moved"
    real_run_git = manager_module.run_git

    def swap_then_run(*args, **kwargs):
        if args[0] == "fetch" and not moved.exists():
            os.rename(a / ".git" / "objects", moved)
            (a / ".git" / "objects").symlink_to(b / ".git" / "objects")
        return real_run_git(*args, **kwargs)

    monkeypatch.setattr(manager_module, "run_git", swap_then_run)

    assert await mgr.pull("ws-a") == new_sha
    assert not _has_object(b / ".git", new_sha)
    assert _has_object(a / ".git", new_sha, objects=moved)


async def test_pull_timeout_kills_git_and_raises_git_pull_error(
    worktree_root, source_repo, monkeypatch
):
    mgr = GitManager(worktree_root)
    path = await mgr.clone("ws-slow", _file_url(source_repo))
    subprocess.run(
        ["git", "config", "--file", str(path / ".git" / "config"),
         "remote.origin.url", "ssh://example.invalid/org/repo.git"],
        check=True,
    )
    monkeypatch.setenv("GIT_SSH_COMMAND", "sleep 30; true")
    monkeypatch.setattr(manager_module, "_PULL_TIMEOUT_S", 0.5)

    started = time.monotonic()
    with pytest.raises(GitPullError, match=r"timed out after 0\.5s"):
        await mgr.pull("ws-slow")
    assert time.monotonic() - started < 10


async def _root_and_folder(mgr: GitManager, source_repo: Path, ws: str) -> tuple[Path, Path]:
    root = await mgr.clone(ws, _file_url(source_repo))
    folder = await mgr.clone_into(mgr.folder_worktree_path(ws, "app"), _file_url(source_repo))
    return root, folder


async def test_folder_clone_not_reachable_through_root_clone(worktree_root, source_repo):
    """The root clone is bind-mounted rw at /workspace; a folder clone inside
    it could be renamed from the workspace while host git checks out into it."""
    mgr = GitManager(worktree_root)
    root, folder = await _root_and_folder(mgr, source_repo, "ws-layout")
    assert folder == mgr.folders_root("ws-layout") / "app"
    assert root not in folder.parents and folder != root
    assert not (root / "app").exists()


async def test_folder_swapped_from_workspace_mid_pull_gets_no_writes(
    worktree_root, source_repo, tmp_path, monkeypatch
):
    """Everything the workspace can write (its root clone mount) is used to
    swap the folder's directory for a symlink to a victim dir right before
    the checkout; the pull's writes still land only in the real folder clone."""
    mgr = GitManager(worktree_root)
    root, folder = await _root_and_folder(mgr, source_repo, "ws-swap")
    victim = tmp_path / "victim"
    victim.mkdir()
    new_sha = _advance_upstream(source_repo)
    real_run_git = manager_module.run_git

    def swap_then_run(*args, **kwargs):
        if args[0] == "merge":
            planted = root / "app"
            if planted.exists():
                os.rename(planted, root / "app-moved")
            planted.symlink_to(victim)
        return real_run_git(*args, **kwargs)

    monkeypatch.setattr(manager_module, "run_git", swap_then_run)

    assert await mgr.pull_at(folder) == new_sha
    assert (folder / "file2.txt").read_text() == "second file"
    assert list(victim.iterdir()) == []


async def test_legacy_nested_folder_migrated_on_provision_and_refused_for_pull(
    worktree_root, source_repo
):
    mgr = GitManager(worktree_root)
    root = await mgr.clone("ws-old", _file_url(source_repo))
    legacy = root / "app"
    Repo.clone_from(_file_url(source_repo), legacy)
    (legacy / "wip.txt").write_text("local work")

    assert mgr.folder_worktree_path("ws-old", "app") == legacy
    with pytest.raises(GitPullError, match="re-provision"):
        await mgr.pull_at(legacy)

    moved = await mgr.clone_into(mgr.folder_worktree_path("ws-old", "app"), _file_url(source_repo))
    assert moved == mgr.folders_root("ws-old") / "app"
    assert (moved / "wip.txt").read_text() == "local work"
    assert not os.path.lexists(legacy)
    assert mgr.folder_worktree_path("ws-old", "app") == moved

    await mgr.remove_worktree("ws-old")
    assert not root.exists() and not mgr.folders_root("ws-old").exists()
