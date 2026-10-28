"""EBS bare seeds in git-materialize.sh, run for real against local file:// repos (no
network): the seed-refresh task's refresh-seed mode, and a workspace's git-init cloning
from a restored seed (runtime/ebs_seeds.py)."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest
from warren.runtime.ebs_seeds import seed_key

from .test_ecs_git import SCRIPT, _git

needs_git = pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")
TOKEN = "ghp_seedsupersecrettoken42"


def _commit(repo: Path, name: str, text: str) -> str:
    (repo / name).write_text(text)
    _git("add", ".", cwd=repo)
    _git("commit", "-m", name, cwd=repo)
    return _git("rev-parse", "HEAD", cwd=repo)


@pytest.fixture
def upstream(tmp_path):
    src = tmp_path / "remotes" / "Org" / "App"
    src.mkdir(parents=True)
    _git("init", cwd=src)
    _commit(src, "README", "v1\n")
    _git("checkout", "-b", "trunk", cwd=src)
    _git("checkout", "main", cwd=src)
    return src


@pytest.fixture
def other(tmp_path):
    src = tmp_path / "remotes" / "org" / "lib"
    src.mkdir(parents=True)
    _git("init", cwd=src)
    _commit(src, "LIB", "lib\n")
    return src


def _env(root, **env):
    return {
        "PATH": os.environ["PATH"],
        "WARREN_GIT_ROOT": str(root),
        "WARREN_GIT_ALLOW_PROTOCOL": "file",
        **env,
    }


def _refresh(root, repos, check=True, **env):
    """repos: [(url, cred_kind, cred_env)]"""
    records = "\n".join("\t".join([seed_key(u) or "x/y", u, ck, ce]) for u, ck, ce in repos)
    return subprocess.run(
        ["sh", str(SCRIPT)],
        env=_env(root, WARREN_GIT_MODE="refresh-seed", WARREN_GIT_SEED_REPOS=records, **env),
        capture_output=True, text=True, check=False,
    )


def _materialize(root, records, **env):
    return subprocess.run(
        ["sh", str(SCRIPT)],
        env=_env(root, WARREN_GIT_FOLDERS="\n".join("\t".join(r) for r in records), **env),
        capture_output=True, text=True, check=True,
    )


def _wt(url, branch="main", cred=("none", "-")):
    return ["worktree", "app", "code/app", url, branch, "warren/dev/abcdef12/code-app", *cred]


def _cl(url, branch="main", cred=("none", "-")):
    return ["clone", "app", "refs/app", url, branch, "-", *cred]


def _bare(root: Path, url: str) -> Path:
    return root / ".warren-bares" / f"{seed_key(url)}.git"


def _no_token_anywhere(root: Path) -> None:
    for p in root.rglob("*"):
        if p.is_file() and not p.is_symlink():
            assert TOKEN.encode() not in p.read_bytes(), p


# --- seed keys -----------------------------------------------------------------------

URLS = [
    "https://github.com/Org/Repo.git",
    "https://x-access-token@github.com/org/repo/",
    "git@github.com:org/repo.git",
    "ssh://git@github.com/org/sub/repo.git",
    "file:///tmp/remotes/Org/App",
    "https://github.com:443/org/repo",
    "https://github.com/org/../repo",
    "https://github.com/org/.hidden",
    "https://github.com/org/x.git/repo",
    "https://github.com/repo",
    "http://github.com/org/repo",
    "https://github.com/org/re po",
    "https://github.com/org//repo",
    "github.com/org/repo",
    "",
]


@pytest.mark.parametrize("url", URLS)
def test_seed_key_matches_the_shell(url):
    out = subprocess.run(["sh", str(SCRIPT), "--seed-key", url], capture_output=True, text=True, env={"PATH": os.environ["PATH"]})
    shell = out.stdout.strip() if out.returncode == 0 else None
    assert seed_key(url) == (shell or None)


def test_seed_key_examples():
    assert seed_key("https://github.com/Org/Repo.git") == "github.com/org/repo"
    assert seed_key("git@github.com:org/repo.git") == "github.com/org/repo"
    assert seed_key("https://github.com:443/org/repo") is None
    assert seed_key("https://github.com/org/../repo") is None


# --- refresh-seed ----------------------------------------------------------------------


@needs_git
def test_refresh_seed_mirrors_updates_and_drops(tmp_path, upstream, other):
    root = tmp_path / "seedvol"
    url, lib = f"file://{upstream}", f"file://{other}"
    r = _refresh(root, [(url, "pat", "MY_PAT"), (lib, "none", "-")], MY_PAT=TOKEN)
    assert r.returncode == 0, r.stderr
    bare = _bare(root, url)
    assert bare.is_dir(), (r.stderr, sorted(str(p) for p in root.rglob("*.git")))
    assert _git("rev-parse", "--is-bare-repository", cwd=bare) == "true"
    assert _git("rev-parse", "refs/heads/trunk", cwd=bare) == _git("rev-parse", "trunk", cwd=upstream)
    assert _git("config", "--get", "core.hooksPath", cwd=bare) == "/dev/null"

    new = _commit(upstream, "NEW", "x\n")
    (root / "stray.txt").write_text("planted\n")
    (root / ".warren-bares" / "junk").write_text("junk\n")
    r = _refresh(root, [(url, "pat", "MY_PAT")], MY_PAT=TOKEN)
    assert r.returncode == 0, r.stderr
    assert _git("rev-parse", "refs/heads/main", cwd=bare) == new
    assert not _bare(root, lib).exists()  # not listed any more
    assert not (root / "stray.txt").exists()
    assert not (root / ".warren-bares" / "junk").exists()
    _no_token_anywhere(root)


@needs_git
def test_refresh_seed_partial_failure_keeps_the_rest_and_exits_3(tmp_path, upstream):
    root = tmp_path / "seedvol"
    url = f"file://{upstream}"
    r = _refresh(root, [(url, "none", "-"), (f"file://{tmp_path}/missing/repo", "none", "-")])
    assert r.returncode == 3
    assert _bare(root, url).is_dir()


@needs_git
def test_refresh_seed_rejects_a_key_that_is_not_its_urls(tmp_path, upstream):
    root = tmp_path / "seedvol"
    url = f"file://{upstream}"
    records = "\t".join(["evil/elsewhere", url, "none", "-"])
    r = subprocess.run(
        ["sh", str(SCRIPT)],
        env=_env(root, WARREN_GIT_MODE="refresh-seed", WARREN_GIT_SEED_REPOS=records),
        capture_output=True, text=True,
    )
    assert r.returncode == 3
    assert "key does not match" in r.stderr
    assert not (root / ".warren-bares" / "evil").exists()


@needs_git
def test_refresh_seed_starts_over_when_the_seed_holds_symlinks(tmp_path, upstream):
    root = tmp_path / "seedvol"
    url = f"file://{upstream}"
    assert _refresh(root, [(url, "none", "-")]).returncode == 0
    (root / ".warren-bares" / "link").symlink_to(tmp_path)
    r = _refresh(root, [(url, "none", "-")])
    assert r.returncode == 0 and "starting it over" in r.stderr
    assert _bare(root, url).is_dir() and not (root / ".warren-bares" / "link").exists()


# --- seeded materialize ----------------------------------------------------------------


def _seeded_volume(tmp_path, url, *urls) -> Path:
    root = tmp_path / "vol"
    r = _refresh(root, [(u, "none", "-") for u in (url, *urls)])
    assert r.returncode == 0, r.stderr
    return root


def _pack_inodes(git_dir: Path) -> set[int]:
    return {p.stat().st_ino for p in (git_dir / "objects").rglob("*") if p.is_file() and p.suffix in (".pack", "")}


@needs_git
def test_seeded_worktree_clones_from_the_seed_and_fetches_the_delta(tmp_path, upstream, other):
    url = f"file://{upstream}"
    root = _seeded_volume(tmp_path, url, f"file://{other}")
    seed_inodes = _pack_inodes(_bare(root, url))
    new = _commit(upstream, "AFTER", "after seed\n")

    r = _materialize(root, [_wt(url, cred=("pat", "MY_PAT"))], WARREN_GIT_SEEDED="1", MY_PAT=TOKEN)

    assert "cloned from the seed" in r.stderr and "0 failed" in r.stderr, r.stderr
    store = root / "git" / "app.git-store"
    target = root / "workspace" / "code" / "app"
    assert _git("rev-parse", "HEAD", cwd=target) == new
    assert (target / "AFTER").read_text() == "after seed\n"
    assert _git("remote", "get-url", "origin", cwd=store) == url
    assert _git("config", "--get", "core.hooksPath", cwd=store) == "/dev/null"
    # The seed's objects were hardlinked, not copied, and the seed is gone from the volume.
    assert seed_inodes & _pack_inodes(store)
    assert not (root / ".warren-bares").exists() and not (root / ".warren-stage").exists()
    _no_token_anywhere(root)


@needs_git
def test_seeded_clone_folder_matches_a_network_clone(tmp_path, upstream):
    url = f"file://{upstream}"
    root = _seeded_volume(tmp_path, url)
    new = _commit(upstream, "AFTER", "x\n")
    _git("checkout", "trunk", cwd=upstream)
    trunk = _commit(upstream, "TRUNK", "t\n")
    _git("checkout", "main", cwd=upstream)

    r = _materialize(root, [_cl(url, branch="trunk")], WARREN_GIT_SEEDED="1")

    assert "cloned from the seed" in r.stderr, r.stderr
    target = root / "workspace" / "refs" / "app"
    assert _git("rev-parse", "HEAD", cwd=target) == trunk
    assert _git("branch", "--show-current", cwd=target) == "trunk"
    assert _git("branch", "--format=%(refname:short)", cwd=target) == "trunk"
    assert _git("rev-parse", "origin/main", cwd=target) == new
    assert _git("remote", "get-url", "origin", cwd=target) == url
    assert _git("remote", "get-url", "--push", "origin", cwd=target) == "no_push"
    assert _git("rev-parse", "--abbrev-ref", "trunk@{upstream}", cwd=target) == "origin/trunk"
    assert not (root / ".warren-bares").exists()


@needs_git
def test_a_seed_on_an_unseeded_launch_is_deleted_unread(tmp_path, upstream):
    url = f"file://{upstream}"
    root = _seeded_volume(tmp_path, url)
    r = _materialize(root, [_wt(url)])  # no WARREN_GIT_SEEDED: e.g. a planted directory
    assert "cloned from the seed" not in r.stderr
    assert (root / "workspace" / "code" / "app" / "README").exists()
    assert not (root / ".warren-bares").exists()


@needs_git
def test_a_volume_with_more_than_the_seed_does_not_use_it(tmp_path, upstream):
    url = f"file://{upstream}"
    root = _seeded_volume(tmp_path, url)
    (root / "workspace").mkdir()
    r = _materialize(root, [_wt(url)], WARREN_GIT_SEEDED="1")
    assert "more than its seed" in r.stderr
    assert "cloned from the seed" not in r.stderr
    assert (root / "workspace" / "code" / "app" / "README").exists()


def _probe(tmp_path, name):
    prog = tmp_path / f"{name}.sh"
    prog.write_text(f"#!/bin/sh\nenv > {tmp_path}/ran-{name}\ncat\n")
    prog.chmod(0o755)
    return prog


@needs_git
def test_a_seed_bare_with_planted_config_runs_nothing(tmp_path, upstream):
    url = f"file://{upstream}"
    root = _seeded_volume(tmp_path, url)
    bare = _bare(root, url)
    with (bare / "config").open("a") as f:
        f.write(
            f"[core]\n\tsshCommand = {_probe(tmp_path, 'ssh')}\n\tfsmonitor = {_probe(tmp_path, 'fsmon')}\n"
            f'[remote "origin"]\n\tuploadpack = {_probe(tmp_path, "up")}\n'
            f"[uploadpack]\n\tpackObjectsHook = {_probe(tmp_path, 'hook')}\n"
        )
    hook = bare / "hooks" / "post-checkout"
    hook.parent.mkdir(exist_ok=True)
    hook.write_text(f"#!/bin/sh\ntouch {tmp_path}/ran-hook\n")
    hook.chmod(0o755)

    r = _materialize(root, [_wt(url, cred=("pat", "MY_PAT"))], WARREN_GIT_SEEDED="1", MY_PAT=TOKEN)

    assert "cloned from the seed" in r.stderr, r.stderr
    assert list(tmp_path.glob("ran-*")) == []
    assert "sshCommand" not in (root / "git" / "app.git-store" / "config").read_text()


@pytest.mark.parametrize("damage", ["remote", "symlink", "alternates", "not-bare"])
@needs_git
def test_a_bad_seed_bare_falls_back_to_a_network_clone(tmp_path, upstream, damage):
    url = f"file://{upstream}"
    root = _seeded_volume(tmp_path, url)
    bare = _bare(root, url)
    if damage == "remote":
        _git("config", "remote.origin.url", f"file://{tmp_path}/elsewhere/repo", cwd=bare)
    elif damage == "symlink":
        (bare / "refs" / "evil").symlink_to(tmp_path)
    elif damage == "alternates":
        (bare / "objects" / "info").mkdir(exist_ok=True)
        (bare / "objects" / "info" / "alternates").write_text(f"{tmp_path}\n")
    else:
        (bare / "HEAD").unlink()

    r = _materialize(root, [_wt(url)], WARREN_GIT_SEEDED="1")

    assert "cloned from the seed" not in r.stderr
    assert "0 failed" in r.stderr, r.stderr
    assert (root / "workspace" / "code" / "app" / "README").read_text() == "v1\n"
    assert not (root / ".warren-bares").exists()


@needs_git
def test_a_repo_missing_from_the_seed_is_cloned_over_the_network(tmp_path, upstream, other):
    root = _seeded_volume(tmp_path, f"file://{other}")
    r = _materialize(root, [_wt(f"file://{upstream}")], WARREN_GIT_SEEDED="1")
    assert "cloned from the seed" not in r.stderr and "0 failed" in r.stderr
    assert (root / "workspace" / "code" / "app" / "README").exists()


@needs_git
def test_a_seeded_fetch_that_fails_falls_back_and_never_fails_the_workspace(tmp_path, upstream):
    url = f"file://{upstream}"
    root = _seeded_volume(tmp_path, url)
    r = _materialize(root, [_cl(url, branch="no-such-branch"), _wt(url)], WARREN_GIT_SEEDED="1")
    assert "seeded clone failed" in r.stderr
    assert r.returncode == 0
    assert (root / "workspace" / "code" / "app" / "README").exists()


# --- WARREN_GIT_CLONE_FILTER -------------------------------------------------------------


@pytest.mark.parametrize("record", [_wt, _cl])
@needs_git
def test_blobless_clone_materializes_with_its_checkout_blobs(tmp_path, upstream, record):
    _git("config", "uploadpack.allowFilter", "true", cwd=upstream)
    _git("config", "uploadpack.allowAnySHA1InWant", "true", cwd=upstream)
    _commit(upstream, "BIG", "b" * 1000 + "\n")
    root = tmp_path / "vol"
    r = _materialize(root, [record(f"file://{upstream}")], WARREN_GIT_CLONE_FILTER="blob:none")
    assert "0 failed" in r.stderr, r.stderr
    mount = "code/app" if record is _wt else "refs/app"
    target = root / "workspace" / mount
    assert (target / "BIG").read_text().startswith("bbb")
    git_dir = root / "git" / "app.git-store" if record is _wt else target / ".git"
    assert _git("config", "--get", "remote.origin.partialclonefilter", cwd=git_dir) == "blob:none"


@needs_git
def test_an_unknown_clone_filter_is_ignored(tmp_path, upstream):
    root = tmp_path / "vol"
    r = _materialize(root, [_wt(f"file://{upstream}")], WARREN_GIT_CLONE_FILTER="sparse:oid=x")
    assert "0 failed" in r.stderr
    store = root / "git" / "app.git-store"
    out = subprocess.run(["git", "config", "--get", "remote.origin.promisor"], cwd=store, capture_output=True, text=True)
    assert out.stdout.strip() == ""
