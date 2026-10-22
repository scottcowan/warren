"""BB7/BB12: host-side git must never run programs named by workspace-planted
repo config (hooks, fsmonitor, filters, sshCommand, credential helpers,
uploadpack, external diff/textconv, pager)."""

from __future__ import annotations

import http.server
import os
import stat
import subprocess
import sys
import threading
from pathlib import Path

import pytest

if sys.platform == "win32":
    pytest.skip(
        "safe_git shadows git dirs via dir_fd/O_NOFOLLOW reads: POSIX hosts only",
        allow_module_level=True,
    )

import pty  # noqa: E402

from warren_common.safe_git import (
    SAFE_GIT_CONFIG,
    SafeGitError,
    readonly_shadow_git_dir,
    run_git,
    safe_git_argv,
    safe_git_config,
    safe_git_env,
    shadow_git_dir,
)

_IDENT = ["-c", "user.email=t@t", "-c", "user.name=t"]


def _git(*args: str, cwd: Path | None = None) -> str:
    return subprocess.check_output(["git", *args], cwd=cwd, text=True)


def _evil_script(tmp_path: Path) -> tuple[Path, Path]:
    marker = tmp_path / "pwned"
    script = tmp_path / "evil.sh"
    script.write_text(f'#!/bin/sh\necho "$0 $*" >> {marker}\nexit 1\n')
    script.chmod(script.stat().st_mode | stat.S_IXUSR)
    return script, marker


def plant_hostile(git_dir: Path, work_tree: Path | None, tmp_path: Path) -> Path:
    """Plant every exec-capable repo config key a workspace could write."""
    script, marker = _evil_script(tmp_path)
    hooks = tmp_path / "evil-hooks"
    hooks.mkdir(exist_ok=True)
    for name in ("pre-commit", "post-merge", "post-checkout", "reference-transaction"):
        (hooks / name).write_text(f"#!/bin/sh\necho hook >> {marker}\n")
        (hooks / name).chmod(0o755)
    entries = {
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
        "core.hooksPath": str(hooks),
    }
    for key, value in entries.items():
        _git("config", "--file", str(git_dir / "config"), key, value)
    (git_dir / "info").mkdir(exist_ok=True)
    (git_dir / "info" / "attributes").write_text("* filter=evil diff=evil\n")
    if work_tree is not None:
        (work_tree / ".gitattributes").write_text("* filter=evil diff=evil\n")
    return marker


@pytest.fixture
def upstream(tmp_path: Path) -> Path:
    src = tmp_path / "upstream"
    _git("init", "-q", "-b", "main", str(src))
    (src / "a.txt").write_text("one\n")
    _git("-C", str(src), "add", "a.txt")
    _git("-C", str(src), *_IDENT, "commit", "-qm", "one")
    return src


def _advance(src: Path) -> str:
    (src / "a.txt").write_text("two\n")
    (src / "b.txt").write_text("new\n")
    _git("-C", str(src), "add", ".")
    _git("-C", str(src), *_IDENT, "commit", "-qm", "two")
    return _git("-C", str(src), "rev-parse", "HEAD").strip()


def test_safe_git_argv_pins_exec_keys():
    argv = safe_git_argv("-C", "/r", "status")
    assert argv[0] == "git"
    assert argv[-3:] == ["-C", "/r", "status"]
    for key, value in SAFE_GIT_CONFIG:
        assert f"{key}={value}" in argv
    for key in ("core.hooksPath", "core.fsmonitor", "core.sshCommand", "core.pager",
                "credential.helper", "diff.external"):
        assert key in dict(SAFE_GIT_CONFIG)


def test_operator_global_values_kept_but_after_reset(tmp_path: Path, monkeypatch):
    gcfg = tmp_path / "gitconfig"
    gcfg.write_text('[core]\n\tsshCommand = my-ssh\n[credential]\n\thelper = mine\n'
                    '[credential "https://h.example"]\n\thelper = scoped\n')
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(gcfg))
    pairs = safe_git_config()
    reset = pairs.index(("credential.helper", ""))
    assert pairs.index(("credential.helper", "mine")) > reset
    assert ("credential.https://h.example.helper", "scoped") in pairs
    assert pairs.index(("core.sshcommand", "my-ssh")) > pairs.index(("core.sshCommand", "ssh"))
    assert safe_git_config(isolated=True) == list(SAFE_GIT_CONFIG)


def test_safe_git_env_appends_after_existing_entries():
    env = safe_git_env({"GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "a.b",
                        "GIT_CONFIG_VALUE_0": "c", "PATH": "/bin", "GIT_DIR": "/x"},
                       isolated=True)
    assert env["PATH"] == "/bin"
    assert "GIT_DIR" not in env
    assert env["GIT_CONFIG_KEY_0"] == "a.b"
    assert env["GIT_CONFIG_COUNT"] == str(1 + len(SAFE_GIT_CONFIG))
    pairs = [(env[f"GIT_CONFIG_KEY_{i}"], env[f"GIT_CONFIG_VALUE_{i}"])
             for i in range(1, 1 + len(SAFE_GIT_CONFIG))]
    assert pairs == list(SAFE_GIT_CONFIG)
    assert env["GIT_CONFIG_NOSYSTEM"] == "1"
    assert env["GIT_CONFIG_GLOBAL"] == os.devnull


def test_plain_git_is_exploitable_baseline(tmp_path: Path, upstream: Path):
    """Sanity check that the fixture really is hostile to unhardened git."""
    clone = tmp_path / "clone"
    _git("clone", "-q", str(upstream), str(clone))
    marker = plant_hostile(clone / ".git", clone, tmp_path)
    _advance(upstream)
    subprocess.run(["git", "-C", str(clone), "pull", "-q", "--ff-only"], capture_output=True, timeout=30)
    assert marker.exists()


def test_pins_block_fixed_name_keys_without_shadow(tmp_path: Path, upstream: Path):
    """Defence in depth: the -c pins alone stop the fixed-name keys."""
    clone = tmp_path / "clone"
    _git("clone", "-q", str(upstream), str(clone))
    marker = plant_hostile(clone / ".git", None, tmp_path)
    env = {k: v for k, v in os.environ.items() if k not in ("GIT_SSH_COMMAND", "GIT_SSH")}
    ssh_url = "ssh://127.0.0.1:1/x"
    subprocess.run(["git", "-C", str(clone), "-c", "core.fsmonitor=false", "ls-remote", ssh_url],
                   capture_output=True, env=env, timeout=30)
    assert marker.exists(), "baseline: planted core.sshCommand should run"
    marker.unlink()
    subprocess.run(safe_git_argv("-C", str(clone), "fetch", "--upload-pack=git-upload-pack", "origin"), check=True,
                   capture_output=True)
    subprocess.run(safe_git_argv("-C", str(clone), "ls-remote", ssh_url),
                   capture_output=True, env=env, timeout=30)
    assert not marker.exists()


def test_pins_block_planted_pager(tmp_path: Path, upstream: Path, monkeypatch):
    monkeypatch.delenv("GIT_PAGER", raising=False)
    monkeypatch.delenv("PAGER", raising=False)
    clone = tmp_path / "clone"
    _git("clone", "-q", str(upstream), str(clone))
    marker = plant_hostile(clone / ".git", None, tmp_path)

    def run_on_tty(argv: list[str]) -> None:
        master, slave = pty.openpty()
        try:
            subprocess.run(argv, stdin=slave, stdout=slave, stderr=slave, timeout=30)
        finally:
            os.close(slave)
            os.close(master)

    run_on_tty(["git", "-C", str(clone), "-c", "core.hooksPath=/dev/null",
                "-c", "core.fsmonitor=false", "log", "-1"])
    assert marker.exists(), "baseline: planted core.pager should run on a tty"
    marker.unlink()
    run_on_tty(safe_git_argv("-C", str(clone), "log", "-1"))
    assert not marker.exists()


class _Auth401(http.server.BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        self.send_response(401)
        self.send_header("WWW-Authenticate", 'Basic realm="x"')
        self.end_headers()

    def log_message(self, *args):
        pass


def test_pins_block_planted_credential_helper(tmp_path: Path, upstream: Path):
    server = http.server.HTTPServer(("127.0.0.1", 0), _Auth401)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{server.server_port}/repo.git"
    try:
        clone = tmp_path / "clone"
        _git("clone", "-q", str(upstream), str(clone))
        marker = plant_hostile(clone / ".git", None, tmp_path)
        env = {**os.environ, "GIT_TERMINAL_PROMPT": "0"}
        subprocess.run(["git", "-C", str(clone), "-c", "core.fsmonitor=false",
                        "ls-remote", url], capture_output=True, env=env, timeout=30)
        assert marker.exists(), "baseline: planted credential.helper should run"
        marker.unlink()
        subprocess.run(safe_git_argv("-C", str(clone), "ls-remote", url, isolated=True),
                       capture_output=True, env=env, timeout=30)
        assert not marker.exists()
    finally:
        server.shutdown()


def test_shadow_fetch_and_merge_run_nothing_planted(tmp_path: Path, upstream: Path):
    clone = tmp_path / "clone"
    _git("clone", "-q", str(upstream), str(clone))
    marker = plant_hostile(clone / ".git", clone, tmp_path)
    new_sha = _advance(upstream)
    config = [("remote.origin.url", str(upstream)),
              ("remote.origin.fetch", "+refs/heads/*:refs/remotes/origin/*")]
    with shadow_git_dir(clone / ".git", tmp_path / "shadow", config, work_tree=clone) as sh:
        run_git("fetch", "origin", extra_env=sh.env(), isolated=True)
        run_git("merge", "--ff-only", "origin/main", extra_env=sh.env(), isolated=True)
        run_git("status", "--porcelain", extra_env=sh.env(), isolated=True)
    assert not marker.exists()
    # refs and index were written back to the real repo
    assert (clone / "b.txt").read_text() == "new\n"
    assert _git("-C", str(clone), "-c", "core.fsmonitor=false", "rev-parse", "HEAD").strip() == new_sha
    assert not list((tmp_path / "shadow").iterdir())


def test_shadow_refuses_symlinked_git_dir(tmp_path: Path, upstream: Path):
    clone = tmp_path / "clone"
    _git("clone", "-q", str(upstream), str(clone))
    (clone / ".git").rename(tmp_path / "elsewhere")
    (clone / ".git").symlink_to(tmp_path / "elsewhere")
    with pytest.raises(SafeGitError):
        with shadow_git_dir(clone / ".git", tmp_path / "shadow", []):
            pass


def test_shadow_write_back_does_not_follow_symlinks(tmp_path: Path, upstream: Path):
    clone = tmp_path / "clone"
    _git("clone", "-q", str(upstream), str(clone))
    victim = tmp_path / "victim"
    victim.mkdir()
    remotes = clone / ".git" / "refs" / "remotes"
    if remotes.exists():
        subprocess.run(["rm", "-rf", str(remotes)], check=True)
    remotes.symlink_to(victim)
    _advance(upstream)
    config = [("remote.origin.url", str(upstream)),
              ("remote.origin.fetch", "+refs/heads/*:refs/remotes/origin/*")]
    with pytest.raises(OSError):
        with shadow_git_dir(clone / ".git", tmp_path / "shadow", config) as sh:
            run_git("fetch", "origin", extra_env=sh.env(), isolated=True)
    assert not list(victim.iterdir())


@pytest.mark.asyncio
async def test_gitmanager_git_runs_hardened(tmp_path: Path):
    from warren_common.git import _git as manager_git

    repo = tmp_path / "repo"
    _git("init", "-q", "-b", "main", str(repo))
    marker = plant_hostile(repo / ".git", None, tmp_path)
    (repo / "f.txt").write_text("x")
    await manager_git("git", "-C", str(repo), "status", "--porcelain")
    await manager_git("git", *_IDENT, "-C", str(repo), "commit", "--allow-empty", "-qm", "m")
    assert not marker.exists()


@pytest.mark.asyncio
async def test_gitmanager_git_requires_git_argv0():
    from warren_common.git import _git as manager_git

    with pytest.raises(ValueError):
        await manager_git("sh", "-c", "true")


def test_readonly_shadow_inspects_without_running_or_writing(tmp_path: Path, upstream: Path):
    clone = tmp_path / "clone"
    _git("clone", "-q", str(upstream), str(clone))
    (clone / "a.txt").write_text("dirty\n")
    marker = plant_hostile(clone / ".git", clone, tmp_path)
    before = {p: p.read_bytes() for p in (clone / ".git").rglob("*") if p.is_file()}
    with readonly_shadow_git_dir(clone / ".git", tmp_path / "shadow", work_tree=clone) as sh:
        head = run_git("rev-parse", "HEAD", extra_env=sh.env(), isolated=True).strip()
        status = run_git("--no-optional-locks", "status", "--porcelain", extra_env=sh.env(), isolated=True)
    assert not marker.exists()
    assert head == _git("-C", str(upstream), "rev-parse", "HEAD").strip()
    assert "a.txt" in status
    after = {p: p.read_bytes() for p in (clone / ".git").rglob("*") if p.is_file()}
    assert after == before
    assert not list((tmp_path / "shadow").iterdir())


def test_readonly_shadow_reads_linked_worktree(tmp_path: Path, upstream: Path):
    store = tmp_path / "store.git"
    _git("clone", "-q", "--bare", str(upstream), str(store))
    wt = tmp_path / "wt"
    _git("-C", str(store), "worktree", "add", "-q", "-b", "warren/x/1/wt", str(wt), "main")
    marker = plant_hostile(store, wt, tmp_path)
    wt_git_dir = store / "worktrees" / "wt"
    with readonly_shadow_git_dir(wt_git_dir, tmp_path / "shadow", common_dir=store, work_tree=wt) as sh:
        branch = run_git("symbolic-ref", "--short", "HEAD", extra_env=sh.env(), isolated=True).strip()
        base = run_git("merge-base", "HEAD", "refs/heads/main", extra_env=sh.env(), isolated=True).strip()
        status = run_git("--no-optional-locks", "status", "--porcelain", extra_env=sh.env(), isolated=True)
    assert not marker.exists()
    assert branch == "warren/x/1/wt"
    assert base == _git("-C", str(upstream), "rev-parse", "HEAD").strip()
    assert status.strip() == "?? .gitattributes"


def test_readonly_shadow_refuses_symlinked_git_dir(tmp_path: Path, upstream: Path):
    clone = tmp_path / "clone"
    _git("clone", "-q", str(upstream), str(clone))
    (clone / ".git").rename(tmp_path / "elsewhere")
    (clone / ".git").symlink_to(tmp_path / "elsewhere")
    with pytest.raises(SafeGitError):
        with readonly_shadow_git_dir(clone / ".git", tmp_path / "shadow"):
            pass
