"""BB7/BB12: local `warren destroy` never runs git against config the
workspace can write."""

from __future__ import annotations

import json
import stat
import subprocess
import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

from warren_cli.main import app

posix_only = pytest.mark.skipif(
    sys.platform == "win32",
    reason="local sandbox workspaces are POSIX-only (Windows local sandboxes are AC2, via WSL2)",
)

runner = CliRunner()


def _git(*args: str) -> str:
    return subprocess.check_output(["git", *args], text=True)


def _hostile_git_dir(home: Path) -> tuple[Path, Path]:
    """A git dir with every exec-capable key a workspace could plant."""
    marker = home / "pwned"
    script = home / "evil.sh"
    script.write_text(f'#!/bin/sh\necho "$0 $*" >> {marker}\nexit 1\n')
    script.chmod(script.stat().st_mode | stat.S_IXUSR)
    evil = home / "evil-gitdir"
    _git("init", "-q", "--bare", str(evil))
    cfg = str(evil / "config")
    for key, value in {
        "core.bare": "false",
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
        _git("config", "--file", cfg, key, value)
    (evil / "info").mkdir(exist_ok=True)
    (evil / "info" / "attributes").write_text("* filter=evil diff=evil\n")
    return evil, marker


def _managed_workspace(home: Path, workspace_id: str) -> Path:
    """A workspace whose code/repo is a worktree of a warren bare store."""
    seed = home / "seed"
    _git("init", "-q", "-b", "main", str(seed))
    (seed / "README.md").write_text("seed\n")
    _git("-C", str(seed), "add", "README.md")
    _git("-C", str(seed), "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "seed")
    bare = home / ".warren" / "projects" / "demo" / "repo.git-store"
    bare.parent.mkdir(parents=True)
    _git("clone", "-q", "--bare", str(seed), str(bare))
    ws = home / ".warren" / "workspaces" / workspace_id
    repo = ws / "code" / "repo"
    repo.parent.mkdir(parents=True)
    _git("-C", str(bare), "worktree", "add", "-q", "-b", f"warren/x/{workspace_id[:8]}/repo",
         str(repo), "main")
    state = home / ".warren" / "state" / workspace_id / "state.json"
    state.parent.mkdir(parents=True)
    state.write_text(json.dumps({
        "project": "demo", "workspace_id": workspace_id,
        "worktree_paths": [[str(repo), "code/repo"]],
    }))
    (repo / "dirty.txt").write_text("uncommitted")
    return repo


def _setup(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("WARREN_PROJECT", raising=False)
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))


@posix_only
def test_destroy_checks_managed_worktree_via_bare_store_only(tmp_path: Path, monkeypatch):
    _setup(tmp_path, monkeypatch)
    workspace_id = "ffffffff-1111-2222-3333-444444444444"
    repo = _managed_workspace(tmp_path, workspace_id)
    evil, marker = _hostile_git_dir(tmp_path)
    # The workspace repoints its .git at a hostile git dir and plants attributes.
    (repo / ".git").write_text(f"gitdir: {evil}\n")
    (repo / ".gitattributes").write_text("* filter=evil diff=evil\n")

    subprocess.run(["git", "-C", str(repo), "status"], capture_output=True, timeout=30)
    assert marker.exists(), "baseline: plain git in the workspace runs planted config"
    marker.unlink()

    result = runner.invoke(app, ["destroy", workspace_id], input="n\n")

    assert "repo: uncommitted changes" in result.output
    assert not marker.exists(), "workspace-controlled git config ran on the host"
    assert repo.exists()  # cancelled


def test_destroy_does_not_run_git_in_unmanaged_repo(tmp_path: Path, monkeypatch):
    _setup(tmp_path, monkeypatch)
    workspace_id = "abababab-1111-2222-3333-444444444444"
    repo = tmp_path / ".warren" / "workspaces" / workspace_id / "code" / "repo"
    repo.parent.mkdir(parents=True)
    evil, marker = _hostile_git_dir(tmp_path)
    repo.mkdir()
    (repo / ".git").write_text(f"gitdir: {evil}\n")

    result = runner.invoke(app, ["destroy", workspace_id], input="n\n")

    assert "repo: not checked" in result.output
    assert not marker.exists()
    assert repo.exists()


def test_destroy_ignores_escaping_project_in_in_tree_state(tmp_path: Path, monkeypatch):
    """An in-tree state.json can't point bare-store discovery at a
    workspace-made "bare" repo."""
    _setup(tmp_path, monkeypatch)
    workspace_id = "cdcdcdcd-1111-2222-3333-444444444444"
    ws = tmp_path / ".warren" / "workspaces" / workspace_id
    ws.mkdir(parents=True)
    evil, marker = _hostile_git_dir(tmp_path)
    fake = ws / "x" / "evil.git-store"
    fake.parent.mkdir()
    evil.rename(fake)
    (tmp_path / ".warren" / "projects").mkdir()
    (ws / "state.json").write_text(json.dumps({
        "project": f"../workspaces/{workspace_id}/x", "workspace_id": workspace_id,
        "worktree_paths": [["/nowhere", "code/repo"]],
    }))

    runner.invoke(app, ["destroy", workspace_id], input="y\n")

    assert not marker.exists()
    assert not ws.exists()


def _merged_setup(tmp_path: Path, monkeypatch, pr_states: dict) -> str:
    from warren_cli import gh

    _setup(tmp_path, monkeypatch)
    monkeypatch.delenv("REAL_HOME", raising=False)
    workspace_id = "cafe0001-0000-0000-0000-000000000000"
    _managed_workspace(tmp_path, workspace_id)
    projects = tmp_path / ".warren" / "projects"
    (projects / "demo.yaml").write_text(
        "name: demo\n"
        "folders:\n"
        "  - name: repo\n"
        "    type: git-worktree\n"
        "    url: git@github.com:acme/repo.git\n"
        "    mount: code/repo\n"
    )
    monkeypatch.setattr("warren_cli.main.PROJECTS_DIR", projects)
    calls = []

    def _pr_state(repo, branch):
        calls.append((repo, branch))
        return pr_states.get(branch)

    monkeypatch.setattr(gh, "pr_state", _pr_state)
    return workspace_id


def test_list_merged_flags_workspace_whose_pr_is_merged(tmp_path: Path, monkeypatch):
    wid = _merged_setup(tmp_path, monkeypatch, {"warren/x/cafe0001/repo": "MERGED"})
    result = runner.invoke(app, ["list", "--merged"])
    assert result.exit_code == 0, result.output
    assert wid[:8] in result.stdout
    assert "acme/repo#warren/x/cafe0001/repo" in result.stdout
    assert "warren destroy" in result.stdout
    assert (tmp_path / ".warren" / "workspaces" / wid).exists()


def test_list_merged_skips_open_or_unknown_prs(tmp_path: Path, monkeypatch):
    _merged_setup(tmp_path, monkeypatch, {"warren/x/cafe0001/repo": "OPEN"})
    result = runner.invoke(app, ["list", "--merged", "--json"])
    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout) == []


def test_list_merged_offers_destroy_on_tty(tmp_path: Path, monkeypatch):
    import sys

    import warren_cli.main as main

    wid = _merged_setup(tmp_path, monkeypatch, {"warren/x/cafe0001/repo": "MERGED"})
    destroyed = []
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True, raising=False)
    monkeypatch.setattr(main.typer, "confirm", lambda *a, **kw: True)
    monkeypatch.setattr(main, "workspaces_destroy", lambda **kw: destroyed.append(kw["workspace_id"]))
    main._list_merged(None, output_json=False)
    assert destroyed == [wid]
