"""Generated SBPL profiles under the real /usr/bin/sandbox-exec (macOS only).

Every path is a throwaway tmp dir; HOME is the per-test fake home from conftest.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from warren_common.models import FolderSpec
from warren_common.runtime.base import WorkspaceSpec
from warren_common.runtime.sbpl import build_sbpl_profile, sandbox_exec_param_args

SANDBOX_EXEC = "/usr/bin/sandbox-exec"

pytestmark = pytest.mark.skipif(
    sys.platform != "darwin" or not os.path.isfile(SANDBOX_EXEC),
    reason="needs macOS sandbox-exec",
)

DOT_GIT = ".git"


def _git(*args: str, cwd: Path) -> None:
    subprocess.run(
        ["git", "-c", "core.hooksPath=/dev/null", *args],
        cwd=cwd,
        check=True,
        capture_output=True,
        env={"PATH": "/usr/bin:/bin", "HOME": os.environ["HOME"]},
    )


@pytest.fixture
def ws(tmp_path):
    home = Path(os.environ["HOME"])
    ref = home / ".warren" / "projects" / "p" / "references" / "repo"
    ref.mkdir(parents=True)
    _git("init", "-q", cwd=ref)
    (ref / "README").write_text("hi\n")
    root = home / ".warren" / "workspaces" / "ws-1"
    root.mkdir(parents=True)
    return {"home": home, "ref": ref, "root": root, "tmp": tmp_path}


def _run(ws, spec: WorkspaceSpec, script: str, cwd: Path | None = None) -> subprocess.CompletedProcess:
    profile = build_sbpl_profile(spec)
    pf = ws["tmp"] / "sandbox.sb"
    pf.write_text(profile.text)
    return subprocess.run(
        [SANDBOX_EXEC, "-f", str(pf), *sandbox_exec_param_args(profile.params), "/bin/sh", "-c", script],
        cwd=cwd or ws["root"],
        capture_output=True,
        text=True,
        env={"PATH": "/usr/bin:/bin", "HOME": str(ws["home"])},
    )


def _spec(ws, **over) -> WorkspaceSpec:
    kw = dict(
        workspace_id="ws-1",
        project="p",
        intent="i",
        image="",
        root_path=str(ws["root"]),
        reference_paths=[(str(ws["ref"]), "refs/repo")],
        folders=[FolderSpec(name="repo", type="git-clone", mount="refs/repo", url="git@x:y.git")],
    )
    kw.update(over)
    return WorkspaceSpec(**kw)


def test_dot_git_rename_bypass_blocked(ws):
    """AE1 regression: rename .git away, plant a hook and fsmonitor, rename back."""
    ref = ws["ref"]
    config_before = (ref / DOT_GIT / "config").read_text()
    script = (
        f'g="{ref}/{DOT_GIT}"; mv "$g" "$g-x" && echo evil > "$g-x/hooks/pre-commit" && '
        f"printf '[core]\\n\\tfsmonitor = evil\\n' > \"$g-x/config\" && mv \"$g-x\" \"$g\""
    )
    r = _run(ws, _spec(ws), script)
    assert r.returncode != 0
    assert "Operation not permitted" in r.stderr
    assert (ref / DOT_GIT / "config").read_text() == config_before
    assert not (ref / DOT_GIT / "hooks" / "pre-commit").exists()
    assert not (ref / f"{DOT_GIT}-x").exists()


def test_clone_root_rename_bypass_blocked(ws):
    r = _run(ws, _spec(ws), f'mv "{ws["ref"]}" "{ws["tmp"]}/moved"')
    assert r.returncode != 0
    assert ws["ref"].is_dir()


def test_reference_clone_still_usable(ws):
    """The .git protections don't stop ordinary work in a writable clone."""
    ref = ws["ref"]
    script = (
        "echo more >> README && git add README && "
        "git -c user.email=t@t -c user.name=t commit -qm x && git log --oneline | wc -l"
    )
    r = _run(ws, _spec(ws), script, cwd=ref)
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip() == "1"


def test_hooks_and_config_direct_write_blocked(ws):
    ref = ws["ref"]
    for target in (f"{DOT_GIT}/hooks/pre-commit", f"{DOT_GIT}/config", f"{DOT_GIT}/commondir"):
        r = _run(ws, _spec(ws), f'echo evil > "{ref}/{target}"')
        assert r.returncode != 0, target


def test_claude_memory_and_rename_blocked(ws):
    """AA1: the host ~/.claude, memory included, is unwritable even when the workspace runs claude (AG3)."""
    claude = ws["home"] / ".claude"
    (claude / "projects" / "-host-proj" / "memory").mkdir(parents=True)
    scratch = ws["tmp"] / "scratch"
    (scratch / "planted" / "memory").mkdir(parents=True)
    (scratch / "planted" / "memory" / "MEMORY.md").write_text("evil\n")
    spec = _spec(ws, app="claude")
    blocked = {
        "memory write": f'echo evil > "{claude}/projects/-host-proj/memory/MEMORY.md"',
        "new memory dir": f'mkdir -p "{claude}/projects/-host-proj2/memory"',
        "rename .claude": f'mv "{claude}" "{scratch}/c"',
        "rename projects": f'mv "{claude}/projects" "{scratch}/p"',
        "rename project": f'mv "{claude}/projects/-host-proj" "{scratch}/x"',
        "rename-in project": f'mv "{scratch}/planted" "{claude}/projects/-future-cwd"',
        "symlink project": f'ln -s "{scratch}/planted" "{claude}/projects/-future-cwd"',
        "settings": f'echo {{}} > "{claude}/settings.json"',
        "CLAUDE.md": f'echo evil > "{claude}/CLAUDE.md"',
    }
    for label, script in blocked.items():
        r = _run(ws, spec, script)
        assert r.returncode != 0, label
    assert not (claude / "projects" / "-host-proj" / "memory" / "MEMORY.md").exists()
    assert not (claude / "projects" / "-future-cwd").exists()
    r = _run(ws, spec, f'echo h > "{claude}/history.jsonl"')
    assert r.returncode != 0
    assert not (claude / "history.jsonl").exists()


def test_claude_dir_unwritable_without_claude_harness(ws):
    claude = ws["home"] / ".claude"
    claude.mkdir()
    r = _run(ws, _spec(ws, app="bash"), f'echo x > "{claude}/history.jsonl"')
    assert r.returncode != 0
    assert not (claude / "history.jsonl").exists()


def test_zsh_sessions_write_blocked(ws):
    """AA2."""
    sessions = ws["home"] / ".zsh_sessions"
    sessions.mkdir()
    r = _run(ws, _spec(ws), f'echo evil > "{sessions}/x.session"')
    assert r.returncode != 0
    assert not (sessions / "x.session").exists()


def test_symlinked_grant_path_is_canonicalized(ws):
    """AA3: a read grant given via a symlink still applies to the real path."""
    real = ws["tmp"] / "real-ref"
    real.mkdir()
    (real / "f").write_text("content\n")
    link = ws["tmp"] / "link-ref"
    link.symlink_to(real)
    spec = _spec(
        ws,
        reference_paths=[(str(link), "ref")],
        folders=[FolderSpec(name="ref", type="local-path", mount="ref", path=str(link), readonly=True)],
    )
    r = _run(ws, spec, f'cat "{real}/f"')
    assert r.returncode == 0, r.stderr
    assert r.stdout == "content\n"


@pytest.mark.parametrize("base", ["/private/tmp", "/tmp", None])
def test_readonly_folder_under_system_tmpdir_refuses_writes(ws, base):
    """A readonly folder (or ro mount) under /tmp, /private/tmp or the pytest
    tmpdir (/private/var/folders) is not writable just because those are."""
    import shutil
    import tempfile

    outer = Path(tempfile.mkdtemp(dir=base, prefix="warren-ro-"))
    try:
        ro_folder, ro_mount, rw_folder = outer / "wiki", outer / "data", outer / "scratch"
        for d in (ro_folder, ro_mount, rw_folder):
            d.mkdir()
        spec = _spec(
            ws,
            reference_paths=[(str(ro_folder), "refs/wiki"), (str(rw_folder), "scratch")],
            folders=[
                FolderSpec(name="wiki", type="local-path", mount="refs/wiki", path=str(ro_folder), readonly=True),
                FolderSpec(name="scratch", type="local-path", mount="scratch", path=str(rw_folder)),
            ],
            bind_mounts=[(str(ro_mount), "/w/data", "ro")],
        )
        script = (
            f': > "{ro_folder}/x" 2>/dev/null && echo ro-folder-written; '
            f': > "{ro_mount}/x" 2>/dev/null && echo ro-mount-written; '
            f': > "{rw_folder}/x" && echo rw-ok; '
            f': > "{outer}/sibling" && echo tmp-ok'
        )
        r = _run(ws, spec, script)
        assert "ro-folder-written" not in r.stdout
        assert "ro-mount-written" not in r.stdout
        assert "rw-ok" in r.stdout and "tmp-ok" in r.stdout, r.stderr
        assert not (ro_folder / "x").exists() and not (ro_mount / "x").exists()
    finally:
        shutil.rmtree(outer, ignore_errors=True)


CODEX_TOML = 'approval_policy = "never"\n'


def _harness_ws(ws):
    hroot = ws["home"] / ".warren" / "state" / "ws-1" / "harness"
    codex = hroot / "codex"
    (codex / "sessions").mkdir(parents=True)
    (codex / "config.toml").write_text(CODEX_TOML)
    host_codex = ws["home"] / ".codex"
    host_codex.mkdir()
    (host_codex / "auth.json").write_text('{"token": "secret"}\n')
    (ws["home"] / ".claude").mkdir()
    (ws["home"] / ".claude.json").write_text("{}\n")
    return hroot, codex, host_codex


def test_codex_only_workspace_cannot_write_host_harness_config(ws):
    """AG6 acceptance: harnesses: [codex] can't write ~/.claude, ~/.claude.json or ~/.codex."""
    hroot, codex, host_codex = _harness_ws(ws)
    spec = _spec(ws, app="bash", harnesses=["codex"], harness_root=str(hroot))
    home = ws["home"]
    blocked = {
        "~/.claude": f'echo x > "{home}/.claude/history.jsonl"',
        "~/.claude.json": f'echo x > "{home}/.claude.json"',
        "~/.codex": f'echo x > "{host_codex}/config.toml"',
        "~/.codex rename": f'mv "{host_codex}" "{ws["tmp"]}/c"',
        "~/.cursor": f'mkdir "{home}/.cursor"',
    }
    for label, script in blocked.items():
        r = _run(ws, spec, script)
        assert r.returncode != 0, label
    assert (home / ".claude.json").read_text() == "{}\n"
    assert not (host_codex / "config.toml").exists()
    assert not (home / ".cursor").exists()
    r = _run(ws, spec, f'cat "{host_codex}/auth.json"')
    assert r.returncode != 0 and "secret" not in r.stdout


def test_codex_generated_config_read_only_and_state_writable(ws):
    hroot, codex, _ = _harness_ws(ws)
    spec = _spec(ws, app="bash", harnesses=["codex"], harness_root=str(hroot))
    r = _run(ws, spec, f'cat "{codex}/config.toml" && echo s > "{codex}/sessions/s.jsonl" && echo h > "{codex}/history.jsonl"')
    assert r.returncode == 0, r.stderr
    assert "never" in r.stdout
    for script in (
        f'echo "[hooks] trusted = true" >> "{codex}/config.toml"',
        f'mv "{codex}/config.toml" "{codex}/old.toml"',
        f'rm "{codex}/config.toml"',
        f'echo evil > "{codex}/hooks.json"',
    ):
        r = _run(ws, spec, script)
        assert r.returncode != 0, script
    assert (codex / "config.toml").read_text() == CODEX_TOML
    assert not (codex / "hooks.json").exists()


def test_warren_prepared_harness_dirs_under_sandbox(ws):
    """AG3 end to end: dirs prepared by warren, then used from inside the sandbox."""
    from warren_common.harness_config import copy_in_credentials, prepare_harness_dirs

    home = ws["home"]
    (home / ".claude").mkdir()
    (home / ".claude" / "settings.json").write_text('{"model": "opus"}')
    (home / ".claude" / ".credentials.json").write_text('{"t": "host"}')
    hroot = home / ".warren" / "state" / "ws-1" / "harness"
    names = ["claude", "codex"]
    prepare_harness_dirs(names, hroot, home=home)
    copy_in_credentials(names, hroot, home=home)
    claude, codex = hroot / "claude", hroot / "codex"
    generated = (codex / "config.toml").read_text()
    spec = _spec(ws, app="bash", harnesses=names, harness_root=str(hroot))

    ok = (
        f'cat "{claude}/.credentials.json" "{claude}/settings.json" | wc -c && '
        f'echo "{{}}" > "{claude}/.claude.json" && mkdir "{claude}/projects/p" && '
        f'echo t > "{claude}/projects/p/s.jsonl" && echo r > "{claude}/.credentials.json" && '
        f'echo s > "{codex}/sessions/s.jsonl"'
    )
    r = _run(ws, spec, ok)
    assert r.returncode == 0, r.stderr
    for script in (
        f'echo "{{}}" > "{claude}/settings.json"',
        f'mkdir "{claude}/hooks/x"',
        f'echo x >> "{codex}/config.toml"',
        f'cat "{home}/.claude/.credentials.json"',
    ):
        r = _run(ws, spec, script)
        assert r.returncode != 0, script
    assert (codex / "config.toml").read_text() == generated
    assert (home / ".claude" / ".credentials.json").read_text() == '{"t": "host"}'
