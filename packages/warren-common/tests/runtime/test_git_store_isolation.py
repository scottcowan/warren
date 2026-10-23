"""BB7: a local sandbox can never write a bare `.git-store` (host git runs
against those stores outside every sandbox), nor move one aside to plant
another in its place."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from warren_common.errors import TemplateDenied
from warren_common.runtime.base import WorkspaceSpec

SANDBOX_EXEC = "/usr/bin/sandbox-exec"


def _spec(root: Path, store: Path, **over) -> WorkspaceSpec:
    kw = dict(
        workspace_id="ws-store-1",
        project="p",
        intent="i",
        image="",
        root_path=str(root),
        worktree_paths=[(str(root / "code"), "code")],
        git_store_paths=[str(store)],
    )
    kw.update(over)
    return WorkspaceSpec(**kw)


@pytest.fixture
def layout(tmp_path: Path) -> tuple[Path, Path]:
    home = Path(os.environ["HOME"])
    root = home / ".warren" / "workspaces" / "ws-store-1"
    (root / "code").mkdir(parents=True)
    store = home / ".warren" / "projects" / "p" / "repo.git-store"
    store.mkdir(parents=True)
    return root, store


def _rw_parent_variants(root: Path, store: Path) -> list[dict]:
    projects = store.parent.parent
    return [
        {"bind_mounts": [(str(projects), "/projects", "rw")]},
        {"bind_mounts": [(str(store), "/store", "rw")]},
        {"root_path": str(store.parent)},
        {"worktree_paths": [(str(store.parent), "code")]},
    ]


@pytest.mark.skipif(sys.platform == "win32", reason="Linux sandboxes")
def test_bwrap_never_binds_store_and_refuses_writable_ancestor(layout, tmp_path):
    from warren_common.runtime.bubblewrap import build_bwrap_args

    root, store = layout
    args = build_bwrap_args(_spec(root, store), env_file=str(tmp_path / "env.sh"))
    assert not any(a == str(store) or a.startswith(str(store) + "/") for a in args)
    for over in _rw_parent_variants(root, store):
        with pytest.raises(TemplateDenied, match="git store"):
            build_bwrap_args(_spec(root, store, **over), env_file=str(tmp_path / "env.sh"))
    ro = _spec(root, store, bind_mounts=[(str(store.parent), "/projects", "ro")])
    build_bwrap_args(ro, env_file=str(tmp_path / "env.sh"))


@pytest.mark.skipif(sys.platform == "win32", reason="Linux sandboxes")
def test_nsjail_never_mounts_store_and_refuses_writable_ancestor(layout):
    from warren_common.runtime.nsjail_config import NsjailConfig

    root, store = layout
    cfg = NsjailConfig.from_spec(_spec(root, store))
    for m in cfg.mounts:
        if m.src:
            assert not (m.src == str(store) or m.src.startswith(str(store) + "/"))
            assert not (m.rw and str(store).startswith(m.src.rstrip("/") + "/"))
    for over in _rw_parent_variants(root, store):
        with pytest.raises(TemplateDenied, match="git store"):
            NsjailConfig.from_spec(_spec(root, store, **over))


def test_sbpl_denies_store_writes_and_ancestor_renames(layout):
    from warren_common.runtime.sbpl import build_sbpl_profile, canonical_path

    root, store = layout
    profile = build_sbpl_profile(_spec(root, store, bind_mounts=[(str(store.parent), "/p", "rw")]))
    canon = canonical_path(str(store))
    key = next(k for k, v in profile.params.items() if v == canon)
    deny = f'(deny file-write* (subpath (param "{key}")))'
    allow_rw = profile.text.index("(allow file-write*")
    assert profile.text.index(deny) > allow_rw
    parent_key = next(k for k, v in profile.params.items() if v == canonical_path(str(store.parent)))
    assert f'(deny file-write-unlink (literal (param "{parent_key}")))' in profile.text


@pytest.mark.skipif(
    sys.platform != "darwin" or not os.path.isfile(SANDBOX_EXEC), reason="needs macOS sandbox-exec"
)
def test_seatbelt_store_under_writable_tmpdir_stays_unwritable(tmp_path):
    """A store under /private/var/folders (writable through the system-tmpdir
    grant) and its ancestors resist every write a planted-store attack needs."""
    from warren_common.runtime.sbpl import build_sbpl_profile, sandbox_exec_param_args

    home = Path(os.environ["HOME"])
    root = home / ".warren" / "workspaces" / "ws-store-1"
    (root / "code").mkdir(parents=True)
    projects = tmp_path / "projects"
    store = projects / "p" / "repo.git-store"
    subprocess.run(["git", "init", "-q", "--bare", str(store)], check=True)
    profile = build_sbpl_profile(_spec(root, store))
    pf = tmp_path / "sandbox.sb"
    pf.write_text(profile.text)

    def sandboxed(script: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [SANDBOX_EXEC, "-f", str(pf), *sandbox_exec_param_args(profile.params),
             "/bin/sh", "-c", script],
            cwd=root, capture_output=True, text=True,
            env={"PATH": "/usr/bin:/bin", "HOME": str(home)},
        )

    assert sandboxed(f"cat '{store}/HEAD'").returncode == 0
    for script in (
        f"echo x >> '{store}/config'",
        f"echo x > '{store}/hooks/post-merge'",
        f"mkdir '{store}/refs/x'",
        f"mv '{store}' '{store}.moved'",
        f"mv '{store.parent}' '{projects}/moved'",
        f"mv '{projects}' '{tmp_path}/moved'",
        f"rm -rf '{store}'",
    ):
        assert sandboxed(script).returncode != 0, script
    assert not (store / "hooks" / "post-merge").exists()
    assert "x" not in (store / "config").read_text().split()
    assert store.is_dir() and not (tmp_path / "moved").exists()
    assert sandboxed(f"echo ok > '{tmp_path}/scratch'").returncode == 0
