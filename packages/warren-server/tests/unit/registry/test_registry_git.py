"""WorkspaceRegistry git materialization + pull_git unit tests (04-06 Task 2, LIFE-03).

Covers all eight Task 2 behaviors with an AsyncMock GitManager. The load-bearing
test is the ordering one (`test_clone_awaited_before_runtime_provision`): a shared
`parent` mock records calls from both `git_manager.clone` and `runtime.provision`,
so call order is asserted directly via `parent.mock_calls`.
"""

from __future__ import annotations

import inspect

import pytest
from unittest.mock import AsyncMock, MagicMock


@pytest.mark.asyncio
async def test_init_accepts_git_manager_defaulting_to_none(sqlite_path, fake_runtime):
    from warren.registry.store import WorkspaceStore
    from warren.registry.registry import WorkspaceRegistry

    store = await WorkspaceStore.open(sqlite_path)
    # Every existing 3-arg construction site must keep working untouched.
    registry = WorkspaceRegistry(runtime=fake_runtime, store=store, server_id="test")

    assert registry.git_manager is None


@pytest.mark.asyncio
async def test_do_provision_clones_before_marking_running(sqlite_path):
    from warren.registry.store import WorkspaceStore
    from warren.registry.registry import WorkspaceRegistry
    from warren_common.runtime.base import WorkspaceHandle, WorkspaceSpec

    store = await WorkspaceStore.open(sqlite_path)
    runtime = AsyncMock()
    runtime.provision.return_value = WorkspaceHandle(
        workspace_id="ws-1", runtime_id="ctr-1", root_path=""
    )
    git_manager = AsyncMock()
    from pathlib import Path

    git_manager.clone.return_value = Path("/var/lib/warren/worktrees/ws-1")

    registry = WorkspaceRegistry(
        runtime=runtime, store=store, server_id="test", git_manager=git_manager
    )
    await store.insert(
        workspace_id="ws-1", project="p", intent="i", image="img", root_path="",
        server_instance="test", status="provisioning",
    )
    spec = WorkspaceSpec(
        workspace_id="ws-1", project="p", intent="i", image="img", root_path="",
        env={"WARREN_GIT_REPO_URL": "https://github.com/o/r.git"},
    )

    await registry._do_provision("ws-1", spec)

    git_manager.clone.assert_awaited_once()
    row = await store.get("ws-1")
    assert row.status == "running"


@pytest.mark.asyncio
async def test_do_provision_translates_clone_path_to_host_path_when_configured(sqlite_path):
    """warren-server itself runs containerized in the normal deployment shape,
    with data_dir bind-mounted in from a different host path -- a GitManager
    clone path under data_dir is only a valid bind-mount SOURCE for a sibling
    podman container once translated to that host path, or podman 500s with
    "statfs: no such file or directory" (real failure observed 2026-10-13,
    even though the clone itself succeeds and is visible from inside
    warren-server's own container)."""
    from pathlib import Path
    from types import SimpleNamespace

    from warren.registry.store import WorkspaceStore
    from warren.registry.registry import WorkspaceRegistry
    from warren_common.runtime.base import WorkspaceHandle, WorkspaceSpec

    store = await WorkspaceStore.open(sqlite_path)
    runtime = AsyncMock()
    runtime.provision.return_value = WorkspaceHandle(
        workspace_id="ws-1", runtime_id="ctr-1", root_path=""
    )
    git_manager = AsyncMock()
    git_manager.clone.return_value = Path("/var/lib/warren/worktrees/ws-1")

    settings = SimpleNamespace(
        data_dir=Path("/var/lib/warren"),
        host_data_dir=Path("/mnt/storage/containers-storage/volumes/warren-data/_data"),
    )
    registry = WorkspaceRegistry(
        runtime=runtime, store=store, server_id="test", git_manager=git_manager, settings=settings
    )
    await store.insert(
        workspace_id="ws-1", project="p", intent="i", image="img", root_path="",
        server_instance="test", status="provisioning",
    )
    spec = WorkspaceSpec(
        workspace_id="ws-1", project="p", intent="i", image="img", root_path="",
        env={"WARREN_GIT_REPO_URL": "https://github.com/o/r.git"},
    )

    await registry._do_provision("ws-1", spec)

    expected_host_path = "/mnt/storage/containers-storage/volumes/warren-data/_data/worktrees/ws-1"
    assert (expected_host_path, "/workspace", "rw") in spec.bind_mounts
    assert (expected_host_path, "/workspace") in spec.worktree_paths
    # The untranslated, container-internal path never leaks into bind_mounts.
    assert not any("/var/lib/warren/worktrees" in m[0] for m in spec.bind_mounts)


def test_to_host_path_noop_when_host_data_dir_unset():
    """warren-server running directly on the host (not containerized) --
    data_dir already IS a host path, so no translation happens."""
    from pathlib import Path
    from types import SimpleNamespace

    from warren.registry.registry import WorkspaceRegistry

    settings = SimpleNamespace(data_dir=Path("/var/lib/warren"), host_data_dir=None)
    registry = WorkspaceRegistry(
        runtime=MagicMock(), store=MagicMock(), server_id="test", settings=settings
    )
    path = Path("/var/lib/warren/worktrees/ws-1")
    assert registry._to_host_path(path) == path


def test_to_host_path_leaves_unrelated_path_untouched():
    """Defensive: a path that isn't actually under data_dir is never mangled."""
    from pathlib import Path
    from types import SimpleNamespace

    from warren.registry.registry import WorkspaceRegistry

    settings = SimpleNamespace(
        data_dir=Path("/var/lib/warren"), host_data_dir=Path("/mnt/host-data")
    )
    registry = WorkspaceRegistry(
        runtime=MagicMock(), store=MagicMock(), server_id="test", settings=settings
    )
    path = Path("/some/other/path")
    assert registry._to_host_path(path) == path


@pytest.mark.asyncio
async def test_clone_awaited_before_runtime_provision(sqlite_path):
    """Load-bearing ordering test: clone must be awaited before runtime.provision()."""
    from warren.registry.store import WorkspaceStore
    from warren.registry.registry import WorkspaceRegistry
    from warren_common.runtime.base import WorkspaceHandle, WorkspaceSpec

    store = await WorkspaceStore.open(sqlite_path)
    parent = MagicMock()
    from pathlib import Path

    runtime = AsyncMock()
    runtime.provision.return_value = WorkspaceHandle(
        workspace_id="ws-1", runtime_id="ctr-1", root_path=""
    )
    git_manager = AsyncMock()
    git_manager.clone.return_value = Path("/var/lib/warren/worktrees/ws-1")
    parent.attach_mock(runtime.provision, "provision")
    parent.attach_mock(git_manager.clone, "clone")

    registry = WorkspaceRegistry(
        runtime=runtime, store=store, server_id="test", git_manager=git_manager
    )
    await store.insert(
        workspace_id="ws-1", project="p", intent="i", image="img", root_path="",
        server_instance="test", status="provisioning",
    )
    spec = WorkspaceSpec(
        workspace_id="ws-1", project="p", intent="i", image="img", root_path="",
        env={"WARREN_GIT_REPO_URL": "https://github.com/o/r.git"},
    )

    await registry._do_provision("ws-1", spec)

    call_names = [c[0] for c in parent.mock_calls]
    assert call_names.index("clone") < call_names.index("provision")


@pytest.mark.asyncio
async def test_do_provision_clone_failure_never_marks_running(sqlite_path):
    from warren.registry.store import WorkspaceStore
    from warren.registry.registry import WorkspaceRegistry
    from warren.git.manager import GitError
    from warren_common.runtime.base import WorkspaceSpec

    store = await WorkspaceStore.open(sqlite_path)
    runtime = AsyncMock()
    git_manager = AsyncMock()
    git_manager.clone.side_effect = GitError("clone failed")

    registry = WorkspaceRegistry(
        runtime=runtime, store=store, server_id="test", git_manager=git_manager
    )
    await store.insert(
        workspace_id="ws-1", project="p", intent="i", image="img", root_path="",
        server_instance="test", status="provisioning",
    )
    spec = WorkspaceSpec(
        workspace_id="ws-1", project="p", intent="i", image="img", root_path="",
        env={"WARREN_GIT_REPO_URL": "https://github.com/o/r.git"},
    )

    await registry._do_provision("ws-1", spec)

    row = await store.get("ws-1")
    assert row.status == "failed"
    runtime.provision.assert_not_awaited()


@pytest.mark.asyncio
async def test_do_provision_without_git_manager_unchanged(sqlite_path, fake_runtime):
    """With no git_manager configured, _do_provision behaves exactly as before."""
    from warren.registry.store import WorkspaceStore
    from warren.registry.registry import WorkspaceRegistry
    from warren_common.runtime.base import WorkspaceSpec

    store = await WorkspaceStore.open(sqlite_path)
    registry = WorkspaceRegistry(runtime=fake_runtime, store=store, server_id="test")
    await store.insert(
        workspace_id="ws-1", project="p", intent="i", image="img", root_path="",
        server_instance="test", status="provisioning",
    )
    spec = WorkspaceSpec(
        workspace_id="ws-1", project="p", intent="i", image="img", root_path="",
        env={"WARREN_GIT_REPO_URL": "https://github.com/o/r.git"},
    )

    await registry._do_provision("ws-1", spec)

    row = await store.get("ws-1")
    assert row.status == "running"


@pytest.mark.asyncio
async def test_pull_git_returns_new_commit_sha(sqlite_path, fake_runtime):
    from warren.registry.store import WorkspaceStore
    from warren.registry.registry import WorkspaceRegistry

    store = await WorkspaceStore.open(sqlite_path)
    git_manager = AsyncMock()
    git_manager.pull.return_value = "abc123deadbeef"
    registry = WorkspaceRegistry(
        runtime=fake_runtime, store=store, server_id="test", git_manager=git_manager
    )
    await store.insert(
        workspace_id="ws-1", project="p", intent="i", image="img", root_path="",
        server_instance="test", status="running",
    )

    sha = await registry.pull_git("ws-1")

    assert sha == {"root": "abc123deadbeef"}
    git_manager.pull.assert_awaited_once_with("ws-1")


@pytest.mark.asyncio
async def test_pull_git_unknown_workspace_returns_none(sqlite_path, fake_runtime):
    from warren.registry.store import WorkspaceStore
    from warren.registry.registry import WorkspaceRegistry

    store = await WorkspaceStore.open(sqlite_path)
    git_manager = AsyncMock()
    registry = WorkspaceRegistry(
        runtime=fake_runtime, store=store, server_id="test", git_manager=git_manager
    )

    sha = await registry.pull_git("ws-does-not-exist")

    assert sha is None
    git_manager.pull.assert_not_awaited()


@pytest.mark.asyncio
async def test_pull_git_no_git_manager_raises(sqlite_path, fake_runtime):
    from warren.registry.store import WorkspaceStore
    from warren.registry.registry import WorkspaceRegistry
    from warren.git.manager import GitPullError

    store = await WorkspaceStore.open(sqlite_path)
    registry = WorkspaceRegistry(runtime=fake_runtime, store=store, server_id="test")
    await store.insert(
        workspace_id="ws-1", project="p", intent="i", image="img", root_path="",
        server_instance="test", status="running",
    )

    with pytest.raises(GitPullError):
        await registry.pull_git("ws-1")


@pytest.mark.asyncio
async def test_do_provision_threads_worktree_path_into_spec(sqlite_path):
    from warren.registry.store import WorkspaceStore
    from warren.registry.registry import WorkspaceRegistry
    from warren_common.runtime.base import WorkspaceHandle, WorkspaceSpec
    from pathlib import Path

    store = await WorkspaceStore.open(sqlite_path)
    runtime = AsyncMock()
    runtime.provision.return_value = WorkspaceHandle(
        workspace_id="ws-1", runtime_id="ctr-1", root_path=""
    )
    git_manager = AsyncMock()
    git_manager.clone.return_value = Path("/var/lib/warren/worktrees/ws-1")

    registry = WorkspaceRegistry(
        runtime=runtime, store=store, server_id="test", git_manager=git_manager
    )
    await store.insert(
        workspace_id="ws-1", project="p", intent="i", image="img", root_path="",
        server_instance="test", status="provisioning",
    )
    spec = WorkspaceSpec(
        workspace_id="ws-1", project="p", intent="i", image="img", root_path="",
        env={"WARREN_GIT_REPO_URL": "https://github.com/o/r.git"},
    )

    await registry._do_provision("ws-1", spec)

    assert ("/var/lib/warren/worktrees/ws-1", "/workspace") in spec.worktree_paths


def test_pull_git_is_coroutine_function():
    from warren.registry.registry import WorkspaceRegistry

    assert "git_manager" in inspect.signature(WorkspaceRegistry.__init__).parameters
    assert inspect.iscoroutinefunction(WorkspaceRegistry.pull_git)


@pytest.mark.asyncio
async def test_do_provision_clones_every_git_worktree_folder(sqlite_path):
    """Multi-repo templates: each git-worktree FolderSpec gets its own clone,
    bind-mounted at /workspace/<folder.mount> -- independent of the single-repo
    WARREN_GIT_REPO_URL path."""
    from pathlib import Path

    from warren.registry.store import WorkspaceStore
    from warren.registry.registry import WorkspaceRegistry
    from warren_common.models import FolderSpec
    from warren_common.runtime.base import WorkspaceHandle, WorkspaceSpec

    store = await WorkspaceStore.open(sqlite_path)
    runtime = AsyncMock()
    runtime.provision.return_value = WorkspaceHandle(
        workspace_id="ws-1", runtime_id="ctr-1", root_path=""
    )
    git_manager = AsyncMock()
    git_manager.folder_worktree_path = MagicMock(
        side_effect=lambda ws_id, name: Path(f"/var/lib/warren/worktrees/{ws_id}/{name}")
    )
    git_manager.clone_into.side_effect = lambda dest, *a, **k: dest

    registry = WorkspaceRegistry(
        runtime=runtime, store=store, server_id="test", git_manager=git_manager
    )
    await store.insert(
        workspace_id="ws-1", project="p", intent="i", image="img", root_path="",
        server_instance="test", status="provisioning",
    )
    folders = [
        FolderSpec(name="repo-a", type="git-worktree", mount="code/repo-a", url="git@bitbucket.org:org/repo-a.git"),
        FolderSpec(name="repo-b", type="git-worktree", mount="code/repo-b", url="https://github.com/org/repo-b.git"),
    ]
    spec = WorkspaceSpec(
        workspace_id="ws-1", project="p", intent="i", image="img", root_path="",
        folders=folders,
    )

    await registry._do_provision("ws-1", spec)

    assert git_manager.clone_into.await_count == 2
    assert ("/var/lib/warren/worktrees/ws-1/repo-a", "/workspace/code/repo-a") in spec.worktree_paths
    assert ("/var/lib/warren/worktrees/ws-1/repo-b", "/workspace/code/repo-b") in spec.worktree_paths
    assert ("/var/lib/warren/worktrees/ws-1/repo-a", "/workspace/code/repo-a", "rw") in spec.bind_mounts
    assert ("/var/lib/warren/worktrees/ws-1/repo-b", "/workspace/code/repo-b", "rw") in spec.bind_mounts


@pytest.mark.asyncio
async def test_do_provision_one_folder_clone_failure_does_not_abort_the_rest(sqlite_path):
    """One folder's auth/clone failure (e.g. an unauthenticated private GitHub
    HTTPS repo) must never abort every OTHER folder's clone, and must never
    fail the whole workspace -- real failure observed 2026-10-13 where the
    first of 26 folders being unauthenticated blocked all 25 working ones
    behind it. The workspace still ends up 'running', not 'failed'."""
    from pathlib import Path

    from warren.git.manager import GitError
    from warren.registry.store import WorkspaceStore
    from warren.registry.registry import WorkspaceRegistry
    from warren_common.models import FolderSpec
    from warren_common.runtime.base import WorkspaceHandle, WorkspaceSpec

    store = await WorkspaceStore.open(sqlite_path)
    runtime = AsyncMock()
    runtime.provision.return_value = WorkspaceHandle(
        workspace_id="ws-1", runtime_id="ctr-1", root_path=""
    )
    git_manager = AsyncMock()
    git_manager.folder_worktree_path = MagicMock(
        side_effect=lambda ws_id, name: Path(f"/var/lib/warren/worktrees/{ws_id}/{name}")
    )

    async def _clone_into(dest, url, **kwargs):
        if "bad-repo" in url:
            raise GitError("auth failed")
        return dest

    git_manager.clone_into.side_effect = _clone_into

    registry = WorkspaceRegistry(
        runtime=runtime, store=store, server_id="test", git_manager=git_manager
    )
    await store.insert(
        workspace_id="ws-1", project="p", intent="i", image="img", root_path="",
        server_instance="test", status="provisioning",
    )
    folders = [
        FolderSpec(name="repo-bad", type="git-worktree", mount="code/repo-bad", url="https://github.com/org/bad-repo.git"),
        FolderSpec(name="repo-good", type="git-worktree", mount="code/repo-good", url="git@bitbucket.org:org/repo-good.git"),
    ]
    spec = WorkspaceSpec(
        workspace_id="ws-1", project="p", intent="i", image="img", root_path="",
        folders=folders,
    )

    await registry._do_provision("ws-1", spec)

    assert git_manager.clone_into.await_count == 2
    # The bad folder never appears -- not cloned, not mounted.
    assert not any("repo-bad" in p[0] for p in spec.worktree_paths)
    assert not any("repo-bad" in p[0] for p in spec.bind_mounts)
    # The good folder still cloned and mounted despite the earlier failure.
    assert ("/var/lib/warren/worktrees/ws-1/repo-good", "/workspace/code/repo-good") in spec.worktree_paths
    assert ("/var/lib/warren/worktrees/ws-1/repo-good", "/workspace/code/repo-good", "rw") in spec.bind_mounts
    # The workspace as a whole still provisions successfully.
    row = await store.get("ws-1")
    assert row.status == "running"


@pytest.mark.asyncio
async def test_do_provision_clones_git_clone_folders(sqlite_path):
    """git-clone folders are materialized the same way as git-worktree ones --
    `clone_into` doesn't distinguish them -- but mounted read-only when the
    folder declares `readonly`."""
    from pathlib import Path

    from warren.registry.store import WorkspaceStore
    from warren.registry.registry import WorkspaceRegistry
    from warren_common.models import FolderSpec
    from warren_common.runtime.base import WorkspaceHandle, WorkspaceSpec

    store = await WorkspaceStore.open(sqlite_path)
    runtime = AsyncMock()
    runtime.provision.return_value = WorkspaceHandle(
        workspace_id="ws-1", runtime_id="ctr-1", root_path=""
    )
    git_manager = AsyncMock()
    cloned_path = Path("/var/lib/warren/worktrees/ws-1/ref-repo")
    git_manager.folder_worktree_path = MagicMock(return_value=cloned_path)
    git_manager.clone_into.return_value = cloned_path

    registry = WorkspaceRegistry(
        runtime=runtime, store=store, server_id="test", git_manager=git_manager
    )
    await store.insert(
        workspace_id="ws-1", project="p", intent="i", image="img", root_path="",
        server_instance="test", status="provisioning",
    )
    folders = [
        FolderSpec(
            name="ref-repo", type="git-clone", mount="refs/ref-repo",
            url="https://github.com/org/ref.git", readonly=True,
        ),
    ]
    spec = WorkspaceSpec(
        workspace_id="ws-1", project="p", intent="i", image="img", root_path="",
        folders=folders,
    )

    await registry._do_provision("ws-1", spec)

    git_manager.clone_into.assert_awaited_once()
    assert spec.bind_mounts == [
        (str(cloned_path), "/workspace/refs/ref-repo", "ro"),
    ]


@pytest.mark.asyncio
async def test_do_provision_mounts_existing_local_path_folder(sqlite_path, tmp_path):
    from warren.registry.store import WorkspaceStore
    from warren.registry.registry import WorkspaceRegistry
    from warren_common.models import FolderSpec
    from warren_common.runtime.base import WorkspaceHandle, WorkspaceSpec

    store = await WorkspaceStore.open(sqlite_path)
    runtime = AsyncMock()
    runtime.provision.return_value = WorkspaceHandle(
        workspace_id="ws-1", runtime_id="ctr-1", root_path=""
    )
    git_manager = AsyncMock()

    registry = WorkspaceRegistry(
        runtime=runtime, store=store, server_id="test", git_manager=git_manager
    )
    await store.insert(
        workspace_id="ws-1", project="p", intent="i", image="img", root_path="",
        server_instance="test", status="provisioning",
    )
    folders = [
        FolderSpec(name="local-thing", type="local-path", mount="local/thing", path=str(tmp_path)),
    ]
    spec = WorkspaceSpec(
        workspace_id="ws-1", project="p", intent="i", image="img", root_path="",
        folders=folders,
    )

    await registry._do_provision("ws-1", spec)

    git_manager.clone_into.assert_not_awaited()
    assert spec.bind_mounts == [(str(tmp_path), "/workspace/local/thing", "rw")]


@pytest.mark.asyncio
async def test_do_provision_skips_missing_local_path_folder(sqlite_path):
    """A local-path folder whose host path doesn't exist is skipped, not
    silently mounted wrong -- same discipline as a failed git-clone."""
    from warren.registry.store import WorkspaceStore
    from warren.registry.registry import WorkspaceRegistry
    from warren_common.models import FolderSpec
    from warren_common.runtime.base import WorkspaceHandle, WorkspaceSpec

    store = await WorkspaceStore.open(sqlite_path)
    runtime = AsyncMock()
    runtime.provision.return_value = WorkspaceHandle(
        workspace_id="ws-1", runtime_id="ctr-1", root_path=""
    )
    git_manager = AsyncMock()

    registry = WorkspaceRegistry(
        runtime=runtime, store=store, server_id="test", git_manager=git_manager
    )
    await store.insert(
        workspace_id="ws-1", project="p", intent="i", image="img", root_path="",
        server_instance="test", status="provisioning",
    )
    folders = [
        FolderSpec(name="local-thing", type="local-path", mount="local/thing", path="/some/nonexistent/host/path"),
    ]
    spec = WorkspaceSpec(
        workspace_id="ws-1", project="p", intent="i", image="img", root_path="",
        folders=folders,
    )

    await registry._do_provision("ws-1", spec)

    assert spec.worktree_paths == []
    assert spec.bind_mounts == []


@pytest.mark.asyncio
async def test_do_provision_passes_ssh_key_to_folder_clones(sqlite_path):
    from pathlib import Path

    from warren.registry.store import WorkspaceStore
    from warren.registry.registry import WorkspaceRegistry
    from warren_common.models import FolderSpec
    from warren_common.runtime.base import WorkspaceHandle, WorkspaceSpec

    store = await WorkspaceStore.open(sqlite_path)
    runtime = AsyncMock()
    runtime.provision.return_value = WorkspaceHandle(
        workspace_id="ws-1", runtime_id="ctr-1", root_path=""
    )
    git_manager = AsyncMock()
    git_manager.folder_worktree_path = MagicMock(return_value=Path("/var/lib/warren/worktrees/ws-1/repo-a"))
    git_manager.clone_into.return_value = Path("/var/lib/warren/worktrees/ws-1/repo-a")

    registry = WorkspaceRegistry(
        runtime=runtime, store=store, server_id="test", git_manager=git_manager
    )
    await store.insert(
        workspace_id="ws-1", project="p", intent="i", image="img", root_path="",
        server_instance="test", status="provisioning",
    )
    folders = [
        FolderSpec(name="repo-a", type="git-worktree", mount="code/repo-a", url="git@bitbucket.org:org/repo-a.git"),
    ]
    spec = WorkspaceSpec(
        workspace_id="ws-1", project="p", intent="i", image="img", root_path="",
        env={"WARREN_GIT_SSH_KEY": "the-ssh-key"},
        folders=folders,
    )

    await registry._do_provision("ws-1", spec)

    git_manager.clone_into.assert_awaited_once_with(
        Path("/var/lib/warren/worktrees/ws-1/repo-a"),
        "git@bitbucket.org:org/repo-a.git",
        ref="main",
        ssh_key="the-ssh-key",
        pat=None,
    )


@pytest.mark.asyncio
async def test_do_provision_per_folder_ssh_key_override(sqlite_path):
    """A folder naming its own ssh_key_secret reads that secret instead of the
    template-wide WARREN_GIT_SSH_KEY -- e.g. a GitLab repo using a different deploy
    key than the Bitbucket repos in the same template. The other folder (no override)
    must still fall back to the shared key unaffected."""
    from pathlib import Path

    from warren.registry.store import WorkspaceStore
    from warren.registry.registry import WorkspaceRegistry
    from warren_common.models import FolderSpec
    from warren_common.runtime.base import WorkspaceHandle, WorkspaceSpec

    store = await WorkspaceStore.open(sqlite_path)
    runtime = AsyncMock()
    runtime.provision.return_value = WorkspaceHandle(
        workspace_id="ws-1", runtime_id="ctr-1", root_path=""
    )
    git_manager = AsyncMock()
    git_manager.folder_worktree_path = MagicMock(
        side_effect=lambda ws_id, name: Path(f"/var/lib/warren/worktrees/{ws_id}/{name}")
    )
    git_manager.clone_into.return_value = Path("/unused")

    registry = WorkspaceRegistry(
        runtime=runtime, store=store, server_id="test", git_manager=git_manager
    )
    await store.insert(
        workspace_id="ws-1", project="p", intent="i", image="img", root_path="",
        server_instance="test", status="provisioning",
    )
    folders = [
        FolderSpec(
            name="repo-a", type="git-worktree", mount="code/repo-a",
            url="git@bitbucket.org:org/repo-a.git",
        ),
        FolderSpec(
            name="repo-b", type="git-worktree", mount="code/repo-b",
            url="git@gitlab.com:org/repo-b.git", ssh_key_secret="WARREN_GIT_SSH_KEY_GITLAB",
        ),
    ]
    spec = WorkspaceSpec(
        workspace_id="ws-1", project="p", intent="i", image="img", root_path="",
        env={
            "WARREN_GIT_SSH_KEY": "the-shared-key",
            "WARREN_GIT_SSH_KEY_GITLAB": "the-gitlab-key",
        },
        folders=folders,
    )

    await registry._do_provision("ws-1", spec)

    assert git_manager.clone_into.await_args_list[0].kwargs["ssh_key"] == "the-shared-key"
    assert git_manager.clone_into.await_args_list[1].kwargs["ssh_key"] == "the-gitlab-key"


@pytest.mark.asyncio
async def test_do_provision_passes_github_pat_to_https_folder_clones(sqlite_path):
    """GITHUB_PAT, resolved into spec.env by routes/workspaces.py from the
    owner's own secrets the same way WARREN_GIT_SSH_KEY is, must reach every
    HTTPS folder clone as `pat=` -- the gap that left 20 of 26 dotmusic
    folders permanently unauthenticated even after GITHUB_PAT was declared
    and stored."""
    from pathlib import Path

    from warren.registry.store import WorkspaceStore
    from warren.registry.registry import WorkspaceRegistry
    from warren_common.models import FolderSpec
    from warren_common.runtime.base import WorkspaceHandle, WorkspaceSpec

    store = await WorkspaceStore.open(sqlite_path)
    runtime = AsyncMock()
    runtime.provision.return_value = WorkspaceHandle(
        workspace_id="ws-1", runtime_id="ctr-1", root_path=""
    )
    git_manager = AsyncMock()
    git_manager.folder_worktree_path = MagicMock(
        side_effect=lambda ws_id, name: Path(f"/var/lib/warren/worktrees/{ws_id}/{name}")
    )
    git_manager.clone_into.return_value = Path("/unused")

    registry = WorkspaceRegistry(
        runtime=runtime, store=store, server_id="test", git_manager=git_manager
    )
    await store.insert(
        workspace_id="ws-1", project="p", intent="i", image="img", root_path="",
        server_instance="test", status="provisioning",
    )
    folders = [
        FolderSpec(
            name="repo-a", type="git-worktree", mount="code/repo-a",
            url="https://github.com/org/repo-a.git",
        ),
    ]
    spec = WorkspaceSpec(
        workspace_id="ws-1", project="p", intent="i", image="img", root_path="",
        env={"GITHUB_PAT": "ghp_faketoken"},
        folders=folders,
    )

    await registry._do_provision("ws-1", spec)

    assert git_manager.clone_into.await_args_list[0].kwargs["pat"] == "ghp_faketoken"


@pytest.mark.asyncio
async def test_do_provision_per_folder_pat_override(sqlite_path):
    """A folder naming its own pat_secret reads that secret instead of the
    template-wide GITHUB_PAT -- needed because a fine-grained PAT only covers one
    GitHub resource owner (personal account OR one org, never both), so a template
    whose folders span two owners' private repos needs two separately-scoped
    tokens. The other folder (no override) must still fall back to the shared
    token unaffected."""
    from pathlib import Path

    from warren.registry.store import WorkspaceStore
    from warren.registry.registry import WorkspaceRegistry
    from warren_common.models import FolderSpec
    from warren_common.runtime.base import WorkspaceHandle, WorkspaceSpec

    store = await WorkspaceStore.open(sqlite_path)
    runtime = AsyncMock()
    runtime.provision.return_value = WorkspaceHandle(
        workspace_id="ws-1", runtime_id="ctr-1", root_path=""
    )
    git_manager = AsyncMock()
    git_manager.folder_worktree_path = MagicMock(
        side_effect=lambda ws_id, name: Path(f"/var/lib/warren/worktrees/{ws_id}/{name}")
    )
    git_manager.clone_into.return_value = Path("/unused")

    registry = WorkspaceRegistry(
        runtime=runtime, store=store, server_id="test", git_manager=git_manager
    )
    await store.insert(
        workspace_id="ws-1", project="p", intent="i", image="img", root_path="",
        server_instance="test", status="provisioning",
    )
    folders = [
        FolderSpec(
            name="org-repo", type="git-worktree", mount="code/org-repo",
            url="https://github.com/DotMusicLtd/org-repo.git",
        ),
        FolderSpec(
            name="personal-repo", type="git-worktree", mount="code/personal-repo",
            url="https://github.com/scottcowan/personal-repo.git",
            pat_secret="PERSONAL_GITHUB_PAT",
        ),
    ]
    spec = WorkspaceSpec(
        workspace_id="ws-1", project="p", intent="i", image="img", root_path="",
        env={
            "GITHUB_PAT": "the-org-token",
            "PERSONAL_GITHUB_PAT": "the-personal-token",
        },
        folders=folders,
    )

    await registry._do_provision("ws-1", spec)

    assert git_manager.clone_into.await_args_list[0].kwargs["pat"] == "the-org-token"
    assert git_manager.clone_into.await_args_list[1].kwargs["pat"] == "the-personal-token"


@pytest.mark.asyncio
async def test_do_provision_single_repo_path_now_bind_mounts(sqlite_path):
    """Regression guard for the gap this session's work closed: the single-repo
    WARREN_GIT_REPO_URL clone must now actually appear in spec.bind_mounts, not
    just the informational worktree_paths list."""
    from pathlib import Path

    from warren.registry.store import WorkspaceStore
    from warren.registry.registry import WorkspaceRegistry
    from warren_common.runtime.base import WorkspaceHandle, WorkspaceSpec

    store = await WorkspaceStore.open(sqlite_path)
    runtime = AsyncMock()
    runtime.provision.return_value = WorkspaceHandle(
        workspace_id="ws-1", runtime_id="ctr-1", root_path=""
    )
    git_manager = AsyncMock()
    git_manager.clone.return_value = Path("/var/lib/warren/worktrees/ws-1")

    registry = WorkspaceRegistry(
        runtime=runtime, store=store, server_id="test", git_manager=git_manager
    )
    await store.insert(
        workspace_id="ws-1", project="p", intent="i", image="img", root_path="",
        server_instance="test", status="provisioning",
    )
    spec = WorkspaceSpec(
        workspace_id="ws-1", project="p", intent="i", image="img", root_path="",
        env={"WARREN_GIT_REPO_URL": "https://github.com/o/r.git"},
    )

    await registry._do_provision("ws-1", spec)

    assert ("/var/lib/warren/worktrees/ws-1", "/workspace", "rw") in spec.bind_mounts
