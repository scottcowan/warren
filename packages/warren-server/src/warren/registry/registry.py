"""WorkspaceRegistry — thin stub wiring runtime + store.

reconcile_from_disk() lands in Plan 03 alongside PodmanRuntime; this module
exists so downstream code can import the symbol without a Plan-03 dependency.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import shutil
import stat
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

import structlog
from warren_common.errors import CapacityExhausted, ProvisionError
from warren_common.models import FolderSpec
from warren_common.runtime.base import WorkspaceHandle

if TYPE_CHECKING:
    from warren.config import WarrenSettings
    from warren.git.manager import GitManager
    from warren.registry.events import WorkspaceEventStore
    from warren.registry.models import Workspace
    from warren.registry.store import WorkspaceStore
    from warren_common.agent_state import AgentState
    from warren_common.runtime.base import ContainerRuntime, WorkspaceSpec
    from warren_common.turn_refs import Snapshot

log = structlog.get_logger(__name__)

ROOT_REPO = "root"


@dataclass(frozen=True)
class BranchSource:
    """HIST-05: a turn snapshot to check out in one repo of a new workspace."""

    repo: str
    snapshot: "Snapshot"
    branch: str

# Finding 7: the WorkspaceSpec fields a bare DB row (project/intent/image/
# root_path/owner_id/idle_ttl_seconds) can't carry on its own -- captured at
# provision time (see serialize_spec_extra, called from
# routes/workspaces.py::create_workspace) and restored by
# WorkspaceRegistry._reprovision_spec() so a reaped-and-gone container comes
# back with the SAME secrets/folders/app it started with. bind_mounts/
# worktree_paths are deliberately NOT included here -- _materialize_and_provision
# rebuilds those fresh via GitManager on every provision, reprovision included.
#
# Audit R1 (critical): "env" used to be in this tuple. For podman/docker,
# spec.env holds DECRYPTED secret values (routes/workspaces.py's
# resolve_secrets_for_names call) -- persisting it here landed every secret's
# plaintext value in workspaces.spec_json, bypassing the Fernet-encrypted
# secrets store entirely, with no way for a rotated/deleted secret to ever
# stop reaching a reprovisioned workspace (the stale decrypted value in
# spec_json would just keep coming back). Only secret_names (just the
# declared names, not values) is persisted; _reprovision_spec re-resolves
# actual values fresh from the secrets store on every reprovision, the same
# way create_workspace does on first provision.
#
# Audit R7: "owner_id" is now in this tuple too. WorkspaceSpec.owner_id is
# the SECRET-resolution owner (secret_owner_id in routes/workspaces.py --
# the caller's verified AWS identity hash on ECS, which differs from the
# workspace ROW's own owner_id=user.user_id on that runtime). Without
# persisting it, _reprovision_spec fell back to the row's owner_id, which is
# the wrong identity for ECS secret resolution -- a reprovisioned ECS
# workspace read the wrong SSM path and got no secrets at all.
_SPEC_EXTRA_FIELDS = (
    "template_env",
    "secret_names",
    "owner_id",
    "ssh_key_paths",
    "ssh_agent_sock",
    "app",
    "harnesses",
    "model_access",
    "docker_networks",
    "ecs_cpu",
    "ecs_memory",
    "efs_retention_days",
    "mode",
    "idle_destroy_seconds",
    "agent",
)

# Audit R11: "aws"/"scope" are pydantic models (warren_common.models.AwsConfig/
# ScopeConfig), not plain JSON-serializable values like everything in
# _SPEC_EXTRA_FIELDS above -- handled separately below (same reasoning as
# "folders"/FolderSpec) so a reprovision carries them forward too instead of
# resurrecting a workspace that silently lost its original ssh/aws/scope config.
_SPEC_EXTRA_MODEL_FIELDS = ("aws", "scope")


def serialize_spec_extra(spec: "WorkspaceSpec") -> str:
    data = {name: getattr(spec, name) for name in _SPEC_EXTRA_FIELDS}
    data["folders"] = [f.model_dump(mode="json") for f in spec.folders]
    for name in _SPEC_EXTRA_MODEL_FIELDS:
        value = getattr(spec, name)
        data[name] = value.model_dump(mode="json") if value is not None else None
    return json.dumps(data)


def deserialize_spec_extra(spec_json: str | None) -> dict:
    if not spec_json:
        return {}
    data = json.loads(spec_json)
    data["folders"] = [FolderSpec.model_validate(f) for f in data.get("folders", [])]
    from warren_common.models import AwsConfig, ScopeConfig  # noqa: PLC0415

    if data.get("aws") is not None:
        data["aws"] = AwsConfig.model_validate(data["aws"])
    if data.get("scope") is not None:
        data["scope"] = ScopeConfig.model_validate(data["scope"])
    return data


def _server_sanctioned_local_paths(folders: list, project: str, settings) -> list:
    """Audit Y1/V2: re-validate every `local-path` folder against the
    server-wide project file independent of the write-time 422 in
    routes/projects.py::_write_project_file. That write-time check alone
    doesn't cover a user-scoped file that already held a `local-path` folder
    before the check existed, or that reached disk by some other path --
    `effective_folders()` comes from the MERGED (server-wide + user-scoped)
    config with no record of which file contributed which folder.

    Audit Z1: lives here (not routes/workspaces.py, where it originated) so
    `_reprovision_spec` below can call it too -- a workspace provisioned
    during the window this fix was itself absent still has an unsanctioned
    `local-path` folder sitting in its persisted spec_json, and reprovision
    was restoring `folders` from that snapshot with no re-check at all,
    re-mounting it on every `ensure_running`/connect. create_workspace in
    routes/workspaces.py imports and calls this same function too, so first
    provision and every later reprovision enforce it identically.

    Only a `local-path` folder whose (name, path, mount, readonly) exactly
    matches one declared anywhere in the server-wide file is kept;
    everything else (git-worktree/git-clone folders, and any local-path
    folder with no server-wide match) passes through or is dropped, logged,
    and the workspace still provisions without that mount -- fail-closed on
    the dangerous bind mount, fail-open on availability, same tradeoff as
    the existing `local_path_folder_not_found` handling elsewhere in this
    file.
    """
    if not any(f.type == "local-path" for f in folders):
        return folders

    from warren_common.loader import ProjectLoader
    from warren_common.models import collect_local_path_folders

    server_wide = ProjectLoader.load_optional(settings.projects_dir / f"{project}.yaml")
    allowed = (
        {
            (f.name, f.path, f.mount, f.readonly)
            for f in collect_local_path_folders(server_wide)
        }
        if server_wide is not None
        else set()
    )

    result = []
    for folder in folders:
        if folder.type != "local-path":
            result.append(folder)
            continue
        if (folder.name, folder.path, folder.mount, folder.readonly) in allowed:
            result.append(folder)
        else:
            log.warning(
                "local_path_folder_not_server_sanctioned",
                project=project,
                folder=folder.name,
            )
    return result


def _server_sanctioned_docker_networks(networks: list[str], project: str, settings) -> list[str]:
    """R24: restrict which host podman/docker network names a resolved template's
    `docker_networks` may actually attach to -- mirrors the exact pattern
    `_server_sanctioned_local_paths` above uses for `local-path` folders
    (audit Y1/V2), including the Z1-class reprovision gap: `docker_networks`
    is persisted in `_SPEC_EXTRA_FIELDS` the same way `folders` is, so
    `_reprovision_spec` needs this same re-check, not just create_workspace.

    Without this, a user-scoped project (one any authenticated non-admin user can
    write themselves -- no admin check on that write path, see routes/projects.py)
    could declare `docker_networks: [...]` naming ANY host network, including ones
    that give access to other workspaces' internal traffic or host-adjacent
    networks. There was no allow-list at all.

    A network name is permitted in either of two ways:
      1. It's declared ANYWHERE in the server-wide project file (checked via
         collect_docker_networks, which walks the whole template tree) -- a
         server-wide (admin-managed) project is unrestricted, same trust tier as
         the local-path exception above.
      2. It's in WarrenSettings.allowed_docker_networks (a deployment-wide
         allow-list an operator configures, same shape as
         github_app_allowed_repos). Empty/unset means NO networks pass this
         check -- fail closed, not "everything allowed".

    Any network failing both is dropped, logged, and the workspace still
    provisions without that attachment -- fail-closed on the network, fail-open
    on availability, same tradeoff `_server_sanctioned_local_paths` already uses.
    """
    if not networks:
        return networks

    from warren_common.loader import ProjectLoader
    from warren_common.models import collect_docker_networks

    server_wide = ProjectLoader.load_optional(settings.projects_dir / f"{project}.yaml")
    admin_sanctioned = collect_docker_networks(server_wide) if server_wide is not None else set()
    allow_list = set(getattr(settings, "allowed_docker_networks", None) or [])

    result = []
    for net in networks:
        if net in admin_sanctioned or net in allow_list:
            result.append(net)
        else:
            log.warning(
                "docker_network_not_sanctioned",
                project=project,
                network=net,
            )
    return result


# Every user's tmux server (the exec may run as root or as the workspace user).
_TMUX_CLIENTS = (
    'for s in /tmp/tmux-*/default; do [ -S "$s" ] && tmux -S "$s" list-clients -t main -F attached; done 2>/dev/null; :'
)


class WorkspaceDestroyedError(Exception):
    """Raised by ensure_running()/issue_ssh_credential() for a workspace row
    whose status is "destroyed" (finding 8) -- the owner explicitly deleted
    it, and a stale container_id that still happens to resolve must never be
    treated as a reason to silently bring it back."""

class WorkspaceStillStarting(ProvisionError):
    """BB4: the workspace's task stayed in a transitional ("starting") state
    past the configured wait. Reprovisioning here would orphan that task."""

    reason = "workspace_starting"

    def __init__(self, message: str = "", *, retry_after_seconds: int = 5) -> None:
        super().__init__(message)
        self.retry_after_seconds = retry_after_seconds


# Fallback port-range bounds used when a WorkspaceRegistry is constructed
# without `settings=` (every existing 3-arg construction in tests / app.py
# must keep working unchanged). Mirrors WarrenSettings' own defaults.
_DEFAULT_SSH_PORT_RANGE_START = 30000
_DEFAULT_SSH_PORT_RANGE_END = 31000


@dataclass
class _WorkspaceRow:
    workspace_id: str
    handle: WorkspaceHandle
    mode: str = "interactive"


def _spec_mode(spec_json: str | None) -> str:
    try:
        return (json.loads(spec_json) if spec_json else {}).get("mode") or "interactive"
    except ValueError:
        return "interactive"


class WorkspaceRegistry:
    def __init__(
        self,
        runtime: "ContainerRuntime",
        store: "WorkspaceStore",
        server_id: str,
        event_store: "WorkspaceEventStore | None" = None,
        settings: "WarrenSettings | None" = None,
        git_manager: "GitManager | None" = None,
    ) -> None:
        self.runtime = runtime
        self.store = store
        self.server_id = server_id
        self.settings = settings
        # LIFE-03/D-06/D-07: optional so every existing construction site (3-arg
        # and 5-arg) keeps working untouched, following the same precedent as
        # the optional event_store/settings parameters above.
        self.git_manager = git_manager
        from warren.registry.events import WorkspaceEventStore
        self.event_store = event_store or WorkspaceEventStore()
        # LIFE-XX: per-workspace serialization for lifecycle transitions
        # (provision/destroy/stop/ensure_running). Without this, e.g. a
        # destroy() racing an in-flight _do_provision() for the same
        # workspace_id can interleave their writes — a delete marking a
        # workspace "stopped" while a slower provision call later overwrites
        # it back to "running", or two concurrent ensure_running() calls both
        # provisioning and leaking an untracked container. Instance-level
        # (not module-level) so multiple WorkspaceRegistry instances in the
        # same process — e.g. across test cases — never share lock state.
        self._locks: dict[str, asyncio.Lock] = {}
        self._locks_guard = asyncio.Lock()
        # Audit 2026-10-16 P1 #33: a bare `asyncio.create_task(...)` with no
        # reference kept anywhere can be garbage-collected mid-run on some
        # Python/asyncio implementations -- keyed by workspace_id so a later
        # (re)start of the same workspace can find and replace its
        # predecessor's task instead of leaking a second tailer alongside it.
        self._log_tasks: dict[str, asyncio.Task] = {}

    async def _lock_for(self, workspace_id: str) -> asyncio.Lock:
        """Return the asyncio.Lock serializing lifecycle transitions for workspace_id.

        Same pattern as warren_common.git.GitManager's _lock_for: a guard lock
        around dict.setdefault so two concurrent callers can't race the
        insertion itself across an await point.
        """
        async with self._locks_guard:
            lock = self._locks.setdefault(workspace_id, asyncio.Lock())
        return lock

    def _to_host_path(self, path: "Path") -> "Path":
        """Translate a path under `settings.data_dir` (valid from
        warren-server's OWN filesystem view) into its host-filesystem
        equivalent, so it's a valid bind-mount SOURCE for a sibling podman
        container.

        Podman always resolves a bind-mount source against the HOST
        filesystem -- it talks to the host's own podman daemon over the
        socket, never through warren-server's container namespace. When
        warren-server itself runs containerized (the normal deployment
        shape) with data_dir bind-mounted in from a different host path, a
        GitManager clone path under data_dir needs this translation before
        it can go into spec.bind_mounts, or podman 500s with "statfs: no
        such file or directory" (observed directly 2026-10-13) even though
        the path is real and the clone succeeded.

        No-op (returns `path` unchanged) when `settings.host_data_dir` is
        unset (warren-server running directly on the host, not
        containerized -- data_dir already IS a host path) or when `path`
        isn't actually under data_dir (defensive; never silently mangle a
        path this translation doesn't apply to).
        """
        if self.settings is None:
            return path
        host_data_dir = getattr(self.settings, "host_data_dir", None)
        if host_data_dir is None:
            return path
        data_dir = self.settings.data_dir
        try:
            relative = path.relative_to(data_dir)
        except ValueError:
            return path
        return host_data_dir / relative

    def _harness_state_dir(self, workspace_id: str) -> "Path | None":
        """AB1: podman/docker keep each workspace's harness state (persisted
        conversation history, AG4 records) in `<data_dir>/harness/<id>`, mounted at
        /var/lib/warren/harness, so it survives a reprovision and an image change.
        ECS keeps it on the workspace's own EFS access point instead."""
        if self.settings is None or getattr(self.settings, "runtime_type", "podman") == "ecs":
            return None
        data_dir = getattr(self.settings, "data_dir", None)
        if not isinstance(data_dir, Path) or not re.fullmatch(r"[A-Za-z0-9-]+", workspace_id):
            return None
        return data_dir / "harness" / workspace_id

    async def agent_state(self, ws: "Workspace") -> "AgentState | None":
        """AM1: the agent state the workspace's harness hooks (AG5) or OSC fallback
        last reported, read host-side without following links. None (unverifiable)
        when this runtime keeps harness state out of reach (ECS) or nothing reported."""
        from warren_common import agent_state as st  # noqa: PLC0415
        from warren_common.harness import SESSION_DIR  # noqa: PLC0415

        from warren.registry.completion import read_nofollow  # noqa: PLC0415

        base = self._agent_state_dir(ws.workspace_id)
        if base is None:
            return None

        def _read(name: str, source: str, *sub: str) -> "AgentState | None":
            try:
                raw = read_nofollow(base, (SESSION_DIR, *sub, name), st.MAX_STATE_BYTES)
                return st.parse_state(raw, source=source)
            except Exception:
                return None

        hook = await asyncio.to_thread(_read, st.STATE_FILE, "hook")
        osc = None if hook is not None else await asyncio.to_thread(_read, st.OSC_STATE_FILE, "osc")
        # AG2b: a supervised agent reports apart from the shell; whichever is busier holds the workspace.
        agent = st.agent_workspace_state(
            await asyncio.to_thread(_read, st.SUPERVISOR_STATE_FILE, "supervisor", st.AGENT_DIR),
            await asyncio.to_thread(_read, st.STATE_FILE, "hook", st.AGENT_DIR),
        )
        return st.busiest(hook or osc, agent)

    def _agent_state_dir(self, workspace_id: str) -> "Path | None":
        """Host-side harness dir the hooks report under: podman's bind-mounted dir, or
        on ECS the workspace's EFS dir (`/var/lib/warren` in the task) through the
        control plane's own mount of the filesystem (WARREN_EFS_LOCAL_MOUNT_PATH)."""
        if self.settings is not None and getattr(self.settings, "runtime_type", "podman") == "ecs":
            mount = getattr(self.settings, "efs_local_mount_path", "") or ""
            if not mount or not re.fullmatch(r"[A-Za-z0-9-]+", workspace_id):
                return None
            return Path(mount) / "workspaces" / workspace_id / "harness"
        return self._harness_state_dir(workspace_id)

    async def client_attached(self, ws: "Workspace", *, timeout: float = 15.0) -> bool:
        """AM1: whether a client is attached to the workspace's tmux session `main`,
        asked through the runtime's exec (podman exec, ECS Exec relay). Any failure
        reads as detached: this only ever holds a workspace back."""
        exec_stream = getattr(self.runtime, "exec_stream", None)
        if exec_stream is None or not ws.container_id:
            return False
        handle = WorkspaceHandle(
            workspace_id=ws.workspace_id, runtime_id=ws.container_id, root_path=ws.root_path, sidecar_url=""
        )
        out = b""
        code: int | None = None
        try:
            async with asyncio.timeout(timeout):
                async for item in exec_stream(handle, ["sh", "-c", _TMUX_CLIENTS]):
                    if isinstance(item, bytes):
                        out = (out + item)[-4096:]
                    else:
                        code = getattr(item, "exit_code", None)
        except Exception:
            log.info("client_attached_unknown", workspace_id=ws.workspace_id)
            return False
        return code in (0, None) and b"attached" in out

    def _start_log_tail(self, workspace_id: str, runtime_id: str) -> None:
        """Start (or restart) `workspace_id`'s log-tailing task (D-08/D-15).

        Audit 2026-10-16 P1 #33: the old call site lived ONLY inside
        `_do_provision` -- a workspace reaped and reconnected (or just
        restarted) via `ensure_running()` silently stopped having its logs
        captured, with no error, just quiet data loss. This is now the ONE
        place that starts a log tailer, called from every path that gets a
        workspace running with a live container: `_do_provision`'s first
        provision, `ensure_running`'s "start a stopped container" branch,
        and its reprovision branch. A no-op when the runtime has no
        `stream_logs` capability (ECS) or `runtime_id` is empty. Cancels any
        task already tracked for this workspace_id first, so a restart never
        leaves two tailers running for the same container at once.
        """
        if not runtime_id or not hasattr(self.runtime, "stream_logs"):
            return
        existing = self._log_tasks.get(workspace_id)
        if existing is not None and not existing.done():
            existing.cancel()
        task = asyncio.create_task(
            self.runtime.stream_logs(
                runtime_id, self.event_store.get_or_create(workspace_id)
            ),
            name=f"log-tail-{workspace_id}",
        )
        self._log_tasks[workspace_id] = task

        def _log_if_failed(t: "asyncio.Task") -> None:
            if t.cancelled():
                return
            exc = t.exception()
            if exc is not None:
                log.error(
                    "log_tail_task_failed",
                    workspace_id=workspace_id,
                    error=str(exc),
                )

        task.add_done_callback(_log_if_failed)

    async def reconcile_from_disk(self) -> None:
        from warren.registry.reconcile import reconcile_from_disk

        await reconcile_from_disk(
            runtime=self.runtime,
            store=self.store,
            server_id=self.server_id,
        )

    async def allocate_ssh_port(self) -> int:
        """First-free scan over the configured SSH host-port range (D-05/D-06/D-07).

        The range is half-open `[start, end)` — scanned with `range(start, end)`,
        matching `WarrenSettings.ssh_port_range_start/end`'s own doc convention.
        A workspace row with a non-null `ssh_port` counts as occupied UNLESS its
        status is `"destroyed"` -- that is this registry's one truly terminal,
        never-reconnectable state (`ensure_running()` raises
        `WorkspaceDestroyedError` for it rather than reviving it). Every other
        status, including `"stopped"` and `"failed"`, stays reserved: D-04's
        `ensure_running()` reuses a `stopped` OR `failed` workspace's stored
        port to reconnect/reprovision it later (it only special-cases
        `"destroyed"`, not those), so treating either of their ports as free
        would let a new workspace grab it while the old one is still
        reconnectable, guaranteeing a collision the first time someone calls
        `/connect` on the old one.

        Audit 2026-10-16 P1 #24: without the `"destroyed"` exclusion, rows are
        never deleted and `ssh_port` is never cleared, so a port leaked
        PERMANENTLY the moment its workspace was destroyed -- after enough
        workspaces had ever existed (cumulatively, not concurrently) over the
        server's lifetime, every port in range was "occupied" by a long-gone
        destroyed row and every new workspace creation failed with
        `CapacityExhausted` forever. Excluding `"destroyed"` reclaims those
        ports for reuse as soon as `destroy()` lands a row there.

        Concurrency posture: two simultaneous `provision()` calls could in
        principle both scan the same free port before either row's
        `ssh_port` is persisted — the same read-then-write window
        `max_workspaces` would have if it were enforced. No new locking
        primitive is added for this (RESEARCH.md "Don't Hand-Roll"); the
        mitigation relied on is the existing `aiosqlite` autocommit + WAL +
        `PRAGMA busy_timeout=5000` setup (`store.py::open_db`) plus the fact
        that a genuine duplicate host-port bind fails loudly at
        `containers.create` with a `RuntimeUnreachable`, never silently.
        """
        start = (
            self.settings.ssh_port_range_start
            if self.settings is not None
            else _DEFAULT_SSH_PORT_RANGE_START
        )
        end = (
            self.settings.ssh_port_range_end
            if self.settings is not None
            else _DEFAULT_SSH_PORT_RANGE_END
        )
        rows = await self.store.list_all()
        occupied = {
            r.ssh_port
            for r in rows
            if r.ssh_port is not None and r.status != "destroyed"
        }
        for port in range(start, end):
            if port not in occupied:
                return port
        raise CapacityExhausted(
            f"SSH port range [{start}, {end}) is fully occupied"
        )

    async def provision(self, workspace_id: str, spec: "WorkspaceSpec") -> None:
        """Fire _do_provision as a background task and return immediately."""
        asyncio.create_task(self._do_provision(workspace_id, spec))

    async def _materialize_and_provision(
        self,
        workspace_id: str,
        spec: "WorkspaceSpec",
        *,
        ssh_port: int | None = None,
        branch_from: BranchSource | None = None,
    ) -> "WorkspaceHandle":
        """Clone this workspace's git state into `spec`, then hand it to the runtime.

        Shared by `_do_provision` (first provision) and `ensure_running`'s
        reprovision branch (finding 7: a reaped-and-gone container must come
        back with the SAME env/secrets/folders/app it started with, not an
        empty shell) -- both need the identical clone-then-provision sequence,
        just with different port-allocation and status-bookkeeping around it
        (see each caller). Raises whatever `runtime.provision`/`GitManager.clone`
        raise; callers decide how to handle that.

        LIFE-03, D-06: materializes the git worktree BEFORE the container is
        created -- spec.worktree_paths is consumed inside PodmanRuntime.provision()
        to build WARREN_WORKTREE_PATHS, so the clone must precede provision(). A
        GitError is a ProvisionError, so it propagates like any other provision
        failure with no special handling needed here.

        WorkspaceSpec (warren_common) has no repo_url field today; per the
        plan's explicit fallback, the repo URL is read defensively from a
        hypothetical future spec.repo_url first, then from
        spec.env["WARREN_GIT_REPO_URL"] (see 04-06-SUMMARY.md for the wiring
        gap this leaves in create_workspace).
        """
        repo_url = getattr(spec, "repo_url", None) or spec.env.get(
            "WARREN_GIT_REPO_URL"
        )
        # warren.secrets: a workspace whose owner stored a
        # WARREN_GIT_SSH_KEY/GITHUB_PAT secret, and whose resolved
        # template declares it by name, has it decrypted straight into
        # spec.env by routes/workspaces.py already -- GitManager only
        # actually uses ssh_key when a given repo_url is itself an SSH
        # remote, and pat only for an HTTPS one (_is_ssh_url), so
        # passing both unconditionally is harmless either way.
        ssh_key = spec.env.get("WARREN_GIT_SSH_KEY") or None
        github_pat = spec.env.get("GITHUB_PAT") or None
        branch_applied = False

        harness_state = self._harness_state_dir(workspace_id) if spec.harnesses else None
        if harness_state is not None:
            from warren_common.harness import SERVER_HARNESS_ROOT  # noqa: PLC0415

            harness_state.mkdir(mode=0o700, parents=True, exist_ok=True)
            spec.bind_mounts.append((str(self._to_host_path(harness_state)), SERVER_HARNESS_ROOT, "rw"))

        async def _apply_branch(repo: str, path: Path) -> None:
            nonlocal branch_applied
            if branch_from is not None and branch_from.repo == repo:
                await self.git_manager.apply_turn_snapshot(
                    path, branch_from.snapshot, branch_from.branch
                )
                branch_applied = True

        if self.git_manager is not None and repo_url:
            ref = spec.env.get("WARREN_GIT_REF") or None
            worktree_path = await self.git_manager.clone(
                workspace_id, repo_url, ref=ref, ssh_key=ssh_key, pat=github_pat
            )
            await _apply_branch(ROOT_REPO, worktree_path)
            # Bind-mount the clone into the container -- this was
            # missing entirely before: worktree_paths only ever fed
            # WARREN_WORKTREE_PATHS (an informational env var), never
            # spec.bind_mounts, so the cloned directory never actually
            # appeared inside the container regardless of this step
            # succeeding (podman.py only mounts spec.bind_mounts).
            host_worktree_path = self._to_host_path(worktree_path)
            spec.worktree_paths.append((str(host_worktree_path), "/workspace"))
            spec.bind_mounts.append((str(host_worktree_path), "/workspace", "rw"))

        # Multi-repo templates (ProjectConfig.folders): clone every
        # git-worktree/git-clone folder the resolved template declares,
        # each into its own subdirectory under this workspace's worktree
        # root, bind-mounted at /workspace/<folder.mount>. Independent of
        # the single-repo WARREN_GIT_REPO_URL path above -- a template can
        # use either or both without conflict (they occupy different
        # paths). git-worktree and git-clone only differ in CLI-side
        # workflow semantics (active-dev branch vs. read-only shared
        # reference) -- server-side, `GitManager.clone_into` materializes
        # either one identically, so both are handled by the same clone
        # here; `folder.readonly` (advisory everywhere else) picks the
        # bind-mount mode so a git-clone folder isn't writable by default.
        #
        # local-path folders bind-mount a path from THIS HOST's own
        # filesystem directly, with no git operation at all -- this only
        # works when warren-server and the podman/docker runtime share a
        # filesystem (the same-host deployment shape this whole block is
        # already scoped to, via `self.git_manager is not None`/
        # runtime_type != "ecs" in app.py). It is NOT translated through
        # `_to_host_path` like a GitManager-cloned path is: a local-path
        # folder's `path` already names a location on the host, not
        # somewhere under warren-server's own `data_dir`.
        if self.git_manager is not None and spec.folders:
            from warren.git.manager import GitError  # noqa: PLC0415

            for folder in spec.folders:
                if folder.type == "local-path":
                    if not folder.path:
                        continue
                    host_path = Path(os.path.expanduser(folder.path))
                    if not host_path.exists():
                        log.warning(
                            "local_path_folder_not_found",
                            workspace_id=workspace_id,
                            folder=folder.name,
                            path=str(host_path),
                        )
                        continue
                    container_path = f"/workspace/{folder.mount}"
                    mode = "ro" if folder.readonly else "rw"
                    spec.bind_mounts.append((str(host_path), container_path, mode))
                    continue

                if folder.type not in ("git-worktree", "git-clone") or not folder.url:
                    continue
                # Per-repo SSH key override: a folder naming its own
                # ssh_key_secret reads that warren.secrets entry instead of
                # the template-wide WARREN_GIT_SSH_KEY -- e.g. a GitLab repo
                # using a different deploy key than the Bitbucket repos in
                # the same template. Falls back to the shared key when unset
                # (old behavior, unchanged for every existing template).
                folder_ssh_key = (
                    spec.env.get(folder.ssh_key_secret)
                    if folder.ssh_key_secret
                    else ssh_key
                )
                # Per-repo PAT override (same reasoning as ssh_key_secret
                # above): a fine-grained PAT only covers one GitHub resource
                # owner (your personal account OR one org, never both), so a
                # template whose folders span two owners' private repos needs
                # two separately-scoped secrets, not one shared GITHUB_PAT.
                folder_pat = (
                    spec.env.get(folder.pat_secret)
                    if folder.pat_secret
                    else github_pat
                )
                dest = self.git_manager.folder_worktree_path(workspace_id, folder.name)
                try:
                    cloned_path = await self.git_manager.clone_into(
                        dest, folder.url, ref=folder.branch,
                        ssh_key=folder_ssh_key, pat=folder_pat,
                    )
                except GitError:
                    # One folder's auth/clone failure (e.g. a private GitHub
                    # HTTPS repo with no PAT support yet -- a separate, known
                    # gap) must never abort every OTHER folder's clone. Before
                    # this, a template with 26 folders and exactly one bad one
                    # got zero of them, including the 25 that would have
                    # worked fine (real failure observed 2026-10-13: the
                    # multi-folder dotmusic template's first folder being
                    # unauthenticated HTTPS blocked all 25 working Bitbucket
                    # SSH clones behind it).
                    log.warning(
                        "folder_clone_failed_skipping",
                        workspace_id=workspace_id,
                        folder=folder.name,
                        url=folder.url,
                        exc_info=True,
                    )
                    continue
                await _apply_branch(folder.name, cloned_path)
                container_path = f"/workspace/{folder.mount}"
                host_cloned_path = self._to_host_path(cloned_path)
                mode = "ro" if folder.readonly else "rw"
                spec.worktree_paths.append((str(host_cloned_path), container_path))
                spec.bind_mounts.append((str(host_cloned_path), container_path, mode))

        if branch_from is not None and not branch_applied:
            from warren.git.manager import GitError  # noqa: PLC0415

            raise GitError(f"branch target repo {branch_from.repo!r} was not materialized")

        if hasattr(self.runtime, "supports_ssh_access"):
            # D-05/D-06/D-07: allocate and publish the SSH host port at
            # provision time. Does NOT mint/inject a keypair here — D-01/
            # D-02 mint per connect, so a freshly provisioned workspace
            # starts with an empty authorized_keys and simply rejects
            # auth until a connect call mints one (issue_ssh_credential).
            # `ssh_port` is only passed in by ensure_running's reprovision
            # branch, reusing the workspace's already-allocated port (D-05);
            # a first provision always allocates fresh here.
            port = ssh_port if ssh_port is not None else await self.allocate_ssh_port()
            # Audit R12: allocation/bookkeeping (the line above, and update_ssh_port
            # below) is unconditional -- only the actual container-level publish is
            # gated, via the settings flag documented on WarrenSettings.ssh_access_enabled.
            publish_ssh_port = bool(
                self.settings is not None
                and getattr(self.settings, "ssh_access_enabled", False)
            )
            handle = await self.runtime.provision(
                spec, ssh_port=port, publish_ssh_port=publish_ssh_port
            )
            await self.store.update_ssh_port(workspace_id, port)
        else:
            handle = await self.runtime.provision(spec)
        return handle

    async def _do_provision(
        self, workspace_id: str, spec: "WorkspaceSpec", *, branch_from: BranchSource | None = None
    ) -> None:
        """Run the container runtime and update workspace status.

        Always updates status — never lets exceptions escape (Pitfall 1).
        Holds this workspace's lifecycle lock for the whole call (issue #7) so
        a concurrent destroy()/stop()/ensure_running() for the same
        workspace_id can't interleave its writes with this one — e.g. a
        delete arriving mid-provision must not be silently overwritten back
        to "running" once this method's slower runtime.provision() call
        finally returns.
        """
        async with await self._lock_for(workspace_id):
            try:
                handle = await self._materialize_and_provision(
                    workspace_id, spec, branch_from=branch_from
                )
                await self.store.mark_running(workspace_id, handle.runtime_id)
                self._start_log_tail(workspace_id, handle.runtime_id)
            except ProvisionError as exc:
                await self.store.update_status(workspace_id, "failed")
                log.warning(
                    "provision_failed",
                    workspace_id=workspace_id,
                    reason=exc.reason,
                )
            except Exception:
                await self.store.update_status(workspace_id, "failed")
                log.exception(
                    "provision_unexpected_error",
                    workspace_id=workspace_id,
                )

    async def list_non_terminal(self) -> list[_WorkspaceRow]:
        """Return non-terminal workspaces as rows carrying a WorkspaceHandle.

        Thin passthrough to the store; reaper consumes ``ws.workspace_id`` and
        ``ws.handle``. Full wiring (sidecar_url, etc.) lands in Phase 6.
        """
        rows = await self.store.list_non_terminal()
        return [
            _WorkspaceRow(
                workspace_id=r.workspace_id,
                handle=WorkspaceHandle(
                    workspace_id=r.workspace_id,
                    runtime_id=r.container_id or "",
                    root_path=r.root_path,
                    sidecar_url="",
                ),
                mode=_spec_mode(r.spec_json),
            )
            for r in rows
        ]

    async def destroy(self, workspace_id: str) -> None:
        """Stop and destroy a workspace. Idempotent — safe to call twice.

        A runtime failure no longer gets recorded as "stopped" (issue #8) —
        that previously let a container that failed to actually destroy stay
        running and reachable while disappearing from reconciliation, since
        "stopped" looks fully resolved. It now lands on "unknown" instead: a
        non-terminal state reconciliation/a retry can act on, not a false
        claim of success. The event buffer is only discarded once destruction
        is confirmed, not on a failed attempt.

        Finding 8: a confirmed destroy lands on the dedicated "destroyed"
        terminal state, not "stopped" -- "stopped" is the idle reaper's own
        reconnectable state (ensure_running() brings it straight back), so
        reusing it here let /connect and /ensure_running resurrect a
        workspace the owner explicitly deleted. container_id is cleared too:
        the container is actually gone, and a stale ID is exactly what let
        ensure_running() go looking for it in the first place.
        """
        async with await self._lock_for(workspace_id):
            await self._destroy_locked(workspace_id)

    async def _destroy_locked(
        self, workspace_id: str, *, keep_events_for: float | None = None
    ) -> None:
        """destroy()'s body; caller holds the workspace lock. `keep_events_for` (AH2)
        closes the event buffer and keeps it replayable that long instead of dropping it."""
        ws = await self.store.get(workspace_id)
        if ws is None:
            return
        if ws.status == "destroyed":
            return
        handle = WorkspaceHandle(
            workspace_id=ws.workspace_id,
            runtime_id=ws.container_id or "",
            root_path=ws.root_path,
            sidecar_url="",
        )
        try:
            await self.runtime.destroy(handle)
        except Exception:
            log.exception("destroy_runtime_error", workspace_id=workspace_id)
            await self.store.update_status(workspace_id, "unknown")
            return
        await self.store.update_status(workspace_id, "destroyed")
        await self.store.update_container_id(workspace_id, None)
        buf = self.event_store.get(workspace_id) if keep_events_for else None
        if buf is not None:
            await buf.close()
            self.event_store.discard_later(workspace_id, keep_events_for)
        else:
            self.event_store.discard(workspace_id)  # T-04-05-02: free ring buffer
        harness_state = self._harness_state_dir(workspace_id)
        if harness_state is not None and harness_state.exists():
            # AB1: persisted harness history goes with the workspace.
            try:
                shutil.rmtree(harness_state)
            except OSError:
                log.exception("destroy_harness_state_cleanup_failed", workspace_id=workspace_id)
        if self.git_manager is not None:
            # Finding #25: without this, every destroyed workspace's
            # cloned repos (private repo clones included) accumulate on
            # disk forever. Best-effort -- a filesystem error here must
            # never undo the destroy that already succeeded above.
            try:
                await self.git_manager.remove_worktree(workspace_id)
            except Exception:
                log.exception(
                    "destroy_worktree_cleanup_failed", workspace_id=workspace_id
                )
        # "destroyed" is terminal -- no further lifecycle transition for this
        # workspace_id will ever need serializing again, so the lock entry can
        # be dropped (audit 2026-10-16 #35: _locks otherwise grows forever,
        # one entry per workspace that has ever existed).
        async with self._locks_guard:
            self._locks.pop(workspace_id, None)

    async def stop(self, workspace_id: str) -> None:
        """Stop a workspace's container but keep it reconnectable (LIFE-01).

        This is deliberately NOT `destroy()`: it does not clear `ssh_port` and
        does not discard the event buffer, so `ensure_running()` can bring the
        workspace straight back on the same SSH port later. `destroy()` now
        lands on the distinct terminal `"destroyed"` status (audit 2026-10-16
        P0 #8) rather than reusing `"stopped"`, so the two ARE distinguishable
        in `WorkspaceStatus` today -- this method's own choice of `"stopped"`
        (reconnectable) vs. `destroy()`'s `"destroyed"` (never resurrected) is
        what actually encodes the difference now, not just what each method
        chooses not to touch.

        An unknown `workspace_id` is a silent no-op, matching `destroy()`'s
        contract. A runtime exception (issue #8) now lands the row on
        `"unknown"` rather than unconditionally claiming `"stopped"` —
        `"stopped"` implied the container was confirmed gone, which was false
        on the exception path; `"unknown"` is still non-terminal, so the row
        doesn't get stuck the way the old docstring's rationale was guarding
        against, but it no longer lies about what actually happened.

        Audit R8: re-checks the row's status UNDER this workspace's lock before
        touching the runtime at all. Without this, the idle reaper's own
        read-then-call of `stop()` races a concurrent `destroy()`: the reaper
        observes "running", the owner destroys the workspace (landing it on
        the genuinely terminal `"destroyed"` status and clearing
        `container_id`) before the reaper's call takes this lock, and
        `stop()` would otherwise write `"stopped"` right back over
        `"destroyed"` -- resurrecting a deleted workspace the next time
        `ensure_running()` is called. `"destroyed"` is terminal (the same
        invariant `ensure_running()` already enforces by raising
        `WorkspaceDestroyedError`), so a `stop()` that finds it is a safe
        no-op, not an error -- the only caller (`idle_reaper`) has no use for
        a signal here and a destroyed workspace is already exactly what
        `stop()` is trying to achieve (not running, not resurrectable).
        """
        async with await self._lock_for(workspace_id):
            ws = await self.store.get(workspace_id)
            if ws is None:
                return
            if ws.status == "destroyed":
                return
            if _spec_mode(ws.spec_json) == "single-turn":
                # AH2: stopping would end the run without a workspace.completed event.
                log.info("stop_skipped_single_turn", workspace_id=workspace_id)
                return
            handle = WorkspaceHandle(
                workspace_id=ws.workspace_id,
                runtime_id=ws.container_id or "",
                root_path=ws.root_path,
                sidecar_url="",
            )
            try:
                if hasattr(self.runtime, "stop"):
                    await self.runtime.stop(handle)
                else:
                    await self.runtime.destroy(handle)
            except Exception:
                log.exception("stop_runtime_error", workspace_id=workspace_id)
                await self.store.update_status(workspace_id, "unknown")
                return
            await self.store.update_status(workspace_id, "stopped")

    async def _reprovision_spec(self, ws: "Workspace") -> "WorkspaceSpec":
        """Rebuild the fully resolved WorkspaceSpec for a workspace whose
        container is gone (finding 7), from the snapshot `serialize_spec_extra`
        captured at its original provision time plus the row's own columns.
        A legacy row with no `spec_json` (provisioned before this fix) falls
        back to the bare DB-row fields, matching the old behavior exactly.

        Audit R1/R7: `env` is never part of the persisted snapshot (see
        _SPEC_EXTRA_FIELDS's comment) -- it's re-resolved fresh here, from
        the persisted `secret_names` and the persisted `owner_id` (the
        original SECRET-resolution owner, which may differ from the row's
        own owner_id on ECS), exactly like routes/workspaces.py's
        create_workspace does on first provision. This also means a secret
        rotated or deleted since the workspace's last provision is reflected
        on this reprovision, instead of resurrecting a stale value.
        """
        from warren_common.runtime.base import WorkspaceSpec

        extra = deserialize_spec_extra(ws.spec_json)
        # Audit V3: a pre-R1 row's spec_json can still carry a stale plaintext "env"
        # snapshot (store.py's open_db() scrubs it from the DB at startup, but strip it
        # here too regardless -- WorkspaceSpec(**extra) below would otherwise set
        # spec.env to that stale blob immediately, and the ECS branch below never
        # overwrites spec.env at all, so it would reach runtime.provision() as plaintext
        # task-environment overrides, visible via ecs:DescribeTasks/CloudTrail -- worse
        # than the original R1 exposure, since SSM SecureString at least encrypts at
        # rest).
        extra.pop("env", None)
        # Legacy rows (provisioned before R7) have no persisted owner_id extra;
        # fall back to the row's own owner_id, matching old behavior exactly.
        owner_id = extra.pop("owner_id", None) or ws.owner_id or ""

        # Audit Z1: re-run the SAME server-wide sanction checks create_workspace
        # applies on first provision. Without this, a workspace provisioned during
        # the window before Y1/V2 (local-path) or R24 (docker_networks) existed --
        # or one whose spec_json otherwise ended up with an unsanctioned entry --
        # has that entry sitting in its persisted spec_json forever, and every
        # ensure_running()/connect() reprovision re-mounts/re-attaches it with no
        # re-check at all. _SPEC_EXTRA_FIELDS persists both "folders" and
        # "docker_networks" verbatim; this re-validates them exactly like a fresh
        # provision would, every single reprovision, not just once at write time.
        if self.settings is not None:
            if extra.get("folders"):
                extra["folders"] = _server_sanctioned_local_paths(
                    extra["folders"], ws.project, self.settings
                )
            if extra.get("docker_networks"):
                extra["docker_networks"] = _server_sanctioned_docker_networks(
                    extra["docker_networks"], ws.project, self.settings
                )

        spec = WorkspaceSpec(
            workspace_id=ws.workspace_id,
            project=ws.project,
            intent=ws.intent,
            image=ws.image,
            root_path=ws.root_path,
            owner_id=owner_id,
            idle_ttl_seconds=ws.idle_ttl_seconds,
            **extra,
        )

        if self.settings is not None and getattr(self.settings, "runtime_type", "podman") != "ecs":
            from warren.secrets import store as local_store
            from warren.secrets.cipher import LocalCipher

            cipher = LocalCipher(self.settings.secret_key.get_secret_value())
            spec.env = await local_store.resolve_secrets_for_names(
                self.store._db, cipher, owner_id, spec.secret_names
            )

        return spec

    async def resolve_current_image(self, ws: "Workspace") -> str | None:
        """AB1 req 6: the image a new task/container for `ws` would run, resolved
        the way create_workspace does (template `ecs_image`, else
        `ecs_default_image`; `docker_image` on podman) through the same
        allow-list check. None when it can't be re-resolved (no project config,
        template gone, a Containerfile build): the stored image is kept then."""
        settings = self.settings
        projects_dir = getattr(settings, "projects_dir", None)
        if settings is None or not isinstance(projects_dir, Path):
            return None
        from warren_common.loader import ProjectLoader  # noqa: PLC0415
        from warren_common.templates import resolve_template  # noqa: PLC0415

        from warren.images.resolve import template_image  # noqa: PLC0415

        try:
            project_cfg = ProjectLoader.load_effective(ws.project, projects_dir, ws.owner_id or "")
            template_cfg = resolve_template(project_cfg, ws.intent)
            if getattr(template_cfg, "containerfile", None) or getattr(project_cfg, "containerfile", None):
                return None
            return template_image(template_cfg, ws.project, ws.intent, settings)
        except Exception:
            log.warning("image_reresolve_failed", workspace_id=ws.workspace_id, exc_info=True)
            return None

    async def ensure_running(self, workspace_id: str) -> "WorkspaceHandle | None":
        """Bring a workspace's container back up if needed, then return its handle (D-04).

        This "ensure running, then connect" decision-making is deliberately
        server-side — the CLI is a thin relay and must never orchestrate
        reprovisioning itself. Returns `None` when the workspace row does not
        exist (the route turns that into a 404). `ProvisionError` subclasses
        raised by the runtime propagate unchanged so the route can map them
        to HTTP status codes. Raises `WorkspaceDestroyedError` for a row whose
        status is "destroyed" (finding 8) -- the route maps that to a 410.

        Holds this workspace's lifecycle lock for the whole call (issue #7):
        without it, two concurrent connect calls for the same workspace_id
        can both observe "not running" and both provision, leaking one
        container that never gets tracked in the store.
        """
        async with await self._lock_for(workspace_id):
            ws = await self.store.get(workspace_id)
            if ws is None:
                return None
            if ws.status == "destroyed":
                raise WorkspaceDestroyedError(workspace_id)
            handle = WorkspaceHandle(
                workspace_id=ws.workspace_id,
                runtime_id=ws.container_id or "",
                root_path=ws.root_path,
                sidecar_url="",
            )

            # D-05: the ssh_port lives for the workspace's whole life — reuse the
            # stored port. Only a legacy row provisioned before this phase (no
            # ssh_port at all) triggers a fresh allocation here.
            port = ws.ssh_port
            if port is None:
                port = await self.allocate_ssh_port()
                await self.store.update_ssh_port(workspace_id, port)

            status = await self.runtime.status(handle) if ws.container_id else "unknown"
            if status == "starting":
                status = await self._wait_while_starting(handle)

            if status == "running":
                return handle

            # AH2: a single-turn workspace runs its app once. Never relaunch it; if it
            # already exited and the reaper hasn't caught up, complete it now.
            if _spec_mode(ws.spec_json) == "single-turn":
                if status == "stopped":
                    await self._complete_locked(ws)
                raise WorkspaceDestroyedError(workspace_id)

            # Finding 9: Fargate has no "start a stopped task" operation --
            # ECSRuntime.start() is a no-op, so a "stopped" status from a
            # runtime with no real supports_ssh_access capability (ECS) is
            # a dead task ARN, not something start() can bring back. Only a
            # runtime that actually supports starting a stopped container
            # (podman/docker) takes this branch; ECS falls through to the
            # reprovision branch below, same as "unknown".
            if status == "stopped" and hasattr(self.runtime, "supports_ssh_access"):
                await self.runtime.start(handle)
                await self.store.update_status(workspace_id, "running")
                self._start_log_tail(workspace_id, handle.runtime_id)
                return handle

            # status == "unknown", no container_id at all, or a stopped ECS
            # task: re-provision (D-04) from the fully resolved spec persisted
            # at the workspace's original provision time -- not a bare
            # WorkspaceSpec built from the DB row alone, which carries no
            # env/secrets, folders, app, or idle_ttl_seconds (finding 7).
            spec = await self._reprovision_spec(ws)
            spec.provision_generation = ws.container_id or ""
            # AB1 req 6: a new task/container runs the image the template resolves
            # to now (never replacing a running one: that returned above).
            image = await self.resolve_current_image(ws)
            if image and image != ws.image:
                log.info(
                    "workspace_image_upgraded", workspace_id=workspace_id, old_image=ws.image, new_image=image
                )
                spec.image = image
            new_handle = await self._materialize_and_provision(
                workspace_id, spec, ssh_port=port
            )
            if spec.image != ws.image:
                await self.store.update_image(workspace_id, spec.image)
            await self.store.update_ssh_port(workspace_id, port)
            await self.store.mark_running(workspace_id, new_handle.runtime_id)
            self._start_log_tail(workspace_id, new_handle.runtime_id)
            log.info(
                "workspace_reprovisioned_for_connect",
                workspace_id=workspace_id,
                ssh_port=port,
            )
            return new_handle

    async def _wait_while_starting(self, handle: WorkspaceHandle) -> str:
        """Poll a "starting" task until it leaves that state (BB4).

        Caller holds the workspace lock. Raises WorkspaceStillStarting once
        `ecs_start_wait_timeout_seconds` passes rather than reprovisioning.
        """
        timeout = float(getattr(self.settings, "ecs_start_wait_timeout_seconds", 45.0))
        interval = float(getattr(self.settings, "ecs_start_poll_interval_seconds", 3.0))
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout
        while True:
            remaining = deadline - loop.time()
            if remaining <= 0:
                log.warning(
                    "workspace_start_wait_timeout",
                    workspace_id=handle.workspace_id,
                    runtime_id=handle.runtime_id,
                    timeout_s=timeout,
                )
                raise WorkspaceStillStarting(
                    f"workspace {handle.workspace_id} is still starting after {timeout:g}s; "
                    "retry shortly",
                    retry_after_seconds=int(
                        getattr(self.settings, "ecs_start_retry_after_seconds", 5)
                    ),
                )
            await asyncio.sleep(min(interval, remaining))
            status = await self.runtime.status(handle)
            if status != "starting":
                return status

    async def issue_ssh_credential(
        self, workspace_id: str
    ) -> "tuple[int, bytes] | None":
        """Ensure the workspace is running, mint a fresh keypair, inject the public
        half, and return the private half exactly once (D-01/D-02).

        Returns `None` for an unknown workspace_id (the route turns that into a
        404). `ProvisionError` subclasses raised via `ensure_running` propagate
        unchanged. The private key is never persisted anywhere — no database
        column, no file, no in-memory cache — it exists only in this method's
        return value, handed back over the already-authenticated HTTPS channel
        (D-01).
        """
        handle = await self.ensure_running(workspace_id)
        if handle is None:
            return None

        from warren.registry.ssh_keys import mint_ssh_keypair

        # D-02: mint a FRESH keypair on every call and overwrite the
        # container's single authorized_keys with it (smallest blast
        # radius). This means a second connect to the SAME workspace
        # invalidates the previous key for that workspace — an intentional
        # narrowing, not a bug.
        private_pem, public_line = mint_ssh_keypair()
        await self.runtime.inject_ssh_key(handle, public_line)

        ws = await self.store.get(workspace_id)
        ssh_port = ws.ssh_port if ws is not None else None
        # Log identifiers only. Never pass private_pem, public_line, or any
        # slice/length/fingerprint of the private key to a logging call —
        # mirrors routes/admin.py::mint_token's raw_token discipline and
        # GitManager's deploy-key log sanitization.
        log.info(
            "ssh_credential_issued", workspace_id=workspace_id, ssh_port=ssh_port
        )
        return ssh_port, private_pem

    async def complete_single_turn(self, workspace_id: str) -> None:
        """AH2: a single-turn workspace's app exited. Emit workspace.completed, then destroy.

        Capture is best-effort: any failure is logged and listed in the event's
        `capture_errors`; the event still fires and the workspace is still destroyed.
        """
        async with await self._lock_for(workspace_id):
            ws = await self.store.get(workspace_id)
            if ws is None or ws.status == "destroyed":
                return
            await self._complete_locked(ws)

    async def _complete_locked(self, ws: "Workspace") -> None:
        handle = WorkspaceHandle(
            workspace_id=ws.workspace_id,
            runtime_id=ws.container_id or "",
            root_path=ws.root_path,
            sidecar_url="",
        )
        event = await self._completion_event(ws, handle)
        await self.event_store.get_or_create(ws.workspace_id).push(json.dumps(event))
        log.info(
            "workspace_completed",
            workspace_id=ws.workspace_id,
            exit_code=event["exit_code"],
            capture_errors=len(event["capture_errors"]),
        )
        retention = float(getattr(self.settings, "single_turn_event_retention_seconds", 3600.0))
        await self._destroy_locked(ws.workspace_id, keep_events_for=retention)

    async def _completion_event(self, ws: "Workspace", handle: WorkspaceHandle) -> dict:
        import time  # noqa: PLC0415

        from warren.registry import completion  # noqa: PLC0415

        errors: list[str] = []
        event: dict = {
            "type": "workspace.completed",
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "workspace_id": ws.workspace_id,
            "exit_code": None,
            "git": None,
            "git_folders": [],
            "verdict": None,
            "capture_errors": errors,
        }

        def failed(what: str, exc: BaseException) -> None:
            log.warning("single_turn_capture_failed", workspace_id=ws.workspace_id, part=what, error=str(exc))
            errors.append(f"{what}: {exc}")

        try:
            if hasattr(self.runtime, "exit_code"):
                event["exit_code"] = await self.runtime.exit_code(handle)
        except Exception as exc:
            failed("exit_code", exc)

        try:
            folders = deserialize_spec_extra(ws.spec_json).get("folders", [])
        except Exception as exc:
            failed("spec", exc)
            folders = []

        verdict_raw: bytes | None = None
        targets: list = []
        shadow_root: Path | None = None
        if getattr(self.settings, "runtime_type", "podman") == "ecs":
            mount = getattr(self.settings, "efs_local_mount_path", "") or ""
            if not mount:
                errors.append(
                    "git/verdict: the workspace volume isn't mounted on the control plane "
                    "(WARREN_EFS_LOCAL_MOUNT_PATH unset)"
                )
            else:
                volume_root = Path(mount) / "workspaces" / ws.workspace_id
                shadow_root = Path(self.settings.data_dir) / "git-shadow"
                try:
                    targets, target_errors = await asyncio.to_thread(
                        completion.ecs_targets, volume_root, folders
                    )
                    errors.extend(target_errors)
                except Exception as exc:
                    failed("git", exc)
                try:
                    verdict_raw = await asyncio.to_thread(
                        completion.read_nofollow,
                        volume_root,
                        ("workspace", *completion.VERDICT_REL),
                        completion.MAX_VERDICT_BYTES,
                    )
                except Exception as exc:
                    failed("verdict", exc)
        elif self.git_manager is not None:
            shadow_root = self.git_manager.shadow_root
            root = self.git_manager.worktree_path(ws.workspace_id)
            try:
                targets = await asyncio.to_thread(
                    completion.podman_targets, self.git_manager, ws.workspace_id, folders
                )
            except Exception as exc:
                failed("git", exc)
            try:
                if os.path.lexists(root / ".git"):
                    verdict_raw = await asyncio.to_thread(
                        completion.read_nofollow, root, completion.VERDICT_REL, completion.MAX_VERDICT_BYTES
                    )
                elif hasattr(self.runtime, "read_file"):
                    verdict_raw = await self.runtime.read_file(
                        handle, completion.VERDICT_PATH, completion.MAX_VERDICT_BYTES
                    )
            except Exception as exc:
                failed("verdict", exc)

        if targets and shadow_root is not None:
            try:
                results, git_errors = await asyncio.to_thread(completion.inspect_all, targets, shadow_root)
                errors.extend(git_errors)
                event["git_folders"] = results
                if results:
                    event["git"] = {k: v for k, v in results[0].items() if k != "mount"}
            except Exception as exc:
                failed("git", exc)

        if verdict_raw is not None:
            try:
                event["verdict"] = completion.parse_verdict(verdict_raw)
            except Exception as exc:
                failed("verdict", exc)
        return event

    async def mark_unknown(self, workspace_id: str) -> None:
        await self.store.update_status(workspace_id, "unknown")

    async def mark_stopped(self, workspace_id: str) -> None:
        await self.store.update_status(workspace_id, "stopped")

    async def pull_git(self, workspace_id: str) -> "dict[str, str] | None":
        """Pull every one of an already-materialized workspace's worktrees to
        the latest git state (D-07), returning `{repo_label: new_head_sha}`.

        Finding #26: a multi-folder template's folder clones live at
        `worktree_root/<workspace_id>/<folder_name>`, not at
        `worktree_root/<workspace_id>` itself (the single-repo convention) --
        the old implementation only ever pulled the latter, so it silently
        did nothing useful for any folder of a multi-folder workspace. This
        now walks the SAME set of paths `_materialize_and_provision` clones
        into, so pull and provision agree on the directory layout: the
        single-repo root (keyed "root") plus every `git-worktree` FolderSpec
        (keyed by `folder.name`), read from the spec snapshot persisted at
        provision time (`serialize_spec_extra`) -- not re-derived from the
        live template, which may have changed since.

        Returns `None` for an unknown workspace_id, matching `ensure_running`'s
        contract so the route can turn that into a 404. Raises `GitPullError`
        when no `git_manager` is configured at all, or when NEITHER a root
        clone nor any folder clone actually exists on disk -- both are a
        server misconfiguration / nothing-to-pull case, not a partial
        success. Deliberately does NOT call `ensure_running()` — pulling
        operates on the server-side worktree on disk regardless of whether
        the workspace's container is currently running, and must never
        silently resurrect a workspace the idle reaper (plan 04-05) stopped
        on purpose.
        """
        from warren.git.manager import GitPullError

        ws = await self.store.get(workspace_id)
        if ws is None:
            return None
        if self.git_manager is None:
            raise GitPullError("no git_manager configured")

        extra = deserialize_spec_extra(ws.spec_json)
        folders = [
            f
            for f in extra.get("folders", [])
            if f.type == "git-worktree" and f.url
        ]

        results: dict[str, str] = {}
        try:
            results["root"] = await self.git_manager.pull(workspace_id)
        except GitPullError:
            # No single-repo clone for this workspace -- fine for a
            # folders-only template, as long as at least one folder below
            # actually has something to pull. Re-raised (below) if not.
            if not folders:
                raise

        for folder in folders:
            folder_path = self.git_manager.folder_worktree_path(
                workspace_id, folder.name
            )
            results[folder.name] = await self.git_manager.pull_at(
                folder_path, log_id=f"{workspace_id}/{folder.name}"
            )

        log.info("git_pull_completed", workspace_id=workspace_id, commits=results)
        return results

    def _git_repo_paths(self, ws: "Workspace") -> dict[str, Path]:
        """Every server-side clone of `ws` that exists on disk, keyed by repo label."""
        if self.git_manager is None:
            return {}
        candidates = {ROOT_REPO: self.git_manager.worktree_path(ws.workspace_id)}
        for folder in deserialize_spec_extra(ws.spec_json).get("folders", []):
            if folder.type in ("git-worktree", "git-clone") and folder.url:
                candidates[folder.name] = self.git_manager.folder_worktree_path(
                    ws.workspace_id, folder.name
                )
        found = {}
        for label, path in candidates.items():
            try:
                if stat.S_ISDIR(os.lstat(path / ".git").st_mode):
                    found[label] = path
            except OSError:
                continue
        return found

    def repo_path(self, ws: "Workspace", repo: str) -> Path | None:
        """HIST-05/09: the server-side clone for `repo` ("root" or a folder name)."""
        return self._git_repo_paths(ws).get(repo)

    async def start_turn_session(
        self, ws: "Workspace", session_id: str | None = None
    ) -> str | None:
        """HIST-10: write a fresh session.json into each of `ws`'s server-side
        clones; returns the session id, or None when none was written."""
        session_id = session_id or str(uuid.uuid4())
        written = False
        for label, path in self._git_repo_paths(ws).items():
            try:
                await self.git_manager.write_turn_session(path, ws.workspace_id, session_id)
                written = True
            except OSError:
                log.warning(
                    "turn_session_write_failed",
                    workspace_id=ws.workspace_id,
                    repo=label,
                    exc_info=True,
                )
        return session_id if written else None
