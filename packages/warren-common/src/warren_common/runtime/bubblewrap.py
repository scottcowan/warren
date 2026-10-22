"""BubblewrapRuntime — Linux directory-backed sandbox (RT-03c).

# bwrap approach informed by github.com/akitaonrails/ai-jail (GPL-3.0)

Platform-native fallback when nsjail is unavailable on Linux (D-01). Mirrors
NsjailRuntime file-layout exactly: workspace directory on disk, state.json
(schema_version=1) written atomically, preflight checks PATH for `bwrap`.

No config file — bwrap flags are assembled as a `list[str]` at exec time from
the WorkspaceSpec via the pure `build_bwrap_args` helper. `--share-net` for
v1.0 full network (D-13); `--unshare-net` is deferred to v1.1.
"""
from __future__ import annotations

import asyncio
import json
import os
import shutil
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import AsyncIterator, Literal

import structlog

from warren_common.errors import RuntimeUnreachable
from warren_common.harness import grants_for_spec
from warren_common.runtime.base import (
    ContainerRuntime,
    RuntimeConfig,
    WorkspaceHandle,
    WorkspaceSpec,
    harness_spec_kwargs,
    harness_state,
)
from warren_common import wsl
from warren_common.runtime_detect import resolve_bwrap
from warren_common.runtime.sandbox_env import (
    ENV_MOUNT_DEST as _ENV_MOUNT_DEST,
    ENV_SOURCE_SCRIPT as _ENV_SOURCE_SCRIPT,
    base_host_env,
    check_no_secret_service_mounts,
    host_mount_sources,
    state_root,
    write_secret_env_file,
)

log = structlog.get_logger(__name__)

_STATE_SCHEMA_VERSION = 1
_CHUNK_SIZE = 4096


def _state_dir_for(workspace_id: str) -> Path:
    """Where this workspace's state.json lives — never under root_path itself
    (audit finding #1): bwrap --bind's root_path rw into the sandbox, so a
    state.json stored there is a state.json the sandboxed process could
    rewrite, choosing its own argv on the next `warren connect`.
    """
    return state_root() / workspace_id

# Optional system paths — may be absent on some distros (Pitfall 3: /lib64 is
# missing on Debian arm64). Mounted via --ro-bind-try so provision does not
# abort when they don't exist. `/usr`, `/etc`, `/bin`, `/lib` are treated as
# mandatory reference mounts and use --ro-bind.
_MANDATORY_SYSTEM_PATHS = ("/usr", "/etc", "/bin", "/lib")
_OPTIONAL_SYSTEM_PATHS = ("/lib64", "/sbin", "/lib32")


def build_bwrap_args(
    spec: WorkspaceSpec, *, env_file: str, cmd: list[str] | None = None
) -> list[str]:
    """Pure builder: WorkspaceSpec → bwrap argv.

    `env_file` is the HOST path of a 0600 file (one `export KEY='value'` line
    per `spec.env` entry — see `write_secret_env_file`) that gets bind-mounted
    into the sandbox and sourced by a tiny shell wrapper before the real
    command runs (audit 2026-10-16 P2 #51: secrets used to go straight onto
    this process's own argv via `--setenv KEY VALUE`, which any user on the
    host can read via `ps`/`/proc/<pid>/cmdline` — not just the operator).
    `cmd` defaults to `[spec.app]` when omitted (the provisioned app).
    """
    check_no_secret_service_mounts(host_mount_sources(spec))
    args: list[str] = [
        "--die-with-parent",
        "--unshare-pid",
        "--unshare-uts",
        "--unshare-ipc",
        "--share-net",
        # Without --clearenv, bwrap's child inherits the CALLING process's full
        # environment on top of the --setenv values below (audit finding #4):
        # any AWS key, API token, or SSH_AUTH_SOCK sitting in the operator's
        # own shell would reach every local workspace. --setenv below is the
        # only env this sandboxed process should get.
        "--clearenv",
        "--proc", "/proc",
        "--dev", "/dev",
        "--tmpfs", "/tmp",
    ]

    for p in _MANDATORY_SYSTEM_PATHS:
        args += ["--ro-bind", p, p]
    for p in _OPTIONAL_SYSTEM_PATHS:
        args += ["--ro-bind-try", p, p]

    root = spec.root_path
    args += ["--bind", root, root]

    for host, container in spec.worktree_paths:
        args += ["--bind", host, container]

    for host, container in spec.reference_paths:
        args += ["--ro-bind", host, container]

    # AG6: union of the template's harness grants; readonly re-bound ro last.
    grants = grants_for_spec(spec, Path.home())
    for path in grants.read:
        args += ["--ro-bind-try", path, path]
    for path in grants.write:
        args += ["--bind-try", path, path]
    for path in grants.readonly:
        args += ["--ro-bind-try", path, path]

    for ssh_path in spec.ssh_key_paths:
        args += ["--ro-bind", ssh_path, ssh_path]
    if spec.ssh_agent_sock:
        args += ["--bind", spec.ssh_agent_sock, spec.ssh_agent_sock]

    for host, container, mode in spec.bind_mounts:
        flag = "--bind" if mode == "rw" else "--ro-bind"
        args += [flag, host, container]

    # base_host_env() only -- just enough for a shell to start (PATH, HOME,
    # TERM, LANG). None of this is secret, so it's fine on argv. Since
    # --clearenv (above) drops the calling process's own environment, this is
    # the ONLY env the sandbox gets besides what the wrapper below sources
    # from env_file -- spec.env (actual secrets) never goes on argv.
    for key, value in base_host_env().items():
        args += ["--setenv", key, value]

    args += ["--ro-bind", env_file, _ENV_MOUNT_DEST]
    args += ["--chdir", root]

    real_cmd = cmd if cmd is not None else [spec.app]
    args += ["--", "/bin/sh", "-c", _ENV_SOURCE_SCRIPT, "sh", _ENV_MOUNT_DEST, *real_cmd]
    return args


class BubblewrapRuntime:
    """ContainerRuntime implementation using bubblewrap (bwrap)."""

    def __init__(self, server_id: str, config: RuntimeConfig | None = None) -> None:
        self.server_id = server_id
        self.config = config
        self.bwrap_path: str | None = None
        self._preflight_ok = False

    def preflight(self) -> None:
        if wsl.wsl_version() == 1:
            raise RuntimeUnreachable(wsl.WSL1_REFUSAL)
        self.bwrap_path = resolve_bwrap()
        if self.bwrap_path is None:
            raise RuntimeUnreachable(
                "bwrap not found on PATH; apt install bubblewrap"
            )
        check_bwrap_namespaces(self.bwrap_path)
        self._preflight_ok = True

    async def provision(self, spec: WorkspaceSpec) -> WorkspaceHandle:
        if not self._preflight_ok:
            self.preflight()

        if spec.image:
            log.warning(
                "bubblewrap_image_ignored",
                workspace_id=spec.workspace_id,
                image=spec.image,
                reason=(
                    "image field ignored in bubblewrap mode; "
                    "use runtime=docker for image-based workspaces"
                ),
            )

        workspace_dir = Path(spec.root_path)
        workspace_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(workspace_dir, 0o700)

        # State dir is deliberately OUTSIDE workspace_dir (finding #1) — bwrap
        # --binds root_path rw into the sandbox, so a state.json stored there
        # is one the sandboxed process could rewrite for the next connect.
        state_dir = _state_dir_for(spec.workspace_id)
        state_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(state_dir, 0o700)

        state = {
            "schema_version": _STATE_SCHEMA_VERSION,
            "workspace_id": spec.workspace_id,
            "project": spec.project,
            "intent": spec.intent,
            "app": spec.app,
            "root_path": str(workspace_dir),
            # Resolved once here and exec'd by this absolute path (AE2).
            "bwrap_path": self.bwrap_path,
            **harness_state(spec),
            "aws": spec.aws.model_dump() if spec.aws else None,
            # env_snapshot carries the template's declared secrets/vars — needed
            # so exec() (re-run after provision) can rebuild the same --setenv
            # list build_bwrap_args produced at connect time (finding #4: without
            # this, exec() had no explicit env at all and depended entirely on
            # inheriting the caller's full environment, same bug as --clearenv
            # above would otherwise reintroduce).
            "env_snapshot": dict(spec.env),
            "worktree_paths": [list(p) for p in spec.worktree_paths],
            "reference_paths": [list(p) for p in spec.reference_paths],
            "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "status": "provisioned",
        }
        state_path = state_dir / "state.json"
        payload = json.dumps(state, indent=2, sort_keys=False)
        _atomic_write_text(state_path, payload, mode=0o600)

        log.info(
            "bubblewrap_provisioned",
            workspace_id=spec.workspace_id,
            root_path=str(workspace_dir),
        )

        return WorkspaceHandle(
            workspace_id=spec.workspace_id,
            runtime_id=str(workspace_dir),
            root_path=str(workspace_dir),
            sidecar_url="",
            state_dir=str(state_dir),
        )

    async def start(self, handle: WorkspaceHandle) -> None:
        return None

    async def stop(self, handle: WorkspaceHandle) -> None:
        return None

    async def destroy(self, handle: WorkspaceHandle) -> None:
        root = Path(handle.root_path)
        if root.exists():
            shutil.rmtree(root)
        if handle.state_dir:
            state_dir = Path(handle.state_dir)
            if state_dir.exists():
                shutil.rmtree(state_dir)

    async def exec(
        self, handle: WorkspaceHandle, cmd: list[str]
    ) -> AsyncIterator[bytes]:
        state_dir = Path(handle.state_dir) if handle.state_dir else Path(handle.root_path)
        state_path = state_dir / "state.json"
        state = json.loads(state_path.read_text())
        spec = _spec_from_state(state, state.get("root_path", handle.root_path))

        env_file = write_secret_env_file(spec.env, state_dir)
        try:
            args = build_bwrap_args(spec, env_file=str(env_file), cmd=cmd)
            proc = await asyncio.create_subprocess_exec(
                bwrap_binary(state),
                *args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )
        finally:
            # bwrap reads/bind-mounts env_file during its own sandbox setup,
            # before the real command ever execs -- by the time the subprocess
            # has been created (whether it started cleanly or create_subprocess_exec
            # itself raised), the host-side temp file is no longer needed.
            env_file.unlink(missing_ok=True)

        assert proc.stdout is not None
        while True:
            chunk = await proc.stdout.read(_CHUNK_SIZE)
            if not chunk:
                break
            yield chunk
        rc = await proc.wait()
        if rc != 0:
            log.info(
                "bubblewrap_exec_nonzero",
                workspace_id=handle.workspace_id,
                rc=rc,
            )

    async def status(
        self, handle: WorkspaceHandle
    ) -> Literal["running", "stopped", "unknown"]:
        state_dir = Path(handle.state_dir) if handle.state_dir else Path(handle.root_path)
        state_json = state_dir / "state.json"
        if not state_json.exists():
            return "unknown"
        pid_file = Path(handle.root_path) / ".warren-pid"
        if pid_file.exists():
            try:
                pid = int(pid_file.read_text().strip())
                os.kill(pid, 0)
                return "running"
            except (ValueError, ProcessLookupError, PermissionError, OSError):
                return "stopped"
        return "stopped"


def check_bwrap_namespaces(bwrap_path: str) -> None:
    """Raise RuntimeUnreachable with the fix (e.g. the Ubuntu 24.04 AppArmor
    profile) when bwrap can't create its namespaces, instead of letting the
    real launch fail with bwrap's raw error (AC2)."""
    probe = wsl.probe_bwrap(bwrap_path)
    if probe.ok:
        return
    if probe.guidance:
        raise RuntimeUnreachable(probe.guidance)
    raise RuntimeUnreachable(f"bwrap sandbox self-test failed: {probe.stderr or 'unknown error'}")


def bwrap_binary(state: dict) -> str:
    """The absolute bwrap path recorded at provision; state from before AE2
    falls back to a fresh resolve."""
    path = state.get("bwrap_path") or resolve_bwrap()
    if not path or not os.path.isabs(path):
        raise RuntimeUnreachable("bwrap not found; apt install bubblewrap")
    return path


def _spec_from_state(state: dict, root_path: str) -> WorkspaceSpec:
    return WorkspaceSpec(
        workspace_id=state["workspace_id"],
        project=state["project"],
        intent=state["intent"],
        image="",
        root_path=root_path,
        app=state.get("app", "bash"),
        env=state.get("env_snapshot", {}),
        worktree_paths=[tuple(p) for p in state.get("worktree_paths", [])],
        reference_paths=[tuple(p) for p in state.get("reference_paths", [])],
        **harness_spec_kwargs(state),
    )


def _atomic_write_text(path: Path, data: str, *, mode: int) -> None:
    """Write `data` to `path` via a same-directory tempfile + os.replace (D-19)."""
    directory = path.parent
    fd, tmp_name = tempfile.mkstemp(
        prefix=path.name + ".", suffix=".tmp", dir=str(directory)
    )
    try:
        with os.fdopen(fd, "w") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp_name, mode)
        os.replace(tmp_name, path)
    except BaseException:
        try:
            os.unlink(tmp_name)
        except FileNotFoundError:
            pass
        raise


_ = ContainerRuntime  # keep import for Protocol conformance reference
