"""
NsjailRuntime — local workspace isolation for Jetson-class ARM64 edge devices.

No container image, no daemon. Workspace is a directory on the local
filesystem; nsjail wraps the agent process with namespace + seccomp
constraints. Fast startup, minimal overhead.
"""
from __future__ import annotations

import asyncio
import json
import os
import shlex
import shutil
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import AsyncIterator, Literal

import structlog

from warren_common.errors import RuntimeUnreachable, WorkspaceNeedsRecreate
from warren_common.runtime.base import (
    ContainerRuntime,
    RuntimeConfig,
    WorkspaceHandle,
    WorkspaceSpec,
    harness_spec_kwargs,
    harness_state,
)
from warren_common.runtime.nsjail_config import NsjailConfig
from warren_common.runtime_detect import DEFAULT_NSJAIL_PATH as _DEFAULT_NSJAIL_PATH, resolve_nsjail
from warren_common.runtime.sandbox_env import (
    ENV_MOUNT_DEST,
    ENV_SOURCE_SCRIPT,
    nsjail_secret_env_path,
    state_root,
)

log = structlog.get_logger(__name__)

_STATE_SCHEMA_VERSION = 1
_CHUNK_SIZE = 4096


def _state_dir_for(workspace_id: str) -> Path:
    """Where this workspace's state.json lives — never under workspace_dir
    itself (R3, same class as seatbelt/bwrap finding #1): nsjail's config
    binds workspace_dir rw into the jail, so a state.json stored there is one
    a jailed process could rewrite and have trusted on the next `warren
    connect`. `nsjail.cfg` lives here too (BB3) and is regenerated from
    state.json before every use, never trusted as a file on disk.
    """
    return state_root() / workspace_id


def _spec_from_state(state: dict, workspace_id: str, default_root: str) -> WorkspaceSpec:
    return WorkspaceSpec(
        workspace_id=state.get("workspace_id", workspace_id),
        project=state.get("project", ""),
        intent=state.get("intent", ""),
        image="",
        root_path=state.get("root_path") or default_root,
        app=state.get("app", "bash"),
        env=dict(state.get("env_snapshot", {})),
        worktree_paths=[tuple(p) for p in state.get("worktree_paths", [])],
        reference_paths=[tuple(p) for p in state.get("reference_paths", [])],
        bind_mounts=[tuple(m) for m in state.get("bind_mounts", [])],
        ssh_key_paths=list(state.get("ssh_key_paths", [])),
        ssh_agent_sock=state.get("ssh_agent_sock"),
        **harness_spec_kwargs(state),
    )


# Persisted since BB3. Older state.json never recorded them, so a regenerated
# config would silently drop the workspace's bind mounts and ssh access (BB14).
_REQUIRED_STATE_KEYS = ("bind_mounts", "ssh_key_paths", "ssh_agent_sock")


def check_nsjail_state(state: dict, workspace_id: str) -> None:
    """Raise WorkspaceNeedsRecreate for state.json written before BB3."""
    missing = [k for k in _REQUIRED_STATE_KEYS if k not in state]
    if missing:
        raise WorkspaceNeedsRecreate(
            f"nsjail workspace {workspace_id} was created by an older warren that "
            f"didn't record {', '.join(missing)}, and its old in-tree nsjail.cfg "
            f"can't be trusted. Recreate it: `warren destroy {workspace_id}`, then "
            "start a new workspace from the same template."
        )


def write_nsjail_cfg(state_dir: Path | str, workspace_id: str, default_root: str = "") -> Path:
    """Regenerate `<state_dir>/nsjail.cfg` from `<state_dir>/state.json` and
    return its path. Call before every nsjail invocation."""
    state_dir = Path(state_dir)
    state_path = state_dir / "state.json"
    state = json.loads(state_path.read_text()) if state_path.is_file() else {}
    check_nsjail_state(state, workspace_id)
    spec = _spec_from_state(state, workspace_id, default_root)
    state_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(state_dir, 0o700)
    cfg_path = state_dir / "nsjail.cfg"
    _atomic_write_text(cfg_path, NsjailConfig.from_spec(spec).to_proto_text(), mode=0o600)
    return cfg_path


class NsjailRuntime:
    """ContainerRuntime implementation using nsjail (local mode)."""

    def __init__(self, server_id: str, config: RuntimeConfig | None = None) -> None:
        self.server_id = server_id
        self.config = config
        self.nsjail_path = resolve_nsjail() or _DEFAULT_NSJAIL_PATH
        self._preflight_ok = False

    def preflight(self) -> None:
        p = Path(self.nsjail_path)
        if not p.is_file() or not os.access(str(p), os.X_OK):
            raise RuntimeUnreachable(
                f"nsjail binary not found at {self.nsjail_path}. "
                "Install: apt install nsjail (Debian) or build from source for ARM64. "
                "Set WARREN_NSJAIL_PATH to override."
            )
        self._preflight_ok = True

    async def provision(self, spec: WorkspaceSpec) -> WorkspaceHandle:
        if not self._preflight_ok:
            self.preflight()

        workspace_dir = Path(spec.root_path)
        workspace_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(workspace_dir, 0o700)

        # state.json (env_snapshot holds secret values) is deliberately OUTSIDE
        # workspace_dir (R3) — the jailed process has rw on workspace_dir via
        # the nsjail config's own binds.
        state_dir = _state_dir_for(spec.workspace_id)
        state_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(state_dir, 0o700)

        state = {
            "schema_version": _STATE_SCHEMA_VERSION,
            "workspace_id": spec.workspace_id,
            "project": spec.project,
            "intent": spec.intent,
            "app": spec.app,
            "runtime_type": "nsjail",
            # Resolved once at detection and exec'd by this absolute path (AE2).
            "nsjail_path": self.nsjail_path,
            **harness_state(spec),
            "aws": spec.aws.model_dump() if spec.aws else None,
            "root_path": str(workspace_dir),
            "worktree_paths": [list(p) for p in spec.worktree_paths],
            "reference_paths": [list(p) for p in spec.reference_paths],
            "bind_mounts": [list(m) for m in spec.bind_mounts],
            "ssh_key_paths": list(spec.ssh_key_paths),
            "ssh_agent_sock": spec.ssh_agent_sock,
            # S6 follow-up (2026-10-17): secrets no longer go into nsjail.cfg
            # as plaintext `envar` lines (see nsjail_config.py). exec() needs
            # them to rebuild the short-lived env file it sources into each
            # invocation -- same 0600-state.json exposure level bubblewrap's
            # own env_snapshot already uses, not a new one.
            "env_snapshot": dict(spec.env),
            "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "status": "provisioned",
        }
        state_path = state_dir / "state.json"
        payload = json.dumps(state, indent=2, sort_keys=False)
        _atomic_write_text(state_path, payload, mode=0o600)
        cfg_path = write_nsjail_cfg(state_dir, spec.workspace_id, str(workspace_dir))

        log.info(
            "nsjail_provisioned",
            workspace_id=spec.workspace_id,
            cfg_path=str(cfg_path),
            cfg_bytes=cfg_path.stat().st_size,
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
        """Remove the workspace dir.

        Caller (dispatch) is responsible for `GitManager.remove_worktree` on any
        bare-repo-backed worktree paths BEFORE calling destroy (D-06). This
        method does not touch git state.
        """
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
        # R3/BB3: state.json and nsjail.cfg live only in the out-of-tree
        # state dir; the cfg is rebuilt from state.json on every exec.
        state_dir = (
            Path(handle.state_dir) if handle.state_dir else _state_dir_for(handle.workspace_id)
        )
        state_path = state_dir / "state.json"
        env_snapshot: dict[str, str] = {}
        if state_path.exists():
            env_snapshot = json.loads(state_path.read_text()).get("env_snapshot", {})
        cfg_path = write_nsjail_cfg(state_dir, handle.workspace_id, handle.root_path)

        # S6 follow-up (2026-10-17): nsjail.cfg declares a mandatory bind
        # mount from this EXACT path to ENV_MOUNT_DEST (see
        # NsjailConfig.from_spec), so this write has to land on that same
        # deterministic filename, not a fresh mkstemp name each time.
        env_file = nsjail_secret_env_path(handle.workspace_id)
        env_file.parent.mkdir(parents=True, exist_ok=True)
        os.chmod(env_file.parent, 0o700)
        env_body = "".join(
            f"export {key}={shlex.quote(value)}\n" for key, value in env_snapshot.items()
        )
        _atomic_write_text(env_file, env_body, mode=0o600)
        try:
            # Code-review fix (2026-10-17): the previous version unlinked
            # env_file in a `finally` around ONLY the create_subprocess_exec
            # call above -- i.e. immediately after the child process is
            # forked/exec'd, not after nsjail has actually performed its own
            # bind-mount setup (nsjail parses nsjail.cfg and does its mounts
            # INSIDE the child's own early startup, asynchronously from this
            # parent process's perspective; create_subprocess_exec returning
            # only means fork+exec completed, not that nsjail's mount() of
            # env_file has happened yet). That's a real TOCTOU race against
            # the bind mount. The unlink now covers the process's entire
            # lifetime -- it can't fire until nsjail has long since read (or
            # failed to read) the file.
            proc = await asyncio.create_subprocess_exec(
                self.nsjail_path,
                "--config",
                str(cfg_path),
                "--",
                "/bin/sh",
                "-c",
                ENV_SOURCE_SCRIPT,
                "sh",
                ENV_MOUNT_DEST,
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )

            assert proc.stdout is not None
            while True:
                chunk = await proc.stdout.read(_CHUNK_SIZE)
                if not chunk:
                    break
                yield chunk
            rc = await proc.wait()
            if rc != 0:
                log.info(
                    "nsjail_exec_nonzero",
                    workspace_id=handle.workspace_id,
                    rc=rc,
                )
        finally:
            env_file.unlink(missing_ok=True)

    async def status(
        self, handle: WorkspaceHandle
    ) -> Literal["running", "stopped", "unknown"]:
        state_dir = (
            Path(handle.state_dir) if handle.state_dir else _state_dir_for(handle.workspace_id)
        )
        state_json = state_dir / "state.json"
        if not state_json.exists():
            return "unknown"
        return "stopped"


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
