"""
SeatbeltRuntime — macOS sandbox-exec runtime (RT-03d).

# sandbox-exec approach informed by github.com/akitaonrails/ai-jail (GPL-3.0)

Writes an SBPL profile (`sandbox.sb`) and `state.json` (schema_version=1)
to the workspace root, then drives `sandbox-exec -f <profile> ...` at
`exec()` time. Env vars flow via subprocess env (D-22), NOT the profile.
`spec.image` is ignored with a WARNING (D-21).

Security notes:
- state.json is 0o600 within a 0o700 *state* directory — `~/.warren/state/
  <workspace_id>/`, NOT the workspace root (audit finding #1, 2026-10-16: the
  workspace root is writable from inside the sandbox itself, so storing
  sandbox.sb/state.json there let a sandboxed process rewrite its own
  profile and have the rewritten one trusted on the next `warren connect`).
  `env_snapshot` contains secret values (T-05b-19, disposition=accept).
  Local-mode only.
- Profile is written atomically via same-dir tempfile + os.replace (T-05b-20).
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
from warren_common.runtime.base import (
    ContainerRuntime,
    RuntimeConfig,
    WorkspaceHandle,
    WorkspaceSpec,
    harness_state,
)
from warren_common.runtime.sandbox_env import base_host_env, workspace_state_dir
from warren_common.runtime.sbpl import build_sbpl_profile, sandbox_exec_param_args
from warren_common.runtime_detect import SANDBOX_EXEC_PATH

log = structlog.get_logger(__name__)

_STATE_SCHEMA_VERSION = 1
_CHUNK_SIZE = 4096


def _state_dir_for(workspace_id: str) -> Path:
    """Where this workspace's sandbox.sb/state.json live — never under the
    workspace root itself (audit finding #1): that path is writable from
    inside the sandbox, so a sandboxed process could otherwise rewrite its
    own profile/argv and have it trusted on the next `warren connect`.
    """
    return workspace_state_dir(workspace_id)


class SeatbeltRuntime:
    """ContainerRuntime implementation using macOS sandbox-exec."""

    def __init__(self, server_id: str, config: RuntimeConfig | None = None) -> None:
        self.server_id = server_id
        self.config = config
        self.sandbox_exec_path = SANDBOX_EXEC_PATH
        self._preflight_ok = False

    def preflight(self) -> None:
        p = Path(self.sandbox_exec_path)
        if not p.is_file() or not os.access(str(p), os.X_OK):
            raise RuntimeUnreachable(
                f"sandbox-exec binary not found at {self.sandbox_exec_path}. "
                "This runtime requires macOS."
            )
        self._preflight_ok = True

    async def provision(self, spec: WorkspaceSpec) -> WorkspaceHandle:
        if not self._preflight_ok:
            self.preflight()

        if spec.image:
            log.warning(
                "seatbelt_ignoring_spec_image",
                workspace_id=spec.workspace_id,
                image=spec.image,
                note="SeatbeltRuntime does not use container images (D-21).",
            )

        workspace_dir = Path(spec.root_path)
        workspace_dir.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(workspace_dir, 0o700)
        except PermissionError:
            # Some test environments (macOS /private/var/folders) disallow chmod
            pass

        # State dir is deliberately OUTSIDE workspace_dir (finding #1) — the
        # sandboxed process has file-write* on workspace_dir, so a profile
        # stored there is a profile the sandboxed process can rewrite.
        state_dir = _state_dir_for(spec.workspace_id)
        state_dir.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(state_dir, 0o700)
        except PermissionError:
            pass

        profile = build_sbpl_profile(spec)
        profile_path = state_dir / "sandbox.sb"
        _atomic_write_text(profile_path, profile.text, mode=0o600)

        state = {
            "schema_version": _STATE_SCHEMA_VERSION,
            "workspace_id": spec.workspace_id,
            "project": spec.project,
            "intent": spec.intent,
            "app": spec.app,
            "root_path": str(workspace_dir),
            "profile_path": str(profile_path),
            "profile_params": profile.params,
            **harness_state(spec),
            "aws": spec.aws.model_dump() if spec.aws else None,
            "env_snapshot": dict(spec.env),
            "worktree_paths": [list(p) for p in spec.worktree_paths],
            "reference_paths": [list(p) for p in spec.reference_paths],
            "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "status": "provisioned",
        }
        state_path = state_dir / "state.json"
        _atomic_write_text(
            state_path, json.dumps(state, indent=2, sort_keys=False), mode=0o600
        )

        log.info(
            "seatbelt_provisioned",
            workspace_id=spec.workspace_id,
            profile_path=str(profile_path),
            profile_bytes=profile_path.stat().st_size,
        )

        return WorkspaceHandle(
            workspace_id=spec.workspace_id,
            runtime_id=str(workspace_dir),
            root_path=str(workspace_dir),
            state_dir=str(state_dir),
        )

    async def start(self, handle: WorkspaceHandle) -> None:
        return None

    async def stop(self, handle: WorkspaceHandle) -> None:
        return None

    async def destroy(self, handle: WorkspaceHandle) -> None:
        """Remove the workspace dir and its (separately stored) sandbox state.

        Caller must ensure any sandbox-exec child processes have exited before
        calling destroy (Pitfall 6). This method does not signal children.
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
        state_dir = _resolve_state_dir(handle)
        profile_path = state_dir / "sandbox.sb"
        env_snapshot = _load_env_snapshot(state_dir)
        params = _load_profile_params(state_dir)
        # Allow-list only (audit finding #4) — NOT the operator's full os.environ,
        # which would leak any AWS/API keys sitting in their own shell into every
        # local workspace. Everything the workspace needs beyond a bare shell is
        # already captured explicitly into env_snapshot at provision time.
        env = {**base_host_env(), **env_snapshot}

        proc = await asyncio.create_subprocess_exec(
            self.sandbox_exec_path,
            "-f",
            str(profile_path),
            *sandbox_exec_param_args(params),
            *cmd,
            env=env,
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
                "seatbelt_exec_nonzero",
                workspace_id=handle.workspace_id,
                rc=rc,
            )

    async def status(
        self, handle: WorkspaceHandle
    ) -> Literal["running", "stopped", "unknown"]:
        state_dir = _resolve_state_dir(handle)
        state_json = state_dir / "state.json"
        if not state_json.exists():
            return "unknown"
        pid_file = Path(handle.root_path) / ".warren-pid"
        if pid_file.exists():
            try:
                pid = int(pid_file.read_text().strip())
                os.kill(pid, 0)
                return "running"
            except (OSError, ValueError):
                return "stopped"
        return "stopped"


def _resolve_state_dir(handle: WorkspaceHandle) -> Path:
    """Where to read this handle's sandbox.sb/state.json from (R3, 2026-10-17).

    Prefers `handle.state_dir` when set. For a handle persisted before the
    state-dir fix (empty `state_dir`), tries the proper out-of-tree location
    for this workspace_id BEFORE falling back to `root_path` — root_path is
    writable from inside the sandbox, so trusting a state.json found there is
    exactly the attack finding #1 exists to prevent. This does not migrate
    on-disk state the way `warren_cli.commands.workspaces._load_workspace_state`
    does; it only avoids trusting root_path when the proper location already
    has a (migrated or fresh) copy.
    """
    if handle.state_dir:
        return Path(handle.state_dir)
    proper = _state_dir_for(handle.workspace_id)
    if (proper / "state.json").is_file():
        return proper
    return Path(handle.root_path)


def _load_env_snapshot(workspace_dir: Path) -> dict[str, str]:
    state_path = workspace_dir / "state.json"
    if not state_path.exists():
        return {}
    try:
        payload = json.loads(state_path.read_text())
    except (OSError, json.JSONDecodeError):
        return {}
    snap = payload.get("env_snapshot") or {}
    return {str(k): str(v) for k, v in snap.items()}


def _load_profile_params(state_dir: Path) -> dict[str, str]:
    """`-D` parameters for sandbox.sb (empty for profiles that predate AE3)."""
    try:
        payload = json.loads((state_dir / "state.json").read_text())
    except (OSError, json.JSONDecodeError):
        return {}
    return {str(k): str(v) for k, v in (payload.get("profile_params") or {}).items()}


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


_ = ContainerRuntime  # Protocol conformance reference
