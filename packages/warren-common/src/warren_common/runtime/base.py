from __future__ import annotations

import secrets
from dataclasses import dataclass, field
from typing import AsyncIterator, Literal, Protocol, runtime_checkable

# Re-export ProvisionError from warren.errors for convenience.
from warren_common.errors import ProvisionError as ProvisionError  # noqa: F401
from warren_common.models import AwsConfig, CustomHarness, FolderSpec, ScopeConfig

# Audit finding 12: the shared secret every sidecar request (bar /healthz) must carry.
SIDECAR_TOKEN_ENV = "WARREN_SIDECAR_TOKEN"


def new_sidecar_token() -> str:
    return secrets.token_urlsafe(32)


@dataclass
class WorkspaceSpec:
    workspace_id: str
    project: str
    intent: str
    image: str
    root_path: str                      # host path mounted into container
    env: dict[str, str] = field(default_factory=dict)   # injected secrets (values never logged)
    template_env: dict[str, str] = field(default_factory=dict)  # resolved template's plain `env` (AH5) -- non-secret, persisted in spec_json; runtimes merge it under `env` and under warren's reserved vars
    secret_names: list[str] = field(default_factory=list)  # resolved template's declared secret names (warren.secrets) — the ECS path's by-name allow-list; podman/docker already got decrypted values straight into `env` above, this is what runtime/ecs.py filters SSM param names against
    owner_id: str = ""                  # creating user's id — isolates warren.secrets lookups to this workspace's own owner, never another user's secrets
    ssh_key_paths: list[str] = field(default_factory=list)   # specific key files declared by intent
    ssh_agent_sock: str | None = None                        # SSH_AUTH_SOCK forwarded if intent.ssh.agent=true
    bind_mounts: list[tuple[str, str, str]] = field(default_factory=list)  # (host, container, mode)
    worktree_paths: list[tuple[str, str]] = field(default_factory=list)    # (host, container) rw worktrees (D-14)
    folders: list[FolderSpec] = field(default_factory=list)                # resolved template's effective_folders() — server-side multi-repo clone (registry.py)
    reference_paths: list[tuple[str, str]] = field(default_factory=list)   # (host, container) ro reference clones (D-15)
    git_store_paths: list[str] = field(default_factory=list)               # host paths of bare `.git-store` dirs backing worktree_paths — read-only (git needs these to resolve refs/objects from a worktree; never write, see sbpl.py)
    app: str = "bash"                                                       # foreground app to exec inside jail (D-16)
    seed_prompt: str | None = None                                          # resolved template's seed_prompt (AH9); first provision only, deliberately not persisted in spec_json so a reprovision never replays it
    harnesses: list[str] = field(default_factory=list)                      # template-declared agent harnesses (warren_common.harness)
    custom_harness: CustomHarness | None = None                             # AJ1 `custom` harness command and its workspace-relative readonly/persist paths
    harness_root: str = ""
    model_access: str = ""                                                  # "bedrock": no OAuth handoff, models via the workspace's AWS identity                                                  # AG3: per-workspace harness config dirs live at <harness_root>/<name>; "" = none
    docker_networks: list[str] = field(default_factory=list)                # (D-07b) intent-declared docker network attachments
    ecs_cpu: str | None = None                                              # per-intent Fargate CPU override (D-02)
    ecs_memory: str | None = None                                           # per-intent Fargate memory override (D-02)
    efs_retention_days: int | None = None                                   # per-intent EFS TTL override (D-03); None falls back to WarrenSettings default
    idle_ttl_seconds: float | None = None                                   # per-project/template idle-reaper TTL override; None falls back to WarrenSettings.idle_ttl_seconds
    idle_destroy_seconds: float | None = None                               # AH10: destroy this long after an idle stop; None falls back to WarrenSettings.idle_destroy_seconds (off by default)
    # Audit R11: the resolved template's `aws`/`scope` blocks (warren_common.models) were
    # silently dropped on the floor on the server-provision path -- never threaded onto
    # WorkspaceSpec at all, unlike docker_networks/ecs_cpu/ecs_memory above. Carried as
    # the whole resolved config object (same shape as `folders` above), not flattened,
    # since no runtime consumes these yet -- flattening now would mean guessing at a
    # shape before there's a real consumer to design it against.
    aws: AwsConfig | None = None
    scope: ScopeConfig | None = None
    # AI3: identifies this launch attempt for idempotent RunTask (ECS clientToken). The
    # previous runtime_id on a reprovision, "" on first provision.
    provision_generation: str = ""
    # AM2: the client's operationId for this launch, if any; ECS derives its clientToken from it.
    operation_id: str = ""
    # AH2: "single-turn" workspaces emit workspace.completed and are destroyed when the app exits.
    mode: str = "interactive"
    # AG2b/AM3: a `kind: agent` workspace's supervisor launch spec (warren_common.agent_launch); None for user workspaces.
    agent: dict | None = None
    # Audit finding 12: this workspace's sidecar token; the registry mints and stores it
    # (encrypted), a runtime mints one when it is unset. Never persisted in spec_json.
    sidecar_token: str = field(default="", repr=False)


def harness_state(spec: WorkspaceSpec) -> dict:
    """WorkspaceSpec harness fields for a local runtime's state.json."""
    return {
        "harnesses": list(spec.harnesses),
        "harness_root": spec.harness_root,
        "model_access": spec.model_access,
        "custom_harness": spec.custom_harness.model_dump() if spec.custom_harness else None,
    }


def harness_spec_kwargs(state: dict) -> dict:
    custom = state.get("custom_harness")
    return {
        "harnesses": list(state.get("harnesses") or []),
        "harness_root": state.get("harness_root") or "",
        "model_access": state.get("model_access") or "",
        "custom_harness": CustomHarness.model_validate(custom) if custom else None,
    }


@dataclass
class WorkspaceHandle:
    workspace_id: str
    runtime_id: str                     # container ID, nsjail PID, etc.
    root_path: str
    sidecar_url: str = ""               # http://... for file/exec/events API (empty for ECS/Fargate)
    sidecar_socket_path: str = ""       # AF_UNIX socket path inside container (D-12)
    sidecar_token: str = field(default="", repr=False)  # sent as X-Warren-Sidecar-Token
    state_dir: str = ""                 # where this runtime's own sandbox.sb/state.json live, when that
                                         # MUST live outside root_path (audit finding #1: root_path is
                                         # writable from inside the sandbox, so a sandboxed process could
                                         # otherwise rewrite its own profile/argv for the next `warren
                                         # connect`). Empty for runtimes with no such on-disk sandbox
                                         # config (docker, ecs) or where root_path is never sandbox-writable.


@dataclass(frozen=True)
class ExecExit:
    """Last item of a runtime's `exec_stream`: the command's exit code (None if unknown)."""

    exit_code: int | None


class ExecUnavailable(RuntimeError):
    """#59: this runtime can't run an exec right now (no exec channel, task not running)."""


@dataclass
class RuntimeConfig:
    type: Literal["nsjail", "podman", "docker", "ecs"]
    host: str | None = None             # None = local; "ssh://user@host" or "tcp://host:port"
    tls: bool = False


@runtime_checkable
class ContainerRuntime(Protocol):
    """
    Warren's runtime abstraction. Callers provision an environment and
    get a handle back. Warren does not schedule, queue, or retry —
    provision() succeeds or raises immediately.
    """

    async def provision(self, spec: WorkspaceSpec) -> WorkspaceHandle:
        """Create the workspace environment. Raises if the host is unavailable."""
        ...

    async def start(self, handle: WorkspaceHandle) -> None:
        """Start a provisioned workspace (idempotent)."""
        ...

    async def stop(self, handle: WorkspaceHandle) -> None:
        """Stop a running workspace; state is preserved."""
        ...

    async def destroy(self, handle: WorkspaceHandle) -> None:
        """Destroy the workspace and release all resources."""
        ...

    async def exec(self, handle: WorkspaceHandle, cmd: list[str]) -> AsyncIterator[bytes]:
        """Run a command inside the workspace; yields stdout/stderr bytes."""
        ...

    async def status(
        self, handle: WorkspaceHandle
    ) -> Literal["running", "starting", "stopped", "unknown"]:
        """"starting" = launched but not yet running (ECS); callers must wait, not reprovision."""
        ...


@runtime_checkable
class WorkspaceVolume(Protocol):
    """Protocol for persistent workspace volume backends.

    ``detach`` must be non-destructive — it only marks the volume as eligible
    for expiry (D-04). ``delete`` is the only destructive path (D-05).
    Implementations must never call a delete operation inside ``detach``.

    NOTE: EFSMount.attach accepts keyword-only ``retention_days`` and
    ``owner_id`` overrides beyond the Protocol signature. runtime_checkable
    Protocols check method presence, not full signatures, so these extra
    kwargs are structurally compatible. Do not "fix" the apparent mismatch.
    """

    async def attach(self, workspace_id: str) -> str:
        """Provision the volume and return the container mount path."""
        ...

    async def detach(self, workspace_id: str) -> None:
        """Release the volume without deleting data (non-destructive, D-04)."""
        ...

    async def delete(self, workspace_id: str) -> None:
        """Permanently destroy the volume and all its data (D-05)."""
        ...
