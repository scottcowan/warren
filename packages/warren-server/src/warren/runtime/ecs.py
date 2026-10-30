"""ECSRuntime — AWS Fargate-backed ContainerRuntime (RT-07).

Full implementation per Plan 07-02. Follows DockerRuntime file-layout
pattern: same module docstring format, same import block, same class layout.

Security invariants (see 07-RESEARCH.md threat model):
    - Secrets live only in warren's encrypted store. They reach a task as a
      file on its own EFS volume, written just before RunTask and consumed
      (then deleted) by the image's entrypoint and git-init (ecs_secrets.py),
      or, for an EBS-backed workspace (runtime/ebs.py), as per-container
      KMS-wrapped ciphertext in the overrides (ecs_kms_secrets.py) -- never as
      plaintext `run_task` overrides (T-07-01, D-07), and never in the task
      definition.
    - cpu/memory validated against VALID_FARGATE_PAIRS before any AWS call
      (T-07-02, D-02).
    - Task ARNs read from warren's own SQLite store (T-07-04).
    - Exceptions wrapped in ProvisionError/RuntimeUnreachable — raw boto3
      exception message passed through but does not include credential values
      (T-07-06).

All boto3 calls are wrapped in asyncio.to_thread (boto3 is fully
synchronous). Clients are initialised lazily on first use via
_ensure_clients so module import stays cheap.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import re
import secrets
import shlex
import shutil
import uuid
from dataclasses import dataclass
from typing import Any, AsyncIterator, Literal

import structlog
from warren.runtime.ecs_git import (
    EFS_MOUNT_PATH,
    GIT_INIT_CONTAINER,
    GIT_INIT_ENTRYPOINT,
    WORKSPACE_DIR,
    GitInitPlan,
    build_git_init_plan,
)
from warren.runtime.ebs import (
    VOLUME_NAME,
    EBSVolumes,
    storage_configured,
)
from warren.runtime.ecs_kms_secrets import BLOB_ENV, seal_with_kms
from warren.runtime.ecs_storage import (
    LEGACY,
    NOT_SET_UP,
    OwnerStorage,
    StorageUnavailable,
    WorkspaceStorageUnavailable,
)
from warren.runtime.ecs_secrets import (
    GIT_INIT_FILE,
    WORKSPACE_FILE,
    is_env_name,
    remove_secrets,
    write_secrets,
)
from warren_common.agent_launch import SPEC_ENV as AGENT_SPEC_ENV
from warren_common.errors import ProvisionError, RuntimeUnreachable
from warren_common.harness_shell import seed_env, server_env, shell_first
from warren_common.models import template_env_for
from warren_common.seed_prompt import app_command_with_seed
from warren_common.runtime.base import (
    ContainerRuntime,
    ExecExit,
    ExecUnavailable,
    WorkspaceHandle,
    WorkspaceSpec,
    WorkspaceVolume,
)

log = structlog.get_logger(__name__)

_STARTING_STATES = frozenset({"PROVISIONING", "PENDING", "ACTIVATING"})
_ROLE_ARN_RE = re.compile(r"^arn:aws[a-z-]*:iam::\d{12}:role/[\w+=,.@/-]{1,512}$")

# RunTask rejects overrides whose JSON exceeds this many characters.
MAX_OVERRIDES_BYTES = 8192


class OverridesTooLarge(ProvisionError):
    """The RunTask overrides (env + secrets envelopes) exceed ECS's 8 KiB limit."""

    reason = "template_denied"

# ---------------------------------------------------------------------------
# Valid Fargate cpu/memory combinations (RESEARCH.md Pitfall 3)
# Keys are cpu strings; values are frozensets of valid memory strings.
# ---------------------------------------------------------------------------
VALID_FARGATE_PAIRS: dict[str, frozenset[str]] = {
    "256": frozenset({"512", "1024", "2048"}),
    "512": frozenset({"1024", "2048", "3072", "4096"}),
    "1024": frozenset({str(m) for m in range(2048, 8192 + 1, 1024)}),
    "2048": frozenset({str(m) for m in range(4096, 16384 + 1, 1024)}),
    "4096": frozenset({str(m) for m in range(8192, 30720 + 1, 1024)}),
    "8192": frozenset({str(m) for m in range(16384, 61440 + 1, 4096)}),
    "16384": frozenset({str(m) for m in range(32768, 122880 + 1, 8192)}),
}


class _MemoryLaunchStore:
    """Process-local launch-attempt store (when no persistent store is wired)."""

    def __init__(self) -> None:
        self._rows: dict[str, dict[str, str]] = {}

    async def get(self, workspace_id: str) -> dict[str, str] | None:
        row = self._rows.get(workspace_id)
        return dict(row) if row else None

    async def put(self, workspace_id: str, attempt: dict[str, str]) -> None:
        self._rows[workspace_id] = dict(attempt)

    async def delete(self, workspace_id: str) -> None:
        self._rows.pop(workspace_id, None)


@dataclass(frozen=True)
class Placement:
    """Which filesystem, control-plane mount and security groups a workspace uses."""

    volume: Any
    efs_id: str
    local_mount: str
    security_group_ids: list[str]


class ECSRuntime:
    """ContainerRuntime backed by AWS Fargate via boto3."""

    def __init__(
        self,
        server_id: str,
        settings: Any = None,
        *,
        ecs_cpu: str | None = None,
        ecs_memory: str | None = None,
        volume: WorkspaceVolume | None = None,
        volumes: dict[str, WorkspaceVolume] | None = None,
        launch_store: Any = None,
        ebs: EBSVolumes | None = None,
    ) -> None:
        self.server_id = server_id
        # AI3: get/put/delete of the per-workspace launch identity; app.py wires the
        # SQLite-backed LaunchAttemptStore so it survives a server restart.
        self.launch_store: Any = launch_store or _MemoryLaunchStore()
        # async (owner_id, names) -> {name: value} over warren's encrypted secret store,
        # wired by app.py. Unset, a workspace gets no secrets.
        self.secret_values: Any = None
        self._settings = settings
        # Allow direct cpu/memory kwargs to override settings (used in tests
        # and when calling without a full WarrenSettings object).
        self._default_cpu = ecs_cpu or (getattr(settings, "ecs_cpu", None) or "256")
        self._default_memory = ecs_memory or (getattr(settings, "ecs_memory", None) or "512")
        # Resource naming/path prefix (issue #2) — SSM paths, log group names, and
        # tag keys all derive from this instead of a hardcoded "warren" literal.
        self._resource_prefix = getattr(settings, "ecs_resource_prefix", None) or "warren"
        self._ecs: Any = None
        self._logs: Any = None
        self._log_retention_days = getattr(settings, "ecs_log_retention_days", None) or 90
        self._ensured_log_groups: set[str] = set()
        self._preflight_ok = False
        self._task_def_cache: dict[str, str] = {}  # canonical task-definition JSON → task_def_arn
        self._volume: WorkspaceVolume | None = volume
        # WARREN_ECS_OWNER_STORAGE (runtime/ecs_storage.py): per-user filesystem, security
        # groups and mount, with one EFSMount per user in `volumes`. Empty: shared mode.
        storage = getattr(settings, "ecs_owner_storage", None)
        self._owner_storage: dict[str, OwnerStorage] = storage if isinstance(storage, dict) else {}
        self._volumes: dict[str, WorkspaceVolume] = dict(volumes or {})
        # async (workspace_id) -> storage key or None, wired by app.py from the
        # workspace's persisted spec; how stop/destroy find a workspace's filesystem.
        self.storage_key_of: Any = None
        # EBS storage (runtime/ebs.py): the snapshot lifecycle, wired by app.py when the
        # deployment has it configured, and async (workspace_id) -> "efs" | "ebs" | None,
        # the mode the workspace was created with (from its persisted spec), so stop/
        # destroy follow that mode even if WARREN_ECS_WORKSPACE_STORAGE changed since.
        self.ebs: EBSVolumes | None = ebs
        self.storage_of: Any = None
        self._kms: Any = None

    @property
    def started_by(self) -> str:
        """RunTask startedBy for this server's tasks (ECS caps it at 36 chars)."""
        return f"{self._resource_prefix}-{self.server_id[:16]}"

    def _task_tags(self, spec: WorkspaceSpec) -> list[dict[str, str]]:
        """RunTask tags. AI1/AI2: `<prefix>.owner_id` is spec.owner_id, which only
        create_workspace/_reprovision_spec set (from resolve_owner_id, never the request
        body); IaC matches it against the caller's `warren-owner` principal tag to scope
        ecs:ExecuteCommand, and it doubles as the cost-allocation tag."""
        p = self._resource_prefix
        tags = [
            {"key": f"{p}.workspace_id", "value": spec.workspace_id},
            {"key": f"{p}.server_instance", "value": self.server_id},
            {"key": f"{p}.project", "value": spec.project},
            {"key": f"{p}.intent", "value": spec.intent},
        ]
        owner_id = getattr(spec, "owner_id", "") or ""
        if owner_id:
            tags.append({"key": f"{p}.owner_id", "value": owner_id})
        return tags

    def _client_token(self, spec: WorkspaceSpec, attempt_id: str) -> str:
        """AI3: RunTask clientToken for one launch attempt (persisted, reused on retry)."""
        raw = "\0".join(
            [self.server_id, spec.workspace_id, getattr(spec, "provision_generation", "") or "", attempt_id]
        )
        return hashlib.sha256(raw.encode()).hexdigest()

    async def _find_live_task(self, workspace_id: str, *, exclude: str) -> str | None:
        """AI3: ARN of a non-stopped task this server already launched for workspace_id."""
        for task in await self.list_owned_tasks():
            if task["workspace_id"] == workspace_id and task["task_arn"] != exclude:
                return task["task_arn"]
        return None

    def _ensure_clients(self) -> Any:
        """Lazily initialise the boto3 ECS (and logs) clients; returns ECS.

        Passes region_name explicitly so WARREN_AWS_REGION controls the boto3
        endpoint — not just the CloudWatch log group config string (WR-02).
        """
        if self._ecs is None:
            import boto3  # deferred — keeps module import cheap

            region = getattr(self._settings, "aws_region", "us-east-1") or "us-east-1"
            session = boto3.Session(region_name=region)
            self._ecs = session.client("ecs")
            self._logs = session.client("logs")
            if self._kms is None:
                self._kms = session.client("kms")
        return self._ecs

    @staticmethod
    def _spec_storage(spec: WorkspaceSpec) -> str:
        return "ebs" if getattr(spec, "ecs_storage", "") == "ebs" else "efs"

    async def _workspace_storage(self, workspace_id: str) -> str:
        mode = await self.storage_of(workspace_id) if self.storage_of is not None else None
        return "ebs" if mode == "ebs" else "efs"

    def _shared_placement(self) -> Placement:
        mount = getattr(self._settings, "efs_local_mount_path", "")
        efs_id = getattr(self._settings, "efs_id", "")
        return Placement(
            volume=self._volume,
            efs_id=efs_id if isinstance(efs_id, str) else "",
            local_mount=mount if isinstance(mount, str) else "",
            security_group_ids=list(getattr(self._settings, "ecs_security_group_ids", None) or []),
        )

    def _placement_for_key(self, key: str) -> Placement:
        cfg = self._owner_storage[key]
        return Placement(
            volume=self._volumes.get(key),
            efs_id=cfg.efs_id,
            local_mount=cfg.local_mount_path,
            security_group_ids=list(cfg.security_group_ids),
        )

    def _ebs_placement(self, key: str) -> Placement:
        """An EBS workspace has no filesystem and no control-plane mount. It runs in its
        owner's security groups when they have a WARREN_ECS_OWNER_STORAGE entry (keeping
        that network isolation), else the shared WARREN_ECS_SECURITY_GROUP_IDS."""
        cfg = self._owner_storage.get(key) if key else None
        sgs = list(cfg.security_group_ids) if cfg is not None else list(
            getattr(self._settings, "ecs_security_group_ids", None) or []
        )
        return Placement(volume=None, efs_id="", local_mount="", security_group_ids=sgs)

    def _placement_for_spec(self, spec: WorkspaceSpec) -> Placement:
        """Where this workspace lives. Raises StorageUnavailable (before any AWS call)
        for a legacy shared-filesystem workspace or an owner with no entry."""
        if self._spec_storage(spec) == "ebs":
            return self._ebs_placement(getattr(spec, "storage_key", "") or "")
        if not self._owner_storage:
            return self._shared_placement()
        key = getattr(spec, "storage_key", "") or ""
        if not key:
            raise StorageUnavailable(LEGACY)
        if key not in self._owner_storage or key not in self._volumes:
            raise StorageUnavailable(NOT_SET_UP)
        return self._placement_for_key(key)

    async def _placement_for_workspace(self, workspace_id: str) -> Placement | None:
        """For stop/destroy: the workspace's own placement, or None when it can't be
        known (legacy row, owner since removed) -- then nothing touches any filesystem."""
        if await self._workspace_storage(workspace_id) == "ebs":
            return self._ebs_placement("")
        if not self._owner_storage:
            return self._shared_placement()
        key = await self.storage_key_of(workspace_id) if self.storage_key_of is not None else None
        if not key or key not in self._owner_storage or key not in self._volumes:
            log.warning("ecs_workspace_storage_unknown", workspace_id=workspace_id)
            return None
        return self._placement_for_key(key)

    async def _resolve_secrets(self, spec: WorkspaceSpec) -> dict[str, str]:
        owner_id = getattr(spec, "owner_id", "") or ""
        declared = list(getattr(spec, "secret_names", []) or [])
        if not owner_id or not declared or self.secret_values is None:
            return {}
        values = await self.secret_values(owner_id, declared)
        out: dict[str, str] = {}
        for name in declared:
            if name not in values:
                continue
            if not is_env_name(name):
                log.warning("ecs_secret_skipped_not_env_name", workspace_id=spec.workspace_id, name=name)
                continue
            out[name] = values[name]
        return out

    async def _deliver_secrets(
        self,
        workspace_id: str,
        delivered: dict[str, str],
        git_plan: GitInitPlan | None,
        placement: Placement,
    ) -> None:
        """Write this launch's secrets files on the workspace's volume (or clear stale
        ones). The git-init credentials go only to git-init's file."""
        local_mount = placement.local_mount
        if not local_mount or placement.volume is None:
            return
        init_names = set(git_plan.init_secret_names) if git_plan is not None else set()
        files = {
            WORKSPACE_FILE: {k: v for k, v in delivered.items() if k not in init_names},
            GIT_INIT_FILE: {k: v for k, v in delivered.items() if k in init_names},
        }
        try:
            await asyncio.to_thread(write_secrets, local_mount, workspace_id, files)
        except (OSError, ValueError) as exc:
            raise ProvisionError(
                f"cannot write secrets onto workspace {workspace_id}'s volume: {type(exc).__name__}"
            ) from exc

    async def _secrets_blobs(
        self, workspace_id: str, delivered: dict[str, str], git_plan: GitInitPlan | None
    ) -> dict[str, str]:
        """EBS storage: one KMS envelope per container that has secrets, split exactly
        like the EFS files (git-init's clone credentials only to git-init)."""
        init_names = set(git_plan.init_secret_names) if git_plan is not None else set()
        split = {
            "workspace": {k: v for k, v in delivered.items() if k not in init_names},
            GIT_INIT_CONTAINER: {k: v for k, v in delivered.items() if k in init_names},
        }
        self._ensure_clients()
        key_id = getattr(self._settings, "ecs_secrets_kms_key_id", "") or ""
        region = getattr(self._settings, "aws_region", "us-east-1") or "us-east-1"
        blobs: dict[str, str] = {}
        for container, values in split.items():
            if values:
                blobs[container] = await seal_with_kms(
                    self._kms, key_id, values,
                    workspace_id=workspace_id, container=container, region=region,
                )
        return blobs

    async def _remove_secrets(self, workspace_id: str, placement: Placement | None) -> None:
        if placement is None or not placement.local_mount or placement.volume is None:
            return
        local_mount = placement.local_mount
        try:
            await asyncio.to_thread(remove_secrets, local_mount, workspace_id)
        except (OSError, ProvisionError):
            log.warning("ecs_secrets_remove_failed", workspace_id=workspace_id)

    async def _ensure_log_group(self, group_name: str) -> None:
        """Idempotently create `group_name` with bounded retention (audit #53).

        `awslogs-create-group: true` on the task definition would otherwise let the
        ECS agent lazily create this group itself with infinite retention and no way
        to expire it. Creating it ourselves first, with retention already set, means
        the agent's auto-create becomes a no-op against an already-correct group.
        Cached per-process so a hot provisioning path isn't doing two extra AWS calls
        per workspace once the group obviously already exists.

        Audit S4: both boto3 calls below are synchronous and were previously called
        directly (not through asyncio.to_thread like every other boto3 call in this
        class) -- each one blocks the whole event loop, including every other
        in-flight workspace's provisioning, for the duration of the network call.
        """
        if group_name in self._ensured_log_groups:
            return
        assert self._logs is not None
        try:
            await asyncio.to_thread(self._logs.create_log_group, logGroupName=group_name)
        except self._logs.exceptions.ResourceAlreadyExistsException:
            pass
        await asyncio.to_thread(
            self._logs.put_retention_policy,
            logGroupName=group_name,
            retentionInDays=self._log_retention_days,
        )
        self._ensured_log_groups.add(group_name)

    async def preflight(self) -> None:
        """Verify ECS cluster is reachable; raise RuntimeUnreachable on failure."""
        ecs = self._ensure_clients()
        cluster = getattr(self._settings, "ecs_cluster", "") or ""
        try:
            resp = await asyncio.to_thread(
                ecs.describe_clusters,
                clusters=[cluster],
            )
        except Exception as exc:
            raise RuntimeUnreachable(
                f"ECS cluster unreachable: {exc}"
            ) from exc
        clusters_found = resp.get("clusters", [])
        if not clusters_found or clusters_found[0].get("status") == "INACTIVE":
            raise RuntimeUnreachable(
                f"ECS cluster not found or inactive: {cluster!r}"
            )
        if getattr(self._settings, "ecs_workspace_storage", "efs") == "ebs":
            problem = self._ebs_settings_problem()
            if problem:
                raise RuntimeUnreachable(f"WARREN_ECS_WORKSPACE_STORAGE=ebs: {problem}")
        self._preflight_ok = True

    def _ebs_settings_problem(self) -> str:
        """Why EBS storage can't be used on this deployment, or "" when it can."""
        role = getattr(self._settings, "ecs_ebs_infra_role_arn", "") or ""
        if not role:
            return "set WARREN_ECS_EBS_INFRA_ROLE_ARN (the ECS infrastructure role for volumes)"
        if not _ROLE_ARN_RE.match(role):
            return f"WARREN_ECS_EBS_INFRA_ROLE_ARN {role!r} is not an IAM role ARN"
        if not getattr(self._settings, "ecs_secrets_kms_key_id", ""):
            return "set WARREN_ECS_SECRETS_KMS_KEY_ID (secrets are delivered as KMS ciphertext)"
        if self.ebs is None or not storage_configured(self._settings, "ebs"):
            return "EBS storage is not wired on this server"
        return ""

    def _validate_cpu_memory(self, cpu: str, memory: str) -> None:
        """Validate cpu/memory against VALID_FARGATE_PAIRS; raise ProvisionError if invalid."""
        valid_memories = VALID_FARGATE_PAIRS.get(cpu)
        if valid_memories is None or memory not in valid_memories:
            raise ProvisionError(
                f"invalid Fargate cpu/memory combination: {cpu}/{memory}. "
                f"Valid pairs per Fargate docs: {VALID_FARGATE_PAIRS}"
            )

    async def provision(self, spec: WorkspaceSpec) -> WorkspaceHandle:
        """Register Fargate task definition (cached), launch task, return handle."""
        try:
            placement = self._placement_for_spec(spec)
        except StorageUnavailable as exc:
            raise WorkspaceStorageUnavailable(str(exc)) from exc
        # Preflight guard — same pattern as DockerRuntime.
        if not self._preflight_ok:
            await self.preflight()

        # Resolve cpu/memory per D-02: spec-level overrides take precedence.
        resolved_cpu = getattr(spec, "ecs_cpu", None) or self._default_cpu
        resolved_memory = getattr(spec, "ecs_memory", None) or self._default_memory

        # Validate before any AWS call (T-07-02).
        self._validate_cpu_memory(resolved_cpu, resolved_memory)

        ebs = self._spec_storage(spec) == "ebs"
        if ebs:
            problem = self._ebs_settings_problem()
            if problem:
                raise ProvisionError(f"this workspace uses EBS storage, but {problem}")

        # Exactly the template-declared secrets this workspace's OWNER has, decrypted
        # from warren's own store. They reach the task only as a file on its EFS volume
        # (runtime/ecs_secrets.py), written just before RunTask, or on EBS storage as
        # KMS ciphertext in the overrides (runtime/ecs_kms_secrets.py).
        delivered = await self._resolve_secrets(spec)
        if delivered and not ebs and not (placement.volume is not None and placement.local_mount):
            raise ProvisionError(
                "this workspace declares secrets, and ECS delivers them through its EFS "
                "volume: set WARREN_EFS_ID and WARREN_EFS_LOCAL_MOUNT_PATH"
            )

        family = _slug(spec.image, self._resource_prefix)
        git_plan = build_git_init_plan(spec, frozenset(delivered))

        if ebs:
            assert self.ebs is not None
            # A launch from an earlier attempt that is still live is adopted as is; its
            # volume is attached, so there is nothing to settle or restore.
            generation = getattr(spec, "provision_generation", "") or ""
            adopted_arn = await self._find_live_task(spec.workspace_id, exclude=generation)
            if adopted_arn:
                log.info("ecs_adopted_task", workspace_id=spec.workspace_id, task_arn=adopted_arn)
                return WorkspaceHandle(workspace_id=spec.workspace_id, runtime_id=adopted_arn, root_path="")
            # Snapshot the previous task's retained volume if nothing did yet, and wait
            # for the newest snapshot to complete; None = first launch, empty volume.
            snapshot_id = await self.ebs.restore_point(spec.workspace_id)
            volume_config = self.ebs.volume_configuration(
                spec.workspace_id,
                owner_id=getattr(spec, "owner_id", "") or None,
                snapshot_id=snapshot_id,
            )
            return await self._register_and_run(
                spec, None, resolved_cpu, resolved_memory, family, delivered, git_plan,
                placement, volume_config=volume_config,
            )

        # D-10: EFS is opt-in — only activate when a volume is wired in
        access_point_id: str | None = None
        volume = placement.volume
        if volume is not None:
            await volume.attach(spec.workspace_id, owner_id=getattr(spec, "owner_id", "") or None)
            access_point_id = getattr(volume, "last_access_point_id", None)

        # Issue #30b: everything below can fail (RegisterTaskDefinition,
        # RunTask) after attach() above already created the access point. On
        # any such failure, detach it (tags warren.expires_at so the reaper
        # eventually cleans it up) rather than leaking it forever with no
        # expiry — then re-raise so the caller still sees the original error.
        try:
            return await self._register_and_run(
                spec, access_point_id, resolved_cpu, resolved_memory, family, delivered, git_plan,
                placement,
            )
        except Exception:
            if volume is not None:
                try:
                    await volume.detach(spec.workspace_id)
                except Exception:
                    log.warning(
                        "efs_cleanup_after_failed_provision_failed",
                        workspace_id=spec.workspace_id,
                    )
            raise

    async def _register_and_run(
        self,
        spec: WorkspaceSpec,
        access_point_id: str | None,
        resolved_cpu: str,
        resolved_memory: str,
        family: str,
        delivered: dict[str, str],
        git_plan: GitInitPlan | None = None,
        placement: Placement | None = None,
        *,
        volume_config: dict[str, Any] | None = None,
    ) -> WorkspaceHandle:
        """`volume_config`: EBS storage's RunTask volume configuration (runtime/ebs.py);
        the task definition then declares the volume `configuredAtLaunch`."""
        placement = placement or self._shared_placement()
        ecs = self._ensure_clients()
        await self._ensure_log_group(f"/{self._resource_prefix}/{self.server_id}")

        region = getattr(self._settings, "aws_region", "us-east-1") or "us-east-1"
        execution_role = (
            getattr(self._settings, "ecs_task_execution_role_arn", "") or ""
        )
        task_role = getattr(self._settings, "ecs_task_role_arn", "") or ""
        log_options = {
            "awslogs-group": f"/{self._resource_prefix}/{self.server_id}",
            "awslogs-region": region,
            "awslogs-stream-prefix": "workspace",
            # We create the group ourselves above (with bounded
            # retention) rather than letting the agent auto-create
            # it with infinite retention — audit #53.
            "awslogs-create-group": "false",
        }

        register_kwargs: dict[str, Any] = {
            "family": family,
            "networkMode": "awsvpc",
            "requiresCompatibilities": ["FARGATE"],
            "cpu": str(resolved_cpu),
            "memory": str(resolved_memory),
            "containerDefinitions": [
                {
                    "name": "workspace",
                    "image": spec.image,
                    "essential": True,
                    # NO environment and no secrets here: non-secret spec.env goes via
                    # run_task overrides below, secrets via the volume (ecs_secrets.py),
                    # so this definition carries nothing owner-specific.
                    "linuxParameters": {"initProcessEnabled": True},
                    "logConfiguration": {"logDriver": "awslogs", "options": log_options},
                }
            ],
            "tags": [
                {"key": f"{self._resource_prefix}.server_instance", "value": self.server_id},
            ],
        }
        # AD3: the workspace container only. git-init always starts as the image's USER
        # (root) so it can run warren-init-volume before it drops to uid 1000 itself.
        task_user = getattr(self._settings, "ecs_task_user", "") or ""
        if task_user:
            register_kwargs["containerDefinitions"][0]["user"] = task_user
        if execution_role:
            register_kwargs["executionRoleArn"] = execution_role
        if task_role:
            register_kwargs["taskRoleArn"] = task_role

        mount_points = [
            {
                "containerPath": EFS_MOUNT_PATH,
                "sourceVolume": "warren-workspace",
                "readOnly": False,
            }
        ]
        if volume_config is not None:
            # Nothing workspace-specific in the definition, so it stays cacheable: the
            # volume itself (size or snapshot, tags) is in RunTask's volumeConfigurations.
            register_kwargs["volumes"] = [{"name": VOLUME_NAME, "configuredAtLaunch": True}]
            register_kwargs["containerDefinitions"][0]["mountPoints"] = mount_points
        elif access_point_id:
            efs_id_val = placement.efs_id
            register_kwargs["volumes"] = [
                {
                    "name": "warren-workspace",
                    "efsVolumeConfiguration": {
                        "fileSystemId": efs_id_val,
                        # ENABLED is required alongside authorizationConfig.iam=ENABLED —
                        # AWS rejects DISABLED+iam-ENABLED at RegisterTaskDefinition/launch.
                        "transitEncryption": "ENABLED",
                        "authorizationConfig": {
                            "accessPointId": access_point_id,
                            "iam": "ENABLED",
                        },
                    },
                }
            ]
            register_kwargs["containerDefinitions"][0]["mountPoints"] = mount_points

        if git_plan is not None:
            if not access_point_id and volume_config is None:
                # No EFS: a task-scoped volume still lets the init container
                # hand the checkout to the workspace container.
                register_kwargs["volumes"] = [{"name": "warren-workspace"}]
                register_kwargs["containerDefinitions"][0]["mountPoints"] = mount_points
            init_image = getattr(self._settings, "ecs_git_init_image", "") or spec.image
            register_kwargs["containerDefinitions"].append(
                {
                    "name": GIT_INIT_CONTAINER,
                    "image": init_image,
                    "essential": False,
                    "entryPoint": [GIT_INIT_ENTRYPOINT],
                    "command": [],
                    "mountPoints": mount_points,
                    "logConfiguration": {
                        "logDriver": "awslogs",
                        "options": {**log_options, "awslogs-stream-prefix": GIT_INIT_CONTAINER},
                    },
                },
            )
            register_kwargs["containerDefinitions"][0]["dependsOn"] = [
                {"containerName": GIT_INIT_CONTAINER, "condition": "SUCCESS"}
            ]

        # Build environment overrides list — spec.env only. Secrets never flow through
        # here (issue #4): RunTask overrides are recorded in DescribeTasks/CloudTrail, so
        # secrets go through the workspace's volume instead (_deliver_secrets below), or on
        # EBS storage as KMS envelopes added after the fingerprint (_secrets_blobs below).
        # ecs-base/entrypoint.sh execs WARREN_APP_CMD as PID 1 when set, falling back to
        # `tail -f /dev/null` (idle, awaiting `aws ecs execute-command`) when unset. "bash"
        # is WorkspaceSpec.app's interactive default and has no business being exec'd as
        # PID 1 here (unlike podman's entrypoint.py, there's no attached tty to run it
        # against) -- only a real declared app (e.g. "claude") should launch eagerly.
        env_dict = {
            **template_env_for(
                spec.template_env, exclude=[*(spec.env or {}), *spec.secret_names]
            ),
            **(spec.env or {}),
        }
        # Audit U1: these were `.setdefault(...)`, so a spec.env (or secret)
        # key that happened to collide with one of these names would silently
        # win over warren's own computed value -- the exact inverse of #34's
        # fix, which established that warren's own computed env vars always
        # take precedence over a same-named user-supplied one. Direct
        # assignment here matches that precedent.
        # AG2a: a user workspace whose app is a shell or a harness starts at the warren
        # shell over ECS Exec (warren-session); only single-turn runs and service apps
        # run as PID 1.
        # AG2b: an agent workspace's entrypoint runs the supervisor (never the harness as
        # PID 1); a human still attaches the warren shell over ECS Exec next to it.
        if spec.agent is not None:
            env_dict[AGENT_SPEC_ENV] = json.dumps(spec.agent, separators=(",", ":"))
        elif shell_first(spec.app, spec.mode):
            env_dict.update(seed_env(spec.app, spec.harnesses, spec.seed_prompt))
        elif spec.app:
            env_dict["WARREN_APP_CMD"] = app_command_with_seed(spec.app, spec.seed_prompt)
        # Read by the shared banner/prompt zsh snippet baked into ecs-base's
        # .zshrc (warren_common/assets/warren_banner.zsh) at shell-start time --
        # UX-1: never set for ECS tasks before this, so a zsh-templated
        # workspace connected via `aws ecs execute-command` had no way to know
        # its own project/template/workspace id.
        # AG3: harness names only; the image's harness.sh/warren-harness-init carry the profile data.
        env_dict.update(server_env(spec.harnesses, app=spec.app, mode=spec.mode))
        if spec.model_access == "bedrock":
            # Bedrock through the workspace task role; Claude Code needs a region.
            env_dict.setdefault("AWS_REGION", getattr(self._settings, "aws_region", "") or "us-east-1")
        env_dict["WARREN_WORKSPACE_ID"] = spec.workspace_id
        env_dict["WARREN_PROJECT"] = spec.project
        env_dict["WARREN_TEMPLATE"] = spec.intent
        if git_plan is not None:
            env_dict["WARREN_WORKSPACE_DIR"] = WORKSPACE_DIR
        env_overrides = [{"name": k, "value": v} for k, v in env_dict.items()]
        container_overrides: list[dict[str, Any]] = [
            {"name": "workspace", "environment": env_overrides}
        ]
        if git_plan is not None:
            git_init_env = [{"name": "WARREN_GIT_FOLDERS", "value": git_plan.folders_env}]
            known_hosts = getattr(self._settings, "ecs_git_known_hosts", "") or ""
            if known_hosts:
                git_init_env.append({"name": "WARREN_GIT_KNOWN_HOSTS", "value": known_hosts})
            container_overrides.append(
                {
                    "name": GIT_INIT_CONTAINER,
                    "environment": git_init_env,
                }
            )

        # Audit BB2: the cache key is the whole canonical task definition, so a cached
        # definition is reused only when it is identical. It holds nothing per-owner
        # (secrets, env and owner tags go per launch), and EFS definitions, which name a
        # workspace's own access point, are never cached.
        cache_key = json.dumps(register_kwargs, sort_keys=True)

        # AI3: a retry of the same provision generation (e.g. after a lost RunTask
        # response) reuses the persisted task definition + clientToken, and adopts a
        # task that launch already started rather than starting a second one. The
        # fingerprint covers the whole multi-container launch payload: the canonical task
        # definition (both containers, volumes, access point) and the
        # RunTask container overrides (incl. git-init's WARREN_GIT_FOLDERS). Any change
        # to what would be launched gets a fresh identity rather than a stale token.
        generation = getattr(spec, "provision_generation", "") or ""
        fingerprint = hashlib.sha256(
            json.dumps(
                {
                    "task_definition": register_kwargs,
                    "container_overrides": container_overrides,
                    "access_point_id": access_point_id,
                    "volume_configuration": volume_config,
                },
                sort_keys=True,
            ).encode()
        ).hexdigest()
        attempt = await self.launch_store.get(spec.workspace_id)
        if attempt and (attempt["generation"], attempt["fingerprint"]) != (generation, fingerprint):
            attempt = None

        adopted_arn = await self._find_live_task(spec.workspace_id, exclude=generation)
        if adopted_arn:
            log.info("ecs_adopted_task", workspace_id=spec.workspace_id, task_arn=adopted_arn)
            return WorkspaceHandle(
                workspace_id=spec.workspace_id, runtime_id=adopted_arn, root_path=""
            )

        if attempt:
            task_def_arn: str | None = attempt["task_definition_arn"]
        else:
            task_def_arn = None if access_point_id else self._task_def_cache.get(cache_key)
        if task_def_arn is None:
            reg_resp = await asyncio.to_thread(
                ecs.register_task_definition, **register_kwargs
            )
            task_def_arn = reg_resp["taskDefinition"]["taskDefinitionArn"]
            # Only cache non-EFS task definitions — EFS defs are workspace-specific
            if not access_point_id:
                self._task_def_cache[cache_key] = task_def_arn

        # EBS: the secrets envelopes are random per encryption, so they are kept out of the
        # fingerprint and persisted with the attempt instead; a retry under the same
        # clientToken then sends the identical request.
        blobs: dict[str, str] = {}
        if volume_config is not None and delivered:
            blobs = _load_blobs(attempt.get("secrets_blobs") if attempt else None)
            if not blobs:
                blobs = await self._secrets_blobs(spec.workspace_id, delivered, git_plan)
                if attempt:
                    attempt = {**attempt, "secrets_blobs": json.dumps(blobs, sort_keys=True)}
                    await self.launch_store.put(spec.workspace_id, attempt)

        if not attempt:
            # AM2: a client operationId makes the token deterministic, so a retry of the
            # same operation that lost its launch row is still deduplicated by ECS.
            operation_id = getattr(spec, "operation_id", "") or ""
            attempt_id = f"op:{operation_id}:{fingerprint}" if operation_id else uuid.uuid4().hex
            attempt = {
                "generation": generation,
                "fingerprint": fingerprint,
                "task_definition_arn": task_def_arn,
                "client_token": self._client_token(spec, attempt_id),
            }
            if blobs:
                attempt["secrets_blobs"] = json.dumps(blobs, sort_keys=True)
            await self.launch_store.put(spec.workspace_id, attempt)

        if blobs:
            for override in container_overrides:
                blob = blobs.get(override["name"])
                if blob:
                    override["environment"] = [
                        *override["environment"],
                        {"name": BLOB_ENV, "value": blob},
                    ]
                    if override["name"] == GIT_INIT_CONTAINER:
                        # warren-secrets-decrypt's encryption context names the workspace.
                        override["environment"].append(
                            {"name": "WARREN_WORKSPACE_ID", "value": spec.workspace_id}
                        )
        overrides = {"containerOverrides": container_overrides}
        size = len(json.dumps(overrides, separators=(",", ":")))
        if size > MAX_OVERRIDES_BYTES:
            await self.launch_store.delete(spec.workspace_id)
            raise OverridesTooLarge(
                f"this workspace's environment and secrets need {size} bytes of RunTask "
                f"overrides; ECS allows {MAX_OVERRIDES_BYTES}. Declare fewer or smaller "
                "secrets or env values"
            )

        # Launch Fargate task.
        cluster = getattr(self._settings, "ecs_cluster", "") or ""
        subnet_ids = list(getattr(self._settings, "ecs_subnet_ids", None) or [])
        sg_ids = list(placement.security_group_ids)
        assign_public_ip = (
            "ENABLED"
            if getattr(self._settings, "ecs_assign_public_ip", False)
            else "DISABLED"
        )

        # Immediately before every RunTask, so a relaunch always gets current values and
        # never a stale file. (An exception from RunTask itself may still have launched
        # a task that needs the file, so only a definitive failure below removes it.)
        if volume_config is None:
            await self._deliver_secrets(spec.workspace_id, delivered, git_plan, placement)

        run_kwargs: dict[str, Any] = {}
        if volume_config is not None:
            run_kwargs["volumeConfigurations"] = [volume_config]
        run_resp = await asyncio.to_thread(
            ecs.run_task,
            cluster=cluster,
            taskDefinition=task_def_arn,
            launchType="FARGATE",
            networkConfiguration={
                "awsvpcConfiguration": {
                    "subnets": subnet_ids,
                    "securityGroups": sg_ids,
                    "assignPublicIp": assign_public_ip,
                }
            },
            overrides=overrides,
            enableExecuteCommand=True,
            tags=self._task_tags(spec),
            startedBy=self.started_by,
            clientToken=attempt["client_token"],
            **run_kwargs,
        )

        # A definitive failure launched nothing, so the next try gets a fresh identity.
        failures = run_resp.get("failures", [])
        if failures:
            await self.launch_store.delete(spec.workspace_id)
            await self._remove_secrets(spec.workspace_id, placement)
            reason = failures[0].get("reason", "unknown")
            raise ProvisionError(f"ECS run_task failed: {reason}")

        tasks = run_resp.get("tasks", [])
        if not tasks:
            await self.launch_store.delete(spec.workspace_id)
            await self._remove_secrets(spec.workspace_id, placement)
            raise ProvisionError("ECS run_task returned no tasks and no failures (unexpected empty response)")

        task_arn: str = tasks[0]["taskArn"]

        log.info(
            "ecs_provisioned",
            workspace_id=spec.workspace_id,
            task_arn=task_arn,
            image=spec.image,
        )

        return WorkspaceHandle(
            workspace_id=spec.workspace_id,
            runtime_id=task_arn,
            root_path="",
        )

    async def start(self, handle: WorkspaceHandle) -> None:
        """No-op — Fargate has no stopped-but-not-destroyed state."""
        log.warning("ecs_start_noop", workspace_id=handle.workspace_id)

    async def _stop_task(self, handle: WorkspaceHandle, *, reason: str) -> None:
        """Call ECS StopTask; idempotent (already stopped is acceptable).

        Shared by `stop()` and `destroy()` -- Fargate's only way to end a
        running task either way is StopTask, the one thing distinguishing the
        two is what happens to the EFS access point afterward (see each
        caller).
        """
        ecs = self._ensure_clients()
        if not handle.runtime_id:
            return
        cluster = getattr(self._settings, "ecs_cluster", "") or ""
        try:
            await asyncio.to_thread(
                ecs.stop_task,
                cluster=cluster,
                task=handle.runtime_id,
                reason=reason,
            )
        except Exception as exc:
            # Convert known "already gone" errors to no-ops; surface everything else.
            # boto3 ClientError.response is a dict; non-ClientErrors have no .response.
            err_code = (getattr(exc, "response", None) or {}).get("Error", {}).get("Code", "")
            if err_code in ("InvalidParameterException", "ClusterNotFoundException"):
                log.debug("ecs_stop_task_already_gone", task=handle.runtime_id, error=str(exc))
            else:
                log.warning("ecs_stop_task_failed", task=handle.runtime_id, error=str(exc))
                raise

    async def list_owned_tasks(self) -> list[dict[str, Any]]:
        """AI3: running/pending tasks this server launched, for the orphan sweep.

        Filters on startedBy, then requires the server_instance tag to equal
        this server_id exactly (startedBy truncates server_id). Returns dicts
        with task_arn, workspace_id (tag, or "") and created_at (datetime or None).
        """
        ecs = self._ensure_clients()
        cluster = getattr(self._settings, "ecs_cluster", "") or ""
        arns: list[str] = []
        kwargs: dict[str, Any] = {"cluster": cluster, "startedBy": self.started_by}
        while True:
            resp = await asyncio.to_thread(ecs.list_tasks, **kwargs)
            arns.extend(resp.get("taskArns", []))
            next_token = resp.get("nextToken")
            if not next_token:
                break
            kwargs["nextToken"] = next_token

        server_tag = f"{self._resource_prefix}.server_instance"
        ws_tag = f"{self._resource_prefix}.workspace_id"
        owned: list[dict[str, Any]] = []
        for i in range(0, len(arns), 100):
            desc = await asyncio.to_thread(
                ecs.describe_tasks, cluster=cluster, tasks=arns[i : i + 100], include=["TAGS"]
            )
            for task in desc.get("tasks", []):
                tags = {t.get("key"): t.get("value") for t in task.get("tags", [])}
                if tags.get(server_tag) != self.server_id:
                    continue
                owned.append(
                    {
                        "task_arn": task["taskArn"],
                        "workspace_id": tags.get(ws_tag, "") or "",
                        "created_at": task.get("createdAt"),
                    }
                )
        return owned

    async def stop_task_arn(self, task_arn: str, *, workspace_id: str, reason: str) -> None:
        """StopTask by ARN (orphan sweep); no EFS detach."""
        await self._stop_task(
            WorkspaceHandle(workspace_id=workspace_id, runtime_id=task_arn, root_path=""),
            reason=reason,
        )

    async def stop(self, handle: WorkspaceHandle) -> None:
        """Stop the Fargate task (finding 9): Fargate tasks aren't "stoppable"
        the way podman containers are -- they're either running or need a real
        StopTask call -- so the previous no-op here left the idle reaper
        marking workspaces "stopped" in the DB while the task (and its
        billing) kept running indefinitely. Does NOT detach the EFS access
        point (unlike `destroy()`) -- a stopped-not-destroyed workspace must
        stay reconnectable via `ensure_running()`, which launches a fresh
        task against the SAME access point (D-04)."""
        await self._stop_task(handle, reason="warren stop (idle)")
        if await self._workspace_storage(handle.workspace_id) == "ebs":
            # Any stop that isn't a destroy (idle reaper, user stop) keeps the data: the
            # retained volume is snapshotted and deleted. A failure here doesn't fail the
            # stop; the next launch or the volume sweep finishes it.
            if self.ebs is not None:
                try:
                    await self.ebs.preserve(handle.workspace_id)
                except Exception:
                    log.exception("ebs_preserve_failed", workspace_id=handle.workspace_id)
            return
        await self._remove_secrets(handle.workspace_id, await self._placement_for_workspace(handle.workspace_id))

    async def destroy(self, handle: WorkspaceHandle) -> None:
        """Stop Fargate task; idempotent (already stopped is acceptable)."""
        # Issue #30c: an EFS-backed workspace's task definition is never
        # shared (provision() forces a fresh registration per workspace,
        # since each access point ARN is unique), so its revision would
        # otherwise accumulate forever. Resolve it from the still-running
        # task before stopping it, then deregister after cleanup below.
        placement = await self._placement_for_workspace(handle.workspace_id)
        volume = placement.volume if placement is not None else None
        task_def_arn: str | None = None
        if volume is not None and handle.runtime_id:
            try:
                ecs = self._ensure_clients()
                cluster = getattr(self._settings, "ecs_cluster", "") or ""
                desc = await asyncio.to_thread(
                    ecs.describe_tasks, cluster=cluster, tasks=[handle.runtime_id]
                )
                tasks = desc.get("tasks", [])
                if tasks:
                    task_def_arn = tasks[0].get("taskDefinitionArn")
            except Exception:
                log.warning(
                    "ecs_describe_task_for_deregister_failed",
                    workspace_id=handle.workspace_id,
                )

        await self._stop_task(handle, reason="warren destroy")
        await self.launch_store.delete(handle.workspace_id)
        if await self._workspace_storage(handle.workspace_id) == "ebs":
            # Explicit destroy: every snapshot now, the volume once it detaches. Raising
            # leaves the row non-terminal so the destroy can be retried; a volume still
            # attached at the deadline is deleted by the sweep (the row is destroyed).
            if self.ebs is None:
                raise ProvisionError("this workspace uses EBS storage, which is not configured here")
            await self.ebs.purge(handle.workspace_id)
            return
        await self._remove_secrets(handle.workspace_id, placement)

        # D-04: detach sets warren.expires_at tag; does NOT delete the access point
        if volume is not None:
            try:
                await volume.detach(handle.workspace_id)
            except Exception:
                log.warning("efs_detach_failed", workspace_id=handle.workspace_id)

        if task_def_arn and task_def_arn not in self._task_def_cache.values():
            try:
                ecs = self._ensure_clients()
                await asyncio.to_thread(ecs.deregister_task_definition, taskDefinition=task_def_arn)
                log.info("ecs_deregistered_task_definition", task_definition_arn=task_def_arn)
            except Exception:
                log.warning(
                    "ecs_deregister_task_definition_failed", task_definition_arn=task_def_arn
                )

    async def exit_code(self, handle: WorkspaceHandle) -> int | None:
        """AH2: the workspace container's exit code from DescribeTasks (None if not recorded)."""
        if not handle.runtime_id:
            return None
        ecs = self._ensure_clients()
        cluster = getattr(self._settings, "ecs_cluster", "") or ""
        resp = await asyncio.to_thread(ecs.describe_tasks, cluster=cluster, tasks=[handle.runtime_id])
        for task in resp.get("tasks", []):
            for container in task.get("containers", []):
                if container.get("name") == "workspace":
                    code = container.get("exitCode")
                    return int(code) if code is not None else None
        return None

    async def exec(
        self, handle: WorkspaceHandle, cmd: list[str]
    ) -> AsyncIterator[bytes]:
        """Raw byte stream of `exec_stream` (exit code dropped)."""
        async for item in self.exec_stream(handle, cmd):
            if isinstance(item, bytes):
                yield item

    async def exec_stream(
        self, handle: WorkspaceHandle, argv: list[str]
    ) -> AsyncIterator[bytes | ExecExit]:
        """#59: ecs:ExecuteCommand with the control plane's own role, read through
        session-manager-plugin. ECS Exec reports no exit code and always allocates a
        TTY, so argv runs under `sh -c` with a per-call sentinel line carrying `$?`."""
        plugin = shutil.which("session-manager-plugin")
        if plugin is None:
            raise ExecUnavailable("session-manager-plugin is not installed on the control plane")
        ecs = self._ensure_clients()
        cluster = getattr(self._settings, "ecs_cluster", "") or ""
        region = getattr(self._settings, "aws_region", "us-east-1") or "us-east-1"
        described = await asyncio.to_thread(ecs.describe_tasks, cluster=cluster, tasks=[handle.runtime_id])
        runtime_id = next(
            (
                c.get("runtimeId")
                for t in described.get("tasks", [])
                for c in t.get("containers", [])
                if c.get("name") == "workspace"
            ),
            None,
        )
        if not runtime_id:
            raise ExecUnavailable("workspace container is not running")
        sentinel = f"__WARREN_EXIT_{secrets.token_hex(8)}__"
        command = "sh -c " + shlex.quote(shlex.join(argv) + "; echo " + sentinel + "$?")
        resp = await asyncio.to_thread(
            ecs.execute_command,
            cluster=cluster,
            task=handle.runtime_id,
            container="workspace",
            interactive=True,
            command=command,
        )
        task_id = handle.runtime_id.rstrip("/").rsplit("/", 1)[-1]
        proc = await asyncio.create_subprocess_exec(
            plugin,
            json.dumps(resp["session"]),
            region,
            "StartSession",
            "",
            json.dumps({"Target": f"ecs:{cluster}_{task_id}_{runtime_id}"}),
            ecs.meta.endpoint_url,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        exit_code: int | None = None
        try:
            assert proc.stdout is not None
            async for line in proc.stdout:
                text = line.decode(errors="replace").rstrip("\r\n")
                if text.startswith(sentinel):
                    tail = text[len(sentinel):].strip()
                    exit_code = int(tail) if tail.isdigit() else None
                    continue
                if text.startswith(("Starting session with SessionId", "Exiting session with sessionId")):
                    continue
                yield line.replace(b"\r\n", b"\n")
            await proc.wait()
            yield ExecExit(exit_code)
        finally:
            if proc.returncode is None:
                proc.kill()
                await proc.wait()

    async def tunnel(self, handle: WorkspaceHandle, port: int) -> None:
        """Not implemented here — same reasoning as ``exec`` above: port
        forwarding rides the operator's own AWS credentials over the same
        ECS Exec SSM channel (`AWS-StartPortForwardingSession` against
        ``ecs:{cluster}_{task_id}_{runtime_id}``, not a document this
        control-plane process brokers), so it's handled entirely by the
        CLI (``warren workspaces tunnel``) rather than this runtime backend.
        Deliberately generic to whatever's listening on ``port`` — this
        runtime backend has no notion of any particular protocol running
        inside the task (D-08: the control plane is protocol-agnostic).
        """
        raise NotImplementedError(
            "ECS port forwarding is handled by the CLI via SSM Session Manager; "
            "use warren workspaces tunnel for a port-forwarded connection"
        )

    async def status(
        self, handle: WorkspaceHandle
    ) -> Literal["running", "starting", "stopped", "unknown"]:
        """Map Fargate lastStatus to warren status literals."""
        if not handle.runtime_id:
            return "unknown"
        ecs = self._ensure_clients()
        cluster = getattr(self._settings, "ecs_cluster", "") or ""
        resp = await asyncio.to_thread(
            ecs.describe_tasks,
            cluster=cluster,
            tasks=[handle.runtime_id],
        )
        tasks = resp.get("tasks", [])
        failures = resp.get("failures", [])
        if not tasks and failures:
            return "stopped"
        if not tasks:
            return "unknown"
        last = tasks[0].get("lastStatus", "")
        if last == "RUNNING":
            return "running"
        if last in ("STOPPED", "STOPPING", "DEPROVISIONING"):
            return "stopped"
        # BB4: a launching task is live; callers must wait, not reprovision.
        if last in _STARTING_STATES:
            return "starting"
        return "unknown"


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------

def _load_blobs(raw: str | None) -> dict[str, str]:
    if not raw:
        return {}
    try:
        data = json.loads(raw)
    except ValueError:
        return {}
    if not isinstance(data, dict):
        return {}
    return {k: v for k, v in data.items() if isinstance(k, str) and isinstance(v, str)}


def _slug(image: str, resource_prefix: str = "warren") -> str:
    """Convert an image string to a safe Fargate task definition family name.

    Replaces non-alphanumeric characters with hyphens, strips leading/trailing
    hyphens, and truncates so the final "{resource_prefix}-{slug}" fits within
    64 chars (the ECS family-name limit). `resource_prefix` must thread
    through here (not just into tags/log groups/SSM paths) so a deployment
    can scope `ecs:RunTask`/`ecs:RegisterTaskDefinition` IAM to its own
    `task-definition/<prefix>-*` families — with the default prefix "warren"
    this produces the same "warren-<slug>" families as before.
    """
    # Strip registry prefix: "public.ecr.aws/org/image:tag" → "org/image:tag"
    # Keep only the path/name portion — drop registry host.
    parts = image.split("/", 1)
    if len(parts) > 1 and ("." in parts[0] or ":" in parts[0]):
        image = parts[1]

    slug = re.sub(r"[^a-zA-Z0-9]+", "-", image)
    slug = slug.strip("-")
    # Fargate family names: practical limit ~255 chars, but keep the whole
    # "{resource_prefix}-{slug}" result ≤ 64.
    max_slug = 64 - len(resource_prefix) - 1
    if len(slug) > max_slug:
        slug = slug[:max_slug].strip("-")
    if not slug:
        raise ProvisionError(f"image {image!r} produces an empty task definition family name")
    return f"{resource_prefix}-{slug}"


_ = ContainerRuntime  # keep import for Protocol conformance reference
