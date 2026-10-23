"""ECSRuntime — AWS Fargate-backed ContainerRuntime (RT-07).

Full implementation per Plan 07-02. Follows DockerRuntime file-layout
pattern: same module docstring format, same import block, same class layout.

Security invariants (see 07-RESEARCH.md threat model):
    - Secrets are declared in the task definition's `secrets` block as SSM
      ARN references, resolved by the ECS agent at container start — never
      as plaintext `run_task` environment overrides (T-07-01, D-07). (Audit
      #61: this docstring previously described the opposite — the plaintext
      containerOverrides approach was the pre-fix design; the registered
      task definition's `secrets` block, built in `_register_and_run`, is
      what's actually used today.)
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
        launch_store: Any = None,
    ) -> None:
        self.server_id = server_id
        # AI3: get/put/delete of the per-workspace launch identity; app.py wires the
        # SQLite-backed LaunchAttemptStore so it survives a server restart.
        self.launch_store: Any = launch_store or _MemoryLaunchStore()
        self._settings = settings
        # Allow direct cpu/memory kwargs to override settings (used in tests
        # and when calling without a full WarrenSettings object).
        self._default_cpu = ecs_cpu or (getattr(settings, "ecs_cpu", None) or "256")
        self._default_memory = ecs_memory or (getattr(settings, "ecs_memory", None) or "512")
        # Resource naming/path prefix (issue #2) — SSM paths, log group names, and
        # tag keys all derive from this instead of a hardcoded "warren" literal.
        self._resource_prefix = getattr(settings, "ecs_resource_prefix", None) or "warren"
        self._ecs: Any = None
        self._ssm: Any = None
        self._sts: Any = None
        self._logs: Any = None
        self._log_retention_days = getattr(settings, "ecs_log_retention_days", None) or 90
        self._ensured_log_groups: set[str] = set()
        self._account_id: str | None = None
        self._preflight_ok = False
        self._task_def_cache: dict[str, str] = {}  # canonical task-definition JSON → task_def_arn
        self._volume: WorkspaceVolume | None = volume

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

    def _ensure_clients(self) -> tuple[Any, Any]:
        """Lazily initialise boto3 ECS and SSM clients (deferred import).

        Passes region_name explicitly so WARREN_AWS_REGION controls the boto3
        endpoint — not just the CloudWatch log group config string (WR-02).
        """
        if self._ecs is None:
            import boto3  # deferred — keeps module import cheap

            region = getattr(self._settings, "aws_region", "us-east-1") or "us-east-1"
            session = boto3.Session(region_name=region)
            self._ecs = session.client("ecs")
            self._ssm = session.client("ssm")
            self._sts = session.client("sts")
            self._logs = session.client("logs")
        return self._ecs, self._ssm

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

    def ssm_client(self) -> Any:
        """Return the lazily-constructed boto3 SSM client.

        Public accessor for routes/secrets.py's write path (PutParameter/
        DeleteParameter) so it reuses this runtime's one boto3 session/client
        instead of opening a second — same client this class's own read path
        (`_fetch_ssm_parameter_names`) already uses.
        """
        _, ssm = self._ensure_clients()
        return ssm

    async def _ensure_account_id(self) -> str:
        """Lazily resolve and cache the AWS account ID (needed to build SSM parameter ARNs)."""
        if self._account_id is None:
            self._ensure_clients()
            identity = await asyncio.to_thread(self._sts.get_caller_identity)
            self._account_id = identity["Account"]
        return self._account_id

    async def preflight(self) -> None:
        """Verify ECS cluster is reachable; raise RuntimeUnreachable on failure."""
        ecs, _ = self._ensure_clients()
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
        self._preflight_ok = True

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
        # Preflight guard — same pattern as DockerRuntime.
        if not self._preflight_ok:
            await self.preflight()

        # Resolve cpu/memory per D-02: spec-level overrides take precedence.
        resolved_cpu = getattr(spec, "ecs_cpu", None) or self._default_cpu
        resolved_memory = getattr(spec, "ecs_memory", None) or self._default_memory

        # Validate before any AWS call (T-07-02).
        self._validate_cpu_memory(resolved_cpu, resolved_memory)

        ecs, ssm = self._ensure_clients()

        # Fetch SSM parameter NAMES (not decrypted values — fixes: secrets exposed through
        # RunTask container overrides, T-07-01/D-07 was violated by the old plaintext-value
        # approach) — scoped to this workspace's OWNER only
        # (/{resource_prefix}/{server_id}/{owner_id}/), never another user's secrets —
        # mirrors warren.secrets.store's per-owner isolation (routes/secrets.py).
        ssm_path = f"/{self._resource_prefix}/{self.server_id}/{getattr(spec, 'owner_id', '')}/"
        all_param_names = await asyncio.to_thread(_fetch_ssm_parameter_names, ssm, ssm_path)

        # Filter by name: spec.secret_names is the resolved template's declared
        # `secrets` list (ProjectConfig.secrets) -- an explicit allow-list, not a
        # permission tier (tiers removed 2026-10-13; see store.py's docstring).
        filtered_param_names = _filter_secrets_by_name(
            all_param_names, getattr(spec, "secret_names", [])
        )

        region = getattr(self._settings, "aws_region", "us-east-1") or "us-east-1"
        account_id = await self._ensure_account_id()
        # ECS `secrets` entries — resolved to plaintext by the ECS agent itself at container
        # start (via the task execution role's ssm:GetParameters), never appearing in
        # RunTask's request/response, DescribeTasks, or CloudTrail as plaintext.
        secret_defs = [
            {
                "name": key,
                "valueFrom": f"arn:aws:ssm:{region}:{account_id}:parameter{full_name}",
            }
            for key, full_name in filtered_param_names.items()
        ]

        family = _slug(spec.image, self._resource_prefix)
        git_plan = build_git_init_plan(spec, secret_defs)

        # D-10: EFS is opt-in — only activate when a volume is wired in
        access_point_id: str | None = None
        if self._volume is not None:
            await self._volume.attach(spec.workspace_id, owner_id=getattr(spec, "owner_id", "") or None)
            access_point_id = getattr(self._volume, "last_access_point_id", None)

        # Issue #30b: everything below can fail (RegisterTaskDefinition,
        # RunTask) after attach() above already created the access point. On
        # any such failure, detach it (tags warren.expires_at so the reaper
        # eventually cleans it up) rather than leaking it forever with no
        # expiry — then re-raise so the caller still sees the original error.
        try:
            return await self._register_and_run(
                spec, access_point_id, resolved_cpu, resolved_memory, family, secret_defs, git_plan,
            )
        except Exception:
            if self._volume is not None:
                try:
                    await self._volume.detach(spec.workspace_id)
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
        secret_defs: list[dict[str, str]],
        git_plan: GitInitPlan | None = None,
    ) -> WorkspaceHandle:
        ecs, _ = self._ensure_clients()
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
                    # NO environment here — non-secret spec.env goes via run_task
                    # overrides below; secrets are declared here as `secrets`
                    # entries (SSM ARN references, resolved by the ECS agent at
                    # container start) — never as plaintext overrides (D-07, T-07-01).
                    "secrets": (
                        git_plan.workspace_secret_defs if git_plan is not None else secret_defs
                    ),
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
        if access_point_id:
            efs_id_val = getattr(self._settings, "efs_id", "") or ""
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
            if not access_point_id:
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
                    "secrets": git_plan.init_secret_defs,
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
        # here (issue #4): they're declared on the task definition's `secrets` field
        # above (ARN references, resolved by the ECS agent itself at container start),
        # never as plaintext RunTask.containerOverrides.environment values.
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
        # definition is reused only when it is identical -- secrets carry owner-specific
        # SSM valueFrom ARNs (and the git-init container's clone credentials), so two
        # owners with the same secret names never share one. EFS definitions are never
        # cached: each has its own access point.
        cache_key = json.dumps(register_kwargs, sort_keys=True)

        # AI3: a retry of the same provision generation (e.g. after a lost RunTask
        # response) reuses the persisted task definition + clientToken, and adopts a
        # task that launch already started rather than starting a second one. The
        # fingerprint covers the whole multi-container launch payload: the canonical task
        # definition (both containers, their secrets, volumes, access point) and the
        # RunTask container overrides (incl. git-init's WARREN_GIT_FOLDERS). Any change
        # to what would be launched gets a fresh identity rather than a stale token.
        generation = getattr(spec, "provision_generation", "") or ""
        fingerprint = hashlib.sha256(
            json.dumps(
                {
                    "task_definition": register_kwargs,
                    "container_overrides": container_overrides,
                    "access_point_id": access_point_id,
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
            await self.launch_store.put(spec.workspace_id, attempt)

        # Launch Fargate task.
        cluster = getattr(self._settings, "ecs_cluster", "") or ""
        subnet_ids = list(getattr(self._settings, "ecs_subnet_ids", None) or [])
        sg_ids = list(getattr(self._settings, "ecs_security_group_ids", None) or [])
        assign_public_ip = (
            "ENABLED"
            if getattr(self._settings, "ecs_assign_public_ip", False)
            else "DISABLED"
        )

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
            overrides={"containerOverrides": container_overrides},
            enableExecuteCommand=True,
            tags=self._task_tags(spec),
            startedBy=self.started_by,
            clientToken=attempt["client_token"],
        )

        # A definitive failure launched nothing, so the next try gets a fresh identity.
        failures = run_resp.get("failures", [])
        if failures:
            await self.launch_store.delete(spec.workspace_id)
            reason = failures[0].get("reason", "unknown")
            raise ProvisionError(f"ECS run_task failed: {reason}")

        tasks = run_resp.get("tasks", [])
        if not tasks:
            await self.launch_store.delete(spec.workspace_id)
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
        ecs, _ = self._ensure_clients()
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
        ecs, _ = self._ensure_clients()
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

    async def destroy(self, handle: WorkspaceHandle) -> None:
        """Stop Fargate task; idempotent (already stopped is acceptable)."""
        # Issue #30c: an EFS-backed workspace's task definition is never
        # shared (provision() forces a fresh registration per workspace,
        # since each access point ARN is unique), so its revision would
        # otherwise accumulate forever. Resolve it from the still-running
        # task before stopping it, then deregister after cleanup below.
        task_def_arn: str | None = None
        if self._volume is not None and handle.runtime_id:
            try:
                ecs, _ = self._ensure_clients()
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

        # D-04: detach sets warren.expires_at tag; does NOT delete the access point
        if self._volume is not None:
            try:
                await self._volume.detach(handle.workspace_id)
            except Exception:
                log.warning("efs_detach_failed", workspace_id=handle.workspace_id)

        if task_def_arn and task_def_arn not in self._task_def_cache.values():
            try:
                ecs, _ = self._ensure_clients()
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
        ecs, _ = self._ensure_clients()
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
        ecs, _ = self._ensure_clients()
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
        ecs, _ = self._ensure_clients()
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

def _fetch_ssm_parameter_names(ssm: Any, path: str) -> dict[str, str]:
    """Fetch the NAMES (not values) of every SSM parameter under ``path`` (synchronous).

    Deliberately does NOT decrypt/return parameter values (fixes: secrets exposed
    through RunTask container overrides — decrypted plaintext ending up in
    DescribeTasks/CloudTrail). Values are resolved by the ECS agent itself at
    container start, via the task definition's `secrets` block referencing each
    parameter's ARN — this function only needs enough to build those ARNs.

    Must be called inside asyncio.to_thread — SSM client is synchronous.
    Handles pagination via NextToken loop (RESEARCH.md Pattern 4).

    Returns: {stripped_key: full_parameter_name} — full_parameter_name is the
    original "/warren/{server_id}/{tier}/{name}" path, needed to build the ARN.
    """
    params: dict[str, str] = {}
    kwargs: dict[str, Any] = {
        "Path": path,
        "Recursive": True,
        # False: we only need parameter Names to build ARNs — never decrypt values here
        # (fixes issue #4: no plaintext secret should ever pass through this process).
        "WithDecryption": False,
        "MaxResults": 10,
    }
    while True:
        resp = ssm.get_parameters_by_path(**kwargs)
        for p in resp.get("Parameters", []):
            full_name = p["Name"]
            stripped = full_name
            if stripped.startswith(path):
                stripped = stripped[len(path):]
            stripped = stripped.lstrip("/")
            params[stripped] = full_name
        next_token = resp.get("NextToken")
        if not next_token:
            break
        kwargs["NextToken"] = next_token
    return params


def _filter_secrets_by_name(
    secrets: dict[str, str], allowed_names: list[str]
) -> dict[str, str]:
    """Filter the owner's SSM secrets dict down to exactly `allowed_names`.

    Path convention: /{resource_prefix}/{server_id}/{owner_id}/{name} -- no
    permission-tier segment (removed 2026-10-13), so keys here are already
    plain leaf names; this is a simple by-name allow-list, not a tier filter.
    `allowed_names` is the resolved template's declared `secrets` list, so a
    template that declares no secrets gets none, not "everything owner has."
    """
    allowed = set(allowed_names)
    return {name: value for name, value in secrets.items() if name in allowed}


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
