"""Workspace lifecycle HTTP endpoints — WS-01..WS-04."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import uuid
import weakref
from collections.abc import AsyncIterator
from typing import Literal, NoReturn

import structlog
from fastapi import APIRouter, HTTPException, Query, Request, Response
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field, model_validator
from warren.audit import audit_event
from warren.auth.deps import (
    current_user,
    current_workspace_scope,
    require_workspace_access,
    resolve_owner_id,
)
from warren.images.build_spec import BuildPathError, resolve_build_spec
from warren.images.resolve import template_image
from warren.ratelimit import SlidingWindowRateLimiter
from warren.registry.models import OperationReceipt, ProvisionedWorkspaceView, WorkspaceView
from warren.registry.store import CapacityExhausted
from warren.registry.registry import (
    ROOT_REPO,
    BranchSource,
    WorkspaceDestroyedError,
    _server_sanctioned_docker_networks,
    _server_sanctioned_local_paths,
    serialize_spec_extra,
)
from warren_common.errors import ProvisionError, TemplateNotFoundError
from warren_common.models import check_aws_mode
from warren_common.agent_launch import template_launch_spec
from warren_common.harness import BEDROCK_ENV, HarnessSelectionError, bedrock_mode, selected_harnesses
from warren_common.templates import resolve_template
from warren_common.turn_refs import TURN_NAMESPACE, TurnRefError, TurnRefNotFound

log = structlog.get_logger(__name__)

router = APIRouter()

# Audit #46: nothing throttled repeated POST /workspaces -- a loop hammering this route
# can exhaust max_workspaces/max_workspaces_per_user's capacity check-then-insert race
# far faster than any legitimate caller would ever provision workspaces. Per-user, not
# per-IP, since every caller here is already authenticated.
GATEWAY_TOKEN_SECRET = "ANTHROPIC_AUTH_TOKEN"

_CREATE_WORKSPACE_MAX = 10
_CREATE_WORKSPACE_WINDOW_SECONDS = 60.0
_create_workspace_limiter = SlidingWindowRateLimiter(
    max_events=_CREATE_WORKSPACE_MAX, window_seconds=_CREATE_WORKSPACE_WINDOW_SECONDS
)

# Map ProvisionError.reason → HTTP status code
_PROVISION_ERROR_STATUS: dict[str, int] = {
    "image_unavailable": 422,
    "runtime_unreachable": 503,
    "capacity_exhausted": 503,
    "template_denied": 422,
    "secret_missing": 422,
    # LIFE-04, D-09: a project-declared Containerfile failed to build.
    "containerfile_build_failed": 422,
    # LIFE-03, D-07: server-side git clone/pull failures.
    "git_clone_failed": 502,
    "git_pull_failed": 502,
    # BB4: task still in PROVISIONING/PENDING/ACTIVATING after the wait.
    "workspace_starting": 503,
}


def _provision_http_error(exc: ProvisionError) -> HTTPException:
    """Map a ProvisionError to an HTTPException.

    BB4: "workspace_starting" carries Retry-After; clients should re-POST
    connect/ensure_running after it (the server-side wait is bounded by
    ecs_start_wait_timeout_seconds, below client request timeouts).
    """
    retry_after = getattr(exc, "retry_after_seconds", None)
    return HTTPException(
        status_code=_PROVISION_ERROR_STATUS.get(exc.reason, 500),
        detail={"error": exc.reason, "detail": str(exc)},
        headers={"Retry-After": str(retry_after)} if retry_after is not None else None,
    )


_OPERATION_ID_PATTERN = r"^[A-Za-z0-9._:-]{1,64}$"


class ProvisionRequest(BaseModel):
    project: str
    template: str
    # AH2: single-turn workspaces emit workspace.completed and are destroyed when the app exits.
    mode: Literal["interactive", "single-turn"] = "interactive"
    # AM2: a retry with the same operationId (per caller) returns the original workspace.
    operation_id: str | None = Field(default=None, pattern=_OPERATION_ID_PATTERN)

    @model_validator(mode="before")
    @classmethod
    def _accept_camel_operation_id(cls, data):
        if isinstance(data, dict) and "operationId" in data and "operation_id" not in data:
            data = {**data, "operation_id": data["operationId"]}
            del data["operationId"]
        return data


# Same allow-list as routes/projects.py's _SAFE_NAME_RE — issue #9's path-traversal
# guard on the project name used to build a filesystem path.
_SAFE_PROJECT_NAME_RE = re.compile(r"^[a-z0-9_-]+$")

# Only reached when there's no `settings` at all (e.g. a test harness that never
# wired up project config) -- NOT a per-field fallback. `docker_image` and
# `ecs_image` each carry their own concrete default on ProjectConfig (the
# Docker/Podman warren-base and the Alpine-based warren-ecs-base respectively)
# and are resolved independently, with no fallback between them: a template
# overriding one (e.g. to a local registry mirror) must never leak into the
# other runtime, which may not even be able to reach it.
_DEFAULT_IMAGE = "ghcr.io/scottcowan/warren-docker-base:latest"


# D-08: the login user routed by the workspace image's sshd `ForceCommand` (default path)
# vs. the deliberately distinct break-glass shell login. Source of truth is the reference
# image's sshd_config (images/workspace-base/sshd_config), not this file — warren-server
# code never names the protocol that rides the default path. That boundary is
# machine-enforced by a dedicated static scan test under tests/unit/.
_SSH_LOGIN_USER = "warren"
_SSH_BREAK_GLASS_USER = "warren-shell"


class ConnectionInfo(BaseModel):
    """Connect-time credential contract for `warren connect` (ACCESS-02/ACCESS-03).

    `private_key` is returned exactly once over this authenticated HTTPS response,
    is never persisted server-side (no DB column, file, or cache), and must never
    be logged, echoed, or truncated anywhere.
    """

    host: str
    port: int
    user: str
    break_glass_user: str
    private_key: str
    session_id: str | None = None


@router.post("/workspaces", status_code=202, response_model=ProvisionedWorkspaceView)
async def create_workspace(body: ProvisionRequest, request: Request) -> ProvisionedWorkspaceView:
    """Provision a new workspace (async — returns 202 + provisioning record).

    AM2: with an operationId, a retry returns the original workspace and its receipt
    instead of launching again; the same id with a different body is a 409.
    """
    if body.operation_id is None:
        view = await _provision_workspace(body, request)
        return ProvisionedWorkspaceView(**view.model_dump())
    user = current_user(request)
    key = (_operation_principal(request, user.user_id), body.operation_id)
    lock = _operation_locks.get(key)
    if lock is None:
        lock = _operation_locks[key] = asyncio.Lock()
    async with lock:
        return await _provision_operation(body, request, key)


# AM2: serializes concurrent requests for one operation within this process; the
# operations table's primary key is the durable guard.
_operation_locks: "weakref.WeakValueDictionary[tuple[str, str], asyncio.Lock]" = weakref.WeakValueDictionary()
_OPERATION_KIND = "provision"


def _operation_principal(request: Request, user_id: str) -> str:
    scope = current_workspace_scope(request)
    return user_id if scope is None else f"{user_id}:workspace:{scope}"


def _operation_hash(body: ProvisionRequest) -> str:
    payload = json.dumps(body.model_dump(exclude={"operation_id"}), sort_keys=True)
    return hashlib.sha256(payload.encode()).hexdigest()


async def _provision_operation(
    body: ProvisionRequest, request: Request, key: tuple[str, str]
) -> ProvisionedWorkspaceView:
    operations = request.app.state.operation_store
    store = request.app.state.registry.store
    principal, operation_id = key
    request_hash = _operation_hash(body)
    row = await operations.get(principal, operation_id)
    resume_id: str | None = None
    if row is not None:
        if (row["kind"], row["request_hash"]) != (_OPERATION_KIND, request_hash):
            raise HTTPException(
                status_code=409,
                detail={
                    "error": "operation_conflict",
                    "detail": f"operationId {operation_id!r} was already used with a different request",
                },
            )
        ws = await store.get(row["workspace_id"])
        if ws is None or (
            row["stage"] != "failed" and not ws.container_id
        ):
            # No runtime id means nothing was launched, whatever the status says (e.g.
            # the server restarted mid-provision and reconcile marked it stopped): launch it now.
            resume_id = row["workspace_id"]
        else:
            if row["stage"] == "accepted":
                await operations.set_stage(principal, operation_id, "failed" if ws.status == "failed" else "started")
                row = await operations.get(principal, operation_id)
            audit_event(
                "workspace.provision",
                request=request,
                outcome="replayed",
                owner_id=ws.owner_id,
                workspace_id=ws.workspace_id,
                operation_id=operation_id,
            )
            return ProvisionedWorkspaceView(
                **WorkspaceView.from_workspace(ws).model_dump(), operation=OperationReceipt.from_row(row)
            )

    view = await _provision_workspace(body, request, operation=(principal, request_hash), resume_id=resume_id)
    ws = await store.get(view.workspace_id)
    stage = "started" if ws is not None and ws.status == "running" else "failed"
    await operations.set_stage(principal, operation_id, stage)
    row = await operations.get(principal, operation_id)
    if ws is not None:
        view = WorkspaceView.from_workspace(ws)
    return ProvisionedWorkspaceView(**view.model_dump(), operation=OperationReceipt.from_row(row))


@router.get("/operations/{operation_id}", response_model=OperationReceipt)
async def get_operation(operation_id: str, request: Request) -> OperationReceipt:
    """AM2: read the caller's receipt for a launch operation."""
    if not re.match(_OPERATION_ID_PATTERN, operation_id):
        raise HTTPException(status_code=422, detail="invalid operation id")
    user = current_user(request)
    row = await request.app.state.operation_store.get(_operation_principal(request, user.user_id), operation_id)
    if row is None:
        raise HTTPException(status_code=404, detail="operation not found")
    return OperationReceipt.from_row(row)


async def _provision_workspace(
    body: ProvisionRequest,
    request: Request,
    *,
    branch_from: BranchSource | None = None,
    operation: tuple[str, str] | None = None,
    resume_id: str | None = None,
) -> WorkspaceView:
    """`operation` is (principal, request_hash) to record body.operation_id as accepted
    before provisioning; `resume_id` re-drives that operation's recorded workspace."""
    from warren_common.runtime.base import WorkspaceSpec

    # D-11: 401 comes from AuthMiddleware first; current_user() is a second explicit gate
    # that also gives us the identity to stamp as this workspace's owner.
    user = current_user(request)

    if resume_id is None and not _create_workspace_limiter.allow(user.user_id):
        raise HTTPException(
            status_code=429,
            detail={
                "error": "rate_limited",
                "detail": (
                    f"at most {_CREATE_WORKSPACE_MAX} workspace creations per "
                    f"{_CREATE_WORKSPACE_WINDOW_SECONDS:.0f}s per user"
                ),
            },
        )

    registry = request.app.state.registry
    settings = request.app.state.settings

    # Issue #9/#11: server-wide and per-owner caps on non-terminal rows (provisioning/
    # running/stopping/unknown). This early check only fails fast before image
    # resolution/builds; the cap itself is enforced atomically by the insert below.
    if settings is not None and resume_id is None:
        active = await registry.store.list_non_terminal()
        if len(active) >= settings.max_workspaces:
            _raise_capacity_exhausted(CapacityExhausted("server", settings.max_workspaces))
        owned_active = [w for w in active if w.owner_id == user.user_id]
        if len(owned_active) >= settings.max_workspaces_per_user:
            _raise_capacity_exhausted(CapacityExhausted("owner", settings.max_workspaces_per_user))

    workspace_id = resume_id or str(uuid.uuid4())
    scoped_to = current_workspace_scope(request) if resume_id is None else None
    if scoped_to is not None:
        # AI8/AJ2: only a reservation token, once, and only for its own workspace id.
        ws_token = getattr(request.state, "workspace_token", None)
        if ws_token is None or not ws_token.provision_grant or await registry.store.get(scoped_to) is not None:
            _deny_scoped_provision(request, scoped_to)
        workspace_id = scoped_to

    # Resolve image from settings/project config if available, else use placeholder
    image = await _resolve_image(body, request)
    template_cfg = await _resolve_template_cfg(body, request)
    secret_names = [ref.name for ref in template_cfg.secrets] if template_cfg is not None else []
    if template_cfg is not None:
        from warren_common.git_crypt import GitCryptError, check_key_not_delivered

        try:
            check_key_not_delivered(secret_names, template_cfg.git_crypt_key_secret)
        except GitCryptError as exc:
            raise HTTPException(
                status_code=422, detail={"error": "template_denied", "detail": str(exc)}
            ) from exc
    folders = template_cfg.effective_folders() if template_cfg is not None else []
    if settings is not None:
        folders = _server_sanctioned_local_paths(folders, body.project, settings)
    app_cmd = template_cfg.app if template_cfg is not None else "bash"
    harnesses = (
        sorted(selected_harnesses(app_cmd, template_cfg.harnesses)) if template_cfg is not None else []
    )
    try:
        agent_spec = template_launch_spec(template_cfg)
    except HarnessSelectionError as exc:
        raise HTTPException(
            status_code=422, detail={"error": "invalid_template", "detail": str(exc)}
        ) from exc
    if agent_spec is not None:
        harnesses = sorted({*harnesses, agent_spec["harness"]})
        if body.mode == "single-turn":
            raise HTTPException(
                status_code=422,
                detail={
                    "error": "single_turn_not_for_agents",
                    "detail": "kind: agent workspaces are supervised and long-lived; single-turn runs use `app`",
                },
            )
    if body.mode == "single-turn" and (not app_cmd or app_cmd == "bash"):
        raise HTTPException(
            status_code=422,
            detail={
                "error": "single_turn_requires_app",
                "detail": "mode single-turn needs a template whose `app` runs to completion, not bash",
            },
        )
    template_env = dict(template_cfg.env) if template_cfg is not None else {}
    # Bedrock: models via the workspace's task role / AWS identity, never a Claude login.
    model_access = (
        "bedrock" if template_cfg is not None and bedrock_mode(template_cfg.model_access, template_env) else ""
    )
    if model_access:
        template_env.update(BEDROCK_ENV)
        gateway = getattr(settings, "bedrock_gateway_url", "") if settings is not None else ""
        if gateway:
            if GATEWAY_TOKEN_SECRET not in secret_names:
                raise HTTPException(
                    status_code=422,
                    detail={
                        "error": "template_denied",
                        "detail": f"this server routes Bedrock through a gateway; the template must "
                        f"declare the {GATEWAY_TOKEN_SECRET} secret holding your gateway key",
                    },
                )
            template_env.setdefault("ANTHROPIC_BEDROCK_BASE_URL", gateway)
            template_env.setdefault("CLAUDE_CODE_SKIP_BEDROCK_AUTH", "1")
    idle_ttl_seconds = template_cfg.idle_ttl_seconds if template_cfg is not None else None
    idle_destroy_seconds = template_cfg.idle_destroy_seconds if template_cfg is not None else None
    # Issue #23: these were silently dropped on the floor -- every workspace got
    # whatever default ecs_cpu/ecs_memory is on `settings` (runtime/ecs.py's own
    # fallback) and no docker_networks attachment, regardless of what the
    # resolved template declared.
    ecs_cpu = template_cfg.ecs_cpu if template_cfg is not None else None
    ecs_memory = template_cfg.ecs_memory if template_cfg is not None else None
    docker_networks = template_cfg.docker_networks if template_cfg is not None else []
    if settings is not None:
        docker_networks = _server_sanctioned_docker_networks(docker_networks, body.project, settings)

    # Audit R11: ssh/aws/scope were silently dropped on the floor here -- never
    # threaded onto WorkspaceSpec at all, so a template declaring e.g. `ssh.keys`
    # provisioned a workspace with no sign any of these fields were ever resolved.
    # ssh_key_paths/ssh_agent_sock mirror warren-cli's own local-sandbox resolution
    # (dispatch.py's create flow) -- explicit opt-in only, no keys/agent unless the
    # template actually declares an `ssh` block. aws/scope have no runtime consumer
    # yet (see WorkspaceSpec's own comment), so they're carried through unflattened.
    ssh_cfg = template_cfg.ssh if template_cfg is not None else None
    ssh_key_paths = list(ssh_cfg.keys) if ssh_cfg is not None else []
    ssh_agent_sock = None
    if ssh_cfg is not None and ssh_cfg.agent:
        ssh_agent_sock = os.environ.get("SSH_AUTH_SOCK") or None
    aws_cfg = template_cfg.aws if template_cfg is not None else None
    # AK3: server runtimes are never local sandboxes, so `aws.mode: sso` (the
    # host's SSO token cache) is always rejected here.
    try:
        check_aws_mode(aws_cfg, f"server ({getattr(settings, 'runtime_type', 'podman')})")
    except ValueError as exc:
        raise HTTPException(
            status_code=422, detail={"error": "invalid_template", "detail": str(exc)}
        ) from exc
    scope_cfg = template_cfg.scope if template_cfg is not None else None

    # warren.secrets: resolve_owner_id is warren's bearer-token user_id on
    # podman/docker, or the caller's verified AWS IAM identity on ECS
    # (warren.auth.deps.resolve_owner_id) -- NOT necessarily the same as
    # `user.user_id` above, which keeps stamping the WORKSPACE RECORD's
    # owner_id (D-11, unaffected by this). Only secret ownership moves to the
    # AWS identity on ECS, so it lines up with who can actually
    # ecs:ExecuteCommand/SSM-tunnel into the resulting task.
    secret_owner_id = await resolve_owner_id(request)

    # For podman/docker, decrypt and inject this workspace OWNER's (never
    # another user's — isolation is per-owner, routes/secrets.py) visible
    # secret tier directly into spec.env. ECS does NOT go through this path --
    # its secrets are resolved by the ECS agent itself from the SSM mirror at
    # container start (runtime/ecs.py reads the same owner_id-scoped path), so
    # a decrypted value never needs to pass through this process for that
    # runtime (routes/secrets.py's module docstring has the full reasoning for
    # why SSM is a write-time mirror rather than a provision-time sync).
    secret_env: dict[str, str] = {}
    if settings is not None and getattr(settings, "runtime_type", "podman") != "ecs":
        from warren.secrets import store as local_store
        from warren.secrets.cipher import LocalCipher

        db = request.app.state.db
        cipher = LocalCipher(settings.secret_key.get_secret_value())
        secret_env = await local_store.resolve_secrets_for_names(db, cipher, secret_owner_id, secret_names)

    spec = WorkspaceSpec(
        workspace_id=workspace_id,
        project=body.project,
        intent=body.template,
        image=image,
        root_path="",
        env=secret_env,
        template_env=template_env,
        seed_prompt=template_cfg.seed_prompt if template_cfg is not None else None,
        secret_names=secret_names,
        owner_id=secret_owner_id,
        folders=folders,
        app=app_cmd,
        harnesses=harnesses,
        model_access=model_access,
        idle_ttl_seconds=idle_ttl_seconds,
        idle_destroy_seconds=idle_destroy_seconds,
        ecs_cpu=ecs_cpu,
        ecs_memory=ecs_memory,
        docker_networks=docker_networks,
        ssh_key_paths=ssh_key_paths,
        ssh_agent_sock=ssh_agent_sock,
        aws=aws_cfg,
        scope=scope_cfg,
        mode=body.mode,
        operation_id=body.operation_id or "",
        agent=agent_spec,
    )

    # Insert row with status=provisioning. D-11: owner_id is set to the creating user so
    # the connect endpoint has an authorization subject to check. The pre-existing lack of
    # ownership checks on list/status/stop/destroy is explicitly out of this phase's scope
    # and must NOT be retrofitted here.
    #
    # Finding 7: spec_json snapshots the fields a bare row can't carry (env/
    # secrets, folders, app, ...) so ensure_running() can reprovision a
    # reaped-and-gone container faithfully instead of as an empty shell.
    if scoped_to is not None and not await request.app.state.auth_store.consume_provision_grant(
        ws_token.token_id
    ):
        _deny_scoped_provision(request, scoped_to)
    created_operation = False
    if operation is not None and resume_id is None:
        principal, request_hash = operation
        if not await request.app.state.operation_store.create(
            principal=principal,
            operation_id=body.operation_id,
            kind=_OPERATION_KIND,
            request_hash=request_hash,
            workspace_id=workspace_id,
        ):
            raise HTTPException(status_code=409, detail={"error": "operation_in_progress"})
        created_operation = True
    if resume_id is None or await registry.store.get(workspace_id) is None:
        try:
            await registry.store.insert(
                workspace_id=workspace_id,
                project=body.project,
                intent=body.template,
                image=image,
                root_path="",
                server_instance=registry.server_id,
                status="provisioning",
                owner_id=user.user_id,
                idle_ttl_seconds=idle_ttl_seconds,
                spec_json=serialize_spec_extra(spec),
                max_total=settings.max_workspaces if settings is not None else None,
                max_per_owner=settings.max_workspaces_per_user if settings is not None else None,
            )
        except CapacityExhausted as exc:
            if created_operation:
                await request.app.state.operation_store.delete(operation[0], body.operation_id)
            _raise_capacity_exhausted(exc)
    else:
        await registry.store.update_status(workspace_id, "provisioning")

    # Fetch inserted row to return in response
    ws = await registry.store.get(workspace_id)

    # Run provisioning inline to propagate ProvisionError to caller
    try:
        if branch_from is None:
            await registry._do_provision(workspace_id, spec)
        else:
            await registry._do_provision(workspace_id, spec, branch_from=branch_from)
    except ProvisionError as exc:
        audit_event(
            "workspace.provision",
            request=request,
            outcome="failure",
            owner_id=user.user_id,
            workspace_id=workspace_id,
            project=body.project,
            template=body.template,
            reason=exc.reason,
        )
        status_code = _PROVISION_ERROR_STATUS.get(exc.reason, 500)
        raise HTTPException(
            status_code=status_code,
            detail={"error": exc.reason, "detail": str(exc)},
        )

    audit_event(
        "workspace.provision",
        request=request,
        owner_id=user.user_id,
        workspace_id=workspace_id,
        project=body.project,
        template=body.template,
    )
    if secret_names:
        is_ecs = settings is not None and getattr(settings, "runtime_type", "podman") == "ecs"
        audit_event(
            "secret.deliver",
            request=request,
            owner_id=secret_owner_id,
            workspace_id=workspace_id,
            secret_names=list(secret_names) if is_ecs else sorted(secret_env),
            delivery="ecs_task_definition" if is_ecs else "workspace_env",
        )

    return WorkspaceView.from_workspace(ws)


def _raise_capacity_exhausted(exc: CapacityExhausted) -> NoReturn:
    if exc.scope == "server":
        detail = f"max_workspaces ({exc.limit}) reached"
    else:
        detail = f"max_workspaces_per_user ({exc.limit}) reached for this user"
    raise HTTPException(status_code=503, detail={"error": "capacity_exhausted", "detail": detail})


def _deny_scoped_provision(request: Request, workspace_id: str) -> None:
    audit_event("workspace.provision", request=request, outcome="denied", workspace_id=workspace_id)
    raise HTTPException(status_code=403, detail="workspace-scoped token cannot provision")


async def _resolve_template_cfg(body: ProvisionRequest, request: Request):
    """Return the resolved template (`secrets` by-name allow-list,
    `effective_folders()`, etc.), or `None` if it can't be resolved.

    Re-resolves the project/template rather than threading a value out of
    `_resolve_image` -- that function's return contract (a single image-string
    return value, patched directly in many existing tests) stays untouched.
    By the time this runs, `_resolve_image` has already validated the project
    and template exist, so a failure here is unexpected; callers fall back to
    the safe, under-granting default for whichever field they need (e.g. no
    declared secrets, an empty folder list) rather than raising a second time
    for an error `_resolve_image` already surfaced.
    """
    settings = getattr(request.app.state, "settings", None)
    if settings is None:
        return None
    try:
        from warren_common.loader import ProjectLoader

        user = current_user(request)
        project_cfg = ProjectLoader.load_effective(body.project, settings.projects_dir, user.user_id)
        return resolve_template(project_cfg, body.template)
    except Exception:
        # Audit #46: this used to swallow every exception silently and fall through to
        # the under-granting defaults documented on the docstring above (no secrets, no
        # folders, bash as the app command) -- a real misconfiguration here produced a
        # degraded-but-seemingly-fine workspace with no record of why. By the time this
        # runs, `_resolve_image` has ALREADY re-validated the same project/template and
        # would have raised 404/422 to the caller on any real failure here (project not
        # found, template denied, invalid YAML) -- so reaching this except branch in
        # practice means something unexpected slipped past that check. Fail loudly in the
        # logs rather than guessing whether under-granting silently is still safe for
        # every template shape; keep the degraded-provision behavior since a real caller
        # already got a clean 404/422 from _resolve_image for the ordinary failure modes.
        log.warning("template_cfg_resolve_failed", project=body.project, template=body.template, exc_info=True)
        return None


async def _resolve_image(body: ProvisionRequest, request: Request) -> str:
    """Resolve the container image for a workspace.

    Resolution order (LIFE-04, D-09):
      1. A project- or template-declared Containerfile, built server-side via
         `resolve_build_spec()` + `runtime.build_image()`, when
         `settings.image_build_enabled` is True AND the active runtime
         exposes the build capability (`hasattr(runtime,
         "supports_image_build")`, mirroring registry.py's
         `hasattr(self.runtime, "supports_ssh_access")` gate). A project
         that declares a Containerfile is NEVER silently downgraded to the
         default/tag-lookup image just because building is disabled --
         that would be exactly the trust violation D-09 exists to prevent
         -- so a disabled build raises 422 `image_build_disabled` instead
         of falling through to step 2. A runtime that lacks the build
         capability, however, is not an operator-facing error; it falls
         through to step 2's existing tag-lookup behavior.
      2. Otherwise, a per-runtime image field, each with its own independent
         default and no fallback between them (a `docker_image` override --
         e.g. a local registry mirror -- must never leak into an ECS node
         that can't reach it, and vice versa):
           - `settings.runtime_type == "ecs"`: the resolved template's
             `ecs_image` (defaults to the Alpine-based
             `ghcr.io/scottcowan/warren-ecs-base:latest`).
           - otherwise (podman/docker): the resolved template's
             `docker_image` (defaults to `ghcr.io/scottcowan/warren-docker-base:latest`).
         Both are independently overridable (inherited from the project
         root unless overridden at some level of the template path).
      3. Otherwise (no settings at all, e.g. in tests) the fixed default
         `_DEFAULT_IMAGE`.

    `warren-common`'s `ProjectLoader`/`ProjectConfig` do not yet surface a
    `containerfile` attribute (a separate repo) -- read it defensively with
    `getattr(..., "containerfile", None)` so this stays a no-op until that
    lands, rather than becoming a blocking dependency of this phase.

    If settings and project config are available, load the project YAML.
    Falls back to a default image when running in tests without project files.
    """
    settings = getattr(request.app.state, "settings", None)
    if settings is None:
        return _DEFAULT_IMAGE

    # D-09/issue #9: validate the project name BEFORE it ever reaches a filesystem
    # path — an unvalidated body.project let a caller point project_path outside
    # projects_dir via "../" segments. Same allow-list shape as routes/projects.py's
    # _SAFE_NAME_RE (path-traversal guard, not merely a style rule).
    if not _SAFE_PROJECT_NAME_RE.match(body.project):
        raise HTTPException(
            status_code=422,
            detail={"error": "invalid_project_name", "detail": "must match ^[a-z0-9_-]+$"},
        )

    try:
        from warren_common.errors import ProjectNotFoundError
        from warren_common.loader import ProjectLoader

        # load_effective merges the caller's own user-scoped override (if any)
        # onto the server-wide project (if any) of this name — both paths are
        # built from the validated `name` and the server-assigned user_id, so
        # there's no traversal surface beyond the regex guard above.
        user = current_user(request)
        project_cfg = ProjectLoader.load_effective(body.project, settings.projects_dir, user.user_id)

        # Validate and resolve the template path (dotted for a nested sub-template).
        try:
            template_cfg = resolve_template(project_cfg, body.template)
        except TemplateNotFoundError:
            raise HTTPException(
                status_code=422,
                detail={
                    "error": "template_denied",
                    "detail": f"template {body.template!r} not found in project",
                },
            )
        except HarnessSelectionError as exc:
            raise HTTPException(
                status_code=422, detail={"error": "invalid_template", "detail": str(exc)}
            ) from exc

        containerfile_rel = getattr(template_cfg, "containerfile", None) or getattr(
            project_cfg, "containerfile", None
        )
        if containerfile_rel:
            if not settings.image_build_enabled:
                raise HTTPException(
                    status_code=422,
                    detail={
                        "error": "image_build_disabled",
                        "detail": "project declares a Containerfile but "
                        "WARREN_IMAGE_BUILD_ENABLED is not set",
                    },
                )
            runtime = getattr(request.app.state, "runtime", None)
            if runtime is not None and hasattr(runtime, "supports_image_build"):
                try:
                    spec = resolve_build_spec(
                        body.project,
                        containerfile_rel,
                        settings.projects_dir,
                        settings,
                    )
                except BuildPathError as exc:
                    # Name the rejected relative path only -- never the
                    # resolved absolute host path, which would leak node2's
                    # filesystem layout to an API caller (T-04-04-ID).
                    raise HTTPException(
                        status_code=422,
                        detail={
                            "error": "containerfile_invalid",
                            "detail": f"invalid containerfile path "
                            f"{containerfile_rel!r}: {exc}",
                        },
                    ) from exc
                try:
                    return await runtime.build_image(spec)
                except ProvisionError as exc:
                    status_code = _PROVISION_ERROR_STATUS.get(exc.reason, 422)
                    raise HTTPException(
                        status_code=status_code,
                        detail={"error": exc.reason, "detail": str(exc)},
                    ) from exc
            # Runtime has no build capability -- fall through to tag lookup
            # rather than raising; this is a capability gap, not a project
            # misconfiguration.

        return template_image(template_cfg, body.project, body.template, settings)

    except HTTPException:
        raise
    except ProjectNotFoundError as exc:
        # Issue #9: a missing project must reject the request, not silently
        # substitute the default image — that fallback ran unconditionally
        # BEFORE template enforcement, so a nonexistent or misspelled project
        # name got a workspace provisioned anyway with none of whatever
        # permission tier a real project would have enforced.
        #
        # Audit #46: ProjectNotFoundError's own message embeds the absolute
        # host path it looked for (warren_common.loader.ProjectLoader.load) --
        # never echo it to the caller. Log the real exception server-side,
        # return only the (already-validated, caller-supplied) project name.
        log.warning("project_not_found", project=body.project, exc_info=True)
        raise HTTPException(
            status_code=404,
            detail={
                "error": "project_not_found",
                "detail": f"project {body.project!r} not found",
            },
        ) from exc
    except Exception as exc:
        # Any other project-load failure (malformed YAML, schema validation,
        # etc.) is a real misconfiguration — reject it rather than paper over
        # it with a default image (same reasoning as ProjectNotFoundError
        # above, same fail-closed direction).
        #
        # Audit #46: this is an unvalidated catch-all over third-party parsing
        # (PyYAML) and pydantic validation -- its exception text can embed
        # host paths or raw YAML content. Log the real exception server-side
        # instead of echoing it.
        log.warning("project_load_failed", project=body.project, exc_info=True)
        raise HTTPException(
            status_code=422,
            detail={
                "error": "project_invalid",
                "detail": f"project {body.project!r} configuration is invalid",
            },
        ) from exc


@router.get("/workspaces", response_model=list[WorkspaceView])
async def list_workspaces(request: Request) -> list[WorkspaceView]:
    """Return workspace rows owned by the caller (including stopped and failed).

    Owner-only, same strict posture as connect/git-pull below (D-11) — no admin
    bypass. `is_admin` today gates only `require_admin`'s separate
    user-management routes; it has never meant "sees every workspace," and
    connect/git-pull are already tested to deny even the bootstrap admin on a
    workspace they don't own. A real admin-visibility feature would be a
    deliberate, separately-designed capability, not a quiet exception here.
    """
    user = current_user(request)
    all_ws = await request.app.state.registry.store.list_all()
    return [WorkspaceView.from_workspace(ws) for ws in all_ws if ws.owner_id == user.user_id]


@router.get("/workspaces/{workspace_id}/status")
async def get_workspace_status(workspace_id: str, request: Request) -> dict:
    """Return the status field for an existing workspace, owner-only (D-11)."""
    user = current_user(request)
    ws = await request.app.state.registry.store.get(workspace_id)
    if ws is None:
        raise HTTPException(status_code=404, detail="workspace not found")
    if ws.owner_id is None or ws.owner_id != user.user_id:
        log.warning("status_denied", workspace_id=workspace_id, user_id=user.user_id)
        raise HTTPException(status_code=403, detail="not workspace owner")
    return {"status": ws.status}


@router.post("/workspaces/{workspace_id}/connect", response_model=ConnectionInfo)
async def connect_workspace(workspace_id: str, request: Request) -> ConnectionInfo:
    """Mint and return a workspace-scoped SSH credential to the workspace's owner (D-01/D-02).

    Reprovisions a stopped/destroyed workspace server-side before minting (D-04). Fails
    closed for anyone other than the owner (D-11), including legacy rows with no
    owner_id at all.
    """
    registry = request.app.state.registry
    settings = request.app.state.settings

    # 401 comes from AuthMiddleware or here — current_user() is the second explicit gate.
    user = current_user(request)

    ws = await registry.store.get(workspace_id)
    if ws is None:
        raise HTTPException(status_code=404, detail="workspace not found")

    # Ownership gate (D-11) — placed BEFORE issue_ssh_credential so a non-owner can never
    # cause a key to be minted at all. A NULL owner_id (legacy, pre-Phase-3 row) fails
    # closed on purpose — never treat an unowned workspace as public.
    if ws.owner_id is None or ws.owner_id != user.user_id:
        log.warning("connect_denied", workspace_id=workspace_id, user_id=user.user_id)
        audit_event("workspace.connect", request=request, outcome="denied", workspace_id=workspace_id)
        raise HTTPException(status_code=403, detail="not workspace owner")

    try:
        result = await registry.issue_ssh_credential(workspace_id)
    except WorkspaceDestroyedError:
        raise HTTPException(status_code=410, detail="workspace was destroyed")
    except ProvisionError as exc:
        raise _provision_http_error(exc)
    if result is None:
        raise HTTPException(status_code=404, detail="workspace not found")

    port, private_pem = result
    host = settings.ssh_advertised_host or settings.server_id

    # Identifiers only. Never log, echo, or truncate private_pem (mirrors
    # routes/admin.py::mint_token's raw_token discipline).
    log.info("connect_issued", workspace_id=workspace_id, user_id=user.user_id, ssh_port=port)
    audit_event(
        "workspace.connect",
        request=request,
        owner_id=ws.owner_id,
        workspace_id=workspace_id,
        method="ssh_credential",
    )

    return ConnectionInfo(
        host=host,
        port=port,
        user=_SSH_LOGIN_USER,
        break_glass_user=_SSH_BREAK_GLASS_USER,
        private_key=private_pem.decode(),
        session_id=await registry.start_turn_session(ws),
    )


class EnsureRunningResult(BaseModel):
    """Response body for POST /workspaces/{id}/ensure_running (`warren connect`,
    podman/docker path). No credential minting -- `warren connect` for these
    runtimes shells into the container directly via the operator's own SSH
    access to the server host (`podman exec`), never SSH into the workspace
    itself (ACCESS-02/ACCESS-03's in-container sshd was never built; see #8).

    `newer_image` (AB1): the image a new task/container would run, when it
    differs from the running one's."""

    container_id: str
    status: str
    session_id: str | None = None
    image: str | None = None
    newer_image: str | None = None


@router.post("/workspaces/{workspace_id}/ensure_running", response_model=EnsureRunningResult)
async def ensure_workspace_running(workspace_id: str, request: Request) -> EnsureRunningResult:
    """Bring a stopped/idle-reaped workspace back up (reusing its existing
    container when possible, reprovisioning only if it's gone), so
    `warren connect` works against a workspace the idle reaper already
    stopped instead of requiring a fresh `warren new`.

    Same ownership gate as POST .../connect, but mints no SSH credential --
    the CLI uses the returned container_id to `podman exec` over its own SSH
    connection to the server host, not an in-container sshd.
    """
    registry = request.app.state.registry

    user = current_user(request)

    ws = await registry.store.get(workspace_id)
    if ws is None:
        raise HTTPException(status_code=404, detail="workspace not found")

    if ws.owner_id is None or ws.owner_id != user.user_id:
        log.warning("ensure_running_denied", workspace_id=workspace_id, user_id=user.user_id)
        audit_event("workspace.connect", request=request, outcome="denied", workspace_id=workspace_id)
        raise HTTPException(status_code=403, detail="not workspace owner")

    try:
        handle = await registry.ensure_running(workspace_id)
    except WorkspaceDestroyedError:
        raise HTTPException(status_code=410, detail="workspace was destroyed")
    except ProvisionError as exc:
        raise _provision_http_error(exc)
    if handle is None:
        raise HTTPException(status_code=404, detail="workspace not found")

    log.info("ensure_running_ok", workspace_id=workspace_id, user_id=user.user_id)
    audit_event(
        "workspace.connect",
        request=request,
        owner_id=ws.owner_id,
        workspace_id=workspace_id,
        method="ensure_running",
    )
    current = await registry.store.get(workspace_id)
    image = current.image if current is not None else ws.image
    resolved = await registry.resolve_current_image(current or ws)
    return EnsureRunningResult(
        container_id=handle.runtime_id,
        status="running",
        session_id=await registry.start_turn_session(ws),
        image=image,
        newer_image=resolved if resolved and resolved != image else None,
    )


class GitPullResult(BaseModel):
    """Response body for POST /workspaces/{id}/git/pull (D-07).

    `commits` maps a repo label ("root" for the single-repo clone, or a
    folder's name for a multi-folder template) to the new HEAD sha pulled
    for it (finding #26) -- a workspace can have more than one clone, so a
    single `commit` field can't represent the result anymore.
    """

    workspace_id: str
    commits: dict[str, str]


@router.post("/workspaces/{workspace_id}/git/pull", response_model=GitPullResult)
async def pull_workspace_git(workspace_id: str, request: Request) -> GitPullResult:
    """Pull the owner's already-materialized worktree to the latest git state (D-07).

    This is a NEW capability beyond provision-time cloning: it refreshes an
    ALREADY-RUNNING (or already-stopped) workspace's worktree without
    reprovisioning. Deliberately does NOT call `ensure_running()` first --
    pulling operates on the server-side worktree on disk regardless of container
    status, and must never silently resurrect a workspace the idle reaper (plan
    04-05) deliberately stopped.
    """
    from warren.git.github_app import GitHubAuthError

    registry = request.app.state.registry

    # 401 comes from AuthMiddleware first; current_user() is a second explicit gate.
    user = current_user(request)

    ws = await registry.store.get(workspace_id)
    if ws is None:
        raise HTTPException(status_code=404, detail="workspace not found")

    # Ownership gate (D-11), placed BEFORE any registry call so a non-owner can
    # never cause a git operation or a token mint to happen at all. A NULL
    # owner_id (legacy, pre-Phase-3 row) fails closed, exactly as
    # connect_workspace does.
    if ws.owner_id is None or ws.owner_id != user.user_id:
        log.warning("git_pull_denied", workspace_id=workspace_id, user_id=user.user_id)
        raise HTTPException(status_code=403, detail="not workspace owner")

    # Audit R8: pull_git() itself has no notion of "destroyed" (it only reads
    # worktree paths off disk, never consults runtime status), so without this
    # check it would happily keep pulling a deleted workspace's git state
    # forever, same class of bug as /events below.
    if ws.status == "destroyed":
        raise HTTPException(status_code=410, detail="workspace was destroyed")

    try:
        result = await registry.pull_git(workspace_id)
    except GitHubAuthError:
        # Never pass the underlying exception's own text through -- a
        # credential-exchange error can echo request details (T-04-06-ID).
        raise HTTPException(
            status_code=502,
            detail={
                "error": "git_auth_failed",
                "detail": "github app credential exchange failed",
            },
        )
    except ProvisionError as exc:
        status_code = _PROVISION_ERROR_STATUS.get(exc.reason, 500)
        raise HTTPException(
            status_code=status_code,
            detail={"error": exc.reason, "detail": str(exc)},
        )
    if result is None:
        raise HTTPException(status_code=404, detail="workspace not found")

    log.info("git_pull_issued", workspace_id=workspace_id, user_id=user.user_id)

    return GitPullResult(workspace_id=workspace_id, commits=result)


_SAFE_SESSION_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


class RefView(BaseModel):
    ref: str
    sha: str


class BranchRequest(BaseModel):
    from_ref: str
    intent: str | None = None
    new_session_id: str | None = None
    repo: str = ROOT_REPO


class BranchResult(BaseModel):
    workspace: WorkspaceView
    parent_workspace_id: str
    from_ref: str
    snapshot_model: str
    source_commit: str
    branch: str
    session_id: str


async def _owned_workspace_repo(request: Request, workspace_id: str, repo: str, action: str):
    """Owner-gated (D-11) lookup of one server-side clone of a live workspace."""
    user = current_user(request)
    require_workspace_access(request, workspace_id)
    registry = request.app.state.registry
    ws = await registry.store.get(workspace_id)
    if ws is None:
        raise HTTPException(status_code=404, detail="workspace not found")
    if ws.owner_id is None or ws.owner_id != user.user_id:
        log.warning(f"{action}_denied", workspace_id=workspace_id, user_id=user.user_id)
        raise HTTPException(status_code=403, detail="not workspace owner")
    if ws.status == "destroyed":
        raise HTTPException(status_code=410, detail="workspace was destroyed")
    if registry.git_manager is None:
        raise HTTPException(
            status_code=409,
            detail={"error": "no_server_worktree", "detail": "this runtime keeps no server-side clone"},
        )
    path = registry.repo_path(ws, repo)
    if path is None:
        raise HTTPException(status_code=404, detail=f"repo {repo!r} not found in workspace")
    return user, ws, path


def _git_http_error(exc: Exception) -> HTTPException:
    if isinstance(exc, TurnRefNotFound):
        return HTTPException(status_code=404, detail={"error": "ref_not_found", "detail": str(exc)})
    if isinstance(exc, TurnRefError):
        return HTTPException(status_code=422, detail={"error": "invalid_ref", "detail": str(exc)})
    return HTTPException(status_code=502, detail={"error": "git_failed", "detail": str(exc)})


@router.get("/workspaces/{workspace_id}/refs", response_model=list[RefView])
async def list_workspace_refs(
    workspace_id: str,
    request: Request,
    prefix: str = Query(default=f"{TURN_NAMESPACE}/"),
    repo: str = Query(default=ROOT_REPO),
) -> list[RefView]:
    """HIST-09: refs under `prefix` in one of the workspace's clones, owner-only."""
    from warren.git.manager import GitError

    _, _, path = await _owned_workspace_repo(request, workspace_id, repo, "refs")
    try:
        refs = await request.app.state.registry.git_manager.list_turn_refs(path, prefix)
    except (TurnRefError, GitError) as exc:
        raise _git_http_error(exc) from exc
    return [RefView(**r) for r in refs]


@router.post("/workspaces/{workspace_id}/branch", status_code=202, response_model=BranchResult)
async def branch_workspace(workspace_id: str, body: BranchRequest, request: Request) -> BranchResult:
    """HIST-05: provision a new workspace whose `repo` starts at turn ref `from_ref`.

    The ref's format (HIST-11) decides whether the new branch carries just the
    snapshot's tree or the ref's commit itself. Not reachable with a
    workspace-scoped token: it creates a workspace.
    """
    from warren.git.manager import GitError

    if current_workspace_scope(request) is not None:
        raise HTTPException(status_code=403, detail="workspace-scoped token cannot branch")
    if body.new_session_id is not None and not _SAFE_SESSION_ID_RE.match(body.new_session_id):
        raise HTTPException(status_code=422, detail="invalid new_session_id")
    user, ws, path = await _owned_workspace_repo(request, workspace_id, body.repo, "branch")
    registry = request.app.state.registry
    try:
        snapshot = await registry.git_manager.resolve_turn_snapshot(path, body.from_ref)
    except (TurnRefError, GitError) as exc:
        raise _git_http_error(exc) from exc

    branch = f"warren/branch/{uuid.uuid4().hex[:8]}"
    view = await _provision_workspace(
        ProvisionRequest(project=ws.project, template=body.intent or ws.intent),
        request,
        branch_from=BranchSource(repo=body.repo, snapshot=snapshot, branch=branch),
    )
    session_id = body.new_session_id or str(uuid.uuid4())
    new_ws = await registry.store.get(view.workspace_id)
    if new_ws is not None:
        view = WorkspaceView.from_workspace(new_ws)
        if new_ws.status == "running":
            await registry.start_turn_session(new_ws, session_id)
    audit_event(
        "workspace.branch",
        request=request,
        owner_id=user.user_id,
        workspace_id=view.workspace_id,
        parent_workspace_id=workspace_id,
        from_ref=body.from_ref,
        snapshot_model=snapshot.snapshot_model,
        source_commit=snapshot.commit,
    )
    return BranchResult(
        workspace=view,
        parent_workspace_id=workspace_id,
        from_ref=body.from_ref,
        snapshot_model=snapshot.snapshot_model,
        source_commit=snapshot.commit,
        branch=branch,
        session_id=session_id,
    )


@router.get("/workspaces/{workspace_id}/events")
async def stream_workspace_events(
    workspace_id: str, request: Request, since: int | None = Query(default=None, ge=-1)
):
    """Stream buffered NDJSON events for a workspace (D-14), owner-only (D-11).

    `?since=<seq>` replays only events after that seq (AH3/SD-05).
    """
    user = current_user(request)
    ws = await request.app.state.registry.store.get(workspace_id)
    if ws is None:
        raise HTTPException(status_code=404, detail="workspace not found")
    if ws.owner_id is None or ws.owner_id != user.user_id:
        log.warning("events_denied", workspace_id=workspace_id, user_id=user.user_id)
        raise HTTPException(status_code=403, detail="not workspace owner")

    # Audit R8: without this, a destroyed workspace's events route created a
    # FRESH event buffer (get_or_create) and streamed from it forever -- there
    # is no container left to ever produce an event into that buffer, so the
    # connection would just hang open indefinitely for a workspace that no
    # longer exists.
    event_store = request.app.state.event_store
    if ws.status == "destroyed":
        # AH2: a completed single-turn workspace's closed buffer stays replayable for a
        # while; stream() ends once it's drained.
        buf = event_store.get(workspace_id) if hasattr(event_store, "get") else None
        if buf is None or not buf.closed:
            raise HTTPException(status_code=410, detail="workspace was destroyed")
    else:
        buf = event_store.get_or_create(workspace_id)

    async def _generate():
        async for line in buf.stream(since=since):
            yield line + "\n"
            if await request.is_disconnected():
                break

    return StreamingResponse(_generate(), media_type="application/x-ndjson")


class ExecRequest(BaseModel):
    argv: list[str]
    timeout_seconds: float | None = Field(default=None, gt=0)


async def open_exec(
    request: Request, workspace_id: str, argv: list[str], timeout_seconds: float | None
) -> AsyncIterator[dict]:
    """#59: owner/scope-checked, audit-logged exec frames (see warren.exec_relay)."""
    from warren import exec_relay  # noqa: PLC0415

    user = current_user(request)
    require_workspace_access(request, workspace_id)
    try:
        exec_relay.validate_argv(argv)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail={"error": "invalid_argv", "detail": str(exc)}) from exc
    registry = request.app.state.registry
    ws = await registry.store.get(workspace_id)
    if ws is None:
        raise HTTPException(status_code=404, detail="workspace not found")
    if ws.owner_id is None or ws.owner_id != user.user_id:
        audit_event("workspace.exec", request=request, outcome="denied", workspace_id=workspace_id)
        raise HTTPException(status_code=403, detail="not workspace owner")
    if ws.status != "running" or not ws.container_id:
        raise HTTPException(status_code=409, detail={"error": "not_running", "detail": f"workspace is {ws.status}"})
    runtime = registry.runtime
    if not hasattr(runtime, "exec_stream"):
        raise HTTPException(status_code=501, detail={"error": "exec_unavailable", "detail": "runtime has no exec channel"})

    settings = request.app.state.settings
    timeout = exec_relay.bounded_timeout(settings, timeout_seconds)
    audit_event(
        "workspace.exec",
        request=request,
        owner_id=ws.owner_id,
        workspace_id=workspace_id,
        command=argv[0],
        argc=len(argv),
        timeout_seconds=timeout,
    )
    frames = exec_relay.relay(
        runtime,
        exec_relay.handle_for(ws),
        argv,
        timeout_seconds=timeout,
        max_output_bytes=int(getattr(settings, "exec_max_output_bytes", 1_048_576)),
    )

    async def _audited() -> AsyncIterator[dict]:
        async for frame in frames:
            if frame["type"] == "exit":
                audit_event(
                    "workspace.exec.finished",
                    request=request,
                    outcome="failure" if frame["error"] else "success",
                    owner_id=ws.owner_id,
                    workspace_id=workspace_id,
                    exit_code=frame["exit_code"],
                    timed_out=frame["timed_out"],
                    truncated=frame["truncated"],
                    output_bytes=frame["output_bytes"],
                )
            yield frame

    return _audited()


@router.post("/workspaces/{workspace_id}/exec")
async def exec_in_workspace(workspace_id: str, body: ExecRequest, request: Request):
    """Run one command in a server workspace and stream NDJSON output/exit frames (#59)."""
    from warren.exec_relay import relay_ndjson  # noqa: PLC0415

    frames = await open_exec(request, workspace_id, body.argv, body.timeout_seconds)
    return StreamingResponse(relay_ndjson(frames), media_type="application/x-ndjson")


@router.delete("/workspaces/{workspace_id}")
async def delete_workspace(workspace_id: str, request: Request) -> Response:
    """Stop and destroy a workspace, owner-only (D-11).

    Idempotent for the owner — still returns 204 if already gone by the time
    destroy() runs. A workspace that doesn't exist at all is also a no-op 204
    (same as before this fix), while an *existing* workspace owned by someone
    else is rejected with 403. The response code therefore does tell a caller
    whether that workspace ID exists — unlike the other owner-gated routes
    (status, events, connect, git-pull), which return 404 vs 403. In practice
    this isn't exploitable: workspace IDs are UUID4s and can't realistically
    be enumerated.
    """
    user = current_user(request)
    require_workspace_access(request, workspace_id)
    registry = request.app.state.registry
    ws = await registry.store.get(workspace_id)
    if ws is not None and (ws.owner_id is None or ws.owner_id != user.user_id):
        log.warning("delete_denied", workspace_id=workspace_id, user_id=user.user_id)
        audit_event("workspace.destroy", request=request, outcome="denied", workspace_id=workspace_id)
        raise HTTPException(status_code=403, detail="not workspace owner")
    await registry.destroy(workspace_id)
    auth_store = getattr(request.app.state, "auth_store", None)
    if auth_store is not None:
        # AI8: a single-turn workspace's own token, destroying it, keeps read access to
        # its verdict until it expires (an MCP client still has calls in flight).
        caller = getattr(request.state, "workspace_token", None)
        keep = None
        if caller is not None and ws is not None and json.loads(ws.spec_json or "{}").get("mode") == "single-turn":
            keep = caller.token_id
        await auth_store.revoke_workspace_tokens(workspace_id, keep_token_id=keep)
    audit_event(
        "workspace.destroy",
        request=request,
        owner_id=ws.owner_id if ws is not None else None,
        workspace_id=workspace_id,
        existed=ws is not None,
    )
    return Response(status_code=204)
