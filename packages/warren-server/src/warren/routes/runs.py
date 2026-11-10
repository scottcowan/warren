"""Headless runs (`warren run`, docs/runs.md): start one, read its status and result.

A run is a single-turn workspace started with a prompt (routes/workspaces.py
`_provision_workspace`, warren_common/headless.py); its id is the workspace id. The
result lives in the registry's `runs` table (registry/runs.py), so it stays readable
after the workspace is destroyed on completion.

Authorization: a user sees only the runs they started; an admin may read every run
(GET only; an admin can't start a run as someone else). Workspace-scoped tokens never
reach these routes (AuthMiddleware's allow-list), and are refused here too.
"""

from __future__ import annotations

from typing import Any

import structlog
from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, Field, model_validator
from warren.audit import audit_event
from warren.auth.deps import current_user, current_workspace_scope
from warren.registry import runs
from warren.state.protocols import RunStoreProtocol
from warren.routes.workspaces import (
    _MAX_PROMPT_CHARS,
    _OPERATION_ID_PATTERN,
    ProvisionRequest,
    create_workspace,
)

log = structlog.get_logger(__name__)

router = APIRouter()


class RunRequest(BaseModel):
    project: str
    template: str
    prompt: str = Field(min_length=1, max_length=_MAX_PROMPT_CHARS)
    timeout_seconds: float | None = Field(default=None, gt=0)
    operation_id: str | None = Field(default=None, pattern=_OPERATION_ID_PATTERN)

    @model_validator(mode="before")
    @classmethod
    def _accept_camel_operation_id(cls, data):
        if isinstance(data, dict) and "operationId" in data and "operation_id" not in data:
            data = {**data, "operation_id": data["operationId"]}
            del data["operationId"]
        return data


def _store(request: Request) -> RunStoreProtocol:
    store = getattr(request.app.state, "run_store", None)
    if store is None:
        raise HTTPException(status_code=503, detail="run store unavailable")
    return store


def _refuse_scoped(request: Request) -> None:
    if current_workspace_scope(request) is not None:
        raise HTTPException(status_code=403, detail="workspace-scoped token cannot access runs")


async def _visible_run(request: Request, run_id: str) -> dict[str, Any]:
    """The run, if the caller owns it or is an admin; 404 otherwise (a missing run and
    another owner's run are indistinguishable, so run ids cannot be probed). A run whose
    workspace ended without completing (destroyed by hand, failed) is finished here."""
    _refuse_scoped(request)
    user = current_user(request)
    store = _store(request)
    run = await store.get(run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="run not found")
    if run["owner_id"] != user.user_id:
        if not user.is_admin:
            log.warning("run_read_denied", run_id=run_id, user_id=user.user_id)
            raise HTTPException(status_code=404, detail="run not found")
        audit_event("run.read", request=request, outcome="admin", owner_id=run["owner_id"], workspace_id=run_id)
    if run["status"] == runs.RUNNING:
        run = await _settle(request, store, run)
    return run


async def _settle(request: Request, store: RunStoreProtocol, run: dict[str, Any]) -> dict[str, Any]:
    registry = getattr(request.app.state, "registry", None)
    if registry is None:
        return run
    ws = await registry.store.get(run["run_id"])
    if ws is not None and ws.status not in ("destroyed", "failed"):
        return run
    # Completion records the run before it destroys the workspace, so a run still
    # "running" here ended some other way.
    error = (
        "the workspace failed before the run completed"
        if ws is not None and ws.status == "failed"
        else "the workspace was destroyed before the run completed"
    )
    ended = runs.utcnow()
    await store.finish(
        run["run_id"], status=runs.FAILED, result=runs.failure_result(run=run, error=error, ended_at=ended),
        ended_at=ended,
    )
    return await store.get(run["run_id"]) or run


def _summary(run: dict[str, Any]) -> dict[str, Any]:
    result = run.get("result") or {}
    return {
        "run_id": run["run_id"],
        "workspace_id": run["run_id"],
        "project": run["project"],
        "template": run["template"],
        "status": run["status"],
        "started_at": run["started_at"],
        "ended_at": run.get("ended_at"),
        "timeout_seconds": run.get("timeout_seconds"),
        "exit_code": result.get("exit_code"),
        "error": result.get("error"),
    }


@router.post("/runs", status_code=202)
async def start_run(body: RunRequest, request: Request) -> dict[str, Any]:
    """Start a headless run: a single-turn workspace of `template` on `prompt`."""
    _refuse_scoped(request)
    provision = ProvisionRequest(
        project=body.project,
        template=body.template,
        mode="single-turn",
        prompt=body.prompt,
        timeout_seconds=body.timeout_seconds,
        operation_id=body.operation_id,
    )
    view = await create_workspace(provision, request)
    run = await _store(request).get(view.workspace_id)
    if run is None:
        raise HTTPException(status_code=500, detail="run was not recorded")
    return {**_summary(run), "workspace_status": view.status}


@router.get("/runs")
async def list_runs(
    request: Request,
    all_owners: bool = Query(default=False, alias="all"),
    limit: int = Query(default=50, ge=1, le=500),
) -> list[dict[str, Any]]:
    """The caller's runs, newest first; `?all=true` lists every owner's (admin only)."""
    _refuse_scoped(request)
    user = current_user(request)
    if all_owners and not user.is_admin:
        raise HTTPException(status_code=403, detail="admin required")
    rows = await _store(request).list(None if all_owners else user.user_id, limit=limit)
    return [_summary(r) for r in rows]


@router.get("/runs/{run_id}")
async def get_run(run_id: str, request: Request) -> dict[str, Any]:
    return _summary(await _visible_run(request, run_id))


@router.get("/runs/{run_id}/result")
async def get_run_result(run_id: str, request: Request) -> dict[str, Any]:
    """The structured result (schema warren.run.result/v1); a short running view until then."""
    run = await _visible_run(request, run_id)
    if run["status"] == runs.RUNNING or run.get("result") is None:
        return runs.running_view(run)
    return run["result"]
