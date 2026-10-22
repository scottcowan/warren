"""AI8: MCP served by warren-server itself, at /mcp (streamable HTTP, stateless, JSON).

Each tool is a thin wrapper over the same route handlers and registry the REST API
uses, called with the MCP request's own authenticated Starlette Request, so owner
checks, workspace-token scope, rate limits and audit events are the REST ones.
Tool names and shapes follow the local CLI-bridge warren-mcp where it has them.

Auth is AuthMiddleware's: a user token, or a workspace-scoped token (AI9). A scoped
token reaches /mcp, and every tool re-checks that it only names the token's own
workspace; only a reservation token can provision, once (POST /workspace-tokens).
"""

from __future__ import annotations

import json
import time
from typing import Any, Literal

import structlog
from fastapi import HTTPException, Request
from mcp.server.fastmcp import Context, FastMCP
from mcp.server.fastmcp.exceptions import ToolError
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from mcp.server.transport_security import TransportSecuritySettings
from mcp.types import ToolAnnotations

from warren.audit import audit_event
from warren.auth.deps import current_user, current_workspace_scope
from warren.registry.models import WorkspaceView

log = structlog.get_logger(__name__)

MAX_EVENTS_PAGE = 500
MAX_WAIT_SECONDS = 300.0
_INACTIVE = frozenset({"stopped", "failed", "destroyed"})

mcp = FastMCP(
    name="warren-control-plane",
    instructions=(
        "Lifecycle tools for warren workspaces on this warren-server: provision (optionally "
        "single-turn), list, status, exec a command, read events (resume with `since`), wait "
        "for a single-turn workspace's workspace.completed verdict, destroy. A workspace-scoped "
        "token can only act on its own workspace."
    ),
)


def new_session_manager() -> StreamableHTTPSessionManager:
    # Bearer-authenticated (AuthMiddleware), which a browser can't attach cross-site, so
    # the Host/Origin DNS-rebinding check adds nothing behind a proxy-chosen Host.
    return StreamableHTTPSessionManager(
        app=mcp._mcp_server,
        json_response=True,
        stateless=True,
        security_settings=TransportSecuritySettings(enable_dns_rebinding_protection=False),
    )


class _MCPEndpoint:
    """Raw ASGI (an instance, so Starlette's Route doesn't wrap it as a request handler)."""

    async def __call__(self, scope, receive, send) -> None:
        await scope["app"].state.mcp_session_manager.handle_request(scope, receive, send)


asgi = _MCPEndpoint()


def _request(ctx: Context, tool: str, workspace_id: str | None = None) -> Request:
    request = ctx.request_context.request
    if request is None:
        raise ToolError("no HTTP request context")
    current_user(request)
    scope = current_workspace_scope(request)
    if workspace_id is not None and scope is not None and scope != workspace_id:
        audit_event("mcp.tool_call", request=request, outcome="denied", workspace_id=workspace_id, tool=tool)
        raise ToolError("403: workspace-scoped token cannot access this resource")
    audit_event("mcp.tool_call", request=request, workspace_id=workspace_id or scope, tool=tool)
    return request


def _tool_error(exc: HTTPException) -> ToolError:
    detail = exc.detail if isinstance(exc.detail, str) else json.dumps(exc.detail)
    return ToolError(f"{exc.status_code}: {detail}")


async def _owned(request: Request, workspace_id: str):
    user = current_user(request)
    ws = await request.app.state.registry.store.get(workspace_id)
    if ws is None:
        raise ToolError("404: workspace not found")
    if ws.owner_id is None or ws.owner_id != user.user_id:
        raise ToolError("403: not workspace owner")
    return ws


async def _buffer(request: Request, workspace_id: str):
    ws = await _owned(request, workspace_id)
    event_store = request.app.state.event_store
    if ws.status == "destroyed":
        buf = event_store.get(workspace_id)
        if buf is None or not buf.closed:
            raise ToolError("410: workspace was destroyed")
        return buf
    return event_store.get_or_create(workspace_id)


def _view(ws) -> dict[str, Any]:
    view = WorkspaceView.from_workspace(ws).model_dump(mode="json", exclude={"spec_json"})
    try:
        view["mode"] = json.loads(ws.spec_json or "{}").get("mode", "interactive")
    except ValueError:
        view["mode"] = "interactive"
    return view


@mcp.tool()
async def new_workspace(
    ctx: Context,
    project: str,
    template: str = "observe",
    mode: Literal["interactive", "single-turn"] = "interactive",
    operation_id: str | None = None,
) -> dict[str, Any]:
    """Provision a workspace from a project template on this server. Returns the new
    workspace record (its `workspace_id` is what every other tool takes).

    template: dotted for a nested sub-template, e.g. "develop.claude".
    mode: "single-turn" runs the template's app once; when it exits the server emits
    a workspace.completed event (exit code, git state, verdict.json) and destroys it.
    operation_id: optional idempotency key (1-64 of A-Z a-z 0-9 . _ : -). Retrying with
    the same one returns the original workspace instead of provisioning another; reusing
    it with different arguments is an error. The result's `operation` is its receipt.
    """
    from pydantic import ValidationError  # noqa: PLC0415

    from warren.routes.workspaces import ProvisionRequest, create_workspace  # noqa: PLC0415

    request = _request(ctx, "new_workspace")
    try:
        body = ProvisionRequest(project=project, template=template, mode=mode, operation_id=operation_id)
    except ValidationError as exc:
        raise ToolError(f"422: invalid operation_id: {exc.errors()[0]['msg']}") from exc
    try:
        view = await create_workspace(body, request)
    except HTTPException as exc:
        raise _tool_error(exc) from exc
    ws = await request.app.state.registry.store.get(view.workspace_id)
    out = _view(ws) if ws is not None else view.model_dump(mode="json", exclude={"spec_json", "operation"})
    if view.operation is not None:
        out["operation"] = view.operation.model_dump(mode="json")
    return out


@mcp.tool()
async def list_workspaces(ctx: Context, include_inactive: bool = False) -> dict[str, Any]:
    """List your workspaces on this server (a workspace-scoped token sees only its own).

    include_inactive: include stopped/failed/destroyed workspaces, not just active ones.
    """
    request = _request(ctx, "list_workspaces")
    user = current_user(request)
    scope = current_workspace_scope(request)
    rows = await request.app.state.registry.store.list_all()
    out = [
        _view(ws)
        for ws in rows
        if ws.owner_id == user.user_id
        and (scope is None or ws.workspace_id == scope)
        and (include_inactive or ws.status not in _INACTIVE)
    ]
    return {"workspaces": out}


@mcp.tool()
async def workspace_status(ctx: Context, workspace_id: str) -> dict[str, Any]:
    """Status and summary of one of your workspaces."""
    request = _request(ctx, "workspace_status", workspace_id)
    return _view(await _owned(request, workspace_id))


@mcp.tool()
async def exec_command(
    ctx: Context, workspace_id: str, command: list[str], timeout_seconds: float | None = None
) -> dict[str, Any]:
    """Run a command non-interactively inside a running workspace and return its output
    (stdout and stderr interleaved), exit_code, and whether it timed out or was truncated.
    Output and time are capped server-side.

    command: the argv to run, e.g. ["pytest", "-q"]. Not run through a shell unless you
    pass one, e.g. ["sh", "-c", "make test"].
    """
    from warren import exec_relay  # noqa: PLC0415
    from warren.routes.workspaces import open_exec  # noqa: PLC0415

    request = _request(ctx, "exec_command", workspace_id)
    try:
        frames = await open_exec(request, workspace_id, command, timeout_seconds)
    except HTTPException as exc:
        raise _tool_error(exc) from exc
    return await exec_relay.collect(frames)


@mcp.tool()
async def workspace_events(
    ctx: Context,
    workspace_id: str,
    since: int | None = None,
    wait_seconds: float = 0.0,
    max_events: int = 100,
) -> dict[str, Any]:
    """Read a workspace's buffered events after `since` (pass the previous call's
    `next_since` to resume; omit for everything still buffered). With wait_seconds > 0,
    waits that long for the first new event. `closed` is true once a destroyed
    workspace's events are fully read. An `events_evicted` event (seq null) means
    events between `since` and the oldest buffered one were dropped.
    """
    request = _request(ctx, "workspace_events", workspace_id)
    buf = await _buffer(request, workspace_id)
    events, next_since, closed = await buf.read(
        since,
        limit=max(1, min(max_events, MAX_EVENTS_PAGE)),
        wait_seconds=max(0.0, min(wait_seconds, MAX_WAIT_SECONDS)),
    )
    return {
        "events": [{"seq": seq, "event": _parse(line)} for seq, line in events],
        "next_since": next_since,
        "closed": closed,
    }


@mcp.tool()
async def wait_completed(ctx: Context, workspace_id: str, timeout_seconds: float = 20.0) -> dict[str, Any]:
    """Wait for a single-turn workspace's workspace.completed event and return it: its
    exit_code, git {branch, head_commit, base_commit, branch_safe, is_clean}, the
    workspace's .warren/verdict.json as `verdict`, and capture_errors. Returns
    completed=false if it hasn't completed within timeout_seconds (call again).
    """
    request = _request(ctx, "wait_completed", workspace_id)
    buf = await _buffer(request, workspace_id)
    deadline = time.monotonic() + max(0.0, min(timeout_seconds, MAX_WAIT_SECONDS))
    since: int | None = None
    while True:
        remaining = deadline - time.monotonic()
        events, since, closed = await buf.read(since, limit=MAX_EVENTS_PAGE, wait_seconds=max(0.0, remaining))
        for _, line in events:
            event = _parse(line)
            if isinstance(event, dict) and event.get("type") == "workspace.completed":
                return {"completed": True, "event": event}
        if closed or time.monotonic() >= deadline:
            return {"completed": False, "closed": closed}


@mcp.tool(annotations=ToolAnnotations(destructiveHint=True, idempotentHint=True, openWorldHint=False))
async def destroy_workspace(ctx: Context, workspace_id: str) -> dict[str, Any]:
    """Stop and destroy one of your workspaces. Idempotent: destroying an already
    destroyed (e.g. completed single-turn) workspace succeeds."""
    from warren.routes.workspaces import delete_workspace  # noqa: PLC0415

    request = _request(ctx, "destroy_workspace", workspace_id)
    try:
        await delete_workspace(workspace_id, request)
    except HTTPException as exc:
        raise _tool_error(exc) from exc
    return {"workspace_id": workspace_id, "destroyed": True}


def _parse(line: str) -> Any:
    try:
        return json.loads(line)
    except ValueError:
        return line
