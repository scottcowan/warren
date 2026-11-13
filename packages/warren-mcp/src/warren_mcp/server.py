"""warren-mcp — exposes the warren CLI as MCP tools.

Every tool below is a thin wrapper around a real `warren` subcommand (see
cli_bridge.py) — nothing here reimplements CLI logic. Tools always pass
every argument the underlying command needs, never relying on an
interactive picker (there's no TTY on the other end of an MCP tool call).

Launch-config environment:
  WARREN_MCP_SERVER  default remote name (a `[remotes.*]` entry, e.g. an ECS
                     remote) used when a tool's `server` argument is omitted
  WARREN_MCP_CONFIG  config file path passed as `--config` to every command
  (plus the cli_bridge variables and AWS_PROFILE / AWS_REGION)
"""

from __future__ import annotations

import json
import os
import re
from typing import Any

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations

from warren_common.paths import PathEscapeError, validate_workspace_id

from .cli_bridge import CLIResult, WarrenCLINotFound, WarrenCLITimeout, failure_hint, run_warren

# Remote / project / template / run-id names: one leading alphanumeric (so a
# value can never look like an option), then a conservative charset.
_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_RUN_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")

_DOCTOR_TIMEOUT = 60.0  # doctor shells out to `aws` several times


def _fail(message: str, returncode: int = 2) -> dict[str, Any]:
    return CLIResult(returncode=returncode, stdout="", stderr=message).as_dict()


def _run_warren_safe(args: list[str], *, timeout: float | None = None) -> CLIResult:
    """run_warren, but a timeout / missing binary becomes a failed CLIResult
    instead of an uncaught exception reaching the MCP caller (audit
    2026-10-16 #29)."""
    try:
        return run_warren(args, timeout=timeout) if timeout else run_warren(args)
    except (WarrenCLITimeout, WarrenCLINotFound) as exc:
        return CLIResult(returncode=-1, stdout="", stderr=str(exc))


def _invalid_workspace_id(workspace_id: str) -> dict[str, Any] | None:
    """A failed-result dict unless `workspace_id` is a plain warren id, so a
    model-chosen path (absolute, `..`, separators) never reaches the CLI."""
    try:
        validate_workspace_id(workspace_id)
    except PathEscapeError as exc:
        return _fail(str(exc))
    return None


def _invalid_name(kind: str, value: str, regex: re.Pattern[str] = _NAME_RE) -> dict[str, Any] | None:
    if not isinstance(value, str) or not regex.fullmatch(value):
        return _fail(f"invalid {kind}: {value!r}")
    return None


def _server(server: str | None) -> tuple[str | None, dict[str, Any] | None]:
    """Explicit argument, else WARREN_MCP_SERVER, else None. Validated."""
    chosen = server if server is not None else (os.environ.get("WARREN_MCP_SERVER") or None)
    if chosen is None:
        return None, None
    if (bad := _invalid_name("server name", chosen)) is not None:
        return None, bad
    return chosen, None


def _build(
    sub: list[str],
    *,
    flags: list[str] | None = None,
    server: str | None = None,
    positionals: list[str] | None = None,
) -> list[str]:
    """`sub` + flags + --server + --config, then `--` and positionals, so a
    model-chosen positional can never be parsed as an option."""
    args = [*sub, *(flags or [])]
    if server:
        args.extend(["--server", server])
    if config := os.environ.get("WARREN_MCP_CONFIG"):
        args.extend(["--config", config])
    if positionals:
        args.extend(["--", *positionals])
    return args


def _json_result(result: CLIResult, *, accept_exit: tuple[int, ...] = ()) -> Any:
    """Parsed JSON stdout, or a failed-result dict — never an exception.

    `accept_exit`: non-zero exit codes that still carry a JSON document
    (e.g. `run result`: 1 failed, 124 timed out, 75 still running); the
    parsed dict then gains an `exit_code` key."""
    if not result.ok and result.returncode not in accept_exit:
        return result.as_dict()
    if result.truncated:
        return {**result.as_dict(), "ok": False, "stderr": "output truncated; refusing to parse partial JSON"}
    try:
        data = json.loads(result.stdout)
    except ValueError:
        return {**result.as_dict(), "ok": False, "stderr": result.stderr or "warren did not return JSON"}
    if not result.ok and isinstance(data, dict):
        data["exit_code"] = result.returncode
    return data


mcp = FastMCP(
    name="warren",
    instructions=(
        "Tools for managing warren AI-agent workspaces: provisioning, listing, "
        "running commands inside them, and tearing them down. Workspaces are "
        "scoped to a project and a template (e.g. 'observe', 'develop', or a "
        "dotted nested path like 'develop.claude'). For a remote warren-server "
        "(including ECS) pass `server` (a `[remotes.*]` name from list_remotes), "
        "or rely on the WARREN_MCP_SERVER default from the launch config; omit "
        "it for local-mode workspaces. A failed call may carry a `hint` (e.g. "
        "expired AWS SSO: the user must run `aws sso login`). Interactive "
        "attach (`warren connect`) and port tunnels are terminal-only."
    ),
)

_RO = ToolAnnotations(readOnlyHint=True, openWorldHint=False)


@mcp.tool(annotations=_RO)
def list_workspaces(include_inactive: bool = False) -> dict[str, Any]:
    """List workspaces — local ones and every configured remote's.

    include_inactive: include stopped/failed workspaces, not just active ones.
    """
    args = _build(["list"], flags=["--json", *(["--all"] if include_inactive else [])])
    return _json_result(_run_warren_safe(args))


@mcp.tool(annotations=_RO)
def list_projects(server: str | None = None) -> dict[str, Any]:
    """List projects (and their templates) registered on a warren-server.

    server: a `[remotes.*]` name (see list_remotes; works for http, ssh and
    ECS remotes). Defaults to WARREN_MCP_SERVER.
    """
    name, bad = _server(server)
    if bad:
        return bad
    if name is None:
        return _fail("server is required (pass `server` or set WARREN_MCP_SERVER)")
    return _json_result(_run_warren_safe(_build(["projects"], flags=["--json"], server=name)))


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, openWorldHint=True))
def new_workspace(project: str, template: str = "observe", server: str | None = None) -> dict[str, Any]:
    """Provision a new workspace. Always runs detached (--daemon) — there is
    no interactive TTY for an MCP tool call to attach to. Use list_workspaces
    afterward to find the new workspace's id (matched by project/template),
    and exec_command/workspace_status to interact with it.

    template: dotted for a nested sub-template, e.g. "develop.claude".
    server: remote name; defaults to WARREN_MCP_SERVER, else local mode.
    """
    for kind, value in (("project", project), ("template", template)):
        if (bad := _invalid_name(kind, value)) is not None:
            return bad
    name, bad = _server(server)
    if bad:
        return bad
    # Options before `--`, then only positionals after it — a model-chosen
    # project/template value that happens to look like a CLI flag (e.g.
    # "--config=/x") must never be parsed as one (audit 2026-10-16 #29).
    args = _build(["new", "--daemon"], server=name, positionals=[project, template])
    return _run_warren_safe(args).as_dict()


@mcp.tool(annotations=_RO)
def workspace_status(workspace_id: str, server: str | None = None) -> dict[str, Any]:
    """Status of a workspace on a remote warren-server (incl. ECS). Local
    workspaces have no server-tracked status — use list_workspaces for those.

    server: remote name; defaults to WARREN_MCP_SERVER.
    """
    if (invalid := _invalid_workspace_id(workspace_id)) is not None:
        return invalid
    name, bad = _server(server)
    if bad:
        return bad
    if name is None:
        return _fail("server is required (pass `server` or set WARREN_MCP_SERVER)")
    args = _build(["status"], flags=["--json"], server=name, positionals=[workspace_id])
    return _json_result(_run_warren_safe(args))


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=True, openWorldHint=True))
def exec_command(workspace_id: str, command: list[str]) -> dict[str, Any]:
    """Run a command non-interactively inside an existing LOCAL workspace and
    return its output. For a server-mode (ECS) workspace use the server's
    control-plane MCP exec_command (or POST /workspaces/{id}/exec) instead —
    `warren exec` refuses non-local configs.

    command: the argv to run, e.g. ["pytest", "packages/warren-server/tests/unit"].
    """
    if (invalid := _invalid_workspace_id(workspace_id)) is not None:
        return invalid
    if not command:
        return _fail("command must not be empty")
    args = _build(["exec"], positionals=[workspace_id, *command])
    return _run_warren_safe(args).as_dict()


@mcp.tool(
    annotations=ToolAnnotations(
        readOnlyHint=False,
        destructiveHint=True,
        idempotentHint=True,  # destroying an already-destroyed workspace is a no-op
        openWorldHint=False,
    )
)
def destroy_workspace(workspace_id: str, server: str | None = None) -> dict[str, Any]:
    """Stop and destroy a workspace. Local mode removes its workspace
    directory; server mode deletes the server-side record.

    server: remote name; defaults to WARREN_MCP_SERVER, else local mode.
    """
    if (invalid := _invalid_workspace_id(workspace_id)) is not None:
        return invalid
    name, bad = _server(server)
    if bad:
        return bad
    args = _build(["destroy"], server=name, positionals=[workspace_id])
    return _run_warren_safe(args).as_dict()


@mcp.tool(annotations=_RO)
def list_remotes() -> dict[str, Any]:
    """List the remotes configured in ~/.warren/config.toml (http, ssh, ecs) —
    the valid values for every other tool's `server` argument."""
    return _json_result(_run_warren_safe(_build(["remote", "list"], flags=["--json"])))


@mcp.tool(annotations=_RO)
def server_health(server: str | None = None) -> dict[str, Any]:
    """Health-check a remote warren-server (for ECS: the tunnel + server
    reachability). server defaults to WARREN_MCP_SERVER."""
    name, bad = _server(server)
    if bad:
        return bad
    if name is None:
        return _fail("server is required (pass `server` or set WARREN_MCP_SERVER)")
    return _json_result(_run_warren_safe(_build(["healthz"], flags=["--json"], server=name)))


@mcp.tool(annotations=_RO)
def run_status(run_id: str, server: str | None = None) -> dict[str, Any]:
    """Status of a headless run on a warren-server (id or unique prefix)."""
    return _run_tool("status", run_id, server)


@mcp.tool(annotations=_RO)
def run_result(run_id: str, server: str | None = None) -> dict[str, Any]:
    """Result of a headless run (schema warren.run.result/v1). A failed (1),
    timed-out (124) or still-running (75) run is returned as data with an
    `exit_code` key, not as an error."""
    return _run_tool("result", run_id, server, accept_exit=(1, 75, 124))


def _run_tool(
    verb: str, run_id: str, server: str | None, accept_exit: tuple[int, ...] = ()
) -> dict[str, Any]:
    if (bad := _invalid_name("run id", run_id, _RUN_ID_RE)) is not None:
        return bad
    name, bad = _server(server)
    if bad:
        return bad
    if name is None:
        return _fail("server is required (pass `server` or set WARREN_MCP_SERVER)")
    args = _build(["run", verb], flags=["--json"], server=name, positionals=[run_id])
    return _json_result(_run_warren_safe(args), accept_exit=accept_exit)


@mcp.tool(annotations=_RO)
def run_list(server: str | None = None, all_owners: bool = False) -> dict[str, Any]:
    """Recent headless runs on a warren-server, newest first.
    all_owners: every owner's runs (admin only)."""
    name, bad = _server(server)
    if bad:
        return bad
    if name is None:
        return _fail("server is required (pass `server` or set WARREN_MCP_SERVER)")
    flags = ["--json", *(["--all"] if all_owners else [])]
    return _json_result(_run_warren_safe(_build(["run", "list"], flags=flags, server=name)))


@mcp.tool(annotations=_RO)
def doctor() -> dict[str, Any]:
    """Diagnose the warren environment — runtimes (incl. ECS), image
    resolution, AWS SSO/credentials, ECS/EFS checks, configured remotes.
    Returns the structured report under `report`; `hint` is set when AWS
    credentials are not valid."""
    result = _run_warren_safe(_build(["doctor"], flags=["--json"]), timeout=_DOCTOR_TIMEOUT)
    if not result.ok:
        return result.as_dict()
    try:
        report = json.loads(result.stdout)
    except ValueError:
        return result.as_dict()
    out: dict[str, Any] = {"ok": True, "report": report}
    if isinstance(report, dict) and report.get("aws_sso") is False:
        out["hint"] = failure_hint("Unable to locate credentials")
    return out


def main() -> None:
    mcp.run(transport="stdio")
