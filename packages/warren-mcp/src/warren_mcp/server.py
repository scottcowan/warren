"""warren-mcp — exposes the warren CLI as MCP tools.

Every tool below is a thin wrapper around a real `warren` subcommand (see
cli_bridge.py) — nothing here reimplements CLI logic. Tools always pass
every argument the underlying command needs, never relying on an
interactive picker (there's no TTY on the other end of an MCP tool call).
"""

from __future__ import annotations

from typing import Any

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations

from warren_common.paths import PathEscapeError, validate_workspace_id

from .cli_bridge import CLIResult, WarrenCLITimeout, run_warren


def _run_warren_safe(args: list[str]) -> CLIResult:
    """run_warren, but a timeout becomes a failed CLIResult instead of an
    uncaught exception reaching the MCP caller (audit 2026-10-16 #29)."""
    try:
        return run_warren(args)
    except WarrenCLITimeout as exc:
        return CLIResult(returncode=-1, stdout="", stderr=str(exc))


def _invalid_workspace_id(workspace_id: str) -> dict[str, Any] | None:
    """A failed-result dict unless `workspace_id` is a plain warren id, so a
    model-chosen path (absolute, `..`, separators) never reaches the CLI."""
    try:
        validate_workspace_id(workspace_id)
    except PathEscapeError as exc:
        return CLIResult(returncode=2, stdout="", stderr=str(exc)).as_dict()
    return None


mcp = FastMCP(
    name="warren",
    instructions=(
        "Tools for managing warren AI-agent workspaces: provisioning, listing, "
        "running commands inside them, and tearing them down. Workspaces are "
        "scoped to a project and a template (e.g. 'observe', 'develop', or a "
        "dotted nested path like 'develop.claude'). Pass --server's remote "
        "name explicitly when working against a remote warren-server; omit "
        "it for local-mode workspaces."
    ),
)


@mcp.tool()
def list_workspaces(include_inactive: bool = False) -> dict[str, Any]:
    """List workspaces — local ones and every configured remote's.

    include_inactive: include stopped/failed workspaces, not just active ones.
    """
    args = ["list", "--json"]
    if include_inactive:
        args.append("--all")
    result = _run_warren_safe(args)
    return result.json_or_raise() if result.ok else result.as_dict()


@mcp.tool()
def list_projects(server: str | None = None) -> dict[str, Any]:
    """List projects (and their templates) registered on a warren-server.

    server: a `warren server add`/`server use` PROFILE name (~/.warren/
    config.toml's [servers.*] — set up with bearer auth), NOT one of
    list_remotes' [remotes.*] entries. This is a real inconsistency in the
    CLI itself (two separate server-connection namespaces behind the same
    `--server` flag name on different commands), not something invented
    here — omit it to use the default profile from `server use`.
    """
    result = _run_warren_safe(["projects", "--server", server] if server else ["projects"])
    return result.json_or_raise() if result.ok else result.as_dict()


@mcp.tool()
def new_workspace(project: str, template: str = "observe", server: str | None = None) -> dict[str, Any]:
    """Provision a new workspace. Always runs detached (--daemon) — there is
    no interactive TTY for an MCP tool call to attach to. Use list_workspaces
    afterward to find the new workspace's id (matched by project/template),
    and exec_command/workspace_status to interact with it.

    template: dotted for a nested sub-template, e.g. "develop.claude".
    """
    # Options before `--`, then only positionals after it — a model-chosen
    # project/template value that happens to look like a CLI flag (e.g.
    # "--config=/x") must never be parsed as one (audit 2026-10-16 #29).
    args = ["new", "--daemon"]
    if server:
        args.extend(["--server", server])
    args.extend(["--", project, template])
    result = _run_warren_safe(args)
    return result.as_dict()


@mcp.tool()
def workspace_status(workspace_id: str, server: str) -> dict[str, Any]:
    """Status of a workspace on a remote warren-server. Local workspaces have
    no server-tracked status — use list_workspaces for those instead."""
    if (invalid := _invalid_workspace_id(workspace_id)) is not None:
        return invalid
    result = _run_warren_safe(["status", "--server", server, "--", workspace_id])
    return result.json_or_raise() if result.ok else result.as_dict()


@mcp.tool()
def exec_command(workspace_id: str, command: list[str]) -> dict[str, Any]:
    """Run a command non-interactively inside an existing LOCAL workspace and
    return its output. For a server-mode workspace use the server's control-plane MCP
    exec_command (or POST /workspaces/{id}/exec) instead.

    command: the argv to run, e.g. ["pytest", "packages/warren-server/tests/unit"].
    """
    if (invalid := _invalid_workspace_id(workspace_id)) is not None:
        return invalid
    result = _run_warren_safe(["exec", "--", workspace_id, *command])
    return result.as_dict()


@mcp.tool(
    annotations=ToolAnnotations(
        destructiveHint=True,
        idempotentHint=True,  # destroying an already-destroyed workspace is a no-op
        openWorldHint=False,
    )
)
def destroy_workspace(workspace_id: str, server: str | None = None) -> dict[str, Any]:
    """Stop and destroy a workspace. Local mode removes its workspace
    directory; server mode deletes the server-side record."""
    if (invalid := _invalid_workspace_id(workspace_id)) is not None:
        return invalid
    args = ["destroy"]
    if server:
        args.extend(["--server", server])
    args.extend(["--", workspace_id])
    result = _run_warren_safe(args)
    return result.as_dict()


@mcp.tool()
def list_remotes() -> dict[str, Any]:
    """List the warren-server remotes configured in ~/.warren/config.toml —
    the valid values for every other tool's `server` argument."""
    result = _run_warren_safe(["remote", "list"])
    return result.as_dict()


@mcp.tool()
def doctor() -> dict[str, Any]:
    """Diagnose the local warren environment — available runtimes, image
    resolution, AWS SSO/ECS reachability, configured remotes."""
    result = _run_warren_safe(["doctor"])
    return result.as_dict()


def main() -> None:
    mcp.run(transport="stdio")
