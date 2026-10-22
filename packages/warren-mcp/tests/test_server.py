"""Tool wrapper tests — mock run_warren, verify each tool builds the right
argv and surfaces results/errors correctly. Not testing the real CLI here
(test_cli_bridge.py's doctor test already proves the bridge itself works);
this is about each tool's own argument-building logic."""

from __future__ import annotations

from unittest.mock import patch

from warren_mcp.cli_bridge import CLIResult
from warren_mcp.server import (
    destroy_workspace,
    exec_command,
    list_projects,
    list_remotes,
    list_workspaces,
    mcp,
    new_workspace,
    workspace_status,
)


def _ok(stdout: str = "") -> CLIResult:
    return CLIResult(returncode=0, stdout=stdout, stderr="")


@patch("warren_mcp.server.run_warren")
def test_list_workspaces_default_args(mock_run):
    mock_run.return_value = _ok("[]")
    list_workspaces()
    assert mock_run.call_args[0][0] == ["list", "--json"]


@patch("warren_mcp.server.run_warren")
def test_list_workspaces_include_inactive(mock_run):
    mock_run.return_value = _ok("[]")
    list_workspaces(include_inactive=True)
    assert mock_run.call_args[0][0] == ["list", "--json", "--all"]


@patch("warren_mcp.server.run_warren")
def test_list_workspaces_parses_json_on_success(mock_run):
    mock_run.return_value = _ok('[{"workspace_id": "ws-1"}]')
    result = list_workspaces()
    assert result == [{"workspace_id": "ws-1"}]


@patch("warren_mcp.server.run_warren")
def test_list_workspaces_returns_error_dict_on_failure(mock_run):
    mock_run.return_value = CLIResult(returncode=1, stdout="", stderr="boom")
    result = list_workspaces()
    assert result["ok"] is False
    assert result["stderr"] == "boom"


@patch("warren_mcp.server.run_warren")
def test_new_workspace_always_daemon_never_interactive(mock_run):
    mock_run.return_value = _ok()
    new_workspace("myproject", "develop.claude")
    args = mock_run.call_args[0][0]
    assert args == ["new", "--daemon", "--", "myproject", "develop.claude"]


@patch("warren_mcp.server.run_warren")
def test_new_workspace_with_server(mock_run):
    mock_run.return_value = _ok()
    new_workspace("myproject", "observe", server="node2")
    args = mock_run.call_args[0][0]
    assert args == ["new", "--daemon", "--server", "node2", "--", "myproject", "observe"]


@patch("warren_mcp.server.run_warren")
def test_new_workspace_flag_looking_project_is_not_parsed_as_an_option(mock_run):
    """Regression guard for audit 2026-10-16 #29: a model-chosen project/
    template value that looks like a CLI flag must reach warren as a
    literal positional, not get parsed as an option."""
    mock_run.return_value = _ok()
    new_workspace("--config=/etc/evil", "--daemon")
    args = mock_run.call_args[0][0]
    assert args == ["new", "--daemon", "--", "--config=/etc/evil", "--daemon"]


@patch("warren_mcp.server.run_warren")
def test_workspace_status_requires_server_arg(mock_run):
    mock_run.return_value = _ok("{}")
    workspace_status("ws-1", "node2")
    assert mock_run.call_args[0][0] == ["status", "--server", "node2", "--", "ws-1"]


@patch("warren_mcp.server.run_warren")
def test_workspace_status_flag_looking_workspace_id_is_not_parsed_as_an_option(mock_run):
    mock_run.return_value = _ok("{}")
    workspace_status("--server", "node2")
    args = mock_run.call_args[0][0]
    assert args == ["status", "--server", "node2", "--", "--server"]


@patch("warren_mcp.server.run_warren")
def test_exec_command_passes_argv_through(mock_run):
    mock_run.return_value = _ok("output")
    exec_command("ws-1", ["pytest", "tests/"])
    assert mock_run.call_args[0][0] == ["exec", "--", "ws-1", "pytest", "tests/"]


@patch("warren_mcp.server.run_warren")
def test_exec_command_flag_looking_argument_is_not_parsed_as_an_option(mock_run):
    """A command list that looks like warren CLI flags (e.g. a model telling
    the sandboxed process to run `warren --help`-style args) must still
    reach the sandbox literally, never get intercepted by warren itself."""
    mock_run.return_value = _ok("output")
    exec_command("ws-1", ["--daemon", "--server", "node2"])
    args = mock_run.call_args[0][0]
    assert args == ["exec", "--", "ws-1", "--daemon", "--server", "node2"]


@patch("warren_mcp.server.run_warren")
def test_destroy_workspace_local(mock_run):
    mock_run.return_value = _ok()
    destroy_workspace("ws-1")
    assert mock_run.call_args[0][0] == ["destroy", "--", "ws-1"]


@patch("warren_mcp.server.run_warren")
def test_destroy_workspace_remote(mock_run):
    mock_run.return_value = _ok()
    destroy_workspace("ws-1", server="node2")
    assert mock_run.call_args[0][0] == ["destroy", "--server", "node2", "--", "ws-1"]


def test_destroy_workspace_has_destructive_hint():
    """Audit 2026-10-16 P2 #52: destroy_workspace must carry destructiveHint=True so an
    MCP client can treat it with the same caution as any other irreversible tool call."""
    tool = mcp._tool_manager.get_tool("destroy_workspace")
    assert tool is not None
    assert tool.annotations is not None
    assert tool.annotations.destructiveHint is True


@patch("warren_mcp.server.run_warren")
def test_list_projects_omits_server_when_not_given(mock_run):
    mock_run.return_value = _ok("[]")
    list_projects()
    assert mock_run.call_args[0][0] == ["projects"]


@patch("warren_mcp.server.run_warren")
def test_list_remotes(mock_run):
    mock_run.return_value = _ok("node2\n")
    list_remotes()
    assert mock_run.call_args[0][0] == ["remote", "list"]


@patch("warren_mcp.server.run_warren")
def test_new_workspace_timeout_surfaces_as_error_dict_not_exception(mock_run):
    """Regression guard for audit 2026-10-16 #29: a real provision in
    progress at the subprocess timeout must surface as a clear error, not
    propagate TimeoutExpired uncaught to the MCP caller."""
    from warren_mcp.cli_bridge import WarrenCLITimeout

    mock_run.side_effect = WarrenCLITimeout("warren 'new' did not complete within 150.0s")
    result = new_workspace("myproject", "observe")
    assert result["ok"] is False
    assert "150.0s" in result["stderr"]
