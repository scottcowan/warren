"""ECS-flow wiring: server selection, doctor, runs, hints, output caps,
annotations. No AWS, no network: run_warren is mocked or a fake `warren`
script is put on PATH."""

from __future__ import annotations

import json
import os
import stat
from unittest.mock import patch

import pytest

from warren_mcp import server as srv
from warren_mcp.cli_bridge import CLIResult, run_warren


def _ok(stdout: str = "") -> CLIResult:
    return CLIResult(returncode=0, stdout=stdout, stderr="")


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for v in ("WARREN_MCP_SERVER", "WARREN_MCP_CONFIG", "WARREN_MCP_BIN",
              "WARREN_MCP_TIMEOUT", "WARREN_MCP_MAX_OUTPUT"):
        monkeypatch.delenv(v, raising=False)


def _fake_warren(tmp_path, body: str):
    d = tmp_path / "bin"
    d.mkdir()
    f = d / "warren"
    f.write_text("#!/bin/sh\n" + body + "\n")
    f.chmod(f.stat().st_mode | stat.S_IEXEC)
    return d


# --- server / config selection -------------------------------------------

@patch("warren_mcp.server.run_warren")
def test_env_default_server_applies_to_remote_commands(mock_run, monkeypatch):
    monkeypatch.setenv("WARREN_MCP_SERVER", "prod-ecs")
    mock_run.return_value = _ok("[]")
    srv.list_projects()
    assert mock_run.call_args[0][0] == ["projects", "--json", "--server", "prod-ecs"]
    srv.new_workspace("p", "t")
    assert mock_run.call_args[0][0] == ["new", "--daemon", "--server", "prod-ecs", "--", "p", "t"]
    mock_run.return_value = _ok("{}")
    srv.workspace_status("ws-1")
    assert mock_run.call_args[0][0] == ["status", "--json", "--server", "prod-ecs", "--", "ws-1"]


@patch("warren_mcp.server.run_warren")
def test_explicit_server_beats_env(mock_run, monkeypatch):
    monkeypatch.setenv("WARREN_MCP_SERVER", "prod-ecs")
    mock_run.return_value = _ok("[]")
    srv.list_projects(server="other")
    assert mock_run.call_args[0][0] == ["projects", "--json", "--server", "other"]


@patch("warren_mcp.server.run_warren")
def test_config_env_passed_as_config_flag(mock_run, monkeypatch):
    monkeypatch.setenv("WARREN_MCP_CONFIG", "/tmp/w.toml")
    mock_run.return_value = _ok("[]")
    srv.list_projects(server="s")
    args = mock_run.call_args[0][0]
    assert args[args.index("--config") + 1] == "/tmp/w.toml"


@patch("warren_mcp.server.run_warren")
def test_status_without_server_or_env_is_a_clear_error(mock_run):
    r = srv.workspace_status("ws-1")
    assert r["ok"] is False and "server" in r["stderr"]
    mock_run.assert_not_called()


@pytest.mark.parametrize("bad", ["--config=/x", "a b", "", "-x", "a/b", "x" * 100])
@patch("warren_mcp.server.run_warren")
def test_bad_server_names_never_reach_cli(mock_run, bad):
    assert srv.list_projects(server=bad)["ok"] is False
    assert srv.new_workspace("p", "t", server=bad)["ok"] is False
    mock_run.assert_not_called()


@pytest.mark.parametrize("bad", ["--x", "a b", "", "../x", "a/b", ".hidden"])
@patch("warren_mcp.server.run_warren")
def test_bad_project_or_template_never_reach_cli(mock_run, bad):
    assert srv.new_workspace(bad, "observe")["ok"] is False
    assert srv.new_workspace("proj", bad)["ok"] is False
    mock_run.assert_not_called()


@patch("warren_mcp.server.run_warren")
def test_dotted_template_ok(mock_run):
    mock_run.return_value = _ok()
    srv.new_workspace("proj", "develop.claude", server="s")
    assert mock_run.call_args[0][0][-2:] == ["proj", "develop.claude"]


# --- runs / health / doctor ----------------------------------------------

@patch("warren_mcp.server.run_warren")
def test_run_tools_argv(mock_run):
    mock_run.return_value = _ok("{}")
    srv.run_status("abc123", server="s")
    assert mock_run.call_args[0][0] == ["run", "status", "--json", "--server", "s", "--", "abc123"]
    srv.run_result("abc123", server="s")
    assert mock_run.call_args[0][0] == ["run", "result", "--json", "--server", "s", "--", "abc123"]
    mock_run.return_value = _ok("[]")
    srv.run_list(server="s", all_owners=True)
    assert mock_run.call_args[0][0] == ["run", "list", "--json", "--all", "--server", "s"]


@patch("warren_mcp.server.run_warren")
def test_run_result_still_running_and_failed_are_data_not_errors(mock_run):
    """CLI exits 75 (running) / 1 (failed) / 124 (timed out) but still prints the result JSON."""
    for rc in (1, 75, 124):
        mock_run.return_value = CLIResult(rc, json.dumps({"status": "x"}), "")
        out = srv.run_result("abc", server="s")
        assert out["status"] == "x" and out["exit_code"] == rc


@pytest.mark.parametrize("bad", ["--x", "a/b", "", "a b"])
@patch("warren_mcp.server.run_warren")
def test_bad_run_id_refused(mock_run, bad):
    assert srv.run_status(bad, server="s")["ok"] is False
    mock_run.assert_not_called()


@patch("warren_mcp.server.run_warren")
def test_server_health(mock_run):
    mock_run.return_value = _ok("{}")
    srv.server_health(server="s")
    assert mock_run.call_args[0][0] == ["healthz", "--json", "--server", "s"]


@patch("warren_mcp.server.run_warren")
def test_doctor_uses_json_and_summarises_aws(mock_run):
    report = {"aws_sso": False, "runtimes": {"ecs": True}, "ecs": {}}
    mock_run.return_value = _ok(json.dumps(report))
    out = srv.doctor()
    assert mock_run.call_args[0][0] == ["doctor", "--json"]
    assert mock_run.call_args.kwargs.get("timeout", 0) >= 30
    assert out["report"]["aws_sso"] is False
    assert "aws sso login" in out["hint"]


@patch("warren_mcp.server.run_warren")
def test_doctor_non_json_falls_back_to_text(mock_run):
    mock_run.return_value = _ok("warren doctor\nRuntimes:")
    out = srv.doctor()
    assert out["ok"] is True and "Runtimes:" in out["stdout"]


# --- error hints -----------------------------------------------------------

@pytest.mark.parametrize(
    "stderr,needle",
    [
        ("The SSO session associated with this profile has expired", "aws sso login"),
        ("Error: Token has expired and refresh failed", "aws sso login"),
        ("Unable to locate credentials", "aws sso login"),
        ("SessionManagerPlugin is not found", "session-manager-plugin"),
        ("session-manager-plugin: command not found", "session-manager-plugin"),
        ("Select a server: non-interactive, pass --server", "server"),
    ],
)
def test_failure_hints(stderr, needle):
    d = CLIResult(1, "", stderr).as_dict()
    assert d["ok"] is False and needle in d["hint"]


def test_success_has_no_hint():
    assert "hint" not in CLIResult(0, "x", "").as_dict()


# --- bridge: binary override, env, caps, timeouts ---------------------------

def test_bin_override_env(tmp_path, monkeypatch):
    d = _fake_warren(tmp_path, 'echo "$@"')
    monkeypatch.setenv("WARREN_MCP_BIN", str(d / "warren"))
    monkeypatch.setenv("PATH", "/usr/bin:/bin")
    assert run_warren(["list"]).stdout.strip() == "list"


def test_child_env_is_noninteractive_and_passes_aws(tmp_path, monkeypatch):
    d = _fake_warren(tmp_path, 'echo "$AWS_PROFILE|$AWS_REGION|$NO_COLOR|$AWS_PAGER|$TERM"')
    monkeypatch.setenv("PATH", f"{d}:{os.environ['PATH']}")
    monkeypatch.setenv("AWS_PROFILE", "dev")
    monkeypatch.setenv("AWS_REGION", "eu-west-2")
    assert run_warren(["x"]).stdout.strip() == "dev|eu-west-2|1||dumb"


def test_output_is_capped(tmp_path, monkeypatch):
    d = _fake_warren(tmp_path, "head -c 5000 /dev/zero | tr '\\0' a")
    monkeypatch.setenv("PATH", f"{d}:{os.environ['PATH']}")
    monkeypatch.setenv("WARREN_MCP_MAX_OUTPUT", "1000")
    r = run_warren(["x"])
    assert len(r.stdout) < 1300 and "truncated" in r.stdout
    assert r.truncated is True


@patch("warren_mcp.server.run_warren")
def test_truncated_json_is_an_error_dict_not_an_exception(mock_run):
    mock_run.return_value = CLIResult(0, '{"a": [1,2', "", truncated=True)
    out = srv.list_projects(server="s")
    assert out["ok"] is False and "truncated" in out["stderr"]


@patch("warren_mcp.server.run_warren")
def test_non_json_success_is_an_error_dict_not_an_exception(mock_run):
    mock_run.return_value = _ok("not json")
    assert srv.list_projects(server="s")["ok"] is False


def test_timeout_env(monkeypatch):
    from warren_mcp.cli_bridge import default_timeout

    monkeypatch.setenv("WARREN_MCP_TIMEOUT", "321")
    assert default_timeout() == 321.0
    monkeypatch.setenv("WARREN_MCP_TIMEOUT", "junk")
    assert default_timeout() > 120.0


# --- annotations ------------------------------------------------------------

READ_ONLY = ["list_workspaces", "list_projects", "workspace_status", "list_remotes",
             "doctor", "server_health", "run_status", "run_result", "run_list"]


@pytest.mark.parametrize("name", READ_ONLY)
def test_readonly_tools_annotated(name):
    t = srv.mcp._tool_manager.get_tool(name)
    assert t is not None and t.annotations.readOnlyHint is True


def test_mutating_tool_annotations():
    g = srv.mcp._tool_manager.get_tool
    assert g("new_workspace").annotations.readOnlyHint is False
    assert g("new_workspace").annotations.destructiveHint is False
    assert g("exec_command").annotations.destructiveHint is True
    assert g("exec_command").annotations.openWorldHint is True
