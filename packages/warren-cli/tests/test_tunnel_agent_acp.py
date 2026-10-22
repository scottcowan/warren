"""AM3: `warren tunnel <ws> [port]` reaches an agent workspace's loopback ACP
endpoint through SSM port forwarding (mocked: no AWS, no session-manager-plugin)."""
from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import httpx
import respx
from typer.testing import CliRunner

from warren_cli import dispatch
from warren_cli.main import app

runner = CliRunner()
_WS = "abc12345-aaaa-bbbb-cccc-ddddeeeeffff"
_TASK = "arn:aws:ecs:us-east-1:1:task/prod-cluster/0123abcd"


def _config(tmp_path: Path) -> Path:
    path = tmp_path / "config.toml"
    path.write_text(
        '[remotes.prodecs]\nruntime_type = "ecs"\necs_cluster = "prod-cluster"\n'
        'ecs_service = "warren-orchestrator"\naws_audience = "warren-prod"\n'
    )
    return path


def _invoke(tmp_path: Path, monkeypatch, ws: dict, *args: str):
    monkeypatch.setattr(dispatch, "start_orchestrator_port_forward", lambda *a, **kw: (MagicMock(), 54323))
    monkeypatch.setattr(dispatch.shutil, "which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(dispatch, "_resolve_ecs_container_runtime_id", lambda cluster, arn: "rt-1")
    handed: list = []
    monkeypatch.setattr(dispatch, "_hand_off", lambda exe, argv, *a: handed.append(argv))
    with respx.mock(base_url="http://127.0.0.1:54323", assert_all_called=False) as m:
        m.get("/workspaces").mock(return_value=httpx.Response(200, json=[{"workspace_id": _WS, **ws}]))
        result = runner.invoke(app, ["tunnel", _WS, *args, "--server", "prodecs", "--config", str(_config(tmp_path))])
    return result, handed


def test_tunnel_defaults_to_the_agent_workspaces_acp_port(tmp_path, monkeypatch):
    result, handed = _invoke(
        tmp_path, monkeypatch, {"container_id": _TASK, "acp_port": 8765, "agent_harness": "opencode"}
    )
    assert result.exit_code == 0, (result.output, result.exception)
    assert handed == [[
        "aws", "ssm", "start-session",
        "--target", "ecs:prod-cluster_0123abcd_rt-1",
        "--document-name", "AWS-StartPortForwardingSession",
        "--parameters", "portNumber=8765,localPortNumber=8765",
    ]]


def test_tunnel_takes_the_port_positionally(tmp_path, monkeypatch):
    result, handed = _invoke(tmp_path, monkeypatch, {"container_id": _TASK, "acp_port": 8765}, "9000",
                             "--local-port", "19000")
    assert result.exit_code == 0, (result.output, result.exception)
    assert handed[0][-1] == "portNumber=9000,localPortNumber=19000"


def test_tunnel_without_a_port_needs_an_agent_workspace(tmp_path, monkeypatch):
    result, handed = _invoke(tmp_path, monkeypatch, {"container_id": _TASK})
    assert result.exit_code == 2 and not handed
    assert "not an agent workspace" in result.output


def test_tunnel_rejects_two_different_ports(tmp_path, monkeypatch):
    result, handed = _invoke(tmp_path, monkeypatch, {"container_id": _TASK}, "9000", "--port", "9001")
    assert result.exit_code == 2 and not handed
