"""AC1.6 smoke: `warren connect` to a podman (ssh) and an ECS remote, with the
server faked and ssh/aws replaced by stub executables, so the foreground-child
hand-off runs for real. Native on Windows; on POSIX the Windows branch is
forced, since the exec hand-off would replace the test process.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from unittest.mock import MagicMock

import httpx
import pytest
import respx
from typer.testing import CliRunner

from warren_cli.main import app

_WS = "abc12345-aaaa-bbbb-cccc-ddddeeeeffff"


def _stub(bin_dir: Path, name: str, exit_code: int, log: Path) -> None:
    script = bin_dir / f"{name}_stub.py"
    script.write_text(
        "import json, sys\n"
        f"with open({str(log)!r}, 'a') as f:\n"
        "    f.write(json.dumps(sys.argv[1:]) + '\\n')\n"
        f"sys.exit({exit_code})\n"
    )
    if sys.platform == "win32":
        (bin_dir / f"{name}.cmd").write_text(f'@"{sys.executable}" "{script}" %*\r\n')
    else:
        exe = bin_dir / name
        exe.write_text(f'#!/bin/sh\nexec "{sys.executable}" "{script}" "$@"\n')
        exe.chmod(0o755)


@pytest.fixture
def stub_path(tmp_path, monkeypatch):
    from warren_common import winsupport

    if sys.platform != "win32":
        monkeypatch.setattr(winsupport, "is_windows", lambda: True)
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    monkeypatch.setenv("PATH", str(bin_dir) + os.pathsep + os.environ.get("PATH", ""))
    return bin_dir


def _calls(log: Path) -> list[list[str]]:
    return [json.loads(line) for line in log.read_text().splitlines()]


def test_connect_podman_remote_returns_child_exit_code(tmp_path, stub_path, monkeypatch):
    log = tmp_path / "ssh.log"
    _stub(stub_path, "ssh", 7, log)
    config = tmp_path / "config.toml"
    config.write_text('[remotes.node2]\nruntime_type = "ssh"\nssh_host = "node2"\nauth_token = "t"\n')
    monkeypatch.setattr(
        "warren_cli.dispatch.start_ssh_port_forward", lambda *a, **kw: (MagicMock(), 54400)
    )

    with respx.mock(base_url="http://127.0.0.1:54400") as m:
        m.get("/workspaces").mock(return_value=httpx.Response(200, json=[
            {"workspace_id": _WS, "project": "p", "intent": "develop", "status": "running"}
        ]))
        m.post(f"/workspaces/{_WS}/ensure_running").mock(
            return_value=httpx.Response(200, json={"container_id": "c0ffee", "status": "running"})
        )
        result = CliRunner().invoke(app, ["connect", _WS[:8], "--server", "node2", "--config", str(config)])

    assert result.exit_code == 7, (result.output, result.exception)
    (argv,) = _calls(log)
    assert argv[0] == "-t"
    assert "node2" in argv


def test_connect_ecs_remote_returns_child_exit_code(tmp_path, stub_path, monkeypatch):
    log = tmp_path / "aws.log"
    _stub(stub_path, "aws", 5, log)
    _stub(stub_path, "session-manager-plugin", 0, tmp_path / "smp.log")
    config = tmp_path / "config.toml"
    config.write_text(
        '[remotes.prodecs]\nruntime_type = "ecs"\necs_cluster = "cl"\n'
        'ecs_service = "warren-orchestrator"\naws_audience = "warren-prod"\n'
    )
    monkeypatch.setattr(
        "warren_cli.dispatch.start_orchestrator_port_forward", lambda *a, **kw: (MagicMock(), 54401)
    )
    monkeypatch.setattr("warren_cli.dispatch.wait_for_ecs_exec_agent", lambda *a, **kw: None)
    task = "arn:aws:ecs:eu-west-1:1:task/cl/abc"

    with respx.mock(base_url="http://127.0.0.1:54401") as m:
        m.get("/workspaces").mock(return_value=httpx.Response(200, json=[
            {"workspace_id": _WS, "project": "p", "intent": "develop", "status": "running"}
        ]))
        m.post(f"/workspaces/{_WS}/ensure_running").mock(
            return_value=httpx.Response(200, json={"container_id": task, "status": "running"})
        )
        result = CliRunner().invoke(app, ["connect", _WS[:8], "--server", "prodecs", "--config", str(config)])

    assert result.exit_code == 5, (result.output, result.exception)
    (argv,) = _calls(log)
    assert argv[:2] == ["ecs", "execute-command"]
    assert task in argv
