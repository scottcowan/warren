"""`warren connect`/`warren tunnel` remote workspace-id resolution and ECS
cluster wiring (audit 2026-10-16 #35):

- Ambiguous short-id prefixes must error clearly, same as the local picker
  (commands/workspaces.py::_load_workspace_state) already does -- not
  silently resolve to the first match.
- `tunnel` must use the targeted remote profile's own `ecs_cluster`, not
  silently fall back to nothing / the wrong source.
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock

import httpx
import pytest
import respx
from typer.testing import CliRunner

from warren_cli.main import app

posix_exec_only = pytest.mark.skipif(
    sys.platform == "win32", reason="asserts the POSIX os.execvp hand-off; Windows covered by test_windows_handoff"
)


runner = CliRunner()

_WS_A = "abc12345-aaaa-bbbb-cccc-ddddeeeeffff"
_WS_B = "abc99999-aaaa-bbbb-cccc-ddddeeeeffff"


def _write_ssh_remote_config(tmp_path: Path) -> Path:
    config_path = tmp_path / "config.toml"
    config_path.write_text(
        '[remotes.node2]\n'
        'runtime_type = "ssh"\n'
        'ssh_host = "node2"\n'
        'auth_token = "tok-node2"\n'
    )
    return config_path


def _write_ecs_remote_config(tmp_path: Path, *, ecs_cluster: str = "prod-cluster") -> Path:
    config_path = tmp_path / "config.toml"
    config_path.write_text(
        '[remotes.prodecs]\n'
        'runtime_type = "ecs"\n'
        f'ecs_cluster = "{ecs_cluster}"\n'
        'ecs_service = "warren-orchestrator"\n'
        'aws_audience = "warren-prod"\n'
    )
    return config_path


def test_connect_ambiguous_prefix_errors_instead_of_picking_first_match(tmp_path: Path, monkeypatch):
    config_path = _write_ssh_remote_config(tmp_path)
    fake_proc = MagicMock()
    monkeypatch.setattr(
        "warren_cli.dispatch.start_ssh_port_forward",
        lambda *a, **kw: (fake_proc, 54321),
    )
    connect_calls = []
    monkeypatch.setattr(
        "warren_cli.dispatch.connect_via_ssh_podman_exec",
        lambda *a, **kw: connect_calls.append((a, kw)),
    )

    with respx.mock(base_url="http://127.0.0.1:54321") as m:
        m.get("/workspaces").mock(
            return_value=httpx.Response(
                200,
                json=[
                    {"workspace_id": _WS_A, "project": "p", "intent": "develop", "status": "running"},
                    {"workspace_id": _WS_B, "project": "p", "intent": "develop", "status": "running"},
                ],
            )
        )

        result = runner.invoke(
            app,
            ["connect", "abc", "--server", "node2", "--config", str(config_path)],
        )

    assert result.exit_code == 1
    assert "ambiguous" in result.output
    assert not connect_calls


@posix_exec_only
def test_tunnel_ambiguous_prefix_errors_instead_of_picking_first_match(tmp_path: Path, monkeypatch):
    config_path = _write_ecs_remote_config(tmp_path)
    fake_proc = MagicMock()
    monkeypatch.setattr(
        "warren_cli.dispatch.start_orchestrator_port_forward",
        lambda *a, **kw: (fake_proc, 54322),
    )
    tunnel_calls = []
    monkeypatch.setattr(
        "warren_cli.dispatch._tunnel_via_execvp",
        lambda *a, **kw: tunnel_calls.append((a, kw)),
    )

    with respx.mock(base_url="http://127.0.0.1:54322") as m:
        m.get("/workspaces").mock(
            return_value=httpx.Response(
                200,
                json=[
                    {"workspace_id": _WS_A, "container_id": "arn:aws:ecs:us-east-1:1:task/c/1"},
                    {"workspace_id": _WS_B, "container_id": "arn:aws:ecs:us-east-1:1:task/c/2"},
                ],
            )
        )

        result = runner.invoke(
            app,
            ["tunnel", "abc", "--port", "8420", "--server", "prodecs", "--config", str(config_path)],
        )

    assert result.exit_code == 1
    assert "ambiguous" in result.output
    assert not tunnel_calls


@posix_exec_only
def test_tunnel_uses_remote_profiles_own_ecs_cluster(tmp_path: Path, monkeypatch):
    """Regression guard: `tunnel` used to read a nonexistent `cfg.ecs_cluster`
    (always missing -- WarrenCLIConfig has no such attribute) and silently
    fall through to WARREN_ECS_CLUSTER / nothing, ignoring the targeted
    remote's own `ecs_cluster` field entirely."""
    config_path = _write_ecs_remote_config(tmp_path, ecs_cluster="prod-cluster")
    # A conflicting env var proves the fix reads the profile, not the env.
    monkeypatch.setenv("WARREN_ECS_CLUSTER", "wrong-cluster-from-env")

    fake_proc = MagicMock()
    monkeypatch.setattr(
        "warren_cli.dispatch.start_orchestrator_port_forward",
        lambda *a, **kw: (fake_proc, 54323),
    )
    tunnel_calls = []
    monkeypatch.setattr(
        "warren_cli.dispatch._tunnel_via_execvp",
        lambda state, **kw: tunnel_calls.append(state),
    )

    with respx.mock(base_url="http://127.0.0.1:54323") as m:
        m.get("/workspaces").mock(
            return_value=httpx.Response(
                200,
                json=[{"workspace_id": _WS_A, "container_id": "arn:aws:ecs:us-east-1:1:task/c/1"}],
            )
        )

        result = runner.invoke(
            app,
            ["tunnel", _WS_A, "--port", "8420", "--server", "prodecs", "--config", str(config_path)],
        )

    assert result.exit_code == 0, (result.output, result.exception)
    assert len(tunnel_calls) == 1
    assert tunnel_calls[0]["ecs_cluster"] == "prod-cluster"


def _mock_ecs_connect_server(
    m, container_id: str = "arn:aws:ecs:us-east-1:1:task/c/1", spec_json=None, harnesses=None, newer_image=None
):
    ws = {"workspace_id": _WS_A, "project": "p", "intent": "develop", "status": "stopped"}
    if spec_json is not None:
        ws["spec_json"] = spec_json
    if harnesses is not None:
        ws["harnesses"] = harnesses
    m.get("/workspaces").mock(return_value=httpx.Response(200, json=[ws]))
    m.post(f"/workspaces/{_WS_A}/ensure_running").mock(
        return_value=httpx.Response(
            200, json={"container_id": container_id, "status": "running", "newer_image": newer_image}
        )
    )


def _patch_ecs_connect(monkeypatch, port: int) -> list:
    fake_proc = MagicMock()
    monkeypatch.setattr(
        "warren_cli.dispatch.start_orchestrator_port_forward",
        lambda *a, **kw: (fake_proc, port),
    )
    calls: list = []
    monkeypatch.setattr(
        "warren_cli.dispatch.connect_via_ecs_exec",
        lambda cluster, task_arn, **kw: calls.append((cluster, task_arn, kw)),
    )
    return calls


def test_connect_ecs_remote_routes_to_ecs_exec_after_ensure_running(tmp_path: Path, monkeypatch):
    """BB8: ECS server-mode connect used to fall into "no direct attach path"
    after ensure_running; it must exec into the task the server returned."""
    config_path = _write_ecs_remote_config(tmp_path, ecs_cluster="prod-cluster")
    monkeypatch.setenv("WARREN_ECS_CLUSTER", "wrong-cluster-from-env")
    calls = _patch_ecs_connect(monkeypatch, 54324)

    with respx.mock(base_url="http://127.0.0.1:54324") as m:
        _mock_ecs_connect_server(m)
        result = runner.invoke(
            app, ["connect", _WS_A[:8], "--server", "prodecs", "--config", str(config_path)]
        )

    assert result.exit_code == 0, (result.output, result.exception)
    assert calls == [("prod-cluster", "arn:aws:ecs:us-east-1:1:task/c/1", {"shell": "bash", "harness": None, "new": False})]
    assert "no direct attach path" not in result.output


def test_connect_ecs_remote_uses_templates_shell_from_spec(tmp_path: Path, monkeypatch):
    config_path = _write_ecs_remote_config(tmp_path)
    calls = _patch_ecs_connect(monkeypatch, 54325)

    with respx.mock(base_url="http://127.0.0.1:54325") as m:
        _mock_ecs_connect_server(m, spec_json='{"app": "zsh"}')
        result = runner.invoke(
            app, ["connect", _WS_A, "--server", "prodecs", "--config", str(config_path)]
        )

    assert result.exit_code == 0, (result.output, result.exception)
    assert calls[0][2] == {"shell": "zsh", "harness": None, "new": False}


def test_connect_ecs_remote_agent_app_still_attaches_a_shell(tmp_path: Path, monkeypatch):
    """A non-shell app (claude) runs as PID 1 via WARREN_APP_CMD; connect opens a
    shell next to it rather than a second copy of the agent."""
    config_path = _write_ecs_remote_config(tmp_path)
    calls = _patch_ecs_connect(monkeypatch, 54326)

    with respx.mock(base_url="http://127.0.0.1:54326") as m:
        _mock_ecs_connect_server(m, spec_json='{"app": "claude"}')
        result = runner.invoke(
            app, ["connect", _WS_A, "--server", "prodecs", "--config", str(config_path)]
        )

    assert result.exit_code == 0, (result.output, result.exception)
    assert calls[0][2] == {"shell": "bash", "harness": None, "new": False}


def test_connect_ecs_remote_without_task_arn_errors(tmp_path: Path, monkeypatch):
    config_path = _write_ecs_remote_config(tmp_path)
    calls = _patch_ecs_connect(monkeypatch, 54327)

    with respx.mock(base_url="http://127.0.0.1:54327") as m:
        _mock_ecs_connect_server(m, container_id="")
        result = runner.invoke(
            app, ["connect", _WS_A, "--server", "prodecs", "--config", str(config_path)]
        )

    assert result.exit_code == 1
    assert "no ECS task ARN" in result.output
    assert not calls


def _patch_connect_sleep(monkeypatch) -> list:
    sleeps: list = []

    async def _fake_sleep(seconds):
        sleeps.append(seconds)

    monkeypatch.setattr("warren_cli.main._sleep", _fake_sleep)
    monkeypatch.setattr("warren_cli.main._clock", lambda: float(sum(sleeps)))
    return sleeps


def test_connect_retries_ensure_running_while_task_is_starting(tmp_path: Path, monkeypatch):
    """The server answers 503 + Retry-After after its own bounded wait; a client
    timeout means the same. Both are "still starting", not failures."""
    config_path = _write_ecs_remote_config(tmp_path)
    calls = _patch_ecs_connect(monkeypatch, 54328)
    sleeps = _patch_connect_sleep(monkeypatch)

    with respx.mock(base_url="http://127.0.0.1:54328") as m:
        _mock_ecs_connect_server(m)
        route = m.post(f"/workspaces/{_WS_A}/ensure_running")
        route.side_effect = [
            httpx.Response(503, headers={"Retry-After": "3"}, json={"detail": "starting"}),
            httpx.ReadTimeout("timed out"),
            httpx.Response(200, json={"container_id": "arn:aws:ecs:us-east-1:1:task/c/1", "status": "running"}),
        ]
        result = runner.invoke(
            app, ["connect", _WS_A, "--server", "prodecs", "--config", str(config_path)]
        )

    assert result.exit_code == 0, (result.output, result.exception)
    assert route.call_count == 3
    assert sleeps == [3.0, 5.0]
    assert "still starting" in result.output
    assert calls == [("prod-cluster", "arn:aws:ecs:us-east-1:1:task/c/1", {"shell": "bash", "harness": None, "new": False})]


def test_connect_ensure_running_gives_up_at_start_timeout(tmp_path: Path, monkeypatch):
    config_path = _write_ecs_remote_config(tmp_path)
    calls = _patch_ecs_connect(monkeypatch, 54329)
    sleeps = _patch_connect_sleep(monkeypatch)

    with respx.mock(base_url="http://127.0.0.1:54329") as m:
        _mock_ecs_connect_server(m)
        route = m.post(f"/workspaces/{_WS_A}/ensure_running")
        route.side_effect = [httpx.Response(503, headers={"Retry-After": "10"})] * 3
        result = runner.invoke(
            app,
            ["connect", _WS_A, "--server", "prodecs", "--config", str(config_path), "--start-timeout", "15"],
        )

    assert result.exit_code == 1
    assert sleeps == [10.0]
    assert "did not start within 15s" in " ".join(result.output.split())
    assert not calls


def test_connect_ensure_running_503_without_retry_after_is_an_error(tmp_path: Path, monkeypatch):
    config_path = _write_ecs_remote_config(tmp_path)
    calls = _patch_ecs_connect(monkeypatch, 54330)
    sleeps = _patch_connect_sleep(monkeypatch)

    with respx.mock(base_url="http://127.0.0.1:54330") as m:
        _mock_ecs_connect_server(m)
        m.post(f"/workspaces/{_WS_A}/ensure_running").mock(return_value=httpx.Response(503, text="down"))
        result = runner.invoke(
            app, ["connect", _WS_A, "--server", "prodecs", "--config", str(config_path)]
        )

    assert result.exit_code == 1
    assert "HTTP 503" in result.output
    assert not sleeps
    assert not calls
def test_connect_ssh_sets_terminal_title_from_workspace_labels(tmp_path: Path, monkeypatch):
    config_path = _write_ssh_remote_config(tmp_path)
    fake_proc = MagicMock()
    monkeypatch.setattr(
        "warren_cli.dispatch.start_ssh_port_forward", lambda *a, **kw: (fake_proc, 54324)
    )
    monkeypatch.setattr("warren_cli.dispatch.connect_via_ssh_podman_exec", lambda *a, **kw: None)
    titles = []
    monkeypatch.setattr("warren_cli.dispatch.set_terminal_title", lambda *a, **kw: titles.append(a))

    with respx.mock(base_url="http://127.0.0.1:54324") as m:
        m.get("/workspaces").mock(
            return_value=httpx.Response(
                200,
                json=[{"workspace_id": _WS_A, "project": "p", "intent": "develop", "status": "running"}],
            )
        )
        m.post(f"/workspaces/{_WS_A}/ensure_running").mock(
            return_value=httpx.Response(200, json={"container_id": "ctr-1"})
        )
        result = runner.invoke(
            app, ["connect", "abc", "--server", "node2", "--config", str(config_path)]
        )

    assert result.exit_code == 0, result.output
    assert titles == [("p", "develop", _WS_A)]


def test_connect_ecs_remote_passes_harness_and_new(tmp_path: Path, monkeypatch):
    """AG2a: `--harness`/`--new` reach the warren shell inside the task."""
    config_path = _write_ecs_remote_config(tmp_path)
    calls = _patch_ecs_connect(monkeypatch, 54331)

    with respx.mock(base_url="http://127.0.0.1:54331") as m:
        _mock_ecs_connect_server(m, harnesses=["claude", "codex"])
        result = runner.invoke(
            app,
            ["connect", _WS_A, "--server", "prodecs", "--config", str(config_path), "--harness", "codex", "--new"],
        )

    assert result.exit_code == 0, (result.output, result.exception)
    assert calls[0][2] == {"shell": "bash", "harness": "codex", "new": True}


def test_connect_ecs_remote_rejects_harness_not_in_template(tmp_path: Path, monkeypatch):
    config_path = _write_ecs_remote_config(tmp_path)
    calls = _patch_ecs_connect(monkeypatch, 54332)

    with respx.mock(base_url="http://127.0.0.1:54332") as m:
        _mock_ecs_connect_server(m, harnesses=["claude"])
        result = runner.invoke(
            app,
            ["connect", _WS_A, "--server", "prodecs", "--config", str(config_path), "--harness", "codex"],
        )

    assert result.exit_code == 1
    assert "not in this workspace's template" in result.output
    assert calls == []


def test_connect_says_when_a_newer_image_is_available(tmp_path: Path, monkeypatch):
    """AB1: a running task keeps its image; connect mentions the newer one."""
    config_path = _write_ecs_remote_config(tmp_path)
    calls = _patch_ecs_connect(monkeypatch, 54333)

    with respx.mock(base_url="http://127.0.0.1:54333") as m:
        _mock_ecs_connect_server(m, newer_image="registry/ws:v2")
        result = runner.invoke(app, ["connect", _WS_A, "--server", "prodecs", "--config", str(config_path)])

    assert result.exit_code == 0, (result.output, result.exception)
    assert "newer image is available" in result.output and "registry/ws:v2" in result.output
    assert len(calls) == 1
