"""AI8: the control-plane MCP endpoint, with user and workspace-scoped (AI9) tokens."""

from __future__ import annotations

import itertools
import json
import time
from contextlib import contextmanager
from unittest.mock import patch

import structlog
from fastapi.testclient import TestClient

from tests.control_plane import ADMIN_TOKEN, TASK_COMMAND, ScriptedRuntime, server_env
from warren.app import app

_ids = itertools.count(1)


@contextmanager
def _client(monkeypatch, tmp_path):
    server_env(monkeypatch, tmp_path)
    runtime = ScriptedRuntime()
    try:
        with patch("warren.app.PodmanRuntime", return_value=runtime), TestClient(app) as client:
            yield client, runtime
    finally:
        app.state._state.clear()


def _headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}", "Accept": "application/json, text/event-stream"}


def _rpc(client, token, method, params=None):
    resp = client.post(
        "/mcp",
        json={"jsonrpc": "2.0", "id": next(_ids), "method": method, "params": params or {}},
        headers=_headers(token),
    )
    return resp


def _call(client, token, tool, **arguments) -> tuple[bool, dict | str]:
    resp = _rpc(client, token, "tools/call", {"name": tool, "arguments": arguments})
    assert resp.status_code == 200, resp.text
    result = resp.json()["result"]
    if result.get("isError"):
        text = result["content"][0]["text"]
        return False, text.split(": ", 1)[1] if text.startswith("Error executing tool") else text
    return True, result["structuredContent"]


def _ok(client, token, tool, **arguments) -> dict:
    ok, body = _call(client, token, tool, **arguments)
    assert ok, body
    return body


def _reserve(client) -> dict:
    resp = client.post("/workspace-tokens", json={}, headers=_headers(ADMIN_TOKEN))
    assert resp.status_code == 201, resp.text
    return resp.json()


def test_tools_list_matches_the_cli_bridge_names(monkeypatch, tmp_path):
    with _client(monkeypatch, tmp_path) as (client, _):
        resp = _rpc(client, ADMIN_TOKEN, "tools/list")
        names = {t["name"] for t in resp.json()["result"]["tools"]}
        assert names == {
            "new_workspace", "list_workspaces", "workspace_status", "exec_command",
            "workspace_events", "wait_completed", "destroy_workspace",
        }


def test_mcp_requires_auth(monkeypatch, tmp_path):
    with _client(monkeypatch, tmp_path) as (client, _):
        resp = client.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
        assert resp.status_code == 401


def test_user_token_lifecycle(monkeypatch, tmp_path):
    with _client(monkeypatch, tmp_path) as (client, runtime):
        with structlog.testing.capture_logs() as logs:
            ws = _ok(client, ADMIN_TOKEN, "new_workspace", project="demo", template="observe")
        assert ws["status"] == "running"
        assert any(e.get("action") == "workspace.provision" and e["outcome"] == "success" for e in logs)
        assert any(e.get("action") == "mcp.tool_call" and e["tool"] == "new_workspace" for e in logs)
        ws_id = ws["workspace_id"]

        listed = _ok(client, ADMIN_TOKEN, "list_workspaces")["workspaces"]
        assert [w["workspace_id"] for w in listed] == [ws_id]
        assert _ok(client, ADMIN_TOKEN, "workspace_status", workspace_id=ws_id)["mode"] == "interactive"

        result = _ok(client, ADMIN_TOKEN, "exec_command", workspace_id=ws_id, command=["echo", "hi"])
        assert result["output"] == "echo hi\n"
        assert result["exit_code"] == 0

        assert _ok(client, ADMIN_TOKEN, "destroy_workspace", workspace_id=ws_id)["destroyed"] is True
        assert _ok(client, ADMIN_TOKEN, "list_workspaces")["workspaces"] == []
        assert len(_ok(client, ADMIN_TOKEN, "list_workspaces", include_inactive=True)["workspaces"]) == 1


def test_errors_are_tool_errors(monkeypatch, tmp_path):
    with _client(monkeypatch, tmp_path) as (client, _):
        ok, text = _call(client, ADMIN_TOKEN, "new_workspace", project="nope", template="observe")
        assert not ok and text.startswith("4")
        ok, text = _call(client, ADMIN_TOKEN, "workspace_status", workspace_id="missing")
        assert not ok and text.startswith("404")
        ok, text = _call(client, ADMIN_TOKEN, "new_workspace", project="demo", template="observe", mode="single-turn")
        assert not ok and "single_turn_requires_app" in text


def test_new_workspace_operation_id_is_idempotent(monkeypatch, tmp_path):
    """AM2: an MCP retry with the same operation_id returns the original workspace."""
    with _client(monkeypatch, tmp_path) as (client, runtime):
        first = _ok(client, ADMIN_TOKEN, "new_workspace", project="demo", operation_id="mcp-op-1")
        again = _ok(client, ADMIN_TOKEN, "new_workspace", project="demo", operation_id="mcp-op-1")
        ok, text = _call(client, ADMIN_TOKEN, "new_workspace", project="demo", template="task", operation_id="mcp-op-1")
        bad_ok, bad = _call(client, ADMIN_TOKEN, "new_workspace", project="demo", operation_id="no spaces")
        assert again["workspace_id"] == first["workspace_id"]
        assert first["operation"] == again["operation"] and first["operation"]["stage"] == "started"
        assert len(runtime._containers) == 1
        assert not ok and text.startswith("409") and "operation_conflict" in text
        assert not bad_ok and bad.startswith("422")


def test_reservation_token_provisions_once_and_only_touches_its_workspace(monkeypatch, tmp_path):
    with _client(monkeypatch, tmp_path) as (client, _):
        other = _ok(client, ADMIN_TOKEN, "new_workspace", project="demo", template="observe")["workspace_id"]
        reservation = _reserve(client)
        token = reservation["token"]
        assert token.startswith("wrnw_")

        assert _ok(client, token, "list_workspaces")["workspaces"] == []
        ws = _ok(client, token, "new_workspace", project="demo", template="task", mode="single-turn")
        assert ws["workspace_id"] == reservation["workspace_id"]
        assert ws["mode"] == "single-turn"
        ws_id = ws["workspace_id"]

        ok, text = _call(client, token, "new_workspace", project="demo", template="observe")
        assert not ok and text.startswith("403")
        assert [w["workspace_id"] for w in _ok(client, token, "list_workspaces")["workspaces"]] == [ws_id]
        for tool, extra in (
            ("workspace_status", {}),
            ("exec_command", {"command": ["id"]}),
            ("workspace_events", {}),
            ("destroy_workspace", {}),
        ):
            ok, text = _call(client, token, tool, workspace_id=other, **extra)
            assert not ok and text.startswith("403"), tool
        assert _ok(client, ADMIN_TOKEN, "workspace_status", workspace_id=other)["status"] == "running"

        assert client.post("/workspaces", json={"project": "demo", "template": "observe"}, headers=_headers(token)).status_code == 403
        assert client.get(f"/workspaces/{other}/status", headers=_headers(token)).status_code == 403
        assert client.post("/workspace-tokens", json={}, headers=_headers(token)).status_code == 403


def test_reservation_survives_a_failed_validation(monkeypatch, tmp_path):
    with _client(monkeypatch, tmp_path) as (client, _):
        token = _reserve(client)["token"]
        ok, _ = _call(client, token, "new_workspace", project="demo", template="observe", mode="single-turn")
        assert not ok
        assert _ok(client, token, "new_workspace", project="demo", template="task", mode="single-turn")


def test_unprovisioned_reservation_reaches_nothing_else(monkeypatch, tmp_path):
    with _client(monkeypatch, tmp_path) as (client, _):
        reservation = _reserve(client)
        h = _headers(reservation["token"])
        assert client.get(f"/workspaces/{reservation['workspace_id']}/status", headers=h).status_code == 403
        assert client.get("/workspaces", headers=h).status_code == 403


def test_events_and_wait_completed_return_the_verdict(monkeypatch, tmp_path):
    with _client(monkeypatch, tmp_path) as (client, runtime):
        token = _reserve(client)["token"]
        ws_id = _ok(client, token, "new_workspace", project="demo", template="task", mode="single-turn")["workspace_id"]

        assert _ok(client, token, "wait_completed", workspace_id=ws_id, timeout_seconds=0.1)["completed"] is False
        result = _ok(client, token, "exec_command", workspace_id=ws_id, command=[TASK_COMMAND, "pass"])
        assert result["exit_code"] == 0
        client.portal.call(app.state.registry.complete_single_turn, ws_id)

        page = _ok(client, token, "workspace_events", workspace_id=ws_id, since=None)
        (completed,) = [e["event"] for e in page["events"] if e["event"].get("type") == "workspace.completed"]
        assert page["closed"] is True
        assert completed["exit_code"] == 0
        assert completed["verdict"] == {"status": "pass", "summary": f"ran {TASK_COMMAND}"}
        assert _ok(client, token, "workspace_events", workspace_id=ws_id, since=page["next_since"])["events"] == []

        waited = _ok(client, token, "wait_completed", workspace_id=ws_id)
        assert waited == {"completed": True, "event": completed}
        assert _ok(client, token, "workspace_status", workspace_id=ws_id)["status"] == "destroyed"
        ok, text = _call(client, token, "exec_command", workspace_id=ws_id, command=["id"])
        assert not ok and text.startswith("409")

        assert _ok(client, token, "destroy_workspace", workspace_id=ws_id)["destroyed"] is True
        assert _ok(client, token, "workspace_status", workspace_id=ws_id)["status"] == "destroyed"
        ok, text = _call(client, token, "new_workspace", project="demo", template="observe")
        assert not ok and text.startswith("403")


def test_events_since_and_wait(monkeypatch, tmp_path):
    with _client(monkeypatch, tmp_path) as (client, _):
        ws_id = _ok(client, ADMIN_TOKEN, "new_workspace", project="demo", template="observe")["workspace_id"]
        buf = app.state.event_store.get_or_create(ws_id)
        for i in range(3):
            client.portal.call(buf.push, json.dumps({"type": "output", "n": i}))
        first = _ok(client, ADMIN_TOKEN, "workspace_events", workspace_id=ws_id, max_events=2)
        assert [e["seq"] for e in first["events"]] == [0, 1]
        rest = _ok(client, ADMIN_TOKEN, "workspace_events", workspace_id=ws_id, since=first["next_since"])
        assert [e["event"]["n"] for e in rest["events"]] == [2]
        start = time.monotonic()
        empty = _ok(client, ADMIN_TOKEN, "workspace_events", workspace_id=ws_id, since=rest["next_since"], wait_seconds=0.2)
        assert empty["events"] == [] and time.monotonic() - start >= 0.2


def test_scoped_token_on_destroyed_interactive_workspace_is_dead(monkeypatch, tmp_path):
    with _client(monkeypatch, tmp_path) as (client, _):
        ws_id = _ok(client, ADMIN_TOKEN, "new_workspace", project="demo", template="observe")["workspace_id"]
        token = client.post(f"/workspaces/{ws_id}/tokens", json={}, headers=_headers(ADMIN_TOKEN)).json()["token"]
        client.portal.call(app.state.registry.store.update_status, ws_id, "destroyed")
        assert _rpc(client, token, "tools/list").status_code == 401


_BEDROCK_YAML = """\
name: demo
templates:
  bedrock:
    app: claude
    model_access: bedrock
  bedrock_env:
    app: claude
    env:
      CLAUDE_CODE_USE_BEDROCK: "1"
  bedrock_oauth:
    app: claude
    model_access: bedrock
    secrets:
      - name: CLAUDE_CODE_OAUTH_TOKEN
"""


def test_new_workspace_applies_bedrock_model_access_like_rest(monkeypatch, tmp_path):
    """MCP provisioning goes through the REST handler, so Bedrock mode and its
    validation are identical."""
    with _client(monkeypatch, tmp_path) as (client, runtime):
        (tmp_path / "projects" / "demo.yaml").write_text(_BEDROCK_YAML)
        specs = []
        provision = runtime.provision

        async def _record(spec):
            specs.append(spec)
            return await provision(spec)

        runtime.provision = _record
        for template in ("bedrock", "bedrock_env"):
            _ok(client, ADMIN_TOKEN, "new_workspace", project="demo", template=template)
        _wait = time.monotonic() + 5
        while len(specs) < 2 and time.monotonic() < _wait:
            time.sleep(0.05)
        assert [s.model_access for s in specs] == ["bedrock", "bedrock"]
        assert all(s.template_env["CLAUDE_CODE_USE_BEDROCK"] == "1" for s in specs)

        ok, text = _call(client, ADMIN_TOKEN, "new_workspace", project="demo", template="bedrock_oauth")
        assert not ok and text.startswith("422") and "AWS identity" in text
        rest = client.post(
            "/workspaces", json={"project": "demo", "template": "bedrock_oauth"}, headers=_headers(ADMIN_TOKEN)
        )
        assert rest.status_code == 422 and "AWS identity" in rest.text
