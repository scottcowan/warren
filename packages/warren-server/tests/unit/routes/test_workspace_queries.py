"""Owner-only workspace queries (files, file, diff, agent-state) over the exec channel."""

from __future__ import annotations

import base64
from unittest.mock import AsyncMock, MagicMock

import structlog
from warren_common.agent_state import AgentState

from tests.unit.routes.test_workspace_exec import _ADMIN, _client


def _answer(ws_id: str, argv: list[str]) -> tuple[list[bytes], int]:
    sub = argv[1]
    if sub == "list":
        return [b"F 3 a.txt\nF 4 src/b.py\nEND\n"], 0
    if sub == "read":
        return [b"OK 5\n" + base64.encodebytes(b"hello") + b"END\n"], 0
    return [b"REPO .\n" + base64.encodebytes(b"diff --git a/a b/a\n") + b"ENDREPO\nEND\n"], 0


def test_owner_lists_reads_and_diffs(monkeypatch, tmp_path):
    with _client(monkeypatch, tmp_path) as (client, registry):
        registry.runtime.exec_handler = _answer
        with structlog.testing.capture_logs() as logs:
            files = client.get("/workspaces/ws-a/files", headers=_ADMIN)
            body = client.get("/workspaces/ws-a/files/src/b.py", headers=_ADMIN)
            diff = client.get("/workspaces/ws-a/diff", headers=_ADMIN)
        assert files.status_code == 200
        assert [e["path"] for e in files.json()] == ["a.txt", "src", "src/b.py"]
        assert body.status_code == 200 and body.content == b"hello"
        assert diff.json() == {"repos": [{"repo": ".", "diff": "diff --git a/a b/a\n", "truncated": False}]}
        assert [argv for _, argv in registry.runtime.exec_calls] == [
            ["/usr/local/bin/warren-query", "list", "/workspace"],
            ["/usr/local/bin/warren-query", "read", "/workspace", "src/b.py", "1048576"],
            ["/usr/local/bin/warren-query", "diff", "/workspace", "1048576"],
        ]
        queries = [e["query"] for e in logs if e.get("action") == "workspace.query"]
        assert queries == ["files", "file", "diff"]


def test_non_owner_missing_and_stopped_are_rejected_before_any_exec(monkeypatch, tmp_path):
    with _client(monkeypatch, tmp_path) as (client, registry):
        registry.runtime.exec_handler = _answer
        for path in ("files", "files/a.txt", "diff", "agent-state"):
            assert client.get(f"/workspaces/ws-other/{path}", headers=_ADMIN).status_code == 403
            assert client.get(f"/workspaces/nope/{path}", headers=_ADMIN).status_code == 404
        for path in ("files", "files/a.txt", "diff"):
            assert client.get(f"/workspaces/ws-stopped/{path}", headers=_ADMIN).status_code == 409
        assert client.get("/workspaces/ws-a/files", headers={}).status_code == 401
        assert registry.runtime.exec_calls == []


def test_bad_and_excluded_paths_never_reach_the_workspace(monkeypatch, tmp_path):
    with _client(monkeypatch, tmp_path) as (client, registry):
        registry.runtime.exec_handler = _answer
        assert client.get("/workspaces/ws-a/files/a%2F..%2F..%2Fetc/passwd", headers=_ADMIN).status_code == 400
        assert client.get("/workspaces/ws-a/files//etc/passwd", headers=_ADMIN).status_code == 400
        assert client.get("/workspaces/ws-a/files/a%0Ab", headers=_ADMIN).status_code in (400, 404)
        assert client.get("/workspaces/ws-a/files/.env", headers=_ADMIN).status_code == 404
        assert client.get("/workspaces/ws-a/files/x/.git/config", headers=_ADMIN).status_code == 404
        assert registry.runtime.exec_calls == []


def test_runtime_without_exec_channel_is_501(monkeypatch, tmp_path):
    with _client(monkeypatch, tmp_path, runtime=MagicMock(spec=["status"])) as (client, _):
        assert client.get("/workspaces/ws-a/files", headers=_ADMIN).status_code == 501


def test_image_without_warren_query_is_501(monkeypatch, tmp_path):
    with _client(monkeypatch, tmp_path) as (client, registry):
        registry.runtime.exec_handler = lambda ws, argv: ([b"not found\n"], 127)
        resp = client.get("/workspaces/ws-a/diff", headers=_ADMIN)
        assert resp.status_code == 501
        assert resp.json()["detail"]["error"] == "query_unavailable"


def test_agent_state_reuses_the_registry(monkeypatch, tmp_path):
    with _client(monkeypatch, tmp_path) as (client, registry):
        registry.agent_state = AsyncMock(return_value=AgentState(state="working", ts=1.5, harness="claude", source="hook"))
        resp = client.get("/workspaces/ws-a/agent-state", headers=_ADMIN)
        assert resp.json() == {"state": "working", "ts": 1.5, "harness": "claude", "event": "", "source": "hook"}
        registry.agent_state = AsyncMock(return_value=None)
        assert client.get("/workspaces/ws-a/agent-state", headers=_ADMIN).json()["state"] == "unverifiable"
        assert registry.runtime.exec_calls == []


def test_workspace_tokens_cannot_reach_the_queries():
    from warren.auth.workspace_tokens import scoped_route_allowed

    for method, path in (
        ("GET", "/workspaces/A/files"),
        ("GET", "/workspaces/A/files/a.txt"),
        ("GET", "/workspaces/A/diff"),
        ("GET", "/workspaces/A/agent-state"),
    ):
        assert not scoped_route_allowed(method, path, "A")
