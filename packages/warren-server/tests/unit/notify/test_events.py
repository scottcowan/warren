"""Event detection from agent-state transitions, and payload shapes."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timezone
from types import SimpleNamespace

import pytest
from warren.notify import events as ev
from warren_common import agent_state as st


def _s(state: str, ts: float, event: str = "", harness: str = "claude") -> st.AgentState:
    return st.AgentState(state=state, ts=ts, event=event, harness=harness)


@pytest.mark.parametrize(
    ("prev", "cur", "expected"),
    [
        (None, _s(st.BLOCKED, 2, "PermissionRequest"), None),  # first sighting is a baseline
        (_s(st.WORKING, 1, "PreToolUse"), _s(st.BLOCKED, 2, "PermissionRequest"), ev.AGENT_WAITING),
        (_s(st.BLOCKED, 1), _s(st.BLOCKED, 2, "PermissionRequest"), None),  # still waiting
        (_s(st.WORKING, 1, "PreToolUse"), _s(st.IDLE, 2, "Stop"), ev.AGENT_FINISHED),
        (_s(st.BLOCKED, 1), _s(st.IDLE, 2, "Stop"), ev.AGENT_FINISHED),
        (_s(st.IDLE, 1, "SessionStart"), _s(st.IDLE, 2, "Stop"), None),
        (_s(st.WORKING, 1), _s(st.IDLE, 2, "StopFailure"), ev.AGENT_FAILED),
        (_s(st.IDLE, 1, "StopFailure"), _s(st.IDLE, 2, "StopFailure"), ev.AGENT_FAILED),  # dedupe's job
        (_s(st.WORKING, 1), _s(st.EXITED, 2, "agent/gave-up"), ev.AGENT_FAILED),
        (_s(st.WORKING, 1), _s(st.EXITED, 2, "agent/rejected"), ev.AGENT_FAILED),
        (_s(st.IDLE, 1), _s(st.EXITED, 2, "agent/exited"), ev.AGENT_FINISHED),
        (_s(st.IDLE, 1), _s(st.EXITED, 2, "SessionEnd"), ev.AGENT_FINISHED),
        (_s(st.IDLE, 1), _s(st.EXITED, 2, "supervisor/stopped"), None),
        (_s(st.IDLE, 1), _s(st.WORKING, 2, "UserPromptSubmit"), None),
        (_s(st.WORKING, 1, "Stop"), _s(st.WORKING, 1, "Stop"), None),  # unchanged reading
    ],
)
def test_detect(prev, cur, expected):
    assert ev.detect(prev, cur) == expected


def test_messages_are_short_and_fixed():
    assert ev.agent_message(ev.AGENT_WAITING, _s(st.BLOCKED, 1)) == "claude is waiting for input"
    assert ev.agent_message(ev.AGENT_FINISHED, _s(st.IDLE, 1)) == "claude finished its turn"
    assert ev.agent_message(ev.AGENT_FINISHED, _s(st.EXITED, 1)) == "claude exited"
    assert ev.agent_message(ev.AGENT_FAILED, _s(st.IDLE, 1, "StopFailure")) == "claude failed (StopFailure)"
    assert ev.agent_message(ev.AGENT_WAITING, _s(st.BLOCKED, 1, harness="")) == "the agent is waiting for input"
    assert ev.code("image_unavailable") == "image_unavailable"
    assert ev.code("boom: /secret/path token=abc") == "unknown"


WS = SimpleNamespace(
    workspace_id="0123456789abcdef", project="my-proj", owner_id="user-1", intent="claude-dev",
    spec_json='{"env": {"TOKEN": "s3cr3t"}}',
)
NOW = datetime(2026, 11, 1, 12, 0, 0, tzinfo=UTC)


def test_json_payload_shape():
    n = ev.Notification.for_workspace(ev.AGENT_WAITING, WS, "claude is waiting for input", now=NOW)
    body = json.loads(ev.render(n, "json"))
    assert body == {
        "event": "agent.waiting",
        "workspace_id": "0123456789abcdef",
        "name": "my-proj",
        "owner": "user-1",
        "template": "claude-dev",
        "timestamp": "2026-11-01T12:00:00Z",
        "message": "claude is waiting for input",
    }
    assert "s3cr3t" not in ev.render(n, "json").decode()


def test_slack_payload_shape_and_escaping():
    ws = SimpleNamespace(**{**vars(WS), "project": "<http://evil|click> & co"})
    n = ev.Notification.for_workspace(ev.IDLE_STOPPED, ws, "stopped by the idle reaper (agent_idle)", now=NOW)
    body = json.loads(ev.render(n, "slack"))
    assert set(body) == {"text", "blocks"}
    assert body["text"].startswith("[warren] stopped by the idle reaper (agent_idle): workspace ")
    assert "<http" not in body["text"] and "&lt;http://evil|click&gt; &amp; co" in body["text"]
    assert "(01234567)" in body["text"]
    assert body["blocks"][0]["type"] == "section"
    ctx = body["blocks"][1]["elements"][0]["text"]
    assert "workspace.idle_stopped" in ctx and "claude-dev" in ctx and "user-1" in ctx
    assert "s3cr3t" not in json.dumps(body)


def test_message_is_truncated():
    n = ev.Notification.for_workspace(ev.AGENT_FAILED, WS, "x" * 1000, now=NOW)
    assert len(n.message) == 200
