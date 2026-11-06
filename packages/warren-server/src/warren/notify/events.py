"""Notification events, how they are detected from agent state, and their payloads.

Agent state comes from the harness hooks (AG5) and the agent supervisor (AG2b), read
host-side by `WorkspaceRegistry.agent_state` (the same reader the idle reaper uses).
A transition between two successive readings maps to at most one event:

    anything      -> event StopFailure / agent/gave-up / agent/rejected   agent.failed
    not blocked   -> blocked (permission or input wait)                    agent.waiting
    working       -> idle (Stop: the turn finished)                        agent.finished
    not exited    -> exited (agent/exited, SessionEnd)                     agent.finished

The first reading of a workspace is a baseline and never notifies (so a server restart
doesn't replay every workspace's current state). `supervisor/stopped` (warren stopping
the agent) is not a finish.

Payloads carry identifiers and a short fixed-vocabulary message only: never transcript
content, prompts, tool output, env, secrets or error text.
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timezone
from typing import Any

from warren_common import agent_state as st

AGENT_WAITING = "agent.waiting"
AGENT_FINISHED = "agent.finished"
AGENT_FAILED = "agent.failed"
IDLE_STOPPED = "workspace.idle_stopped"
PROVISION_FAILED = "workspace.provision_failed"
EVENTS: tuple[str, ...] = (AGENT_WAITING, AGENT_FINISHED, AGENT_FAILED, IDLE_STOPPED, PROVISION_FAILED)

# Hook / supervisor `event` values that mean the agent failed.
FAILURE_EVENTS = frozenset({"StopFailure", "agent/gave-up", "agent/rejected"})
_NOT_A_FINISH = frozenset({"supervisor/stopped"})

_CODE = re.compile(r"^[a-z0-9_-]{1,64}$")


def detect(prev: st.AgentState | None, cur: st.AgentState | None) -> str | None:
    """The event the reading `cur` (after `prev`) represents, if any."""
    if prev is None or cur is None:
        return None
    if (cur.state, cur.ts, cur.event) == (prev.state, prev.ts, prev.event):
        return None
    if cur.event in FAILURE_EVENTS:
        return AGENT_FAILED
    if cur.state == st.BLOCKED and prev.state != st.BLOCKED:
        return AGENT_WAITING
    if cur.state == st.IDLE and prev.state in (st.WORKING, st.BLOCKED):
        return AGENT_FINISHED
    if cur.state == st.EXITED and prev.state != st.EXITED and cur.event not in _NOT_A_FINISH:
        return AGENT_FINISHED
    return None


def agent_message(event: str, agent: st.AgentState | None) -> str:
    who = agent.harness if agent is not None and agent.harness else "the agent"
    if event == AGENT_WAITING:
        return f"{who} is waiting for input"
    if event == AGENT_FINISHED:
        return f"{who} finished its turn" if agent is None or agent.state != st.EXITED else f"{who} exited"
    if event == AGENT_FAILED:
        return f"{who} failed" + (" (StopFailure)" if agent is not None and agent.event == "StopFailure" else "")
    return event


def code(value: Any, default: str = "unknown") -> str:
    """A machine code (reason, harness) safe to put in a message, else `default`."""
    return value if isinstance(value, str) and _CODE.match(value) else default


@dataclass(frozen=True)
class Notification:
    event: str
    workspace_id: str
    name: str
    owner: str
    template: str
    timestamp: str
    message: str

    @classmethod
    def for_workspace(cls, event: str, ws: Any, message: str, *, now: datetime | None = None) -> Notification:
        ts = (now or datetime.now(UTC)).astimezone(UTC)
        return cls(
            event=event,
            workspace_id=str(getattr(ws, "workspace_id", "") or ""),
            # A workspace has no name of its own; it is launched for a project.
            name=str(getattr(ws, "project", "") or ""),
            owner=str(getattr(ws, "owner_id", "") or ""),
            template=str(getattr(ws, "intent", "") or ""),
            timestamp=ts.strftime("%Y-%m-%dT%H:%M:%SZ"),
            message=message[:200],
        )


def json_payload(n: Notification) -> dict[str, str]:
    return asdict(n)


def _slack_escape(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def slack_payload(n: Notification) -> dict[str, Any]:
    """A Slack incoming-webhook body: `text` (also the notification fallback) plus a
    context block. Values are escaped so a project name can't inject mrkdwn links."""
    e = _slack_escape
    text = f"[warren] {e(n.message)}: workspace {e(n.name)} ({e(n.workspace_id[:8])})"
    detail = f"event `{e(n.event)}` | template `{e(n.template)}` | owner `{e(n.owner)}` | {e(n.timestamp)}"
    return {
        "text": text,
        "blocks": [
            {"type": "section", "text": {"type": "mrkdwn", "text": text}},
            {"type": "context", "elements": [{"type": "mrkdwn", "text": detail}]},
        ],
    }


def render(n: Notification, fmt: str) -> bytes:
    body = slack_payload(n) if fmt == "slack" else json_payload(n)
    return json.dumps(body, separators=(",", ":")).encode()
