"""AJ2: a CrewAI crew drives a single-turn workspace end to end over warren's MCP.

The crew's LLM is scripted (no model, no network): it reads the tool list and each
Observation from the prompt CrewAI builds and answers in CrewAI's ReAct format, so
everything between it and warren -- tool discovery, argument schemas, MCP calls --
is CrewAI's own code path."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("crewai")
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from crewai.llms.base_llm import BaseLLM  # noqa: E402
from crewai_crew import build_crew  # noqa: E402

pytestmark = pytest.mark.frameworks


def _text(messages: Any) -> str:
    if isinstance(messages, str):
        return messages
    return "\n".join(str(m.get("content", "")) for m in messages)


class ScriptedLLM(BaseLLM):
    other_workspace: str = ""
    steps: list[str] = []
    observations: list[str] = []
    phase: str = "provision"
    workspace_id: str | None = None
    since: int | None = None
    verdict: dict = {}

    def call(self, messages, tools=None, callbacks=None, available_functions=None,
             from_task=None, from_agent=None, response_model=None) -> str:
        text = _text(messages)
        names = set(re.findall(r"Tool Name: (\S+)", text))
        tool = {suffix: next(n for n in names if n.endswith(suffix)) for suffix in (
            "new_workspace", "exec_command", "workspace_events", "wait_completed", "destroy_workspace")}
        replies = [str(m.get("content", "")) for m in messages if m.get("role") == "assistant"]
        last = replies[-1] if replies and self.steps else ""
        obs = last.split("\nObservation:", 1)[1] if "\nObservation:" in last else ""
        if obs:
            self.observations.append(obs)
        if self.workspace_id is None and self.steps:
            self.workspace_id = next(iter(re.findall(r'"workspace_id":\s*"([0-9a-f-]{36})"', obs)), None)
        ws = self.workspace_id

        def act(name: str, args: dict) -> str:
            self.steps.append(name)
            return f"Thought: next step\nAction: {tool[name]}\nAction Input: {json.dumps(args)}"

        phase = self.phase
        if phase == "provision":
            self.phase = "exec"
            return act("new_workspace", {"project": "demo", "template": "task", "mode": "single-turn"})
        if phase == "exec":
            self.phase = "events"
            return act("exec_command", {"workspace_id": ws, "command": ["warren-test-task", "pass"]})
        if phase == "events":
            self.phase = "after_events"
            args = {"workspace_id": ws, "wait_seconds": 5}
            if self.since is not None:
                args["since"] = self.since
            return act("workspace_events", args)
        if phase == "after_events":
            found = re.findall(r'"next_since":\s*(-?\d+)', obs)
            assert found, obs[:2000]
            self.since = int(found[-1])
            if "workspace.completed" in obs:
                self.phase = "verdict"
            else:
                self.phase = "events"
                return act("wait_completed", {"workspace_id": ws, "timeout_seconds": 60})
        if self.phase == "verdict":
            self.phase = "destroy_other"
            return act("wait_completed", {"workspace_id": ws, "timeout_seconds": 30})
        if phase == "destroy_other":
            self.verdict, _ = json.JSONDecoder().raw_decode(obs[obs.index("{"):])
            self.phase = "provision_again"
            return act("destroy_workspace", {"workspace_id": self.other_workspace})
        if phase == "provision_again":
            self.phase = "destroy"
            return act("new_workspace", {"project": "demo", "template": "observe"})
        if phase == "destroy":
            self.phase = "answer"
            return act("destroy_workspace", {"workspace_id": ws})
        return f"Thought: I now know the final answer\nFinal Answer: {json.dumps(self.verdict['event'])}"

    def supports_function_calling(self) -> bool:
        return False

    def supports_stop_words(self) -> bool:
        return False

    def get_context_window_size(self) -> int:
        return 200_000


def test_crewai_single_turn_flow(warren):
    llm = ScriptedLLM(model="scripted", other_workspace=warren.other_users_workspace, steps=[], observations=[])
    crew = build_crew(
        warren.mcp_url, warren.reservation["token"], llm,
        project="demo", template="task", goal="run warren-test-task",
    )

    result = crew.kickoff()

    assert result.raw.startswith("{"), (llm.steps, llm.observations)
    event = json.loads(result.raw)
    assert event["type"] == "workspace.completed"
    assert event["workspace_id"] == warren.reservation["workspace_id"]
    assert event["exit_code"] == 0
    assert event["verdict"] == {"status": "pass", "summary": "ran warren-test-task"}
    assert llm.steps[:2] == ["new_workspace", "exec_command"]
    assert "workspace_events" in llm.steps and llm.since is not None
    assert llm.steps[-3:] == ["destroy_workspace", "new_workspace", "destroy_workspace"]
    destroy_other, second_provision, _ = llm.observations[-3:]
    assert "403" in destroy_other and "403" in second_provision
    assert warren.status(warren.other_users_workspace, warren.other_user_token) == "running"
    assert warren.status(warren.reservation["workspace_id"]) == "destroyed"
