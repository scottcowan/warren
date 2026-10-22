"""A minimal CrewAI crew whose one agent gets warren's control-plane MCP tools through
CrewAI's native MCP support (`Agent(mcps=[MCPServerHTTP(...)])`).

    WARREN_URL=https://warren.example/mcp WARREN_TOKEN=wrnw_... \\
      python crewai_crew.py demo task "run make test and report the verdict"

Any CrewAI-supported model works (`--llm` / CREWAI_LLM, e.g. "anthropic/claude-sonnet-4-5").
"""

from __future__ import annotations

import os
import sys
from typing import Any

from crewai import Agent, Crew, Process, Task
from crewai.mcp import MCPServerHTTP

TASK = (
    "Using the warren tools: provision a single-turn workspace for project {project}, "
    "template {template}. In it, {goal}. Read its events (pass next_since back as since) "
    "until a workspace.completed event arrives, then destroy the workspace. Answer with "
    "the workspace.completed event's JSON."
)


def build_crew(mcp_url: str, token: str, llm: Any, *, project: str, template: str, goal: str) -> Crew:
    operator = Agent(
        role="Warren operator",
        goal="Run one task in an isolated warren workspace and report its verdict",
        backstory="You drive warren workspaces only through the tools you were given.",
        llm=llm,
        mcps=[MCPServerHTTP(url=mcp_url, headers={"Authorization": f"Bearer {token}"}, streamable=True)],
        allow_delegation=False,
        max_iter=25,
        verbose=False,
    )
    task = Task(
        description=TASK.format(project=project, template=template, goal=goal),
        expected_output="The workspace.completed event as JSON",
        agent=operator,
    )
    return Crew(agents=[operator], tasks=[task], process=Process.sequential, verbose=False)


if __name__ == "__main__":
    project, template, goal = sys.argv[1:4]
    crew = build_crew(
        os.environ["WARREN_URL"],
        os.environ["WARREN_TOKEN"],
        os.environ.get("CREWAI_LLM", "anthropic/claude-sonnet-4-5"),
        project=project,
        template=template,
        goal=goal,
    )
    print(crew.kickoff().raw)
