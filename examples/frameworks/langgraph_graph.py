"""A minimal LangGraph graph that drives warren through its control-plane MCP server.

provision (single-turn) -> run task -> read events with `since` until
workspace.completed -> destroy. The nodes call warren's MCP tools loaded with
langchain-mcp-adapters; nothing here is warren-specific beyond tool names.

    WARREN_URL=https://warren.example/mcp WARREN_TOKEN=wrnw_... python langgraph_graph.py demo task -- make test
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from typing import Any, TypedDict

from langchain_mcp_adapters.client import MultiServerMCPClient
from langgraph.graph import END, START, StateGraph


class RunState(TypedDict, total=False):
    project: str
    template: str
    command: list[str]
    workspace_id: str
    exec_result: dict
    since: int | None
    events: list[dict]
    verdict: dict


def tool_json(content: Any) -> Any:
    """An MCP tool result's text content, parsed as JSON."""
    if isinstance(content, str):
        return json.loads(content)
    return json.loads("".join(block["text"] for block in content if block.get("type") == "text"))


async def load_tools(url: str, token: str) -> dict[str, Any]:
    client = MultiServerMCPClient(
        {"warren": {"transport": "streamable_http", "url": url, "headers": {"Authorization": f"Bearer {token}"}}}
    )
    return {tool.name: tool for tool in await client.get_tools()}


def build_graph(tools: dict[str, Any], **compile_kwargs: Any):
    async def call(name: str, **args: Any) -> Any:
        return tool_json(await tools[name].ainvoke(args))

    async def provision(state: RunState) -> RunState:
        ws = await call("new_workspace", project=state["project"], template=state["template"], mode="single-turn")
        return {"workspace_id": ws["workspace_id"], "since": None, "events": []}

    async def run_task(state: RunState) -> RunState:
        return {"exec_result": await call("exec_command", workspace_id=state["workspace_id"], command=state["command"])}

    async def read_events(state: RunState) -> RunState:
        page = await call(
            "workspace_events", workspace_id=state["workspace_id"], since=state.get("since"), wait_seconds=5
        )
        events = state.get("events", []) + [e["event"] for e in page["events"]]
        done = next((e for e in events if isinstance(e, dict) and e.get("type") == "workspace.completed"), None)
        return {"events": events, "since": page["next_since"], **({"verdict": done} if done else {})}

    async def destroy(state: RunState) -> RunState:
        await call("destroy_workspace", workspace_id=state["workspace_id"])
        return {}

    graph = StateGraph(RunState)
    graph.add_node("provision", provision)
    graph.add_node("run_task", run_task)
    graph.add_node("read_events", read_events)
    graph.add_node("destroy", destroy)
    graph.add_edge(START, "provision")
    graph.add_edge("provision", "run_task")
    graph.add_edge("run_task", "read_events")
    graph.add_conditional_edges("read_events", lambda s: "destroy" if "verdict" in s else "read_events")
    graph.add_edge("destroy", END)
    return graph.compile(**compile_kwargs)


async def main(argv: list[str]) -> None:
    project, template, *rest = argv
    command = rest[1:] if rest[:1] == ["--"] else rest
    tools = await load_tools(os.environ["WARREN_URL"], os.environ["WARREN_TOKEN"])
    final = await build_graph(tools).ainvoke(
        {"project": project, "template": template, "command": command}, {"recursion_limit": 200}
    )
    print(json.dumps(final["verdict"], indent=2))


if __name__ == "__main__":
    asyncio.run(main(sys.argv[1:]))
