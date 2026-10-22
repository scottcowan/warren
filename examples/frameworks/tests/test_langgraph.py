"""AJ2: a LangGraph graph drives a single-turn workspace end to end over warren's MCP."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

pytest.importorskip("langgraph")
pytest.importorskip("langchain_mcp_adapters")
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from langgraph.checkpoint.memory import MemorySaver  # noqa: E402
from langgraph_graph import build_graph, load_tools, tool_json  # noqa: E402

pytestmark = pytest.mark.frameworks


async def test_langgraph_single_turn_flow(warren):
    token = warren.reservation["token"]
    tools = await load_tools(warren.mcp_url, token)

    graph = build_graph(tools, checkpointer=MemorySaver(), interrupt_before=["destroy"])
    config = {"configurable": {"thread_id": "aj2"}, "recursion_limit": 100}
    final = await graph.ainvoke(
        {"project": "demo", "template": "task", "command": ["warren-test-task", "pass"]}, config
    )

    assert final["workspace_id"] == warren.reservation["workspace_id"]
    assert final["exec_result"]["exit_code"] == 0
    assert final["exec_result"]["output"] == "task done\n"
    verdict = final["verdict"]
    assert verdict["type"] == "workspace.completed"
    assert verdict["exit_code"] == 0
    assert verdict["verdict"] == {"status": "pass", "summary": "ran warren-test-task"}
    assert {"exit_code", "git", "verdict", "capture_errors"} <= verdict.keys()
    assert final["since"] is not None
    assert warren.status(final["workspace_id"]) == "destroyed"

    # Paused before the graph's destroy: the same token can't reach anything else.
    for name, args in (
        ("new_workspace", {"project": "demo", "template": "observe"}),
        ("destroy_workspace", {"workspace_id": warren.other_users_workspace}),
        ("destroy_workspace", {"workspace_id": warren.sibling_workspace}),
        ("exec_command", {"workspace_id": warren.sibling_workspace, "command": ["id"]}),
    ):
        assert "403" in str(await tools[name].ainvoke(args)), name
    assert warren.status(warren.sibling_workspace) == "running"
    assert warren.status(warren.other_users_workspace, warren.other_user_token) == "running"
    listed = tool_json(await tools["list_workspaces"].ainvoke({"include_inactive": True}))["workspaces"]
    assert [w["workspace_id"] for w in listed] == [final["workspace_id"]]

    await graph.ainvoke(None, config)
    assert graph.get_state(config).next == ()
