# Orchestration frameworks on warren (AJ2)

warren provides the environment and the harness lifecycle; the framework provides the
agent logic. A framework talks to warren only through warren-server's control-plane MCP
endpoint (`/mcp`, streamable HTTP), so there is no framework-specific code in warren.

| File | Framework | How it loads warren |
|------|-----------|---------------------|
| `langgraph_graph.py` | LangGraph 1.2.16 | `langchain-mcp-adapters` 0.3.2 `MultiServerMCPClient` |
| `crewai_crew.py` | CrewAI 1.15.28 | native `Agent(mcps=[MCPServerHTTP(...)])` |

Both run the same flow: provision a `single-turn` workspace, run a task in it
(`exec_command`), read events with `since` until `workspace.completed`, read the
verdict (exit code, git state, `.warren/verdict.json`), destroy the workspace.

## Tools

`new_workspace(project, template, mode)`, `list_workspaces`, `workspace_status`,
`exec_command(workspace_id, command, timeout_seconds)`,
`workspace_events(workspace_id, since, wait_seconds, max_events)`,
`wait_completed(workspace_id, timeout_seconds)`, `destroy_workspace`. The names match
the local CLI-bridge `warren-mcp` where it has the same tool.

## Auth: a workspace-scoped token, not yours

Mint a reservation token with your own token. It names a workspace id the server picks,
can provision that workspace once, and can then act only on it:

```sh
curl -s -X POST "$WARREN/workspace-tokens" -H "Authorization: Bearer $MY_TOKEN" \
  -H 'content-type: application/json' -d '{"ttl_seconds": 900}'
# {"token": "wrnw_...", "workspace_id": "...", "expires_at": "...", ...}
```

Pass `public_key` (base64 raw Ed25519) to bind the token to a key; the client must then
sign every request (`X-Warren-Proof`), which these examples don't do. With the token, a
second `new_workspace`, or any tool naming another workspace, returns 403. After a
single-turn workspace completes, the token can still read its status and events and call
`destroy_workspace` (a no-op) until it expires.

## Run against a server

```sh
uv sync
WARREN_URL=https://warren.example/mcp WARREN_TOKEN=wrnw_... \
  uv run python langgraph_graph.py myproject mytemplate -- make test
WARREN_URL=... WARREN_TOKEN=wrnw_... CREWAI_LLM=anthropic/claude-sonnet-4-5 \
  uv run python crewai_crew.py myproject mytemplate "run make test"
```

The template must have an `app` that runs to completion (single-turn). The CrewAI example
needs a model; the LangGraph graph is deterministic and needs none.

## Acceptance test

`tests/` starts a real warren-server (from the repo's workspace venv, in its own
process) on 127.0.0.1 with a scripted in-memory runtime, then runs both flows against
it. The CrewAI test uses a scripted LLM, so no model or network is involved.

```sh
uv sync --package warren-server --extra dev   # repo root
cd examples/frameworks && uv sync && uv run pytest -m frameworks
```

Python 3.12+ (CrewAI 1.15.28's MCP client fails on 3.11). This project has its own
`uv.lock` and is not a workspace member: CrewAI pins
`pydantic<2.13` and `mcp~=1.28.1`, which warren-server doesn't allow. Set
`WARREN_SERVER_PYTHON` to a Python with warren-server installed to skip `uv run`.
CI: `.github/workflows/warren-frameworks-e2e.yml`. Manual runs against podman and ECS
use the commands above.
