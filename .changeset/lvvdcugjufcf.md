---
warren: minor
warren-common: patch
---

Agent workspaces expose one ACP endpoint (AM3): JSON-RPC 2.0 NDJSON on 127.0.0.1:agent.port inside the workspace, native ACP passed through from stdio and other harnesses behind the configurable agent.adapter command; non-loopback listeners stop the agent, lines and peers are bounded. warren tunnel <ws> [port] defaults to that port
