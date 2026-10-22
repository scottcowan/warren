---
warren-server: minor
---

Control-plane MCP server at /mcp (streamable HTTP): new_workspace (incl. mode single-turn), list_workspaces, workspace_status, exec_command, workspace_events (since), wait_completed, destroy_workspace over the registry, with user or workspace-scoped tokens; POST /workspace-tokens mints a reservation token that can provision its one workspace once (AI8)
