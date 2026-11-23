---
warren-mcp: patch
---

ECS flow: tools take the server from `server` or WARREN_MCP_SERVER (no interactive picker); `workspace_status`/`list_projects`/`list_remotes`/`doctor` now request `--json` (they failed to parse text output before); new `server_health` and `run_status`/`run_result`/`run_list` tools; project/template/server/run-id validation; AWS SSO and session-manager-plugin error hints; output cap, timeout and binary-path env overrides; readOnly/destructive annotations; README launch config for an ECS server
