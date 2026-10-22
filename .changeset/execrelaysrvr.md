---
warren-server: minor
warren-common: minor
---

POST /workspaces/{id}/exec: server-mode exec relay over the Podman exec API or ECS ExecuteCommand (control-plane role, session-manager-plugin), owner- and workspace-token-scoped, audit-logged, bounded by WARREN_EXEC_MAX_OUTPUT_BYTES and WARREN_EXEC_MAX_TIMEOUT_SECONDS (#59)
