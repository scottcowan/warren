---
warren-server: patch
---

Workspace (max_workspaces, max_workspaces_per_user) and token (max_tokens_per_user) caps and the last-enabled-admin disable guard are each enforced in one SQL statement, so concurrent requests can no longer overshoot them
