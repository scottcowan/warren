---
warren-server: minor
warren-common: minor
---

POST /workspaces mode: single-turn; on app exit (podman, or ECS via DescribeTasks) the server emits workspace.completed with exit_code, git state and verdict.json, then destroys the workspace; events stay replayable with ?since= for a retention window. warren-common gains WorkspaceSpec.mode and safe_git.readonly_shadow_git_dir (AH2)
