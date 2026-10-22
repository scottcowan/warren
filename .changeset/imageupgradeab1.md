---
warren-server: minor
warren: minor
---

When `ensure_running` has to start a new task or container, it re-resolves the workspace's image like create_workspace (template `ecs_image`, else `ecs_default_image`; `docker_image` on podman) through the same allow-list check and records it on the row; a template's pinned image is kept and a running task is never replaced. `ensure_running` returns `image`/`newer_image`, and `warren connect` says when a newer image is available (AB1 req 6)
