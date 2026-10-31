---
warren: minor
---

warren proxy (add/list/rm/run): stable 127.0.0.1 addresses for ports inside ECS workspaces. The SSM port-forward starts on the first connection, is shared by concurrent connections, closes when idle, and follows the workspace to a new task after a restart (docs/proxy.md)
