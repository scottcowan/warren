---
warren: minor
---

`warren ssh-config <ws>` prints an ~/.ssh/config Host block for editor remoting (VS Code Remote-SSH, Cursor, JetBrains Gateway), with HostKeyAlias pinned to the workspace. ECS workspaces on the new opt-in warren-ecs-ssh-base image are reached through `warren proxy stdio <ws> 2222`, a new ProxyCommand that pipes stdio through an SSM port-forward to the task's loopback sshd; podman/docker-server workspaces use the server's per-workspace key mint (POST /workspaces/{id}/connect, key kept in ~/.warren/ssh/) and jump through the server host
