---
warren-common: minor
warren: minor
warren-server: minor
---

User workspaces (`kind: user`, the default; `agent` reserved) start at the warren shell on every runtime: local sandboxes wrap the shell, podman and ECS run it in tmux session `main`. Each template harness is a shell command applying its profile's launch args and lockdown env, exiting returns to the shell, `warren resume [<harness>]` continues a conversation, and `warren connect --harness <name> [--new]` starts one on connect. Leaving the shell no longer stops a podman workspace; `app` is only the default harness (AG2a)
