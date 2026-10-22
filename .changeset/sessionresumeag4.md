---
warren-common: minor
warren-server: minor
---

Reconnect returns to the conversation you were in: while a harness runs, the warren shell records `{harness, session_id, cwd, started_at}` in the workspace's `.session` dir (cleared on normal exit). A connect that finds the harness gone relaunches it on that conversation with `resume_by_id_args`, falling back to `resume_args` with a message when no id was recorded; podman/ECS reattach tmux when it is still running. `warren resume <harness>` keeps a last id per harness; session ids are read from claude/codex/pi session stores; the banner marks the last-used harness and which have a conversation for this directory (AG4)
