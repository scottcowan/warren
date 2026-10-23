# warren-sidecar

The in-workspace agent-state recorder. The `warren-docker-base` image entrypoint
(`images/warren-docker-base/entrypoint.py`) starts it as a daemon thread before the
workspace app runs.

It attaches `tmux pipe-pane` to the workspace's `main` session and tails a copy of the
pane output. It never starts, owns or signals the app. Every OSC 7501 status escape it
sees (`working`, `blocked`, `idle`, `exited`) is written to
`$WARREN_HARNESS_ROOT/.session/osc-state.json`. This is the fallback for harnesses that
have no state hooks. The server reads that file host-side (`warren_common.agent_state`),
with hook state taking precedence. When there is no tmux session (local/TTY mode), it logs
a warning and does nothing else.

## Design rule: the orchestrator never dials the sidecar

All orchestrator→workspace traffic uses the runtime's own authenticated control channel:
podman API exec or the ECS Exec relay, container logs, and host-side state files. The
sidecar has no socket, port or API. If the orchestrator needs structured data from inside
a workspace, it runs a command through the control channel and reads the output. No
runtime has an inbound network listener on a workspace.

## Tests

```bash
uv run pytest -q packages/warren-sidecar/tests
```
