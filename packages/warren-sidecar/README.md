# warren-sidecar

In-workspace helper started by the `warren-docker-base` image entrypoint
(`images/warren-docker-base/entrypoint.py`). It records the agent's terminal state
(`osc-state.json`, which the server reads host-side) and serves a small file, diff, exec
and events HTTP API on a Unix socket inside the container.

## Design rule: the orchestrator never dials the sidecar

All orchestrator→workspace traffic uses the runtime's own authenticated control channel:
podman API exec or the ECS Exec relay, container logs, and host-side state files. The
sidecar is an in-container helper on a root-only Unix socket. If the orchestrator needs
structured data from inside a workspace, it runs a command through the control channel
(which may talk to the local socket) and reads the output. No runtime has an inbound
network listener on a workspace.

## Access control

- The socket is `/tmp/warren-sidecar.sock`, mode `0600`, owned by root.
- Every route except `/healthz` requires `X-Warren-Sidecar-Token`. The runtime puts a
  fresh random token in each container's `WARREN_SIDECAR_TOKEN`, and nothing stores it. The
  entrypoint removes it from the workspace app's environment. With no token configured,
  the sidecar refuses every request.
- File access is relative to the workspace root and never follows symlinks. A direct read
  applies the listing's exclusions: `.git`, `node_modules`, `.venv`, `__pycache__`, `.env*`
  and `.gitignore` matches.

## Tests

```bash
uv run pytest -q packages/warren-sidecar/tests
```
