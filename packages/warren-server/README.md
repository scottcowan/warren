# warren-server

The server half of [Warren](https://github.com/scottcowan/warren) — an environment broker for
AI agent workspaces. warren-server provisions isolated, permission-scoped containers on a host
(or in ECS Fargate) and exposes them over a small HTTP API: create a workspace, connect to it,
stream its events, tear it down.

It doesn't care what runs inside a workspace. It materializes the right git state, injects
secrets at provision time, and gets out of the way.

This package lives in the `warren` monorepo at `packages/warren-server`, alongside the CLI
(`packages/warren-cli`), shared models (`packages/warren-common`), and the in-workspace sidecar
(`packages/warren-sidecar`).

## Runtimes

Pick one at a time via `WARREN_RUNTIME_TYPE`:

| Runtime | `WARREN_RUNTIME_TYPE` | Use case |
|---|---|---|
| Podman | `podman` (default) | Rootless, daemonless — a single host you control |
| Docker | `docker` | Remote hosts / cloud VMs already running Docker |
| ECS Fargate | `ecs` | One Fargate task per workspace, no host to manage |

See [`resources/ecs/`](../../resources/ecs/) for the Terraform/CDK to stand up the ECS path.
Fargate allows no sandbox inside a task, so everything in an ECS workspace task is
agent-controlled and the workspace task role is the control; see
[Fargate isolation](../../resources/ecs/README.md#fargate-isolation-the-task-role-is-the-control).

## Quickstart (Podman, local)

Requires Python 3.11+, [uv](https://docs.astral.sh/uv/), and a rootless Podman socket.

```bash
git clone https://github.com/scottcowan/warren.git
cd warren
uv sync --package warren-server --extra dev

export WARREN_SECRET_KEY="$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')"
export WARREN_BOOTSTRAP_TOKEN="$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')"

uv run --package warren-server python -m warren
```

The server binds `127.0.0.1:8420` (loopback only; see [Listening address](#listening-address)). On first boot (empty `users` table), `WARREN_BOOTSTRAP_TOKEN`
mints the first admin user — use it as a bearer token to create further users and tokens via
the admin API, then unset it (re-triggering bootstrap is a no-op once an admin exists).

```bash
curl http://localhost:8420/healthz
curl -H "Authorization: Bearer $WARREN_BOOTSTRAP_TOKEN" http://localhost:8420/workspaces
```

Every route except `/_status` and `/healthz` requires a bearer token.

### Listening address

Bearer tokens and SSH private keys cross the API socket, so the default is loopback.

| Env | Default | |
|---|---|---|
| `WARREN_HOST` | `127.0.0.1` | Address to bind. Anything non-loopback is an explicit opt-in. |
| `WARREN_PORT` | `8420` | |
| `WARREN_TLS_CERTFILE` / `WARREN_TLS_KEYFILE` | unset | Serve HTTPS. Set both or neither. |
| `WARREN_ALLOW_INSECURE_HTTP` | `0` | Required to serve plain HTTP on a non-loopback `WARREN_HOST`; logs `insecure_http_listener` at startup. |

With a non-loopback `WARREN_HOST` and neither TLS nor `WARREN_ALLOW_INSECURE_HTTP=1`, the
server exits with an error. Typical setups:

- **Local, or an SSH tunnel** (`runtime_type = "ssh"` remotes): leave the defaults.
- **ECS Fargate**: leave the defaults. The CLI reaches the control plane through an SSM
  port-forward (`AWS-StartPortForwardingSession`), which connects to the task's own loopback.
- **Server image under podman/docker with `-p`**: published ports arrive on the container's
  interface, not its loopback, so set `WARREN_HOST=0.0.0.0` plus TLS, or keep the publish
  loopback-only and acknowledge cleartext:
  `-p 127.0.0.1:8420:8420 -e WARREN_HOST=0.0.0.0 -e WARREN_ALLOW_INSECURE_HTTP=1`.
- **Clients connecting over the network** (`url = "https://node2:8420"`): set `WARREN_HOST`
  and TLS.

## API surface

| Method | Path | Notes |
|---|---|---|
| `POST` | `/workspaces` | Provision a workspace (202, async) |
| `GET` | `/workspaces` | List your own workspaces |
| `GET` | `/workspaces/{id}/status` | Status (owner-only) |
| `POST` | `/workspaces/{id}/connect` | Connection info (owner-only) |
| `POST` | `/workspaces/{id}/git/pull` | Pull latest into the workspace worktree |
| `GET` | `/workspaces/{id}/events` | NDJSON event stream (owner-only) |
| `DELETE` | `/workspaces/{id}` | Tear down (owner-only) |
| `GET` | `/projects` | List registered projects |
| `PUT` | `/projects/{name}` | Register/update a project (admin-only) |
| `POST` | `/admin/users` | Create a user + mint its first token (admin-only) |
| `GET` | `/healthz` | Runtime/workspace/secret-store health — always 200 |
| `GET` | `/peers` | Peer discovery (stub) |

Workspace routes are owner-scoped: a non-admin can only see/act on workspaces they created.

### Single-turn workspaces

`POST /workspaces` takes `"mode": "single-turn"` (default `"interactive"`). The template's
`app` must run to completion (`bash` is rejected with 422). When the app exits, the server
pushes one `workspace.completed` event and then destroys the workspace:

```json
{"type": "workspace.completed", "ts": "...", "workspace_id": "...", "exit_code": 0,
 "git": {"branch": "warren/fix/1a2b3c4d/app", "head_commit": "...", "base_commit": "...",
         "branch_safe": true, "is_clean": true},
 "git_folders": [{"mount": "app", "branch": "...", "...": "..."}],
 "verdict": {"...": "contents of /workspace/.warren/verdict.json, if present"},
 "capture_errors": []}
```

`git` is the first checkout's state and `git_folders` lists every checkout. `branch_safe`
means HEAD is on a named branch other than the base branch it started from. Capture is
best-effort: a part that can't be read is `null` and listed in `capture_errors`, and the event
is still sent and the workspace still destroyed. Git state is read through a read-only shadow
git dir (no repo config, hooks or filters run). `verdict.json` must be a regular file holding
a JSON object of at most 256 KiB, and symlinks aren't followed. The destroyed workspace's event
stream stays replayable with `GET /workspaces/{id}/events?since=<seq>` for
`WARREN_SINGLE_TURN_EVENT_RETENTION_SECONDS` (default 3600), then returns 410. The buffer is
in memory, so a server restart loses it.

Exit is detected by the reaper: podman container state, or ECS `DescribeTasks` (the
`workspace` container's `exitCode`). On ECS the server reads git and `verdict.json` from the
workspace's EFS directory, so it needs the file system root mounted on the control plane
(`WARREN_EFS_LOCAL_MOUNT_PATH`, e.g. Terraform `efs_delete_workspace_data_on_destroy`).
Without it the event carries only `exit_code`.

## Configuration

All settings are `WARREN_*` environment variables, loaded by `src/warren/config.py`. Key ones:

- `WARREN_SECRET_KEY` — required, used to derive the token pepper
- `WARREN_BOOTSTRAP_TOKEN` — mints the first admin on an empty database
- `WARREN_RUNTIME_TYPE` — `podman` (default) / `docker` / `ecs`
- `WARREN_PODMAN_SOCKET` — path to the rootless Podman socket
- `WARREN_DATA_DIR` — SQLite registry + auth DB location
- `WARREN_MAX_WORKSPACES` — concurrency cap
- `WARREN_IDLE_TTL_SECONDS` / `WARREN_IDLE_REAPER_ENABLED` — idle-workspace reaping
- `WARREN_ECS_*`, `WARREN_EFS_ID`, `WARREN_AWS_REGION` — only consulted when `runtime_type=ecs`

Full list and defaults in `src/warren/config.py`.

## Development

```bash
uv sync --package warren-server --extra dev
uv run --package warren-server pytest packages/warren-server/tests
```

Tests spin up a rootless Podman socket (see `../../.github/workflows/warren-server-test.yml`
for the exact CI setup) and run against it — no AWS account is needed for the unit suite,
including the ECS runtime tests (mocked boto3).

## License

MIT — see [LICENSE](LICENSE).
