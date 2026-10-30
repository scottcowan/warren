# warren

Environment broker for AI agent workspaces. Warren provisions isolated, permission-scoped project environments and makes them available to any agent runtime — Claude Code, Cursor, or custom agents.

Warren does not care what runs inside a workspace. It ensures the right files, secrets, and git state are present when the agent lands, then gets out of the way.

This repo is the monorepo: the `warren` CLI (`packages/warren-cli`), shared models
(`warren-common`), the in-workspace sidecar (`warren-sidecar`), the server itself
(`warren-server`), and a local MCP server (`warren-mcp`) — five independently versioned `uv`
workspace members.

---

## Install

Requires Python 3.11+ and [uv](https://docs.astral.sh/uv/).

```bash
git clone https://github.com/scottcowan/warren.git
cd warren
uv sync
```

This installs the `warren` CLI (from `packages/warren-cli`) into the workspace venv, along
with `warren-common` and `warren-sidecar` as workspace members.

## Quickstart

Point the CLI at a running warren-server instance (`packages/warren-server`; run it with
`uv run --package warren-server warren-server` or deploy it per
[`resources/ecs/README.md`](resources/ecs/README.md)):

```bash
uv run warren init                                    # choose "server" mode when prompted
uv run warren server add myserver http://localhost:8420 --token <bearer-token>
uv run warren server use myserver

uv run warren projects                # list projects registered on the server
uv run warren new myproject develop   # provision + connect in one step
uv run warren list                    # active workspaces (local + remotes)
uv run warren connect <workspace-id>  # drop into an existing one
uv run warren status <workspace-id>   # remote-only — local workspaces have no server status
```

Workspace commands (`new`, `list`, `connect`, `status`, `exec`, `tunnel`, `destroy`) live at
the top level — they're what the CLI is for. `projects` (plural, server-registered) is also
top-level; `secrets`, `server`, `project` (singular — local YAML definitions), and `remote`
are namespaced subcommands for the less central nouns. Omit `--server` on `status`/`tunnel`
and you get an interactive picker over your configured remotes.

Or run entirely local (no server) against a `config.toml` project definition — see `warren
init` to scaffold one:

```bash
uv run warren init
```

Run `uv run warren --help` for the full command tree.

## MCP server

`packages/warren-mcp` exposes the CLI as MCP tools (`list_workspaces`, `new_workspace`,
`exec_command`, `destroy_workspace`, `workspace_status`, `list_projects`, `list_remotes`,
`doctor`) so an MCP client — Claude Desktop, Claude Code, anything that speaks MCP — can drive
warren directly. It's a thin subprocess wrapper around the real `warren` binary (same config
resolution, same validation, same error messages — no second code path to drift), always
passing every argument a tool needs so it never falls through to an interactive picker, since
there's no TTY on the other end of a tool call.

```bash
uv run --package warren-mcp warren-mcp   # stdio transport — run by the MCP client, not by hand
```

Point an MCP client at it (Claude Desktop's `claude_desktop_config.json`, or Claude Code's MCP
settings):

```json
{
  "mcpServers": {
    "warren": {
      "command": "uv",
      "args": ["run", "--project", "/path/to/warren", "--package", "warren-mcp", "warren-mcp"]
    }
  }
}
```

It talks to whatever `~/.warren/config.toml` already points at — local mode or a configured
remote — exactly like running `warren` by hand would.

---

## What it does

- **Projects** — named collections of workspaces (one repo, multiple templates)
- **Workspaces** — isolated environments scoped to a project template (whatever templates the project defines — `observe`, `develop`, `claude`, anything — and templates can nest, inheriting from their parent)
- **Runtimes** — pluggable: Bubblewrap/Seatbelt/Nsjail/Docker (local, no server), Podman (remote host), ECS Fargate (cloud)
- **Secret store** — SQLite + Fernet; secrets injected at provision time, never written to container filesystem
- **Multi-server** — `warren server add`/`warren remote add` register any number of warren-server instances; the CLI fans commands out across all of them
- **NDJSON event stream** — the server streams each workspace's structured lifecycle events over HTTP

## What it doesn't do

- Queue management or retry logic — that's the caller's job
- Agent protocol (ACP, stdio) — agnostic to what runs inside
- Model routing — your own agent platform handles that
- Scheduling decisions — warren answers yes/no; callers decide when to ask

---

## Architecture

```
warren-server (packages/warren-server)
├── /projects        project registry (YAML configs)
├── /workspaces      lifecycle: provision, start, stop, destroy, connect
└── /workspaces/{id}/events   NDJSON event stream (tailed from the workspace container's log)

server-side runtimes (warren-server)
├── PodmanRuntime    rootless, daemonless — remote Docker/Podman hosts over SSH
└── ECSRuntime       AWS Fargate — SSM Exec for interactive access, no sshd needed

local runtimes (warren-common, used by the warren CLI directly, no server involved)
├── BubblewrapRuntime   Linux sandboxing (bwrap)
├── SeatbeltRuntime     macOS sandboxing (sandbox-exec)
├── NsjailRuntime       nsjail-based isolation
└── DockerRuntime       local Docker/Podman daemon

container images
├── warren-base / warren-ecs-base           minimal — git, ssh-client/jq/curl, uv; no sshd
├── warren-dev-base / warren-ecs-dev-base   + Claude Code CLI, nvm/pyenv, common dev tools
└── warren-agent-base / warren-ecs-agent-base   stubs for purpose-built agent tooling (deferred)

warren-sidecar (in-workspace)
└── agent-state recorder: tails the tmux pane for OSC 7501 state and writes
    osc-state.json, which the server reads host-side. No listener; the server uses the
    runtime's own exec, log stream and host-side state reads.
```

Interactive remote SSH access (for a Docker/Podman-backed workspace on a remote host) uses
an ACP-over-SSH ForceCommand pattern — the mechanism itself is extracted and generic, in
[`agent-poc`](https://github.com/scottcowan/agent-poc). ECS-backed workspaces don't need it:
`aws ecs execute-command` over SSM gives the same interactive access with no exposed port.

## Project config shape

`~/.warren/projects/<name>.yaml` — created by `warren project add`, edited by hand after.
There's no separate "intent" type — each named entry under `templates` is a full project
node itself, so it can nest its own `templates` in turn. A child inherits everything from
its parent unless it overrides it: scalars (`docker_image`, `app`, `permission`, ...) are
replaced, lists (`mounts`, `secrets`, `docker_networks`) are appended to, and `scope`/`aws`/
`ssh` are merged key-by-key. A workspace gets exactly the `secrets` its template declares,
from its owner's own secrets in warren's store; the sandbox itself is enforced through `mounts` (each one explicitly `ro` or `rw`) — not through `scope`,
which exists on the model today but isn't enforced yet.

```yaml
name: myproject
description: Example project definition
repo: git@github.com:youruser/myproject.git
bare_path: /workspaces/myproject/.git-store
docker_image: ghcr.io/scottcowan/warren-docker-base:latest

mounts:
  - host: ~/.warren/projects/myproject/knowledge/refs
    container: /workspace/knowledge/refs
    mode: rw

secrets:
  - name: GITHUB_TOKEN
    permission: readonly

# Plain, non-secret settings, merged key-by-key into child templates. Never put
# secrets here: values are stored in the workspace record and visible in ECS task
# overrides. WARREN_* and HOME/REAL_HOME/PATH/USER/SHELL/PWD/ZDOTDIR/SSH_AUTH_SOCK are reserved.
env:
  OLLAMA_HOST: http://gpu-box:11434

# Server-side idle handling: stop after idle_ttl_seconds without egress, then destroy
# once it has stayed stopped for idle_destroy_seconds. Destroy is off unless this or
# the server's WARREN_IDLE_DESTROY_SECONDS is set; a reconnect resets it.
idle_ttl_seconds: 3600
idle_destroy_seconds: 604800

templates:
  observe:
    description: Browse code, ask questions, view logs
    permission: readonly
    app: zsh

  develop:
    description: Normal development work
    permission: write
    app: zsh
    # Agent harnesses this workspace may run (claude, codex, opencode, cursor-agent,
    # pi, or custom with custom_harness.command). Each gets its own config dir in
    # the workspace (CLAUDE_CONFIG_DIR, CODEX_HOME, ...), seeded from your
    # non-secret settings; your real ~/.claude, ~/.codex etc. are never writable.
    # Auth: API-key secrets, or (claude only) ~/.claude/.credentials.json copied
    # in on each connect and never copied back.
    # Every runtime opens the warren shell; each harness is a command in it, and
    # exiting one returns to the shell. `warren resume [<harness>]` continues a
    # conversation, `warren connect --harness codex [--new]` starts one on connect,
    # and leaving the shell disconnects without stopping the workspace.
    # Reconnecting returns to what you were doing: podman/ECS reattach tmux with a
    # harness still running; a harness cut off by a task relaunch (or, locally, a
    # closed terminal: local sandboxes have no tmux) restarts on the same
    # conversation by session id; `--new` ignores that and opens the shell.
    harnesses: [claude, codex]
    # false rejects harnesses that can hand a session to the vendor's cloud.
    allow_vendor_cloud: true
    # bedrock: Claude reaches models through this workspace's own AWS identity
    # (the `aws` profile below locally; the workspace task role on ECS) and your
    # Claude login is never handed over. Also implied by CLAUDE_CODE_USE_BEDROCK or
    # ANTHROPIC_BEDROCK_BASE_URL in env. Connect fails if no AWS credentials or
    # region are configured. Omit (or `subscription`) to copy in your Claude
    # access token, without its refresh token, on each connect.
    model_access: subscription
    # export (default): warren serves this one profile's short-lived credentials
    # from the host. sso: share the host SSO token cache (local runtimes only;
    # reaches every account and role you have).
    aws:
      mode: export
      profile: dev
    secrets:
      - name: ANTHROPIC_API_KEY
        permission: write

    # Nested sub-template — provision with `warren new myproject develop.claude`.
    # Inherits develop's permission/secrets/app above, overrides what it needs.
    templates:
      claude:
        description: Claude Code agent session
        docker_image: ghcr.io/scottcowan/warren-base-claude-code:latest
        # Optional: the harness `--harness`/`warren resume` default to. A shell or
        # harness app never runs on its own; `kind: agent` (headless) comes later.
        app: claude
        # First turn handed to the app on provision. Supported by claude, codex and
        # gemini (-i); ignored by any other app. Not replayed on reconnect/reprovision.
        seed_prompt: Read CONTRIBUTING.md and run the test suite.
        ssh:
          keys: [~/.ssh/id_ed25519]
          agent: true
```

### Server-wide vs. user-scoped projects

On a shared warren-server, a project can be **server-wide** (one shared, admin-managed
definition) or **user-scoped** (owned by whoever pushed it). Authoring still happens
locally either way — `warren project sync <name> --server <server>` pushes your local
YAML; add `--server-wide` to publish it as the shared one (admin-only). A user-scoped
project automatically inherits from a server-wide project of the same name — same name is
the relationship, nothing to declare — merged with the same rules templates use (scalars
override, lists append, `templates` union by key).

Syncing a name that already exists server-wide, with no override of your own yet, prompts
you to just use the shared one instead of silently forking a copy. `warren project promote
<name> --server <server>` publishes your user-scoped version as the new server-wide one —
if a server-wide version already exists, it prints a diff and asks for confirmation first,
and the publish is version-checked so a concurrent edit from someone else gets a 409
instead of being silently overwritten.

## CLI config (`~/.warren/config.toml`)

Local mode picks a sandbox runtime; server mode registers one or more remotes. Both can
coexist — `warren list`/`connect`/etc. work against local workspaces and every registered
remote in the same command.

```toml
[defaults]
mode = "local"   # local | server

[runtime]
type = "auto"    # auto | docker | bwrap | seatbelt | nsjail — local sandboxing only

[remotes.node2]
url = "https://node2:8420"   # server must opt in: WARREN_HOST + TLS (see packages/warren-server/README.md)

[remotes.prod]
runtime_type = "ecs"      # no direct URL — reached via an SSM port-forward instead
ecs_cluster = "warren-cluster-prod"
ecs_service = "warren-server"
```

There's no auto-discovery — `warren remote add <name> <url>` (or hand-editing the
`[remotes.*]` table) is the only way a server becomes known to the CLI.

On Windows, local workspaces run in WSL2 with bubblewrap. See [docs/wsl2.md](docs/wsl2.md)
for setup, the Ubuntu 24.04 AppArmor fix, and where credentials should live.

---

## Examples

Agent-framework integration examples (LangGraph, CrewAI) driving warren's control-plane
MCP endpoint live in a separate repo,
[warren-examples](https://github.com/scottcowan/warren-examples) — split out so this
repo's own Dependabot alerts stay about warren itself, not example-framework
dependencies.

---

## Prior Art

Warren's Bubblewrap (Linux) and Seatbelt (macOS) runtime patterns are
informed by [ai-jail](https://github.com/akitaonrails/ai-jail) (GPL-3.0),
which explores the same bwrap and sandbox-exec primitives for isolating
AI-agent processes. Warren adds warren's project/template/secret/git layer
on top of those primitives.

---

## Contributing

Bug-fix PRs are welcome directly. Feature PRs should start as an issue — see
[CONTRIBUTING.md](CONTRIBUTING.md). Found a security issue? See [SECURITY.md](SECURITY.md)
instead of opening a public issue. The trust boundary of each runtime, and which control
covers which threat, are in [docs/threat-model.md](docs/threat-model.md).

## License

MIT — see [LICENSE](LICENSE).
