# Agent harnesses

A template lists the harnesses a workspace may run (`harnesses: [claude, codex, opencode]`).
Each one is a profile in `packages/warren-common/src/warren_common/harness.py`: its config
dir and the env var that points at it, the paths that persist across task relaunches, the
config warren generates, its state hooks, and how it runs headless. Everything else
(`/etc/warren/harness.sh`, `warren-harness-init`, the sandbox grants, the supervisor's
launch spec) is generated from that data.

## Matrix

| Harness | Interactive (warren shell) | Headless / server modes (`agent.mode`) | ACP | State hooks | Persisted under `<root>/<harness>/` | Never persisted |
|---|---|---|---|---|---|---|
| claude | `claude` | `stream-json` (default): `claude -p --output-format stream-json` | through `agent.adapter` | `settings.json` hooks, 12 events | `projects/`, `history.jsonl`, `todos/` | `.credentials.json`, `.claude.json`, settings |
| opencode | `opencode` (TUI) | `acp` (default): `opencode acp`; `serve`: `opencode serve --hostname 127.0.0.1 --port <port>` | native (`opencode acp`) | plugin `config/plugins/warren-state.js` | `data/` (XDG data dir and `opencode.db`), `state/` (XDG state: prompt history) | `auth.json`, `mcp-auth.json` anywhere under them; `config/` |
| codex | `codex` (TUI) | `exec` (default): `codex exec --json`; `app-server`: `codex app-server --listen ws://127.0.0.1:<port>`; `app-server-stdio`: `--listen stdio://` | not native; an adapter such as `codex-acp` via `agent.adapter` | `hooks.json`, 10 events, trusted by hash in `config.toml` | `sessions/`, `history.jsonl`, `log/` | `auth.json`; `config.toml`, `hooks.json` (regenerated); the SQLite state DBs |
| cursor-agent | `cursor-agent` / `agent` | `acp` (default) | native | `hooks.json`, 3 events | `chats/`, `projects/`, `data/` | `auth.json` |
| pi | `pi` | `rpc` (default): `pi --mode rpc` | through `agent.adapter` | extension `extensions/warren-state.ts` | `sessions/` | `auth.json`, `mcp-auth.json` |

`<root>` is `/var/lib/warren/harness` on podman and ECS (on the workspace's volume), and
`<state>/<id>/harness` locally. At every container start `warren-harness-init` deletes
everything in a harness dir except its persisted paths, deletes credential files inside
those, and rewrites warren's generated config.

## Server modes

A `kind: agent` template runs one harness under `warren-agent-supervisor`, which starts it
when the container starts (as the workspace user, with the workspace's env and secrets),
restarts it per `agent.restart`, and stops it for good if anything in its process tree
listens on a non-loopback address. `agent.mode` picks the mode:

```yaml
templates:
  opencode-server:
    kind: agent
    harness: opencode
    agent:
      mode: serve      # opencode's HTTP API on 127.0.0.1:4096
      port: 4096
    secrets:
      - name: OPENCODE_SERVER_PASSWORD   # optional: basic auth on the API
```

- **Native ACP** (`opencode acp`, `cursor-agent acp`): the supervisor serves ACP on
  `127.0.0.1:<port>` and bridges it to the harness's stdio.
- **Self-serving** (`opencode serve`, `codex app-server`): the harness listens on
  `127.0.0.1:<port>` itself (spec `transport: self`). The supervisor proxies nothing; it
  only runs and checks the process. Clients reach the port through `warren tunnel` or
  `warren proxy`: `opencode attach http://127.0.0.1:4096`, the T3 desktop app, or
  `codex --remote ws://127.0.0.1:<port>`. Without `OPENCODE_SERVER_PASSWORD` opencode's
  API is unauthenticated to anything inside the workspace that can reach loopback.
- **Other protocols** (claude stream-json, codex exec JSONL, codex app-server on stdio, pi
  RPC) need `agent.adapter`, a command that serves ACP for them.

The runtimes set `WARREN_AGENT_SPEC` (the launch spec) and `WARREN_APP_PORT` (the agent
port) on agent workspaces. `WARREN_APP_CMD` stays the PID 1 command of a service `app`
that isn't a shell or a harness (ECS), as before; an agent workspace never sets it.

## Per runtime

| | ECS (`warren-ecs-base`, `warren-ecs-dev-base`) | podman / docker (`warren-docker-base`, `warren-docker-dev-base`) | local sandboxes (seatbelt, bwrap, nsjail) |
|---|---|---|---|
| Harness dir | `/var/lib/warren/harness` on the workspace volume (EFS/EBS) | `/var/lib/warren/harness`, a bind mount of `<data_dir>/harness/<id>` | `<state>/<id>/harness` in the workspace's sandbox state dir |
| Prune + regenerate at start | `entrypoint.sh` runs `warren-harness-init`, as `warren` | `entrypoint.py` runs `warren-harness-init` | `prepare_harness_dirs` on create and every connect, with the template env |
| Agent auto-start (`kind: agent`) | `entrypoint.sh` execs the supervisor as PID 1 after dropping to `warren` (uid 1000); the shell attaches over ECS Exec | `entrypoint.py` starts the supervisor next to tmux session `main`; it runs as the container user (root in these images, which rootless podman maps to the operator's uid) | not run locally (no supervisor) |
| Env the harness sees | task env (template env, secrets, bedrock/gateway env) | container env (template env, secrets) | the template's `env_snapshot` |
| Model config from env | at container start | at container start | on create/connect |
| Harnesses installed | `warren-ecs-dev-base`: claude, codex, pi | `warren-docker-dev-base`: claude, opencode, codex, pi | whatever is on the host |

The image's `harness.sh`, `warren-harness-init`, `warren-state-hook` and
`warren-agent-supervisor` come from `warren-docker-base` / `warren-ecs-base`. A dev-base
pins its base by digest, so these changes reach `warren-docker-dev-base` only after
`warren-docker-base` is republished and the digest is bumped.

## Which image ships which harness

The base images (`warren-ecs-base`, `warren-docker-base`) carry the workspace contract
and no harnesses. The dev-bases carry them:

| Harness | `warren-ecs-dev-base` (1.3.0) | `warren-docker-dev-base` (1.1.0) | Installed from | Verified by | Self-update off by |
|---|---|---|---|---|---|
| claude | 2.1.309 | 2.1.309 | Anthropic's `claude.ai/install.sh`, pinned version | ECS: the binary's sha256 against Anthropic's GPG-signed release manifest; docker: none beyond the installer's own | `DISABLE_AUTOUPDATER=1` |
| opencode | no | 1.19.5 | GitHub release `opencode-linux-{x64,arm64}.tar.gz` (glibc) | sha256 pinned per arch (GitHub asset digest) | `OPENCODE_DISABLE_AUTOUPDATE=1` (the harness profile also sets `autoupdate: false`) |
| codex | 0.166.0 | 0.166.0 | GitHub release `codex-{x86_64,aarch64}-unknown-linux-musl.tar.gz` (static, runs on glibc) | sha256 pinned per arch (GitHub asset digest) | `check_for_update_on_startup = false` in `/etc/codex/config.toml` (codex has no env var) |
| pi | 1.5.0 | 1.5.0 | npm `@earendil-works/pi-coding-agent`, `npm ci --ignore-scripts` from `pi/package-lock.json` into `/opt/pi` | the lockfile's sha512 integrity for every package | `PI_SKIP_VERSION_CHECK=1` (pi only notifies; `pi update` is manual) |

Every harness is a root-owned file (or, for pi, a symlink into `/opt/pi`) in
`/usr/local/bin`, runnable by root and by the workspace user (uid 1000). Both images are
multi-arch through `TARGETARCH` (linux/amd64, linux/arm64). pi was published as
`@mariozechner/pi-coding-agent` up to 0.73.1; npm deprecated that name in favour of
`@earendil-works/pi-coding-agent` (1.x needs Node >= 22.19; both dev-bases have Node 24
or newer). pi 1.5.0 has no install-time native build: its image codec and code-mode
sandbox are WebAssembly, and pi-tui's prebuilt X11 clipboard addon is only loaded when
`DISPLAY` is set. Its `--help` still lists every flag and env var warren's pi profile uses
(`--mode rpc`, `--no-approve`, `--continue`, `--session`, `PI_CODING_AGENT_DIR`,
`PI_CODING_AGENT_SESSION_DIR`, `PI_OFFLINE`, `PI_TELEMETRY`); the profile wasn't otherwise
re-run against 1.5.0. codex reads `/etc/codex/config.toml`: a wrong-typed
`check_for_update_on_startup` there makes it fail to load its config.

`warren-ecs-ssh-base` (FROM `warren-ecs-dev-base:1.3.0`) gets the same harnesses as
the ECS dev-base. `warren-docker-ssh-base` pins `warren-docker-dev-base` by digest, so it
gets them once dev-base 1.1.0 is published and that digest is bumped.

`scripts/bump_pins.py` checks every pin weekly (Claude Code's npm `stable` tag,
opencode's and codex's latest GitHub release with their asset digests, pi's npm `latest`
tag). A pi bump rewrites `pi/package.json` and regenerates `pi/package-lock.json` in a
`node:<NODE_VERSION>-bookworm-slim` container. To do it by hand, from the repo root, for
each `pi/` dir:

```bash
docker run --rm --user "$(id -u):$(id -g)" -v "$PWD/packages/warren-server/images/warren-ecs-dev-base/pi:/w" -w /w \
  -e HOME=/tmp node:24.22.2-bookworm-slim \
  npm install --package-lock-only --ignore-scripts --omit=dev --no-audit --no-fund
cp packages/warren-server/images/warren-ecs-dev-base/pi/package*.json images/warren-docker-dev-base/pi/
```

A codex bump also needs the codex checks below redone, since warren trusts its own codex
hooks by hash.

## State hooks

Every hook runs `warren-state-hook <harness> <event> [session id]`, which writes
`<root>/.session/state.json` (`working`, `blocked`, `idle`, `exited`) for the idle reaper
and notifications, plus `<harness>.sid` for exact resume.

| Harness | Events → state |
|---|---|
| opencode | `session.created` → idle, `chat.message` → working, `tool.execute.before` → working, `permission.asked`/`permission.updated` → blocked, `session.idle` → idle, `session.deleted` → exited |
| codex | `SessionStart` → idle; `UserPromptSubmit`, `PreToolUse`, `PostToolUse`, `SubagentStart`, `SubagentStop`, `PostCompact` → working; `PermissionRequest` → blocked; `Stop` → idle; `SessionEnd` → exited |

codex runs a user hook only after it is trusted: `config.toml` must carry
`[hooks.state."<hooks.json path>:<event>:<group>:<handler>"] trusted_hash = "sha256:..."`,
the sha256 of codex's normalized form of the hook. warren generates those entries for its
own hooks (`agent_state.codex_hook_trust`), so they run without
`--dangerously-bypass-hook-trust` and a repository's hooks stay untrusted. If a codex
release changes how it normalizes hooks, the hashes stop matching and the hooks silently
don't run. State then falls back to what the supervisor sees for an agent workspace (ACP
traffic, process liveness) and to the OSC 7501 / egress signals for a user workspace.
`warren doctor` warns about a codex older than the version checked here.

In `serve` and `app-server` modes the supervisor sees no protocol traffic, so the
harness's hooks are the only source of `working`/`blocked`; without them the workspace
reads `idle` while the process runs and `exited` when the supervisor gives up.

## Model access (Bedrock and a Bedrock gateway)

Claude Code reads `CLAUDE_CODE_USE_BEDROCK`, `ANTHROPIC_BEDROCK_BASE_URL`,
`CLAUDE_CODE_SKIP_BEDROCK_AUTH` and `ANTHROPIC_AUTH_TOKEN` from the env (the server sets
them in bedrock mode, with `WARREN_BEDROCK_GATEWAY_URL` for a gateway). warren turns the
same env into the other harnesses' provider config, at container start
(`warren-harness-init`) and on every local connect:

- **opencode** (`config/opencode.json`): `enabled_providers: ["amazon-bedrock"]`;
  `model` from `ANTHROPIC_MODEL` and `small_model` from `ANTHROPIC_DEFAULT_HAIKU_MODEL`
  (as `amazon-bedrock/<id>`); `provider.amazon-bedrock.options` gets `region` from
  `AWS_REGION`, `endpoint` from `ANTHROPIC_BEDROCK_BASE_URL`, and, with
  `CLAUDE_CODE_SKIP_BEDROCK_AUTH`, `apiKey: "{env:ANTHROPIC_AUTH_TOKEN}"`, which opencode
  resolves at load time, so the key never lands in a file. Without a gateway opencode
  signs requests with the workspace's AWS identity (the ECS task role). Set
  `ANTHROPIC_DEFAULT_HAIKU_MODEL` when you route through a gateway: opencode's own
  default small model (for titles) is a `global.` inference profile the gateway may not
  serve.
- **codex** (`config.toml`): in bedrock mode without a gateway,
  `model_provider = "amazon-bedrock"` and `[model_providers.amazon-bedrock.aws] region`.
  codex calls Bedrock's OpenAI-compatible endpoint (`bedrock-mantle.<region>.api.aws`,
  `/openai/v1/responses`, SigV4 or `AWS_BEARER_TOKEN_BEDROCK`) with OpenAI models such as
  `openai.gpt-oss-120b`, not the InvokeModel/Converse API a Claude gateway proxies.
  warren doesn't point codex at `ANTHROPIC_BEDROCK_BASE_URL`; to use a gateway that also
  proxies Mantle, set `model_providers.amazon-bedrock.base_url` yourself.

Values with characters outside a conservative set (URL, model id, region) are dropped,
not escaped.

## opencode data dirs

`OPENCODE_CONFIG_DIR` only adds a config dir. opencode keeps its data (`auth.json`, logs,
snapshots, the session DB) in `$XDG_DATA_HOME/opencode` and prompt history in
`$XDG_STATE_HOME/opencode`. warren sets both to the harness dir (`data/`, `state/`), but
only on opencode's own process (`process_env`), never in the shell: Claude Code also reads
`XDG_DATA_HOME` to find its installed versions. Tools opencode runs inherit them. opencode's
cache (`~/.cache/opencode`, models catalog and plugin installs) stays in `$HOME` and isn't
persisted; it installs its plugin dependencies into `config/` on first start, which the
next container start removes.

## What was checked, and how

Checked on 2026-11-01 in a throwaway container (warren-ecs-dev-base 1.3.0, Debian
bookworm, glibc, linux/arm64), with `opencode-ai@1.19.5` and `@openai/codex@0.166.0`
from npm, a fake model endpoint on loopback, and warren's generated `harness.sh`,
`warren-harness-init`, `warren-state-hook` and `warren-agent-supervisor`:

- opencode 1.19.5: `acp`, `serve`, `attach` and their flags (`--hostname` defaults to
  127.0.0.1, `--port`); `OPENCODE_CONFIG_DIR`, `OPENCODE_DB` and the XDG dirs as above
  (`opencode debug paths`, `opencode db path`); through the warren shell, the generated
  gateway config sent `POST <gateway>/model/<id>/converse-stream` with
  `Authorization: Bearer <ANTHROPIC_AUTH_TOKEN>`; the state plugin reported SessionStart,
  UserPromptSubmit and Stop with the session id; under the supervisor, `opencode serve`
  answered `GET /config` with 200 on the agent port, and `opencode acp` answered
  `initialize` (loadSession: true) and `session/new` through the supervisor's ACP endpoint,
  which recorded the session id. `auth.json`/`mcp-auth.json` planted under `data/` were gone
  after init.
- codex 0.166.0: subcommands (`exec`, `resume`, `app-server --listen
  stdio://|ws://IP:PORT`; there is no `mcp-server` or ACP subcommand); `[features]
  codex_hooks` is deprecated in favour of `hooks`; warren's hooks fire only when trusted,
  and the generated hashes equal the ones `codex app-server` reports in `hooks/list`;
  through the warren shell, SessionStart, UserPromptSubmit and Stop reached the state hook
  without the bypass flag; `codex exec resume <id>` resumed a thread after init pruned the
  dir to `sessions/`, `history.jsonl` and `log/`; the generated `amazon-bedrock` provider
  sent `POST /openai/v1/responses` with the bearer token (base URL overridden to the fake);
  `codex app-server --listen ws://127.0.0.1:<port>` ran under the supervisor and refused a
  plain HTTP request on the port with 400 (websocket only); `--sandbox` is rejected by
  `app-server`.

- podman path: `warren-docker-base` built from this branch plus the dev-base opencode
  install step (sha256 checked, `opencode --version` = 1.19.5), run with the exact env
  `PodmanRuntime.provision()` builds for `kind: agent`, `agent.mode: serve`: the
  entrypoint ran `warren-harness-init` and started the supervisor, which started
  `opencode serve` on 127.0.0.1:4096 (`GET /config` 200).

Not checked: opencode's musl build (Alpine) and linux/amd64; a real Bedrock gateway
(only that the request shape is Bedrock's Converse API, which the gateway must proxy);
`opencode attach` and the T3 desktop app against `serve`, and `codex --remote` against
`app-server` (both interactive); opencode's `permission.asked` and `tool.execute.before`
events and codex's PermissionRequest/Subagent/Compact/SessionEnd events (no tool calls or
approvals in the fake runs); any codex ACP adapter. The checks above used codex from npm;
the dev-bases install the same version's standalone release binary.
