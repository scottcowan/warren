# ecs-t3code: an example ECS workspace image with T3 Code

This is an example ECS workspace image that runs [T3 Code](https://t3.codes)'s server,
`t3 serve`, next to Claude Code. T3 Code is a control-plane UI for coding agents. The
server runs on the machine where the agents work, and the T3 desktop, web or phone app
connects to it.

**CI doesn't build or publish this image.** No workflow builds it, it isn't a component
in `.github/releases.json`, and no image-workflow path filter matches `examples/`. If you
want to use it, build and push it yourself.

## Why it isn't `FROM warren-ecs-base`

T3 Code's prebuilt server is glibc-only. On Alpine it fails with
`fcntl64: symbol not found`, even with gcompat. So this image is Debian bookworm-slim
with warren's ECS workspace contract rebuilt on top. Everything below matches
[`packages/warren-server/images/ecs-base`](../../packages/warren-server/images/ecs-base/Dockerfile):

- The same files at the same paths and modes, copied out of the published,
  digest-pinned `ghcr.io/scottcowan/warren-ecs-base:1.4.0`. That covers `entrypoint.sh`,
  `warren-session`, `warren-init-volume`, `warren-git-materialize`,
  `warren-harness-init`, `warren-state-hook`, `warren-agent-supervisor`,
  `/usr/local/lib/warren/secrets.sh`, `/etc/warren/{harness.sh,banner.bash,ssh_known_hosts}`
  and `/etc/zsh/zshrc`.
- The same uid/gid 1000 `warren` user, with a 2755 `/home/warren` that has no skel files.
- `/workspace` and `/var/lib/warren` owned by 1000.
- `USER root`, `WORKDIR /home/warren`, `ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]`
  and no CMD.

The default workspace behaves the same as ecs-base. It idles on `tail -f /dev/null` as
uid 1000 for ECS Exec, runs `WARREN_APP_CMD` when one is set, and uses the same git-init
and secrets handling. The image also works as the task's `git-init` container.

### Debian vs Alpine

| Piece | ecs-base (Alpine) | here (Debian) |
| --- | --- | --- |
| `su-exec` | apk `su-exec` (musl) | bookworm has no `su-exec` package, so ncopa/su-exec 0.2 (the same source Alpine packages; sha256 pinned, matches Alpine's sha512) is built for glibc and installed as `/usr/sbin/su-exec`. `/sbin` is a symlink to `usr/sbin`, so `/sbin/su-exec` works. |
| `warren-secrets-decrypt` | built in the image | ecs-base is published for linux/amd64 only. The binary is built from the ecs-base release commit (`3a0dbdd`) with ecs-base's Go image (same digest), tests and flags. On amd64 the build fails unless the result is byte-identical to the published binary (checked: both are sha256 `7ddb979f…1ddaf`). |
| bash hooks | appended to `/etc/bash/bashrc` | Debian's bash reads `/etc/bash.bashrc`, so the same two lines are appended there, and `/etc/bash/bashrc` links to it. |
| zsh | `/etc/zsh/zshrc` | same file. Debian's `zsh-newuser-install` menu is removed so a home without `.zshrc` doesn't prompt. |
| `/etc/warren` | 0644 in ecs-base 1.4.0 | 0755. In 1.4.0 the directory has no search bit, so uid 1000 can't read `banner.bash` or `harness.sh`, and the warren shell commands are missing for the workspace user. This is an ecs-base bug, not a Debian difference. |
| shell tools | busybox | dash, coreutils, findutils, sed, grep, mawk, tar. The scripts only use options these share with busybox (`stat -c`, `find -mindepth/-prune/-empty`, `base64 -d`, `mktemp`, `head -c`, `ls -ldn`, `sed -n -E`). Every absolute path the scripts call (`/bin/rm`, `/bin/stat`, `/usr/bin/id`, `/usr/bin/tmux`, `/sbin/su-exec`, …) exists through merged `/usr`. |
| git | 2.45 | 2.39.5. The options git-materialize uses all predate 2.39, and its end-to-end checks pass (see below). |

## What's in the image

| | Version | Pinned by |
| --- | --- | --- |
| Debian | bookworm-slim (12.15) | index digest `sha256:99c0b25c…22b6f3` |
| warren files | warren-ecs-base 1.4.0 | `ghcr.io/scottcowan/warren-ecs-base:1.4.0@sha256:43b4196a…c202b7` (commit `3a0dbddf74b405c4115249d8ebf0caf7d921712c`) |
| t3 | 0.1.6 (stable) | `T3_VERSION` plus the per-arch sha256 from the release's `SHA256SUMS` |
| Claude Code | 2.1.308 | `CLAUDE_CODE_VERSION`, sha256 from Anthropic's GPG-signed manifest |
| apt | git, openssh-client, bash, zsh, tmux, ca-certificates, curl, python3 (3.11), jq, ripgrep | the bookworm archive at build time (not version-pinned) |

- **t3** comes from the release archive that `https://t3.codes/install.sh` downloads,
  `t3-<version>-linux-{arm64,x64}.tar.gz`. The archive is the `t3` executable plus the
  native modules it loads. It's unpacked to `/opt/t3/<version>`, and `/usr/local/bin/t3`
  links to it, so nothing lives in a home directory.
- **Claude Code** is verified the same way as
  [`warren-ecs-dev-base`](../../packages/warren-server/images/warren-ecs-dev-base/Dockerfile):
  the image checks the GPG-signed `manifest.json` (key `31DD DE24 … 1A7E CACE`), then
  checks the binary's sha256 against it. One difference: the binary is fetched straight
  from the release bucket that `install.sh` downloads from (`linux-arm64`/`linux-x64`,
  the glibc builds), not through `install.sh`. It goes into `/usr/local/bin/claude`.
- **Updates**: there are none at runtime, so rebuild with new ARGs instead.
  - Claude Code: `DISABLE_AUTOUPDATER=1` is set (its binary is root-owned).
  - t3: started with `t3 serve` rather than `t3 service install`, the server has no
    service launcher and refuses update requests from the apps ("Remote updates require
    the T3 Code background service"). T3 has no env switch for this; this is how
    `t3 serve` behaves. Don't run `t3 update` in the workspace. It would download a
    second runtime into `~/.t3`.
- **Telemetry**: `T3CODE_TELEMETRY_ENABLED=false` turns off T3's product-usage events
  and relay traces. To turn them back on, set the variable in the template's `env`.

## Build

The build context is just this directory. It needs no repo files.

```bash
docker buildx build --platform linux/arm64 --load -t warren-ecs-t3code:local examples/ecs-t3code
# or, on an amd64 host / for an ECS task on X86_64:
docker buildx build --platform linux/amd64 --load -t warren-ecs-t3code:local examples/ecs-t3code
```

Push it to a registry your ECS tasks can pull from (for example your ECR repository),
then point a template's `docker_image` at that tag (or digest).

## Running `t3 serve` in the workspace

`t3 serve` listens on **127.0.0.1:3773** by default. That address was verified in this
image: with no `--port`, it takes 3773, or the next free port if 3773 is taken. The
flags are:

- `--port <n>`: a fixed port. Use one so the proxy port stays stable.
- `--host <addr>`: bind address. Keep the 127.0.0.1 default. The connection comes in
  through a warren proxy into the task (below), not through the task's network
  interface. `--lan` or `--host 0.0.0.0` would expose the server on the VPC.
- `--no-browser`: don't try to open a browser.
- `--base-dir <dir>`: the data dir (`T3CODE_HOME`, default `~/.t3`). Put it under
  `/var/lib/warren` to keep threads across task restarts.

There are two ways to start it.

**As the workspace app.** The entrypoint runs it as PID 1, as uid 1000, from the
checkout:

```yaml
templates:
  t3:
    description: T3 Code server with Claude Code
    docker_image: <your-registry>/warren-ecs-t3code:<tag>
    permission: write
    harnesses: [claude]
    app: t3 serve --host 127.0.0.1 --port 3773 --no-browser --base-dir /var/lib/warren/t3
```

warren treats an `app` that isn't a shell or a harness as a service and passes it to the
entrypoint as `WARREN_APP_CMD`. You can still attach the warren shell next to it with
`warren connect`.

**In a session.** Use the default `app` (the warren shell) and start it in tmux when you
want it:

```bash
warren connect <workspace>
t3 serve --port 3773 --no-browser --base-dir /var/lib/warren/t3   # in a tmux window
```

## Pairing the T3 desktop app

1. On your machine, run `warren proxy add <workspace> 3773`. It prints a stable
   `127.0.0.1:<local-port>` that forwards to port 3773 inside the workspace. (`warren
   proxy` is a new CLI command, being added separately.)
2. Get a pairing link inside the workspace. `t3 serve` prints one when it starts. For
   a fresh one, run `t3 pair` from a warren shell in the workspace (pass `--ttl` and
   `--scope` to narrow it).
3. In the desktop app, open **Settings → Environments → Add environment** and add
   `http://127.0.0.1:<local-port>` with the pairing code, or paste the pairing URL with
   its host swapped for `127.0.0.1:<local-port>`. The token's `#token=…` stays the same.

Pairing links and codes are passwords. Keep them out of logs, screenshots and issues.

## Things to know

- **Don't use T3 Connect (`t3 up`, `t3 connect`) for company code.** It relays the
  environment through T3's cloud. Pair directly through `warren proxy` instead, and
  leave **Sharing & access → T3 Connect** off.
- **T3's commit/push/PR button won't work as-is.** It needs a git credential inside the
  workspace, and warren deliberately doesn't give the workspace container one. The
  clone PAT only reaches the `git-init` container, and the workspace's checkout has no
  credential helper. Agents and T3 can commit locally. To push, either give the
  template a scoped token as a secret and configure git with it yourself, or push from
  outside the workspace.
- **Claude Code reads warren's existing env.** On a Bedrock template
  (`model_access: bedrock`), warren sets `CLAUDE_CODE_USE_BEDROCK=1` and `AWS_REGION`,
  and Claude uses the task role. With `WARREN_BEDROCK_GATEWAY_URL` it also sets
  `ANTHROPIC_BEDROCK_BASE_URL`, plus the gateway key in `ANTHROPIC_AUTH_TOKEN`. T3
  starts `claude` from the server's environment, so those values reach every T3
  thread. Nothing T3-specific needs configuring. In T3's provider settings, enable
  **Claude**. Skip `claude auth login` on Bedrock.
- **The browser panel doesn't work.** T3's headless browser for browser tabs and HTML
  previews isn't installed. At startup the server warns that the sandbox is blocked.
  `t3 browser setup` needs root and apt, so add Chrome's libraries in a derived image if
  you need the panel.
- **You'll need a different port if 3773 is taken.** Pick another `--port` and pass
  the same number to `warren proxy add`.

## Verified locally (2026-10-31)

Host: Apple Silicon Mac, colima (BuildKit v0.30.0), native linux/arm64. linux/amd64 was
not run, because emulated Go/bun binaries crash on this host. The amd64-only part was
checked by cross-compiling (below).

```bash
docker buildx build --platform linux/arm64 --load -t warren-ecs-t3code:local examples/ecs-t3code
# built clean, first try; image 1.31 GB. Build-time checks print:
#   t3 v0.1.6
#   2.1.308 (Claude Code)

# amd64 secrets-decrypt provenance (the Go stage runs on the build platform, so no emulation):
docker buildx build --platform linux/amd64 --target secrets-decrypt \
  --output type=local,dest=/tmp/decrypt-amd64 examples/ecs-t3code
shasum -a 256 /tmp/decrypt-amd64/out/warren-secrets-decrypt /tmp/decrypt-amd64/published/warren-secrets-decrypt
# 7ddb979f3bc6df7195af131fba8dfe0d670d11ae8a04e79a676b53bbcdd1ddaf  (both: byte-identical; the in-build cmp passed)
```

Then a script ran every applicable check from
`.github/workflows/warren-ecs-base-smoke.yml` against the image, plus the T3 checks.
**Result: 49 passed, 0 failed.**

| Check | Command (abridged) | Result |
| --- | --- | --- |
| versions | `docker run --rm --entrypoint <tool> IMG --version` | t3 v0.1.6; Claude Code 2.1.308; git 2.39.5; bash 5.2.15; tmux 3.3a; OpenSSH 9.2p1; zsh 5.9; Python 3.11.2; jq 1.6; ripgrep 13.0.0; Debian 12.15 |
| script syntax | `sh -n` and `bash -n` on entrypoint.sh, warren-session, warren-init-volume, warren-git-materialize, warren-harness-init, warren-state-hook, secrets.sh; `bash -n` harness.sh, banner.bash, /etc/bash.bashrc; `zsh -n /etc/zsh/zshrc`; `python3 -m py_compile warren-agent-supervisor` | all pass (`/bin/sh` is dash) |
| su-exec | `--entrypoint /sbin/su-exec IMG 1000:1000 id` | `uid=1000(warren) gid=1000(warren) groups=1000(warren)`; HOME `/home/warren` |
| entrypoint drop | `-e WARREN_APP_CMD='id -u; echo $HOME' IMG` | `1000 /home/warren` |
| decrypt usage | `--entrypoint /usr/local/bin/warren-secrets-decrypt IMG` | `usage: warren-secrets-decrypt <workspace\|git-init>`, non-zero; no blob → fails, empty stdout; junk blob → app never runs |
| modes | `stat -c %u:%g:%a` on the helpers, /usr, /usr/local{,/bin,/lib,/lib/warren}, /etc/warren | `0:0:755`; ssh_known_hosts `0:0:444`; secrets.sh `0:0:644`; /workspace, /var/lib/warren, /home/warren `1000:1000`, home 2755 and empty |
| image config | `docker image inspect` | User=root, WorkingDir=/home/warren, Entrypoint=["/usr/local/bin/entrypoint.sh"], Cmd=null |
| fresh volume | tmpfs on /var/lib/warren, `touch` as the app | `1000:1000` |
| shell hooks | `su-exec warren bash -ic 'type -t warren'`, `zsh -ic 'whence -v warren'` | function from /etc/warren/harness.sh, no zsh-newuser menu |
| warren-session PATH | planted su-exec/tmux/id first on PATH | not used; reaches tmux (`open terminal failed: not a terminal`) |
| git-init (AH1) | file:// worktree materialize, then entrypoint | `1000:1000`, `/workspace` → `/var/lib/warren/workspace`, branch `warren/dev/abcdef12/code-app` |
| EBS bare seeds | `--seed-key`, `refresh-seed`, seeded clone | `cloned from the seed` ×1, seed removed, sees the later commit |
| EFS secrets | workspace.env + git-init.env on the volume | exported, both files gone, git PAT not loaded, root copy unreadable to warren |
| idle workspace | `docker run -d IMG`, wait 5 s, `docker inspect`, `docker rm -f` | running; PID 1 `tail -f /dev/null` as uid 1000 |
| t3 serve | `docker run -d -e WARREN_APP_CMD='exec t3 serve --host 127.0.0.1 --port 3773 --no-browser' IMG`; `docker exec … curl -sS -m 3 -w '%{http_code}' http://127.0.0.1:3773/` | HTTP 200 after 2 s (the web app's HTML); PID 1 is uid 1000; logs `Listening on`, `T3 Code server is ready.`, a pairing URL; one WARN (browser sandbox, see above) |
| t3 pair | `docker exec … su-exec warren t3 pair --ttl 1m` | exit 0, pairing URL on `http://127.0.0.1:3773` |
| t3 default bind | `WARREN_APP_CMD='exec t3 serve --no-browser'` | listens only on 127.0.0.1:3773 |

Every container was started with `--rm` or removed with `docker rm -f`.

Not verified here: linux/amd64 runtime, and a real ECS task (Fargate pull, ECS Exec,
EFS/EBS volumes, KMS decrypt against the real service). `warren proxy add` comes from a
separate branch, and pairing from the desktop app through it wasn't tested.
