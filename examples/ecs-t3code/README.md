# ecs-t3code: an example ECS workspace image with T3 Code

This is an example ECS workspace image that runs [T3 Code](https://t3.codes)'s server,
`t3 serve`, next to Claude Code. T3 Code is a control-plane UI for coding agents. The
server runs on the machine where the agents work, and the T3 desktop, web or phone app
connects to it.

**CI doesn't build or publish this image.** No workflow builds it, it isn't a component
in `.github/releases.json`, and no image-workflow path filter matches `examples/`. If you
want to use it, build and push it yourself.

## Base image: `warren-ecs-base` 1.5.0

This image targets **`warren-ecs-base` 1.5.0**, the first Debian bookworm-slim (glibc)
release. T3 Code's prebuilt server is glibc-only: on the 1.4 and earlier Alpine images it fails with
`fcntl64: symbol not found`, even with gcompat. So build it on 1.5.0 or later, not 1.4 or earlier.

Everything warren needs comes from ecs-base unchanged: `entrypoint.sh`,
`warren-session`, `warren-init-volume`, `warren-git-materialize`, the harness and
secrets helpers, `su-exec`, the uid/gid 1000 `warren` user, `USER root`,
`WORKDIR /home/warren`, `ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]` and no CMD. This
image only adds apt packages, Claude Code and t3, so the default workspace behaves the
same as ecs-base. It idles on `tail -f /dev/null` as uid 1000 for ECS Exec, runs
`WARREN_APP_CMD` when one is set, and uses the same git-init and secrets handling. It
also works as the task's `git-init` container.

`WARREN_ECS_BASE` defaults to `ghcr.io/scottcowan/warren-ecs-base:1.5.0`, pinned by digest.
To use a newer base, pass `--build-arg WARREN_ECS_BASE=ghcr.io/scottcowan/warren-ecs-base:<version>@sha256:...`.

## What's in the image

| | Version | Pinned by |
| --- | --- | --- |
| base | warren-ecs-base 1.5.0 (Debian bookworm-slim) | `WARREN_ECS_BASE` (pinned by tag and digest) |
| t3 | 0.1.6 (stable) | `T3_VERSION` plus the per-arch sha256 from the release's `SHA256SUMS` |
| Claude Code | 2.1.308 | `CLAUDE_CODE_VERSION`, sha256 from Anthropic's GPG-signed manifest |
| apt (on top of ecs-base) | curl, python3 (3.11), jq, ripgrep | the bookworm archive at build time (not version-pinned) |

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

To build on an ecs-base you built from this repo (for example to test changes to
the base before they are released):

```bash
docker buildx build --platform linux/arm64 --load -t warren-ecs-base:local \
  -f packages/warren-server/images/ecs-base/Dockerfile .
docker buildx build --platform linux/arm64 --load -t warren-ecs-t3code:local \
  --build-arg WARREN_ECS_BASE=warren-ecs-base:local examples/ecs-t3code
```

This needs a builder that can see local images (the `docker` driver, which Docker
Desktop and colima use by default).

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
    ports: {t3: 3773}   # lets `warren proxy add <workspace> --from-template` find it
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

1. On your machine, run `warren proxy add <workspace> --from-template` (and keep
   `warren proxy run` going). With `ports: {t3: 3773}` in the template, it prints a
   stable `127.0.0.1:<local-port>` for `<server>/<workspace>/t3` that forwards to port
   3773 inside the workspace. Without `ports`, `warren proxy add <workspace> 3773` does
   the same. See [docs/proxy.md](../../docs/proxy.md).
2. Get a pairing link inside the workspace. `t3 serve` prints one when it starts. For
   a fresh one, run `t3 pair` from a warren shell in the workspace (pass `--ttl` and
   `--scope` to narrow it).
3. In the desktop app, open **Settings → Environments → Add environment** and add
   `http://127.0.0.1:<local-port>` with the pairing code, or paste the pairing URL with
   its host swapped for `127.0.0.1:<local-port>`. The token's `#token=…` stays the same.

Pairing links and codes are passwords. Keep them out of logs, screenshots and issues.

## On a podman or docker server

`warren proxy` reaches podman/docker workspaces too, through an `ssh` remote (an
SSH forward to the server host) or a local `http` remote (no SSH). The server
publishes each declared port on its own loopback; see
[docs/proxy.md](../../docs/proxy.md#podmandocker-servers). Three differences from
ECS:

- **Declare the port.** Only ports under `ports:` are published, so keep
  `ports: {t3: 3773}` in the template; `warren proxy add <workspace> 3773` without
  it has nothing to reach. Recreate a workspace made before the port was declared.
- **Bind `0.0.0.0` inside the container.** The published port enters through the
  container's interface, not its loopback, so run
  `t3 serve --host 0.0.0.0 --port 3773 --no-browser`. It is still only reachable
  from the server host's loopback: the workspace's bridge network is isolated from
  other workspaces, and the host port is bound to `127.0.0.1`. Under rootless
  podman, the server requires slirp4netns rather than pasta unless
  `WARREN_PODMAN_ALLOW_PASTA=1` (residual risk 6 in [threat-model.md](../../docs/threat-model.md)).
- **Start it in a session.** This image's entrypoint (from ecs-base) runs
  `WARREN_APP_CMD`, which only the ECS runtime sets; on podman/docker it idles, so
  start `t3 serve` from `warren connect`, or use a podman workspace image that runs
  the template's `app`.

Then `warren proxy add <workspace> --from-template --server <ssh-remote>` and pair
the app with the printed address, as above.

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
- **You'll need a different port if 3773 is taken.** Pick another `--port` and put
  the same number in the template's `ports` (or pass it to `warren proxy add`).

## Verified locally (2026-10-31)

Host: Apple Silicon Mac, colima (BuildKit v0.30.0), native linux/arm64, on an ecs-base
built from this repo (`--build-arg WARREN_ECS_BASE=<local tag>`, the 1.5.0 Dockerfile).
linux/amd64 was not run.

- The build-time checks print `t3 v0.1.6` and `2.1.308 (Claude Code)`.
- Image config is inherited from ecs-base: User=root, WorkingDir=/home/warren,
  Entrypoint=["/usr/local/bin/entrypoint.sh"], Cmd=null, LANG=C.UTF-8.
- `.github/scripts/ecs-base-smoke.sh` (the ecs-base smoke checks) passes against this
  image too.
- `docker run -d -e WARREN_APP_CMD='exec t3 serve --host 127.0.0.1 --port 3773 --no-browser' IMG`,
  then `curl http://127.0.0.1:3773/` inside the container: HTTP 200 after 3 s, PID 1 is
  uid 1000, and the log shows `Listening on http://127.0.0.1:3773` and
  `T3 Code server is ready.`

Not verified here: linux/amd64 runtime, and a real ECS task (Fargate pull, ECS Exec,
EFS/EBS volumes, KMS decrypt against the real service). Pairing the desktop app
through `warren proxy add` wasn't tested, on ECS or on podman/docker, and this image
hasn't been run as a podman workspace.
