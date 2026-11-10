# SSH into workspaces (editor remoting)

Editors that remote over SSH (VS Code Remote-SSH, Cursor, JetBrains Gateway) need an
sshd in the workspace. warren's base images deliberately ship none: ECS workspaces get
a shell through ECS Exec over SSM, and podman/docker workspaces through `podman exec`
over your SSH access to the server host (`warren connect`). For editors there are two
opt-in images, one per server runtime, with the same hardened sshd, and one CLI command
that writes the matching `~/.ssh/config` entry:

| Image | FROM | Runtime |
|---|---|---|
| **`ghcr.io/scottcowan/warren-ecs-ssh-base`** | `warren-ecs-dev-base` (Debian, 1.3.0) | ECS Fargate |
| **`ghcr.io/scottcowan/warren-docker-ssh-base`** | `warren-docker-dev-base` (pinned by digest) | podman/docker servers |

Nothing changes for templates that don't use them.

## How it fits together

ECS:

```
editor ─ ssh ─ ProxyCommand: warren proxy stdio <ws> 2222
                   │  control plane: GET /workspaces -> the workspace's current task
                   │  aws ssm start-session --document-name AWS-StartPortForwardingSession
                   ▼     --target ecs:<cluster>_<task>_<runtime-id> portNumber=2222
             Fargate task ── 127.0.0.1:2222 ── sshd (uid 1000, key-only) ── warren user
```

podman/docker:

```
editor ─ ssh ─ ProxyJump <server host> ── server host's 127.0.0.1:<published port>
                                              │  (WARREN_SSH_ACCESS_ENABLED=true,
                                              ▼   WARREN_SSH_PUBLISH_HOST=127.0.0.1)
                                  container port 22 ── sshd ── warren-shell / warren
```

- **ECS.** The sshd listens on the task's **127.0.0.1:2222 only**. The task has no port
  mapping, load balancer or inbound rule for it, so the only way in is an SSM
  port-forward to the task's loopback. That takes `ssm:StartSession` on that task, the
  same permission ECS Exec (`warren connect`) needs, so whoever can SSH in could already
  open a root shell in the task. `warren proxy stdio <ws> <port>` resolves the
  workspace's current task through the control plane on every connection (like
  `warren proxy run`), starts the forward on an ephemeral loopback port and pipes
  stdin/stdout through it. It stops the forward when ssh closes it. A stopped workspace
  fails with a message saying so; start it with `warren connect <ws>` first.
- **podman/docker.** The server publishes the container's port 22 on the server host's
  `127.0.0.1` only (when the operator sets `WARREN_SSH_ACCESS_ENABLED=true`). Rootless
  podman gives containers no route to host loopback, so other workspaces can't reach it.
  You reach it through the server host, with the same SSH access `warren connect` uses.
  The key is minted per workspace by the server (`POST /workspaces/{id}/connect`) and
  written into the running container.
- In both, the host key is per workspace and is never in the image. `HostKeyAlias`
  pins the client's known_hosts entry to the workspace.

## Image layout

### warren-ecs-ssh-base (`packages/warren-server/images/warren-ecs-ssh-base/`)

| Path | What |
|---|---|
| `/etc/ssh/sshd_config` | the hardened config (root-owned, 0644); `/etc/ssh/sshd_config.d/` is empty and read first, for derived images |
| `/usr/local/bin/warren-sshd` | generates the host key, writes `authorized_keys`, runs `sshd -D -e` as uid 1000 with a clean environment |
| `/usr/local/bin/entrypoint.sh` | small wrapper: after ecs-base's entrypoint has loaded the secrets and dropped to uid 1000, starts `warren-sshd` in the background and hands over |
| `/usr/local/lib/warren/ecs-entrypoint.sh` | ecs-base's entrypoint, unchanged, moved here |
| `/etc/profile.d/warren-path.sh` | the image's PATH (pyenv shims, `/usr/local`) for SSH login shells |
| `/var/lib/warren/.warren-ssh/ssh_host_ed25519_key` | host key, on the volume, created at first start; survives task restarts |
| `~warren/.ssh/authorized_keys` | rewritten from `SSH_AUTHORIZED_KEYS` at every start |

sshd's logs (including the host key fingerprint, and the fingerprints of the authorized
keys) go to the container log.

### warren-docker-ssh-base (`images/warren-docker-ssh-base/`)

Built to match what warren-server's podman runtime already does for SSH access (the
integration-test image `packages/warren-server/tests/integration/fixtures/ssh_test_image`
was the reference):

| Path | What |
|---|---|
| `/etc/ssh/sshd_config` | the same hardening, port 22, `AllowUsers warren warren-shell`, `AuthorizedKeysFile /etc/warren/authorized_keys` |
| `/usr/local/bin/warren-sshd-start` | the entrypoint: generates the host key, creates an empty `/etc/warren/authorized_keys` (root, 0644) if the server hasn't written one, starts sshd in the background with a clean environment, then execs warren-docker-base's `/entrypoint.py` unchanged |
| `/etc/warren/authorized_keys` | written by the server with the key `POST /workspaces/{id}/connect` mints (one key; the next mint replaces it, stop/destroy empties it) |
| `/etc/ssh/warren/ssh_host_ed25519_key` | host key (root, 0700 dir), created at the container's first start; survives stop/start, a re-provisioned container gets a new one |
| users `warren` (1000), `warren-shell` (1001) | the names the server hands out; both get a plain login shell here (this image has no ACP ForceCommand on `warren`) |
| `/etc/profile.d/warren-path.sh` | the image's PATH for SSH login shells |

sshd runs as the container's root here, because it serves two users. `PermitRootLogin`
stays `no`.

**Rootless podman:** under the server's default `keep-id:uid=1000,gid=1000` mapping
the checkout is owned by uid 1000 and warren-docker-base runs the workload as `warren`
(uid 1000) after its root phase, so the SSH `warren` login and the workload are the same
user: an editor can write what the agent made and the agent can use what the editor
saves. `warren-shell` (1001) is a separate account without write access to the checkout.
Under `WARREN_PODMAN_USERNS=host` the checkout belongs to container root and the SSH
logins can read but not write it (the workload stays root there); see the server README's
runtime table. A dev-base/ssh-base published before warren-docker-base's uid-1000 drop
still has a root workload.

## sshd hardening

Both `sshd_config`s carry the same settings, asserted with `sshd -T` by each image's
smoke test:

- key-only: `AuthenticationMethods publickey`; `PasswordAuthentication`,
  `KbdInteractiveAuthentication`, `PermitEmptyPasswords`, `HostbasedAuthentication`,
  `GSSAPIAuthentication`, `KerberosAuthentication`, `UsePAM` all `no`;
- `PermitRootLogin no`, `AllowUsers` limited to the workspace user(s), `StrictModes yes`,
  `PermitUserEnvironment no`, `MaxAuthTries 3`;
- `AllowTcpForwarding local` (what editors use); `GatewayPorts no`, `PermitListen none`,
  `AllowStreamLocalForwarding no`, `PermitTunnel no`;
- `X11Forwarding no`, `AllowAgentForwarding no`;
- `Subsystem sftp internal-sftp` (JetBrains Gateway uploads its backend over SFTP).

The differences come from the runtime:

| | ECS | podman/docker |
|---|---|---|
| listen | `ListenAddress 127.0.0.1:2222` (task loopback; the only TCP listener in the task) | port 22 on the container's interfaces, published by the server on host `127.0.0.1` only |
| sshd runs as | uid 1000, the workload's own user (it can only log in that user) | container root (serves two users), no root logins |
| keys | `~warren/.ssh/authorized_keys` from `SSH_AUTHORIZED_KEYS` | `/etc/warren/authorized_keys`, written by the server |
| users | `warren` | `warren`, `warren-shell` |

On ECS the workload still runs as uid 1000 exactly as in ecs-base; on podman the
workload runs through warren-docker-base's `/entrypoint.py`, which drops to uid 1000 over
uid-1000-owned mounts (keep-id) and stays root otherwise.

### Enabling agent forwarding

Off by default: a forwarded agent can be used by any process in the workspace for as
long as you are connected. If you want it anyway (for example to `git push` with your
own key), build on either image:

```dockerfile
FROM ghcr.io/scottcowan/warren-ecs-ssh-base:<version>   # or warren-docker-ssh-base
RUN printf 'AllowAgentForwarding yes\n' > /etc/ssh/sshd_config.d/agent-forwarding.conf
```

and add `ForwardAgent yes` to your Host block. The drop-in directory is read before the
main config, and sshd takes the first value it reads.

## Getting your public key in (ECS)

On podman/docker there is nothing to do: the server mints the key (see Client setup).

On ECS the workspace takes its authorized keys from the `SSH_AUTHORIZED_KEYS`
environment variable (one or more public key lines), which `warren-sshd` writes to
`~warren/.ssh/authorized_keys` at each start. There is no separate user-key API (the
podman credential is a per-workspace key the server mints and writes into a running
container, which an ECS task can't be handed after it starts). A public key isn't
secret, but the per-owner secret store is the launch-time delivery path that is per
user, so use it. Declare the name in the template, so each owner's workspace gets that
owner's own key (on ECS a secret's owner is your AWS identity, the same one SSM
authorizes):

```yaml
templates:
  editor:
    docker_image: ghcr.io/scottcowan/warren-ecs-ssh-base:<version>
    secrets:
      - name: SSH_AUTHORIZED_KEYS
```

then store your public key and push it with the project (the push uploads the declared
secrets you hold locally, to your own scope on that server):

```bash
warren secrets add SSH_AUTHORIZED_KEYS --project myproject   # paste the contents of ~/.ssh/id_ed25519.pub
warren project sync myproject --server prodecs
```

It reaches the task the way every ECS secret does (a file on the EFS volume, or a KMS
envelope on EBS), never RunTask overrides. A template's plain `env:` works too
(`SSH_AUTHORIZED_KEYS: "ssh-ed25519 AAAA... me"`), for a key every user of the template
shares. Removing the key and restarting the workspace revokes it. Lines that don't parse
as public keys leave the file unchanged, with a warning in the log.

A task started as non-root (`WARREN_ECS_TASK_USER`) only gets the plain `env:` key: the
wrapper runs before the secrets are loaded in that mode.

On both runtimes, SSH sessions get a fresh login environment, not the workload's: the
workspace secrets are not in it (ECS Exec and `warren connect` sessions do get them).

## Client setup: `warren ssh-config`, ECS and podman/docker

One command for both server runtimes. It prints a Host block on stdout (anything else
goes to stderr), so append it:

```bash
warren ssh-config <workspace> [--server NAME] [--host NAME] >> ~/.ssh/config
ssh warren-abc12345
```

In both cases `HostName` is `127.0.0.1` (the sshd is on a loopback, the task's or the
server host's), `HostKeyAlias` is `warren-<server>-<workspace id>`, so the known_hosts
entry belongs to the workspace and stays valid whatever task, forward port or route
reaches it, and the client is set to publickey only, with agent and X11 forwarding off.
The workspace id is resolved from a unique prefix on the control plane (`--no-resolve`
uses it as given). The first connection records the host key (`accept-new`); if it ever
changes, ssh refuses, and `ssh-keygen -R warren-<server>-<id>` clears the old entry.

| | ECS (`warren-ecs-ssh-base`) | podman/docker (`warren-docker-ssh-base`) |
|---|---|---|
| route | `ProxyCommand warren proxy stdio <ws> 2222` (SSM port-forward) | `ProxyJump` through the server host: the remote's `ssh_host` (a ProxyCommand passing `ssh_key_path` when set, as the CLI's own control-plane forward does), none for a server on this machine (`http://127.0.0.1...`), else the host the server advertises (`WARREN_SSH_ADVERTISED_HOST`); `--jump HOST` overrides, `--jump ''` connects directly |
| your key | yours, delivered as `SSH_AUTHORIZED_KEYS` (above); `--identity-file` names the private half | minted by the server: `warren ssh-config` calls `POST /workspaces/{id}/connect` (owner only; starts a stopped workspace), saves the private key to `~/.warren/ssh/<server>-<id>` (0600) and points `IdentityFile` at it. Each run mints a new key and the previous one stops working; a re-provisioned container needs a new run |
| user | `warren` | the server's shell user (`break_glass_user`, `warren-shell`); `--user` overrides |
| needs | AWS CLI, `session-manager-plugin`, `ssm:StartSession` on the task | SSH access to the server host (the same access `warren connect` uses for `podman exec`); the server's `WARREN_SSH_ACCESS_ENABLED=true` |
| host key | on the workspace volume, survives task restarts | in the container, survives stop/start |

An ECS block:

```
Host warren-abc12345
    HostName 127.0.0.1
    Port 2222
    User warren
    ProxyCommand /usr/local/bin/warren proxy stdio --server prodecs abc12345-... 2222
    HostKeyAlias warren-prodecs-abc12345-...
    StrictHostKeyChecking accept-new
    IdentityFile ~/.ssh/id_ed25519
    IdentitiesOnly yes
    PreferredAuthentications publickey
    PasswordAuthentication no
    KbdInteractiveAuthentication no
    ForwardAgent no
    ForwardX11 no
    ServerAliveInterval 30
    ServerAliveCountMax 4
```

A podman one (remote `homelab` with `ssh_host = "node2"`) differs only in its route,
port, user and key:

```
Host warren-abc12345
    HostName 127.0.0.1
    Port 30007
    User warren-shell
    ProxyJump node2
    HostKeyAlias warren-homelab-abc12345-...
    IdentityFile ~/.warren/ssh/homelab-abc12345-...
    ...
```

To check the host key before the first connection, compare with the
`warren-sshd: host key SHA256:...` line in the workspace's log (both images print it).

### VS Code Remote-SSH and Cursor

Both run your OpenSSH client with `~/.ssh/config`, so the block (ProxyCommand or
ProxyJump, HostKeyAlias and all) applies as written. Add it, then run "Remote-SSH:
Connect to Host..." and pick `warren-abc12345` (Cursor has the same command). The
editor's server installs into the login user's home (`.vscode-server` or
`.cursor-server`), which is not on the workspace volume, so it is downloaded again after
a re-provision (ECS: after a restart). The first connection to a stopped-then-started
ECS workspace can take longer than the extension's default connect timeout while SSM
sets up; raise `remote.SSH.connectTimeout` if it gives up.

### JetBrains Gateway

Gateway lists the hosts in `~/.ssh/config`; pick `warren-abc12345` for a new SSH
connection. Its backend is uploaded over SFTP, which both images' sshd serves
(`internal-sftp`). Gateway has its own SSH implementation: if your version doesn't run
the block's `ProxyCommand`/`ProxyJump`, point it at a local forward instead
(`ssh -N -L 2222:127.0.0.1:<sshd port> warren-abc12345`, where the sshd's own port is
2222 on ECS and 22 in the podman image; then connect Gateway to `127.0.0.1:2222` with
the block's user). Where it doesn't apply `HostKeyAlias`, check the fingerprint it shows
against the `warren-sshd: host key` log line before accepting.

### Other forwards

Editors forward their own ports over the SSH session (local forwarding is allowed).
For a plain port without SSH, `warren proxy add`/`warren tunnel` still work (ECS).

## Verifying locally

Both smoke tests need only docker.

ECS: build the three images from one commit and pass each into the next, as the smoke
workflow does:

```bash
docker buildx build --load -t warren-ecs-base:local -f packages/warren-server/images/ecs-base/Dockerfile .
docker buildx build --load -t warren-ecs-dev-base:local --build-arg WARREN_ECS_BASE=warren-ecs-base:local \
  packages/warren-server/images/warren-ecs-dev-base
docker buildx build --load -t warren-ecs-ssh-base:local --build-arg WARREN_ECS_DEV_BASE=warren-ecs-dev-base:local \
  packages/warren-server/images/warren-ecs-ssh-base
.github/scripts/ecs-ssh-base-smoke.sh warren-ecs-ssh-base:local
```

podman/docker: the image builds FROM the digest-pinned published dev-base:

```bash
docker buildx build --load -t warren-docker-ssh-base:local images/warren-docker-ssh-base
.github/scripts/docker-ssh-base-smoke.sh warren-docker-ssh-base:local
```

Against a real podman server path (provision, connect-time key mint, published port,
key invalidated on stop), the opt-in integration test builds the image itself:

```bash
PODMAN_SOCKET=/path/to/podman.sock WARREN_ITEST_DOCKER_SSH_BASE=build \
  uv run --package warren-server pytest packages/warren-server/tests/integration/test_ssh_access.py
```

(`WARREN_ITEST_DOCKER_SSH_BASE` may instead name an image podman already has.)

See [threat-model.md](threat-model.md) (T20, residual risk 14) for the security argument.
