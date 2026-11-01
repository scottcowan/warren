# SSH into workspaces (editor remoting)

`warren-ecs-base` and `warren-ecs-dev-base` ship no sshd: ECS Exec over SSM is how you
get a shell (`warren connect`). Editors that remote over SSH (VS Code Remote-SSH,
Cursor, JetBrains Gateway) need an sshd, so there is an opt-in image for them:
**`ghcr.io/scottcowan/warren-ecs-ssh-base`**, built FROM `warren-ecs-dev-base`.

Nothing changes for templates that don't use it. `warren ssh-config` also writes Host
blocks for podman/docker-server workspaces whose image runs an sshd (see
[Client setup](#client-setup-warren-ssh-config-ecs-and-podmandocker)).

## How it fits together

```
editor ─ ssh ─ ProxyCommand: warren proxy stdio <ws> 2222
                   │  control plane: GET /workspaces -> the workspace's current task
                   │  aws ssm start-session --document-name AWS-StartPortForwardingSession
                   ▼     --target ecs:<cluster>_<task>_<runtime-id> portNumber=2222
             Fargate task ── 127.0.0.1:2222 ── sshd (uid 1000, key-only) ── warren user
```

- The sshd listens on the task's **127.0.0.1:2222 only**. The task has no port mapping,
  load balancer or inbound rule for it, so the only way in is an SSM port-forward to the
  task's loopback. That takes `ssm:StartSession` on that task, the same permission ECS
  Exec (`warren connect`) needs, so whoever can SSH in could already open a root shell
  in the task.
- `warren proxy stdio <ws> <port>` resolves the workspace's current task through the
  control plane on every connection (like `warren proxy run`), starts the forward on an
  ephemeral loopback port and pipes stdin/stdout through it. It stops the forward when
  ssh closes it. A stopped workspace fails with a message saying so; start it with
  `warren connect <ws>` first.
- The host key is generated on first start onto the workspace volume, so it is the same
  after a restart and the client's known_hosts entry, pinned to the workspace through
  `HostKeyAlias`, stays valid. A destroyed and re-created workspace has a new id and a
  new key.

## Image layout

| Path | What |
|---|---|
| `/etc/ssh/sshd_config` | the hardened config (root-owned, 0644); `/etc/ssh/sshd_config.d/` is empty and read first, for derived images |
| `/usr/local/bin/warren-sshd` | generates the host key, writes `authorized_keys`, runs `sshd -D -e` as uid 1000 with a clean environment |
| `/usr/local/bin/entrypoint.sh` | small wrapper: after ecs-base's entrypoint has loaded the secrets and dropped to uid 1000, starts `warren-sshd` in the background and hands over |
| `/usr/local/lib/warren/ecs-entrypoint.sh` | ecs-base's entrypoint, unchanged, moved here |
| `/etc/profile.d/warren-path.sh` | the image's PATH (pyenv shims, `/usr/local`) for SSH login shells |
| `/var/lib/warren/.warren-ssh/ssh_host_ed25519_key` | host key, on the volume, created at first start (none in the image) |
| `~warren/.ssh/authorized_keys` | rewritten from `SSH_AUTHORIZED_KEYS` at every start |

sshd's logs (including the host key fingerprint, and the fingerprints of the authorized
keys) go to the container log.

## sshd hardening

From `packages/warren-server/images/warren-ecs-ssh-base/sshd_config`, asserted with
`sshd -T` by the smoke test:

- `ListenAddress 127.0.0.1:2222`, `AddressFamily inet`;
- `AuthenticationMethods publickey`; `PasswordAuthentication`,
  `KbdInteractiveAuthentication`, `PermitEmptyPasswords`, `HostbasedAuthentication`,
  `GSSAPIAuthentication`, `KerberosAuthentication`, `UsePAM` all `no`;
- `PermitRootLogin no`, `AllowUsers warren`, `StrictModes yes`,
  `PermitUserEnvironment no`, `MaxAuthTries 3`;
- `AllowTcpForwarding local` (what editors use); `GatewayPorts no`, `PermitListen none`,
  `AllowStreamLocalForwarding no`, `PermitTunnel no`;
- `X11Forwarding no`, `AllowAgentForwarding no`.

sshd itself runs as the workspace user (uid 1000), not root, so it has no privileges the
workload doesn't already have, and it can only log in that user. The workload still runs
as uid 1000 exactly as in ecs-base.

### Enabling agent forwarding

Off by default: a forwarded agent can be used by any process in the workspace (which
runs as the same user as your SSH session) for as long as you are connected. If you want
it anyway (for example to `git push` with your own key), build on this image:

```dockerfile
FROM ghcr.io/scottcowan/warren-ecs-ssh-base:<version>
RUN printf 'AllowAgentForwarding yes\n' > /etc/ssh/sshd_config.d/agent-forwarding.conf
```

and add `ForwardAgent yes` to your Host block. The drop-in directory is read before the
main config, and sshd takes the first value it reads.

## Getting your public key in

The workspace takes its authorized keys from the `SSH_AUTHORIZED_KEYS` environment
variable (one or more public key lines), which `warren-sshd` writes to
`~warren/.ssh/authorized_keys` at each start. There is no separate user-key API (the
podman runtime's SSH credential is a per-connection key the server mints, which an ECS
task can't be handed after it starts). A public key isn't secret, but the per-owner
secret store is the launch-time delivery path that is per user, so use it. Declare the
name in the template, so each owner's workspace gets that owner's own key (on ECS a
secret's owner is your AWS identity, the same one SSM authorizes):

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

SSH sessions get a fresh login environment, not the workload's: the workspace secrets
are not in it (ECS Exec sessions via `warren connect` do get them).

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

| | ECS (`warren-ecs-ssh-base`) | podman/docker server |
|---|---|---|
| sshd | in the task, `127.0.0.1:2222`, uid 1000 | in the container, its port published on the server host's `127.0.0.1` (`WARREN_SSH_PUBLISH_HOST`) when `WARREN_SSH_ACCESS_ENABLED=true` |
| route | `ProxyCommand warren proxy stdio <ws> 2222` (SSM port-forward) | `ProxyJump` through the server host: the remote's `ssh_host` (a ProxyCommand passing `ssh_key_path` when set, as the CLI's own control-plane forward does), none for a server on this machine (`http://127.0.0.1...`), else the host the server advertises (`WARREN_SSH_ADVERTISED_HOST`); `--jump HOST` overrides, `--jump ''` connects directly |
| your key | yours, delivered as `SSH_AUTHORIZED_KEYS` (above); `--identity-file` names the private half | minted by the server: `warren ssh-config` calls `POST /workspaces/{id}/connect` (owner only; starts a stopped workspace), saves the private key to `~/.warren/ssh/<server>-<id>` (0600) and points `IdentityFile` at it. Each run mints a new key and the previous one stops working; a re-provisioned container needs a new run |
| user | `warren` | the server's shell user (`break_glass_user`, `warren-shell`; `warren` is ForceCommand'd to ACP); `--user` overrides |
| needs | AWS CLI, `session-manager-plugin`, `ssm:StartSession` on the task | SSH access to the server host (the same access `warren connect` uses for `podman exec`) |
| host key | generated on the workspace volume at first start | the workspace image's |

The podman/docker path needs a workspace image that runs sshd on port 22 and reads
`/etc/warren/authorized_keys` (where the server injects the minted key), as the
integration-test image in `packages/warren-server/tests/integration/fixtures/ssh_test_image`
does. `warren-docker-base` and `warren-docker-dev-base` ship no sshd, and the server
publishes the port only with `WARREN_SSH_ACCESS_ENABLED=true`, so this is opt-in on that
side too.

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

On ECS, to check the host key before the first connection, compare with the
`warren-sshd: host key SHA256:...` line in the task's log.

### VS Code Remote-SSH and Cursor

Both run your OpenSSH client with `~/.ssh/config`, so the block (ProxyCommand,
HostKeyAlias and all) applies as written. Add it, then run "Remote-SSH: Connect to
Host..." and pick `warren-abc12345` (Cursor has the same command). The editor's server
installs into `~warren/.vscode-server` (or `.cursor-server`) in the workspace's home,
which is not on the volume, so it is downloaded again after a restart. The first
connection to a stopped-then-started workspace can take longer than the extension's
default connect timeout while SSM sets up; raise `remote.SSH.connectTimeout` if it
gives up.

### JetBrains Gateway

Gateway lists the hosts in `~/.ssh/config`; pick `warren-abc12345` for a new SSH
connection. Its backend is uploaded over SFTP, which warren-ecs-ssh-base's sshd serves
(`internal-sftp`; a podman image needs an sftp subsystem too). Gateway has its own SSH
implementation: if your version doesn't run the block's `ProxyCommand`/`ProxyJump`,
point it at a local forward instead (`ssh -N -L 2222:127.0.0.1:<sshd port>
warren-abc12345`, the sshd's own port, 2222 on ECS and 22 in a podman image; then connect Gateway to `127.0.0.1:2222` with the block's user).
Where it doesn't apply `HostKeyAlias`, check the fingerprint it shows (on ECS, against
the `warren-sshd: host key` line in the task's log) before accepting.

### Other forwards

Editors forward their own ports over the SSH session (local forwarding is allowed).
For a plain port without SSH, `warren proxy add`/`warren tunnel` still work.

## Verifying locally

The smoke test (`.github/scripts/ecs-ssh-base-smoke.sh IMAGE`) needs only docker. Build
the three images from one commit:

```bash
docker buildx build --load -t warren-ecs-base:local -f packages/warren-server/images/ecs-base/Dockerfile .
docker buildx build --load -t warren-ecs-dev-base:local --build-arg WARREN_ECS_BASE=warren-ecs-base:local \
  packages/warren-server/images/warren-ecs-dev-base
docker buildx build --load -t warren-ecs-ssh-base:local --build-arg WARREN_ECS_DEV_BASE=warren-ecs-dev-base:local \
  packages/warren-server/images/warren-ecs-ssh-base
.github/scripts/ecs-ssh-base-smoke.sh warren-ecs-ssh-base:local
```

See [threat-model.md](threat-model.md) (T19) for the security argument.
