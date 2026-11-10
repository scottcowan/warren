# warren proxy

`warren proxy` gives a port inside a workspace a stable address on your own
machine, `http://127.0.0.1:<local-port>`, that keeps working when the forward
drops, when the proxy restarts, and when the workspace comes back on a new ECS
task or a new container. It is meant for desktop or browser apps that store a
server address, such as the T3 Code app talking to a `t3 serve` inside a
workspace.

It works with three kinds of remote:

| Remote (`warren remote add`) | Server runtime | How a connection reaches the port |
| --- | --- | --- |
| `ecs` | ECS | an SSM port-forwarding session to the task |
| `ssh` | podman or docker | `ssh -L` to the server host's loopback, where the port is published |
| `http` on `127.0.0.1`/`localhost` | podman or docker on this machine | straight to the published port, no SSH |

An `http` remote on another host is refused: its published ports are on that
host's loopback, which only an SSH forward reaches, so add the server as an `ssh`
remote instead. On podman/docker only ports the template declares under
[`ports:`](#named-ports) are published; see [Podman/docker servers](#podmandocker-servers).

`warren tunnel` is still the one-off, foreground way to forward a port. The
proxy is the long-running version of it.

## Commands

```bash
warren proxy add <workspace> <remote-port | port-name> [--local-port N] [--kind tcp|http] [--server NAME]
warren proxy add <workspace> --from-template [--server NAME]
warren proxy list [--json]
warren proxy rm <local-port | workspace | workspace:remote-port | workspace/port-name> [--server NAME]
warren proxy run [--open] [--idle-minutes M] [--keepalive-seconds S] [--log-level info]
warren proxy stdio <workspace> <remote-port> [--server NAME]
```

- `add` records a mapping and prints its address. With a port number it does not
  contact the server. The local port is picked once (the first free port from
  `port_base`, or the one you pass with `--local-port`) and saved, so adding the
  same mapping again returns the same address. `--server` defaults to
  `[defaults] server` if the proxy can reach it, else to your only `ecs`, `ssh` or
  local `http` remote.
- `add <workspace> <port-name>` and `add <workspace> --from-template` map ports
  the workspace's template declares by name (see [Named ports](#named-ports)).
  They read the names from the control plane (`GET /workspaces`), so they need
  the same access as `warren list` (AWS for ECS, SSH for an `ssh` remote).
- `run` serves every mapping in the foreground until it gets SIGINT/SIGTERM. It
  rereads the mapping file every few seconds, so `add`/`rm` take effect without a
  restart. It logs with the CLI's structlog setup: JSON lines when stderr is not a
  terminal, which suits launchd and journald.
- `stdio` forwards one connection: it resolves the task, starts a forward and pipes
  stdin/stdout through it until either side closes. It is an ssh `ProxyCommand`; see
  `warren ssh-config` and [workspace-ssh.md](workspace-ssh.md).
- Mappings live in `~/.warren/proxy.json` (owner-only), next to the CLI's
  `config.toml`.

### Named ports

A template can name the ports its workspace serves:

```yaml
templates:
  t3:
    ports:
      t3: 3773                                  # shorthand for {port: 3773}
      code: {port: 8080, description: code-server}
```

Names are lowercase letters, digits and `-`; ports are 1-65535 and no two names
may share one. Nested templates merge `ports` key by key, the child winning, like
`env`. On ECS, declaring a port exposes nothing by itself: it only tells the CLI
what to map. On podman/docker, each declared port is also published on the
server host's loopback (see [Podman/docker servers](#podmandocker-servers)). The
server returns the declared ports in each workspace's `ports` field, and on
podman/docker their host bindings in `host_ports`.

```bash
warren proxy add <workspace> --from-template   # one mapping per declared port
warren proxy add <workspace> t3                # just one, by name
warren proxy list
# http://127.0.0.1:47100   -> prod/<workspace>/code (port 8080)
# http://127.0.0.1:47101   -> prod/<workspace>/t3 (port 3773)
```

Running `--from-template` again is safe: ports already mapped keep their local
address and nothing new is printed as `added`. If the template later moves a name
to a different port, the next `--from-template` points the same local address at
the new port. If that new port is already mapped under another entry, `add` stops
and asks you to `warren proxy rm` one of them. `--local-port` can't be combined
with `--from-template`, since it maps a single port.

## Mapping kinds

Each mapping has a `kind`, stored in `proxy.json` (files without one load as `tcp`).

```bash
warren proxy add <workspace> 8080 --kind http     # HTTP gateway
warren proxy add <workspace> --from-template      # each port's `protocol:` (tcp|http) picks the kind
```

A template port declares its kind with `protocol: tcp|http` (default `tcp`):
`ports: {code: {port: 8080, protocol: http}}`. The workspace API returns it next to `ports`.

### `tcp` (default)

A plain bidirectional byte relay: SSH, ACP, T3's native pairing, anything that is not a
browser-reachable web UI. It adds no authentication, so it relies on the service's own.

- Refuses to bind anything but loopback (`--bind 0.0.0.0` or a LAN address fails closed).
- `add --local-port` refuses a port another process already listens on. `proxy run` exits
  non-zero if any mapped port cannot be bound (a squatter on a predictable port), and
  never serves a client from a port it does not hold.
- `proxy.json` is written atomically via an exclusive temp file (0600), in a 0700 directory,
  and the CLI refuses to write through a symlink.
- Workspace, server and port names are validated (`[A-Za-z0-9-]` workspaces, lowercase port
  names) before they reach a file, a log or a command line.
- If a mapping later resolves to a different workspace id than it first served, the proxy
  logs `proxy_workspace_identity_changed` and stops serving that mapping until restarted.
- It does not protect against: a DNS-rebinding page or any local process reaching a web app on
  that port. Use `http` for those.

### `http`

An HTTP-aware gateway (stdlib asyncio) in front of a web UI. What it stops:

| Threat | Control |
| --- | --- |
| DNS rebinding (a page on `evil.example` resolving to 127.0.0.1) | `Host` must be exactly `127.0.0.1:<port>`, `localhost:<port>` (or `[::1]:<port>` when bound there); anything else gets 421. Case, trailing dots, `0x7f.1` and `127.0.0.1.evil.example` do not pass |
| Any local process or page using the port | Every request needs a session cookie; without one, 401. The cookie comes from a one-time link (below) printed only to the terminal that runs `warren proxy run` |
| Cross-site requests and cross-site WebSockets | State-changing methods and upgrades need `Origin` equal to one of the allowed origins and `Sec-Fetch-Site` of `same-origin` or `none`; the cookie is `SameSite=Strict`. No CORS header is ever emitted (the upstream's are removed) and `OPTIONS` is refused |
| Request smuggling / header injection | Strict parser: one `Host`, no `Content-Length` with `Transfer-Encoding`, no duplicate or signed lengths, only `chunked`, no obs-fold, no bare CR/LF/NUL, origin-form targets only; chunk framing is validated and re-encoded; hop-by-hop headers are dropped; each request uses its own upstream connection |
| Resource exhaustion | Head size (16 KiB), header count, request body size (64 MiB), header and keep-alive timeouts, upstream connect and response timeouts, at most 64 concurrent connections per mapping |

Gateway responses set `Cache-Control: no-store` (start/exchange and errors),
`X-Content-Type-Options: nosniff` and `Referrer-Policy: no-referrer` (added to upstream responses
if absent). The app's own CSP is left alone. Streaming (SSE, chunked, WebSocket) passes through
after validation; streamed response bodies are not size limited.

**The exchange flow.** `warren proxy run` prints, per http mapping, to stderr:

```
prod/<workspace>/code: open http://127.0.0.1:47100/__proxy/start?k=<secret>  (single use, expires in 120s)
```

(`--open` also opens it in a browser.) The secret is `secrets.token_urlsafe(32)`, compared in
constant time, valid once and for 120 seconds, and never logged; it is not in the daemon's log.
A GET to that path answers `303` to `/` and sets `warren_proxy_<port>=<session-id>; HttpOnly;
SameSite=Strict; Path=/` (no `Domain`; no `Secure`, which is not possible for plain http on
loopback). The session id is a separate random value validated server-side; it expires when
the proxy process exits and after 30 idle minutes. The cookie never reaches the app. Expired or
spent link: `kill -USR1 <pid>` (POSIX) prints fresh ones, or restart `proxy run`.

**What it does not protect against.** Another process running as you can read the terminal,
the process environment, or the browser's cookies. Browsers share cookies across ports of
`127.0.0.1`, so another local web service on a different port can see the session cookie in
requests to it (the cookie name carries the port so mappings do not overwrite each other).
Non-browser clients without `Origin`/`Sec-Fetch-Site` pass the origin check but still need the
cookie. TLS is not used on loopback. The upstream app's own authorization still applies.

**Extension point.** `warren_cli.proxy_http.UpstreamAuthProvider` (set as
`ProxySettings.upstream_auth`) is called once per allowed request and may return headers to add
upstream, replacing any same-named client header. The default adds none. Injecting the operator's
identity for the control plane is intentionally not implemented yet.

### Unix sockets

`--unix` serves a mapping on a Unix socket instead of a loopback TCP port. No local port is
allocated, so nothing else on the machine can connect to a TCP port that happens to be open.

```bash
warren proxy add <workspace> 8080 --unix --kind http          # ~/.warren/run/<server>-<workspace>-<name>.sock
warren proxy add <workspace> t3 --unix --socket /run/user/1000/t3.sock
warren proxy add <workspace> --from-template --unix           # default path for each port
```

The socket is created 0600 in a 0700 directory owned by you (`~/.warren/run` by default; a custom
`--socket` must be an absolute path), is never bound through a symlink or over a file that is not a
stale socket of yours, and the proxy also checks each connection's peer uid against yours (macOS
and Linux). `warren proxy rm` removes the socket if it is a socket you own and leaves anything
else alone. File permissions are the authentication, so an `http` mapping on a socket has no start
link, session cookie, Host check or Origin check (a socket is not reachable from a web page); strict request parsing and the size, time and connection limits still apply.
`warren proxy list` shows `unix:<path>`.

```bash
curl --unix-socket ~/.warren/run/prod-ws1-code.sock http://localhost/
```

```python
import httpx
client = httpx.Client(transport=httpx.HTTPTransport(uds="/home/me/.warren/run/prod-ws1-code.sock"))
client.get("http://localhost/")
```

```
# ~/.ssh/config: ssh over the socket of a mapping to the workspace's sshd (port 2222)
Host ws1
    ProxyCommand nc -U /home/me/.warren/run/prod-ws1-ssh.sock
```

Browsers cannot connect to a Unix socket, so use a TCP `http` mapping for a web UI. The T3 Code
desktop app likewise needs a TCP address; keep T3 on a TCP mapping. Unix sockets are not
supported on Windows: `--unix` fails there with a clear error.

### Settings

`[proxy]` in `~/.warren/config.toml`; the `run` flags override these values.

```toml
[proxy]
idle_minutes = 30        # stop a mapping's SSM session after 30 min with no connections (0 = never)
keepalive_seconds = 240  # probe interval while clients are connected (0 = off), see Keepalive
port_base = 47100        # first port `warren proxy add` tries
```

## How it works

1. **Loopback only.** Each mapping listens on `127.0.0.1:<local-port>`. `--bind`
   accepts only loopback addresses (`127.0.0.1`, `::1`, `localhost`) and refuses
   anything else, because the forward carries your own AWS or SSH access into the
   workspace. The listener has no authentication of its own, so any local process
   can use it. Don't run the proxy on a shared machine (see
   [threat-model.md](threat-model.md), residual risk 12).
2. **Lazy.** Nothing touches AWS until a client connects. On the first
   connection the proxy asks the control plane (`GET /workspaces`, through the
   same orchestrator SSM tunnel every other remote command uses) for the
   workspace's current status and task ARN. It then looks up the container's
   `runtimeId` (`aws ecs describe-tasks`) and starts
   `aws ssm start-session --document-name AWS-StartPortForwardingSession` to
   `ecs:<cluster>_<task-id>_<runtime-id>` on an ephemeral local port. This is the
   same target and document `warren tunnel` uses.
3. **Relay.** Each client connection gets its own TCP connection through the
   forward, and the proxy copies bytes both ways (asyncio streams, half-close
   passed on). It does not interpret the protocol, so HTTP, WebSockets and
   anything else that runs over one TCP connection work.
4. **Shared.** Concurrent connections to one mapping share one SSM session.
   Starting the session is serialised, so a burst of first connections starts it
   only once. This needs an SSM agent and session-manager-plugin recent enough to
   multiplex several TCP connections over one port-forwarding session; very old
   ones handle only one connection at a time.
5. **Idle close.** When the last connection of a mapping closes, a timer starts.
   If nothing connects within `idle_minutes`, the session is stopped. The next
   connection starts a new one.
6. **Self-healing.** If the `aws ssm` process exits (SSM timeout, network change,
   the task stopped or was replaced), connections that are open at that moment
   end, because their stream is gone. The next connection finds the session
   dead, asks the control plane again, and starts a session to whatever task the
   workspace runs now. A restarted workspace has a new task id, so this is what
   keeps the saved address working. Log events: `proxy_session_exited`,
   `proxy_task_changed`, `proxy_session_started`.

### Errors a client sees

- **Workspace not running** (stopped, failed, destroyed, not found, or still
  starting): the proxy does not start the workspace. It logs
  `proxy_connection_refused` with the reason and closes the connection. If the
  client has already sent an HTTP request line, it first gets a
  `503 Service Unavailable` whose body says why, for example "workspace abc12345
  is stopped; start it with `warren connect abc12345 --server prod`".
- **Expired AWS SSO credentials**: the AWS CLI's expired-token messages
  ("Token has expired and refresh failed", "The SSO session associated with this
  profile has expired", `ExpiredTokenException`, ...) are recognised on both the
  control-plane tunnel and the workspace forward. The proxy logs
  "AWS credentials have expired: run `aws sso login --profile <AWS_PROFILE>`, then
  retry" (`default` when `AWS_PROFILE` isn't set). The next connection after you log in
  works; the proxy doesn't need a restart.

### Podman/docker servers

**Server side.** When a podman or docker workspace is created, each port its
template declares under `ports:` is published on the server host's loopback, on a
host port the container engine picks (`-p 127.0.0.1::<port>`). The address is the
host part of `WARREN_SSH_PUBLISH_HOST` when that is a loopback address, else
`127.0.0.1`: setting `WARREN_SSH_PUBLISH_HOST` to a LAN address or `""` exposes the
SSH port, never template ports, and nothing is ever published on `0.0.0.0`. The
server reads the bindings back after every container create or start (docker
picks new host ports on each start) and returns them next to `ports`:

```json
"ports":      {"t3": {"port": 3773, "description": ""}},
"host_ports": {"t3": {"host": "127.0.0.1", "port": 41007}}
```

Ports that aren't declared aren't published, so `warren proxy add <ws> 5173` on a
podman remote only works once `5173` is in the template's `ports` and the
workspace was created (or recreated) with it. A workspace created before its
template declared a port, or by a server older than this feature, has no
`host_ports`; recreate it.

The traffic arrives on the container's network interface, not on its loopback,
so the app inside must listen on `0.0.0.0` (or the container's address), not
`127.0.0.1`. That address is only reachable through the workspace's own isolated
bridge network and the loopback-published host port.

**CLI side.** For an `ssh` remote the proxy's session is
`ssh -N -L <ephemeral>:127.0.0.1:<host-port> <ssh_host>`, the same forward (and
the same `ssh_host`/`ssh_key_path`) the CLI uses for that server's control plane.
For an `http` remote on this machine's loopback it connects straight to
`127.0.0.1:<host-port>`. Lazy start, sharing, idle close and the loopback-only
listener work as for ECS. A container that comes back with a different host port
is followed the same way as a replaced task: a direct connection to the old port
is refused, so the next connection resolves again; an SSH forward to the old port
stays up and drops connections, so a connection that is the only one open checks
the control plane first if the previous one closed without the workspace sending
a byte, or if the last check is more than 15 seconds old
(`ProxySettings.revalidate_seconds`). Log event: `proxy_host_port_changed`. The
keepalive probe is only used for SSM sessions.

**Isolation.** A published port is reachable from the server host's loopback,
which other workspaces can't reach under rootless podman with slirp4netns (its
default `allow_host_loopback=false`), so other workspaces can't reach it.
`tests/integration/test_network_isolation.py` checks this in CI (slirp4netns on
ubuntu-latest) through the bridge gateway, `host.containers.internal`,
`10.0.2.2`, `169.254.1.2`, the host's own IP and the owning container's IP.
**With pasta** this doesn't hold everywhere: on podman 6.0.1 with default
options, `169.254.1.2` reached host loopback, and so published SSH and template
ports, from other workspaces. The server therefore refuses to start on rootless
pasta unless `WARREN_PODMAN_ALLOW_PASTA=1` (then it logs
`podman_pasta_host_loopback`); use slirp4netns
(`default_rootless_network_cmd = "slirp4netns"` under `[network]` in
`containers.conf`). On
Docker Desktop and colima, `host.docker.internal` reaches the desktop host's
loopback, and with it these ports. See [threat-model.md](threat-model.md),
residual risk 6.

## Keepalive

What can keep a long-lived connection, such as a WebSocket, from being cut by
SSM:

- **TCP keepalive does nothing useful here.** The relayed sockets are loopback
  connections that end at the local session-manager-plugin. Keepalive probes on
  them never become SSM traffic, so the proxy doesn't set `SO_KEEPALIVE`.
- **SSM's idle session timeout** (Session Manager preferences: 20 minutes by
  default, 1 to 60) ends a session that carries no data. Bytes the app sends
  through the relay count as data. An app protocol that pings (WebSocket ping
  frames, heartbeats) therefore keeps its own connection alive. **That is the
  reliable keepalive, and it has to come from the app.**
- **The proxy's probe** (`keepalive_seconds`, default 240, which is under the
  default 20-minute timeout): while at least one client is connected, the proxy
  opens a TCP connection through the session and closes it again. With
  multiplexed port forwarding each open and close is a message on the SSM data
  channel, which should count as session activity even when the app is quiet.
  This is best-effort and **has not been checked against a live SSM session**.
  The app on the remote port sees a connection that opens and closes without
  sending anything; HTTP and WebSocket servers ignore these.
- **A maximum session duration**, if your Session Manager preferences set one,
  can't be extended by anything. When the session ends, open connections close.
  The client reconnects, which T3 Code and browsers do on their own, and the
  proxy starts a new session.

## Running it in the background

The proxy has no installer. Run it under your own service manager; the examples
below are templates. Find `warren` with `command -v warren`. For ECS remotes the
service needs `aws` and `session-manager-plugin` on its `PATH`, and the AWS
profile it should use. For `ssh` remotes it needs `ssh` and non-interactive key
authentication (an agent the service can reach, or `ssh_key_path` on the remote
without a passphrase): the forward runs with `BatchMode=yes`.

### macOS launchd

`~/Library/LaunchAgents/dev.warren.proxy.plist`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>dev.warren.proxy</string>
  <key>ProgramArguments</key>
  <array>
    <string>/Users/YOU/.local/bin/warren</string>
    <string>proxy</string>
    <string>run</string>
  </array>
  <key>EnvironmentVariables</key>
  <dict>
    <key>PATH</key><string>/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin</string>
    <key>AWS_PROFILE</key><string>your-sso-profile</string>
  </dict>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardErrorPath</key><string>/Users/YOU/Library/Logs/warren-proxy.log</string>
</dict>
</plist>
```

```bash
launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/dev.warren.proxy.plist
launchctl kickstart -k gui/$(id -u)/dev.warren.proxy   # restart
launchctl bootout gui/$(id -u)/dev.warren.proxy        # stop and unload
```

### Linux systemd (user unit)

`~/.config/systemd/user/warren-proxy.service`:

```ini
[Unit]
Description=warren proxy (stable local addresses for ECS workspace ports)

[Service]
ExecStart=%h/.local/bin/warren proxy run
Environment=AWS_PROFILE=your-sso-profile
Environment=PATH=%h/.local/bin:/usr/local/bin:/usr/bin:/bin
Restart=on-failure
RestartSec=5

[Install]
WantedBy=default.target
```

```bash
systemctl --user daemon-reload
systemctl --user enable --now warren-proxy
journalctl --user -u warren-proxy -f
```

## IAM

This section is about ECS remotes; an `ssh` remote needs only your SSH access to
the server host, the same as `warren connect`.

The proxy runs AWS calls with **your own AWS credentials**, exactly as `warren
tunnel` and `warren connect` do. warren-server never sees them, and the proxy
adds no new server-side authorization path. Your principal needs:

- Whatever the control-plane tunnel already needs: `ecs:ListTasks` and
  `ecs:DescribeTasks` on the orchestrator service's tasks, and `ssm:StartSession`
  to the orchestrator task.
- `ecs:DescribeTasks` on the workspace task, to read the container `runtimeId`.
- `ssm:StartSession` on the workspace task
  (`arn:aws:ecs:<region>:<account>:task/<cluster>/*`) **and** on the document
  `arn:aws:ssm:<region>::document/AWS-StartPortForwardingSession`.
- `ssm:TerminateSession` (and `ssm:ResumeSession`) on your own sessions, so the
  plugin can close and resume them.
- The tasks must run with `enableExecuteCommand`, which warren sets for
  workspace tasks, because the SSM channel is the ECS Exec agent.

A least-privilege operator role should scope `ssm:StartSession` on task ARNs, and
`ecs:ExecuteCommand` for `warren connect`, to tasks tagged with the caller's own
owner id. warren tags each workspace task `<prefix>.owner_id` (prefix `warren` by
default, `ecs_resource_prefix` on the server), and the IaC matches that tag
against the caller's `warren-owner` principal tag, e.g.
`"Condition": {"StringEquals": {"aws:ResourceTag/warren.owner_id": "${aws:PrincipalTag/warren-owner}"}}`.
Without that condition, anyone holding the role can forward ports into every
workspace in the cluster.

## Using it with T3 Code

With a workspace running `t3 serve` on, say, port 3773, declare the port in the
template:

```yaml
templates:
  t3:
    ports: {t3: {port: 3773, protocol: http}}
```

`protocol: http` maps it with the [HTTP gateway](#mapping-kinds); T3 serves HTTP and WebSockets, so
it gets the Host, Origin and session-cookie checks. Open the link `warren proxy run` prints in a
browser to start a session; a client that cannot hold the session cookie (a native app that just
stores an address) needs `protocol: tcp` and relies on T3's own pairing instead.

Then connect with one command:

```bash
warren proxy add <workspace> --from-template   # prints <server>/<workspace>/t3 added: http://127.0.0.1:47100
warren proxy run                               # or keep it running under launchd/systemd
```

`warren proxy add <workspace> 3773` still works for a template without `ports`.

Then pair the T3 desktop app with `http://127.0.0.1:47100`. Don't use T3 Connect
for company code: it relays traffic through T3's cloud. The workspace image and
how to start `t3 serve` are described in [examples/ecs-t3code](../examples/ecs-t3code/README.md).

The same commands work against an `ssh` (or local) podman/docker remote. There,
start `t3 serve` with `--host 0.0.0.0`: the published port enters through the
container's interface, not its loopback.
