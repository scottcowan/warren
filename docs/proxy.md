# warren proxy

`warren proxy` gives a port inside an ECS workspace a stable address on your own
machine, `http://127.0.0.1:<local-port>`, that keeps working when the SSM session
drops, when the proxy restarts, and when the workspace comes back on a new task.
It is meant for desktop or browser apps that store a server address, such as
the T3 Code app talking to a `t3 serve` inside a workspace.

`warren tunnel` is still the one-off, foreground way to forward a port. The
proxy is the long-running version of it.

## Commands

```bash
warren proxy add <workspace> <remote-port> [--local-port N] [--server NAME]
warren proxy list [--json]
warren proxy rm <local-port | workspace | workspace:remote-port> [--server NAME]
warren proxy run [--idle-minutes M] [--keepalive-seconds S] [--log-level info]
```

- `add` records a mapping and prints its address. It does not contact AWS. The
  local port is picked once (the first free port from `port_base`, or the one you
  pass with `--local-port`) and saved, so adding the same mapping again returns
  the same address. `--server` defaults to your only ECS remote.
- `run` serves every mapping in the foreground until it gets SIGINT/SIGTERM. It
  rereads the mapping file every few seconds, so `add`/`rm` take effect without a
  restart. It logs with the CLI's structlog setup: JSON lines when stderr is not a
  terminal, which suits launchd and journald.
- Mappings live in `~/.warren/proxy.json` (owner-only), next to the CLI's
  `config.toml`.

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
   anything else, because the forward carries your own AWS access into the
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

`warren proxy` refuses `http` and `ssh` remotes, at `add` and at connection time.
Their workspace ports are inside containers on the server host. The CLI's SSH
forward only reaches that host's loopback control plane, and the containers'
ports usually aren't published at all. Use your own `ssh -L` to the server host if
the port is published there.

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
below are templates. Find `warren` with `command -v warren`. The service needs
`aws` and `session-manager-plugin` on its `PATH`, and the AWS profile it should
use.

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

With a workspace running `t3 serve` on, say, port 3773:

```bash
warren proxy add <workspace> 3773      # prints http://127.0.0.1:47100
warren proxy run                       # or keep it running under launchd/systemd
```

Then pair the T3 desktop app with `http://127.0.0.1:47100`. Don't use T3 Connect
for company code: it relays traffic through T3's cloud. The workspace image and
how to start `t3 serve` are described in [examples/ecs-t3code](../examples/ecs-t3code/README.md).
