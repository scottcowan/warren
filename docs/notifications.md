# Agent notifications

warren-server can POST a webhook when an agent needs you, finishes, or fails, and when
a workspace is idle-stopped or fails to provision. There are two kinds of webhook:

- **Server-wide**, set by the operator (`WARREN_NOTIFY_WEBHOOK_URL`). Gets events for
  every workspace.
- **Per-owner**, registered by a user through the API. Gets events only for that
  user's own workspaces, and only the events they choose.

Delivery is best-effort. A lost notification never affects a workspace.

## Events

| Event | When |
|---|---|
| `agent.waiting` | The agent went from not blocked to blocked: a permission request or other input wait |
| `agent.finished` | A turn finished (working to idle, the harness `Stop` hook), or the agent exited normally |
| `agent.failed` | The harness reported `StopFailure`, or the agent supervisor gave up restarting it or rejected it |
| `workspace.idle_stopped` | The idle reaper stopped the workspace |
| `workspace.provision_failed` | Provisioning failed |

### Where agent state comes from

The harness hooks warren installs (`warren-state-hook`, AG5) write
`<harness root>/.session/state.json` inside the workspace on every hook event. The
agent supervisor (AG2b) writes `.session/agent/supervisor.json`. Harnesses without
hooks can print an OSC 7501 escape instead, which the sidecar records. The server reads
these files host-side with `WorkspaceRegistry.agent_state`, the same reader the idle
reaper uses. On podman that is the bind-mounted harness dir. On ECS it is the
workspace's EFS dir through the control plane's mount, so a workspace on EBS, or a
control plane without the mount, can't report agent state.

A watcher task polls every running workspace each `WARREN_NOTIFY_POLL_INTERVAL`
seconds. It skips workspaces nobody is listening for: if there is no server-wide
webhook, it only reads workspaces whose owner registered one, and if nobody has one it
reads nothing. An event comes from comparing two readings in a row. The first reading
of a workspace is a baseline and doesn't notify, so a server restart doesn't replay
every workspace's current state. A state that lasts less than one poll interval can be
missed.

## Server-wide settings

| Variable | Default | |
|---|---|---|
| `WARREN_NOTIFY_ENABLED` | `true` | Turns off both kinds of webhook and the watcher |
| `WARREN_NOTIFY_WEBHOOK_URL` | unset | `https://` only. No credentials, query or fragment (the same rule as `WARREN_BEDROCK_GATEWAY_URL`). Held as a secret and never logged |
| `WARREN_NOTIFY_FORMAT` | `json` | `json` or `slack` (Slack incoming-webhook body) |
| `WARREN_NOTIFY_EVENTS` | all | Comma-separated event names for the server-wide webhook |
| `WARREN_NOTIFY_POLL_INTERVAL` | `30` | Seconds between agent-state polls |
| `WARREN_NOTIFY_DEDUPE_SECONDS` | `300` | Minimum gap between two notifications for the same workspace and event |
| `WARREN_NOTIFY_TIMEOUT_SECONDS` | `5` | Per-request timeout |
| `WARREN_NOTIFY_MAX_RETRIES` | `3` | Retries after the first attempt (0 to 10) |
| `WARREN_NOTIFY_QUEUE_SIZE` | `100` | Pending notifications before new ones are dropped |

## Per-owner webhook API

```
PUT    /notifications/webhook   {"url": "https://...", "format": "json"|"slack", "events": ["agent.waiting", ...]}
GET    /notifications/webhook   -> {"configured": true, "format": "slack", "events": [...], "available_events": [...]}
DELETE /notifications/webhook
```

- `events` left out or empty means every event.
- The URL is validated like the server-wide one. `GET` never returns it.
- The record (URL, format, events) is encrypted with `WARREN_SECRET_KEY` and kept in
  the secrets store under the reserved name `warren.notify.webhook`, keyed by your
  warren user id (the id that owns your workspaces). `PUT /secrets` rejects names
  starting `warren.notify.`. That name isn't an environment variable name, so it can
  never be delivered into a workspace.
- Before each delivery to a per-owner URL, its host has to resolve only to public
  addresses. Loopback, private, link-local (including `169.254.169.254`) and other
  non-global addresses are refused, which keeps users from aiming the control plane at
  its own network. The check doesn't pin the address (DNS can change between the check
  and the connect). Redirects are never followed. The operator's server-wide URL skips
  this check.
- Workspace-scoped tokens can't call these routes.

```sh
curl -X PUT "$WARREN_URL/notifications/webhook" \
  -H "Authorization: Bearer $WARREN_TOKEN" -H "Content-Type: application/json" \
  -d '{"url": "https://hooks.slack.com/services/T000/B000/XXXX", "format": "slack",
       "events": ["agent.waiting", "agent.failed"]}'
```

## Payloads

### `json`

`Content-Type: application/json`, `User-Agent: warren-notify`:

```json
{
  "event": "agent.waiting",
  "workspace_id": "3f2c9a1e-...",
  "name": "my-project",
  "owner": "user-id",
  "template": "claude-dev",
  "timestamp": "2026-11-01T12:00:00Z",
  "message": "claude is waiting for input"
}
```

| Field | Type | |
|---|---|---|
| `event` | string | One of the event names above |
| `workspace_id` | string | |
| `name` | string | The project the workspace was launched for (a workspace has no name of its own) |
| `owner` | string | The owner's warren user id |
| `template` | string | The template name |
| `timestamp` | string | UTC, ISO 8601, second precision |
| `message` | string | At most 200 characters, from a fixed vocabulary: the harness name, and a reason code for idle stops (`egress_idle`, `agent_idle`, `blocked_ttl`, `hook_max_hold`) or provision failures (`image_unavailable`, `capacity_exhausted`, ..., `unexpected_error`) |

Payloads never include transcript content, prompts, tool output, environment, secrets
or error text.

### `slack`

A Slack [incoming webhook](https://api.slack.com/messaging/webhooks) body. `text` is
also the notification fallback. Values are escaped so a project name can't inject
mrkdwn links.

```json
{
  "text": "[warren] claude is waiting for input: workspace my-project (3f2c9a1e)",
  "blocks": [
    {"type": "section", "text": {"type": "mrkdwn", "text": "[warren] claude is waiting for input: workspace my-project (3f2c9a1e)"}},
    {"type": "context", "elements": [{"type": "mrkdwn",
      "text": "event `agent.waiting` | template `claude-dev` | owner `user-id` | 2026-11-01T12:00:00Z"}]}
  ]
}
```

Slack example, server-wide:

```sh
WARREN_NOTIFY_WEBHOOK_URL=https://hooks.slack.com/services/T000/B000/XXXX
WARREN_NOTIFY_FORMAT=slack
WARREN_NOTIFY_EVENTS=agent.waiting,agent.failed,workspace.provision_failed
```

## Delivery

- Producers (the watcher, the idle reaper, provisioning) never wait on delivery. An
  event is first deduped: the same workspace and event within
  `WARREN_NOTIFY_DEDUPE_SECONDS` is dropped, so a flapping agent can't spam you. Then it
  goes on a bounded in-memory queue. If the queue is full, it is dropped and logged.
- Two worker tasks deliver to every target that wants the event, one POST each.
- A timeout, a connection error, 408, 425, 429 or a 5xx is retried up to
  `WARREN_NOTIFY_MAX_RETRIES` times, with exponential backoff (1s, 2s, 4s, ... capped at
  30s). Any other non-2xx is dropped without retrying.
- Failures are logged (`notify_dropped`, `notify_rejected`, `notify_target_rejected`)
  with the event, workspace id, target kind (`server` / `owner`) and an HTTP status or
  exception class. The URL and exception text are never logged.
- The queue is in memory, so a restart drops pending notifications.
