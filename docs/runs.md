# Headless runs

`warren run` starts a template on a prompt with nobody attached, and keeps the result after
the workspace is gone. A run is a single-turn workspace (see the server README's
"Single-turn workspaces"): the template's `app` runs once, the server records what it left
behind, then destroys the workspace. The run id is the workspace id.

## Usage

```sh
# Start a run and print its id
warren run demo/fix --prompt "Add a --verbose flag to the CLI and open a PR" --server node2

# Prompt from a file ('-' reads stdin), wait for it, print the result
warren run demo/fix --prompt-file task.md --wait --server node2

# Machine-readable: the result JSON (schema below) on stdout, progress on stderr
warren run demo/fix --prompt-file task.md --wait --json --timeout 1800 --server node2

warren run status 0a1b2c3d --server node2          # id or a unique prefix
warren run result 0a1b2c3d --json --server node2
warren run list [--all] --server node2             # --all: every owner's (admin)
```

`<project>/<template>` names the template; `--project demo fix` works too, and template
paths may be dotted (`demo/develop.claude`). A project literally named `status`, `result`,
`list` or `start` needs the explicit form: `warren run start status/fix ...`.

| Option | |
|---|---|
| `--prompt TEXT` / `--prompt-file PATH` | the task (exactly one) |
| `--timeout S` | the server ends the run as `timed_out` after S seconds (default `WARREN_RUN_DEFAULT_TIMEOUT_SECONDS`, 3600; at most `WARREN_RUN_MAX_TIMEOUT_SECONDS`, 86400) |
| `--wait` | poll until the run finishes, then print the result |
| `--poll-interval S` | seconds between polls with `--wait` (default 10) |
| `--wait-timeout S` | stop waiting after S seconds; the run keeps going |
| `--json` | print JSON |

Exit codes of `--wait` and `warren run result`: `0` succeeded, `1` failed, `124` timed out,
`75` still running.

### What runs

The template must declare an `app` that runs to completion (`bash` is refused). The server
builds the command from it (`warren_common/headless.py`), keeping the template's own flags:

| app | runs |
|---|---|
| `claude ...` | `claude ... -p --output-format json <prompt>` |
| `codex ...` | `codex exec ... <prompt>` |
| `gemini ...` | `gemini ... -p <prompt>` |
| anything else | `<app> <prompt>` (the prompt is the last argument) |

stdin is `/dev/null`. stdout is kept in `/var/lib/warren/harness/.session/run-output.txt`
inside the workspace and echoed to the container log when the app exits. A template's
`seed_prompt` is ignored for runs. Permission prompts would hang a headless run, so give the
template's `app` whatever non-interactive flags its harness needs (e.g.
`claude --dangerously-skip-permissions`), and scope the workspace's credentials accordingly.

The prompt isn't a secret: like `seed_prompt` it is in the workspace's environment and in
its spec in the registry. On ECS it travels in the RunTask overrides (visible to
`DescribeTasks` and CloudTrail), which ECS caps at 8 KiB, so the server rejects prompts
over 4096 bytes there (`prompt_too_large`).

## Server API

All routes need a user token. Workspace-scoped tokens are refused.

| Route | |
|---|---|
| `POST /runs` | `{"project", "template", "prompt", "timeout_seconds"?, "operationId"?}` → 202 and the run summary. A retry with the same `operationId` returns the same run. Same errors as `POST /workspaces` (422 `single_turn_requires_app`, `timeout_too_long`, `prompt_too_large`, 503 `capacity_exhausted`, ...) |
| `GET /runs` | the caller's runs, newest first (`?limit=`, max 500). `?all=true`: every owner's, admin only |
| `GET /runs/{id}` | the run summary: `run_id`, `project`, `template`, `status`, `started_at`, `ended_at`, `timeout_seconds`, `exit_code`, `error` |
| `GET /runs/{id}/result` | the full result (below); while running, a short view with `status: "running"` |

`POST /workspaces` with `"mode": "single-turn"` also accepts `prompt` and `timeout_seconds`,
and every single-turn workspace is recorded as a run, with or without a prompt.

Authorization: an owner sees only their own runs; an admin can read every run (each
admin read of someone else's run is audited as `run.read`). Nobody can start a run as
someone else. A non-owner gets 403, an unknown id 404.

## Result schema (`warren.run.result/v1`)

```json
{
  "schema": "warren.run.result/v1",
  "run_id": "0a1b2c3d-...",
  "workspace_id": "0a1b2c3d-...",
  "project": "demo",
  "template": "fix",
  "status": "succeeded",
  "started_at": "2026-11-01T12:00:00Z",
  "ended_at": "2026-11-01T12:03:10Z",
  "duration_seconds": 190.0,
  "exit_code": 0,
  "harness": "claude",
  "final_message": "Added --verbose and opened https://github.com/acme/app/pull/12",
  "harness_result": {"subtype": "success", "is_error": false, "num_turns": 9,
                     "duration_ms": 181234, "total_cost_usd": 0.41, "session_id": "5e1f..."},
  "git": [
    {"mount": "code/app", "branch": "warren/fix", "base_branch": "main",
     "head_commit": "9c1e...", "base_commit": "41d0...", "is_clean": true,
     "changed_files": [{"path": "src/cli.py", "status": "modified", "insertions": 12, "deletions": 2}],
     "changed_files_truncated": false,
     "diffstat": {"files": 1, "insertions": 12, "deletions": 2},
     "remote_branch": "origin/warren/fix", "pushed": true}
  ],
  "pull_requests": ["https://github.com/acme/app/pull/12"],
  "verdict": null,
  "transcript": {"harness": "claude", "session_id": "5e1f...",
                 "location": "/var/lib/warren/harness/claude/projects/*/5e1f....jsonl",
                 "retained": false},
  "result_source": "control-plane",
  "capture_errors": [],
  "error": null
}
```

| Field | |
|---|---|
| `status` | `running`, `succeeded` (exit code 0 and the harness didn't report an error), `failed`, or `timed_out` |
| `exit_code` | the app's exit code; `null` when unknown (timed out, provision failure) |
| `final_message` | claude: the JSON result's `result`. Other apps: the end of stdout. At most 64 KiB |
| `harness_result` | claude's result fields (`subtype`, `is_error`, `num_turns`, `duration_ms`, `total_cost_usd`, `session_id`); `null` otherwise |
| `git[]` | one entry per checkout (the root clone and each `git-worktree`/`git-clone` folder). The diff is from the merge base with the folder's base branch (or from `HEAD` when there is none) to the working tree, plus untracked files; `.warren/` is left out. `status` is the working-tree state (`modified`, `added`, `deleted`, `renamed`, `untracked`); a change that is only committed shows as `modified`. At most 500 files are listed; `diffstat` counts them all. An entry that couldn't be read has only `mount` and `error` |
| `remote_branch`, `pushed` | observed, never done by warren: the checkout's `refs/remotes/origin/<branch>`, which a push from inside the workspace updates, and whether it equals `HEAD` |
| `pull_requests` | GitHub, GitLab and Bitbucket pull/merge request URLs found in the final message, the output and the verdict (at most 10). Whether the agent can push or open a PR depends on the credentials its template gives it |
| `verdict` | the workspace's `/workspace/.warren/verdict.json`, if it wrote one |
| `transcript` | where the harness's own transcript was. `retained` is true only on EFS, where the workspace's directory outlives the workspace until the EFS retention reaper removes it; podman and EBS delete it with the workspace. The run's stdout itself is what `final_message` keeps |
| `result_source` | `control-plane` (read by the server), `workspace` (reported by an EBS task, below) or `none` |
| `capture_errors` | parts that couldn't be read; the rest of the result is still recorded |
| `error` | why a run ended without completing (provision failure, workspace destroyed by hand) |

Everything except the times, status and exit code comes out of the workspace, so treat it
as the agent's report: the server caps its size, parses it as data and never acts on it.
Git state is read through a read-only shadow git dir (no repo config, hooks or filters).

## Retention

Runs live in the registry's `runs` table (or, with `WARREN_STATE_BACKEND=dynamodb`, as
`RUN#<run_id>` items in the workspace's partition; `--migrate-state` copies them), so the
result is there after the workspace is destroyed and after a server restart. Finished runs are pruned when another run finishes:
those older than `WARREN_RUN_RETENTION_SECONDS` (default 30 days), then each owner's oldest
beyond `WARREN_RUN_MAX_PER_OWNER` (default 500). Running runs are never pruned.

## Timeouts

The reaper checks each running run once per poll. Past its timeout the server ends it:
it records what it can (git state and output as they are), destroys the workspace and marks
the run `timed_out`.

## Runtimes

`warren run` works the same on every server runtime; what differs is where the server
reads the result from once the app exits.

| | podman / docker | ECS, EFS | ECS, EBS |
|---|---|---|---|
| exit detected by | container state, reaper poll (2 s) | `DescribeTasks`, reaper poll | the task's own record, ECS Exec probe (below) |
| checkouts (`git`) | the server's own clones under `<data_dir>/worktrees/<id>`, bind-mounted into the container | the control plane's EFS mount (`WARREN_EFS_LOCAL_MOUNT_PATH` or the owner's storage entry) | recorded in the task |
| output, exit code | `<data_dir>/harness/<id>/.session/`, bind-mounted at `/var/lib/warren/harness` for every single-turn workspace; podman reads the stopped container when the dir is missing | the workspace's `harness/.session/` on EFS | recorded in the task |
| `verdict` | the root clone's `.warren/verdict.json`, else (podman) the stopped container's `/workspace/.warren/verdict.json` | `workspace/.warren/verdict.json` on EFS | recorded in the task |
| `transcript.retained` | false (the harness dir is deleted on destroy) | true until the EFS retention reaper | false (snapshots are deleted on destroy) |
| `result_source` | `control-plane` | `control-plane` | `workspace` |

The run's exit code is the one its command writes beside its output
(`.session/run-exit-code`). On podman and docker the warren-docker-base image runs the app
inside tmux, so the container itself exits with tmux's code (0); the `workspace.completed`
event keeps reporting the container's code, the run reports the app's. When the file is
missing (the app couldn't write the harness dir) the run falls back to the container's.

On ECS with EFS the control plane needs the file system mounted; without it the run gets
only its exit code, as with EBS's fallback below.

## ECS with EBS storage

An EBS volume is attached only to its own task, so for an EBS-backed run the task reports
its own result instead:

1. The server sets `WARREN_RUN_RESULT=1` (plus the checkouts to report) on the task.
2. ecs-base's entrypoint runs the app as a child instead of `exec`ing it. When it exits,
   `warren-run-result write <exit code>` records the exit code, the output tail, the verdict
   and each checkout's raw git state in `/tmp/warren-run/result.v1` (one
   `key<TAB>base64` line per field, POSIX sh and git only).
3. The task then stays up for `WARREN_RUN_RESULT_HOLD_SECONDS` (default 300).
4. The server polls `warren-run-result cat` over ECS Exec (`exec_stream`, the control
   plane's own role) every `WARREN_RUN_RESULT_PROBE_SECONDS` (default 20) while the task
   runs. Once it gets the record it completes the run (`result_source: "workspace"`) and
   destroys the task. A run that times out is read with `warren-run-result snapshot`.

Fallbacks: with an image older than this change or a custom image without
`/usr/local/bin/warren-run-result`, with no `session-manager-plugin` on the control plane,
or when no probe succeeds before the hold ends, the task stops and the run completes from
the control plane's view only: status, times and exit code are right, `git` is empty,
`final_message` is `null`, and `capture_errors` says why. Each probe is one ECS Exec
session, so a long EBS run leaves one CloudTrail `ExecuteCommand` event per probe interval.
