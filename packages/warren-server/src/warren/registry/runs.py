"""Headless runs: a single-turn workspace's result, kept in the registry after destroy.

Every single-turn workspace (AH2) is a run whose id is its workspace id. The `runs` row
is written when the workspace is created (status `running`) and finished when it
completes (registry.complete_single_turn), fails to provision, times out, or is
destroyed first. `result_json` holds the structured result (docs/runs.md, schema
`warren.run.result/v1`); rows outlive the workspace and are pruned by age and by a
per-owner count.

Everything in a result except the exit code, times and status came out of the
workspace (the app's stdout, the checkouts, .warren/verdict.json), so it is reported,
not trusted: it is size-capped, parsed as data only, and never acted on.
"""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime, timedelta
from typing import Any

import aiosqlite
from warren_common.harness import SERVER_HARNESS_ROOT

SCHEMA = "warren.run.result/v1"
RUNNING = "running"
SUCCEEDED = "succeeded"
FAILED = "failed"
TIMED_OUT = "timed_out"
STATUSES = (RUNNING, SUCCEEDED, FAILED, TIMED_OUT)

MAX_FINAL_MESSAGE = 64 * 1024
MAX_CHANGED_FILES = 500
MAX_PR_URLS = 10
_PR_URL = re.compile(
    r"https://(?:github\.com/[\w.-]+/[\w.-]+/pull/\d+"
    r"|gitlab\.com/[\w./-]+?/-/merge_requests/\d+"
    r"|bitbucket\.org/[\w.-]+/[\w.-]+/pull-requests/\d+)"
)
_HARNESS_FIELDS = ("subtype", "is_error", "num_turns", "duration_ms", "total_cost_usd", "session_id")
# The run's own bookkeeping, not the agent's changes.
_IGNORED_PREFIXES = (".warren/",)


def utcnow() -> datetime:
    return datetime.now(UTC)


def iso(dt: datetime) -> str:
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_iso(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


# ---------------------------------------------------------------------------
# Store
# ---------------------------------------------------------------------------

_COLUMNS = (
    "run_id", "owner_id", "project", "template", "status", "created_at", "started_at",
    "ended_at", "timeout_seconds", "result_json",
)


class RunStore:
    def __init__(self, db: aiosqlite.Connection) -> None:
        self._db = db

    async def create(
        self,
        *,
        run_id: str,
        owner_id: str,
        project: str,
        template: str,
        timeout_seconds: float | None,
        started_at: datetime | None = None,
    ) -> None:
        now = iso(started_at or utcnow())
        await self._db.execute(
            """
            INSERT OR IGNORE INTO runs (
                run_id, owner_id, project, template, status, created_at, started_at, timeout_seconds
            ) VALUES (?, ?, ?, ?, 'running', ?, ?, ?)
            """,
            (run_id, owner_id, project, template, now, now, timeout_seconds),
        )

    async def get(self, run_id: str) -> dict[str, Any] | None:
        async with self._db.execute(
            f"SELECT {', '.join(_COLUMNS)} FROM runs WHERE run_id = ?", (run_id,)
        ) as cur:
            row = await cur.fetchone()
        return _row(row) if row is not None else None

    async def list(self, owner_id: str | None, limit: int = 50) -> list[dict[str, Any]]:
        """Newest first; every owner's when `owner_id` is None (admin)."""
        if owner_id is None:
            sql, args = f"SELECT {', '.join(_COLUMNS)} FROM runs ORDER BY created_at DESC LIMIT ?", (limit,)
        else:
            sql = f"SELECT {', '.join(_COLUMNS)} FROM runs WHERE owner_id = ? ORDER BY created_at DESC LIMIT ?"
            args = (owner_id, limit)
        async with self._db.execute(sql, args) as cur:
            rows = await cur.fetchall()
        return [_row(r) for r in rows]

    async def finish(
        self, run_id: str, *, status: str, result: dict[str, Any], ended_at: datetime | None = None
    ) -> bool:
        """Record the result of a still-running run. False if it had already finished."""
        if status not in STATUSES or status == RUNNING:
            raise ValueError(f"not a final run status: {status!r}")
        cur = await self._db.execute(
            "UPDATE runs SET status = ?, ended_at = ?, result_json = ? WHERE run_id = ? AND status = 'running'",
            (status, iso(ended_at or utcnow()), json.dumps(result, separators=(",", ":")), run_id),
        )
        return (cur.rowcount or 0) > 0

    async def prune(self, *, retention_seconds: float, max_per_owner: int, now: datetime | None = None) -> int:
        """Drop finished runs older than the retention, then each owner's oldest finished
        runs beyond `max_per_owner`. Running rows are never pruned."""
        cutoff = iso((now or utcnow()) - timedelta(seconds=retention_seconds))
        cur = await self._db.execute(
            "DELETE FROM runs WHERE status != 'running' AND COALESCE(ended_at, created_at) < ?", (cutoff,)
        )
        removed = cur.rowcount or 0
        cur = await self._db.execute(
            """
            DELETE FROM runs WHERE run_id IN (
                SELECT run_id FROM (
                    SELECT run_id, status, ROW_NUMBER() OVER (
                        PARTITION BY owner_id ORDER BY created_at DESC, run_id DESC
                    ) AS n FROM runs
                ) WHERE n > ? AND status != 'running'
            )
            """,
            (max_per_owner,),
        )
        return removed + (cur.rowcount or 0)


def _row(row: Any) -> dict[str, Any]:
    return run_view(dict(zip(_COLUMNS, row)))


def run_view(data: dict[str, Any]) -> dict[str, Any]:
    """A stored run (its `_COLUMNS`) as the store returns it: `result_json` decoded
    into `result`. Shared by the SQLite and DynamoDB (state/dynamodb.py) stores."""
    data = {c: data.get(c) for c in _COLUMNS}
    raw = data.pop("result_json")
    try:
        data["result"] = json.loads(raw) if raw else None
    except ValueError:
        data["result"] = None
    return data


# ---------------------------------------------------------------------------
# Result assembly
# ---------------------------------------------------------------------------


def _split_z(raw: str) -> list[str]:
    return [p for p in raw.split("\0")]


def parse_numstat(raw: str) -> dict[str, tuple[int | None, int | None]]:
    """`git diff --numstat -z` -> {path: (insertions, deletions)} (None for binary)."""
    out: dict[str, tuple[int | None, int | None]] = {}
    parts = _split_z(raw)
    i = 0
    while i < len(parts):
        entry = parts[i]
        i += 1
        if not entry:
            continue
        fields = entry.split("\t", 2)
        if len(fields) < 3:
            continue
        added, deleted, path = fields
        if path == "" and i + 1 < len(parts):  # rename/copy: "a\td\t\0src\0dst"
            path = parts[i + 1]
            i += 2
        out[path] = (int(added) if added.isdigit() else None, int(deleted) if deleted.isdigit() else None)
    return out


def parse_status(raw: str) -> list[tuple[str, str]]:
    """`git status --porcelain=v1 -z` -> [(XY, path)] (a rename's new path)."""
    out: list[tuple[str, str]] = []
    parts = _split_z(raw)
    i = 0
    while i < len(parts):
        entry = parts[i]
        i += 1
        if len(entry) < 4:
            continue
        xy, path = entry[:2], entry[3:]
        if "R" in xy or "C" in xy:
            i += 1  # the original path follows
        out.append((xy, path))
    return out


def _status_word(xy: str) -> str:
    if xy == "??":
        return "untracked"
    for letter, word in (("D", "deleted"), ("A", "added"), ("R", "renamed"), ("C", "copied")):
        if letter in xy:
            return word
    return "modified"


def summarize_repo(raw: dict[str, str]) -> dict[str, Any]:
    """One checkout's entry in a result's `git` list, from collect_repo_raw (control
    plane) or a warren-run-result record (workspace)."""
    if raw.get("error"):
        return {"mount": raw.get("mount", ""), "error": raw["error"][:500]}
    numstat = parse_numstat(raw.get("numstat", ""))
    status = parse_status(raw.get("status", ""))
    files: dict[str, dict[str, Any]] = {}
    for path, (ins, dels) in numstat.items():
        files[path] = {"path": path, "status": "modified", "insertions": ins, "deletions": dels}
    for xy, path in status:
        entry = files.setdefault(path, {"path": path, "status": "modified", "insertions": None, "deletions": None})
        entry["status"] = _status_word(xy)
    changed = sorted(
        (f for f in files.values() if not f["path"].startswith(_IGNORED_PREFIXES)), key=lambda f: f["path"]
    )
    branch = raw.get("branch") or None
    head = raw.get("head") or None
    remote = raw.get("remote") or None
    diffstat = {
        "files": len(changed),
        "insertions": sum(f["insertions"] or 0 for f in changed),
        "deletions": sum(f["deletions"] or 0 for f in changed),
    }
    return {
        "mount": raw.get("mount", ""),
        "branch": branch,
        "base_branch": raw.get("base_branch") or None,
        "head_commit": head,
        "base_commit": raw.get("base") or None,
        "is_clean": not [s for s in status if not s[1].startswith(_IGNORED_PREFIXES)],
        "changed_files": changed[:MAX_CHANGED_FILES],
        "changed_files_truncated": len(changed) > MAX_CHANGED_FILES,
        "diffstat": diffstat,
        # Observed only: the local remote-tracking ref of the branch, which a push from
        # inside the workspace updates. warren itself never pushes.
        "remote_branch": f"origin/{branch}" if branch and remote else None,
        "pushed": bool(branch and remote and head and remote == head),
    }


def parse_harness_output(text: str, harness: str) -> tuple[str | None, dict[str, Any] | None]:
    """(final_message, harness_result) from the app's stdout.

    claude `--output-format json` prints one result object (stream-json: the last
    `"type": "result"` line); its `result` is the final message. Anything else: the
    stdout itself (its tail) is the summary."""
    stripped = text.strip()
    if not stripped:
        return None, None
    if harness == "claude":
        candidates: list[str] = [stripped, *reversed(stripped.splitlines())]
        for candidate in candidates:
            candidate = candidate.strip()
            if not (candidate.startswith("{") and candidate.endswith("}")):
                continue
            try:
                obj = json.loads(candidate)
            except ValueError:
                continue
            if isinstance(obj, dict) and (obj.get("type") == "result" or "result" in obj):
                message = obj.get("result")
                result = {k: obj[k] for k in _HARNESS_FIELDS if k in obj and _scalar(obj[k])}
                return (message[-MAX_FINAL_MESSAGE:] if isinstance(message, str) else None), result
    return stripped[-MAX_FINAL_MESSAGE:], None


def _scalar(value: Any) -> bool:
    return value is None or isinstance(value, (str, int, float, bool))


def find_pr_urls(*texts: str | None) -> list[str]:
    seen: list[str] = []
    for text in texts:
        for url in _PR_URL.findall(text or ""):
            if url not in seen:
                seen.append(url)
            if len(seen) >= MAX_PR_URLS:
                return seen
    return seen


def run_status(*, exit_code: int | None, harness_result: dict[str, Any] | None, timed_out: bool) -> str:
    if timed_out:
        return TIMED_OUT
    if harness_result and harness_result.get("is_error") is True:
        return FAILED
    return SUCCEEDED if exit_code == 0 else FAILED


def transcript_pointer(harness: str, harness_result: dict[str, Any] | None, storage: str) -> dict[str, Any] | None:
    """Where the harness's own transcript was, when the result names a session.
    `retained`: whether it outlives the workspace (only an EFS volume, until the EFS
    retention reaper removes it; podman and EBS delete it on destroy)."""
    session = (harness_result or {}).get("session_id")
    if harness != "claude" or not isinstance(session, str) or not re.fullmatch(r"[A-Za-z0-9-]{1,128}", session):
        return None
    return {
        "harness": "claude",
        "session_id": session,
        "location": f"{SERVER_HARNESS_ROOT}/claude/projects/*/{session}.jsonl",
        "retained": storage == "efs",
    }


def build_result(
    *,
    run: dict[str, Any] | None,
    workspace: Any,
    event: dict[str, Any],
    repos_raw: list[dict[str, str]] | None,
    output: str | None,
    harness: str,
    storage: str,
    source: str,
    errors: list[str],
    timed_out: bool,
    ended_at: datetime,
    recorded_exit_code: int | None = None,
) -> tuple[str, dict[str, Any]]:
    """`recorded_exit_code`: the code the run's command wrote beside its output
    (warren_common/headless.py), preferred over the container's: on podman/docker the
    image runs the app inside tmux, whose exit code the container reports."""
    final_message, harness_result = parse_harness_output(output or "", harness)
    exit_code = recorded_exit_code if recorded_exit_code is not None else event.get("exit_code")
    status = run_status(exit_code=exit_code, harness_result=harness_result, timed_out=timed_out)
    started = parse_iso((run or {}).get("started_at")) or workspace.created_at
    verdict = event.get("verdict")
    verdict_text = json.dumps(verdict) if verdict is not None else None
    result = {
        "schema": SCHEMA,
        "run_id": workspace.workspace_id,
        "workspace_id": workspace.workspace_id,
        "project": workspace.project,
        "template": workspace.intent,
        "status": status,
        "started_at": iso(started),
        "ended_at": iso(ended_at),
        "duration_seconds": round((ended_at - started).total_seconds(), 3),
        "exit_code": exit_code,
        "harness": harness or None,
        "final_message": final_message,
        "harness_result": harness_result,
        "git": [summarize_repo(r) for r in (repos_raw or [])],
        "pull_requests": find_pr_urls(final_message, output, verdict_text),
        "verdict": verdict,
        "transcript": transcript_pointer(harness, harness_result, storage),
        "result_source": source,
        "capture_errors": [*event.get("capture_errors", []), *errors][:50],
        "error": None,
    }
    return status, result


def failure_result(
    *, run: dict[str, Any], error: str, ended_at: datetime, status: str = FAILED
) -> dict[str, Any]:
    """A run that ended without a completion (provision failure, destroyed early)."""
    started = parse_iso(run.get("started_at")) or ended_at
    return {
        "schema": SCHEMA,
        "run_id": run["run_id"],
        "workspace_id": run["run_id"],
        "project": run["project"],
        "template": run["template"],
        "status": status,
        "started_at": iso(started),
        "ended_at": iso(ended_at),
        "duration_seconds": round((ended_at - started).total_seconds(), 3),
        "exit_code": None,
        "harness": None,
        "final_message": None,
        "harness_result": None,
        "git": [],
        "pull_requests": [],
        "verdict": None,
        "transcript": None,
        "result_source": "none",
        "capture_errors": [],
        "error": error[:2000],
    }


def running_view(run: dict[str, Any], now: datetime | None = None) -> dict[str, Any]:
    """What status/result report for a run that hasn't finished."""
    started = parse_iso(run.get("started_at"))
    return {
        "schema": SCHEMA,
        "run_id": run["run_id"],
        "workspace_id": run["run_id"],
        "project": run["project"],
        "template": run["template"],
        "status": RUNNING,
        "started_at": run.get("started_at"),
        "ended_at": None,
        "duration_seconds": round(((now or utcnow()) - started).total_seconds(), 3) if started else None,
        "timeout_seconds": run.get("timeout_seconds"),
    }
