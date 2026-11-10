"""Single-turn runs on EBS-backed ECS workspaces: the result comes from the task itself.

An EBS volume is attached only to its own task (runtime/ebs.py), so the control plane
can't inspect the checkouts after the app exits, as it does on podman and EFS
(registry/completion.py). For such a run the task gets WARREN_RUN_RESULT=1: ecs-base's
entrypoint then runs the app as a child, records the result with `warren-run-result
write <rc>` (images/ecs-base/warren-run-result.sh) and stays up for
WARREN_RUN_RESULT_HOLD_SECONDS. The control plane polls `warren-run-result cat` over ECS
Exec (`exec_stream`, the control plane's own role) and destroys the task once it has the
record; a timed-out run is read with `snapshot` instead.

Fallbacks, all recorded as capture errors rather than failures: an image without
warren-run-result (old ecs-base, custom image) exits straight away like any other
single-turn task; a control plane without session-manager-plugin can't exec; a probe
that never succeeds before the hold ends. In each case the run still completes with
its exit code, and the git/verdict/output fields stay empty.
"""

from __future__ import annotations

import asyncio
import base64
import re
from collections.abc import Iterable
from typing import Any

import structlog
from warren_common.runtime.base import WorkspaceHandle

log = structlog.get_logger(__name__)

RESULT_COMMAND = "/usr/local/bin/warren-run-result"
DEFAULT_HOLD_SECONDS = 300
MAX_RECORD_BYTES = 1024 * 1024
_SAFE = re.compile(r"^[A-Za-z0-9_.][A-Za-z0-9_./-]*$")


class ResultUnavailable(Exception):
    """The task has no result record (yet), or it couldn't be read."""


def run_result_env(folders: Iterable[Any], hold_seconds: int = DEFAULT_HOLD_SECONDS) -> dict[str, str]:
    """Task env for a single-turn EBS run: which checkouts to report, and the hold."""
    repos = []
    for f in folders:
        if getattr(f, "type", "") not in ("git-worktree", "git-clone") or not getattr(f, "url", None):
            continue
        mount, branch = f.mount, f.branch or ""
        if not _SAFE.fullmatch(mount) or ".." in mount.split("/"):
            continue
        repos.append(f"{mount}={branch}" if branch and _SAFE.fullmatch(branch) else mount)
    return {
        "WARREN_RUN_RESULT": "1",
        "WARREN_RUN_RESULT_HOLD_SECONDS": str(max(0, int(hold_seconds))),
        "WARREN_RUN_REPOS": " ".join(repos),
    }


async def read_result(runtime: Any, handle: WorkspaceHandle, *, snapshot: bool = False, timeout: float = 60.0) -> bytes:
    """The task's result record via ECS Exec. Raises ResultUnavailable when there is none."""
    exec_stream = getattr(runtime, "exec_stream", None)
    if exec_stream is None or not handle.runtime_id:
        raise ResultUnavailable("the runtime has no exec")
    out = bytearray()
    code: int | None = None
    try:
        async with asyncio.timeout(timeout):
            async for item in exec_stream(handle, [RESULT_COMMAND, "snapshot" if snapshot else "cat"]):
                if isinstance(item, bytes):
                    out += item
                    if len(out) > MAX_RECORD_BYTES:
                        raise ResultUnavailable(f"result record exceeds {MAX_RECORD_BYTES} bytes")
                else:
                    code = getattr(item, "exit_code", None)
    except ResultUnavailable:
        raise
    except Exception as exc:
        raise ResultUnavailable(f"exec failed: {type(exc).__name__}: {exc}") from exc
    if code not in (0, None):
        raise ResultUnavailable("no result recorded yet" if code == 3 else f"warren-run-result exited {code}")
    if not out.strip():
        raise ResultUnavailable("empty result record")
    return bytes(out)


def parse_record(raw: bytes) -> dict[str, Any]:
    """`key<TAB>base64` lines -> {fields..., "repos": [{...}, ...]} (values decoded as text).

    Lines that don't parse (ECS Exec noise, a truncated line) are skipped."""
    fields: dict[str, Any] = {}
    repos: list[dict[str, str]] = []
    for line in raw.replace(b"\r", b"").split(b"\n"):
        key, sep, value = line.partition(b"\t")
        if not sep:
            continue
        name = key.decode("ascii", "replace").strip()
        try:
            text = base64.b64decode(value.strip(), validate=True).decode("utf-8", "replace")
        except ValueError:  # binascii.Error included
            continue
        if name == "repo":
            repos.append({"mount": text})
        elif name.startswith("repo."):
            if repos:
                repos[-1][name[len("repo."):]] = text
        else:
            fields[name] = text
    if fields.get("version") != "1":
        raise ResultUnavailable("not a warren-run-result v1 record")
    fields["repos"] = repos
    return fields
