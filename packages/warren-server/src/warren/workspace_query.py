"""Structured, read-only workspace queries over the runtime's control channel.

The orchestrator never dials the sidecar (docs/threat-model.md). To list files, read
one, or diff a workspace it runs the image's `warren-query` script
(warren_common/assets/warren_query.sh) through the runtime's `exec_stream`, the same
podman API exec / ECS Exec relay channel `POST /workspaces/{id}/exec` uses. The argv
is fixed: the only caller-supplied value is a file path, validated here and passed as
its own argv item, never through a shell. The script drops to the workspace's
unprivileged user before touching anything.

Everything the script prints comes from inside the workspace, so it is parsed
strictly and treated as untrusted: paths are re-validated and re-filtered, sizes and
entry counts are capped, and anything malformed is dropped.
"""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass
from typing import Any

from warren import exec_relay
from warren_common.runtime.base import WorkspaceHandle

QUERY_BIN = "/usr/local/bin/warren-query"
WORKSPACE_ROOT = "/workspace"
QUERY_TIMEOUT_SECONDS = 30.0
MAX_PATH_CHARS = 1024
MAX_FILE_BYTES = 1_048_576
MAX_DIFF_BYTES = 1_048_576
MAX_LIST_ENTRIES = 20_000
_LIST_OUTPUT_BYTES = 8 * 1_048_576
# base64 is 4/3 the size, plus line breaks and the framing lines.
_FILE_OUTPUT_BYTES = MAX_FILE_BYTES * 3 // 2 + 4096
_DIFF_OUTPUT_BYTES = 8 * 1_048_576
_ALWAYS_EXCLUDE = frozenset({".git", "node_modules", ".venv", "__pycache__"})
# Exit codes 126/127: the image has no (executable) warren-query.
_MISSING_EXIT_CODES = frozenset({126, 127})


class QueryError(Exception):
    def __init__(self, status: int, error: str, detail: str = "") -> None:
        super().__init__(detail or error)
        self.status = status
        self.error = error
        self.detail = detail


@dataclass(frozen=True)
class RepoDiff:
    repo: str
    diff: str
    truncated: bool


def validate_path(path: str) -> str:
    """A request path, relative to the workspace root: normalised, no `..`, capped."""
    if not path or len(path) > MAX_PATH_CHARS:
        raise QueryError(400, "invalid_path", f"path must be 1-{MAX_PATH_CHARS} characters")
    if path.startswith("/") or any(ord(c) < 0x20 or c == "\x7f" for c in path):
        raise QueryError(400, "invalid_path", "path must be relative with no control characters")
    parts = path.split("/")
    if any(p in ("", ".", "..") for p in parts):
        raise QueryError(400, "invalid_path", "path must be normalised, with no '.' or '..'")
    return path


def is_excluded(path: str) -> bool:
    """Same rules as the sidecar: .git, node_modules, .venv, __pycache__, .env*."""
    parts = path.split("/")
    return any(p in _ALWAYS_EXCLUDE or p.startswith(".env") for p in parts)


async def _run(runtime: Any, handle: WorkspaceHandle, args: list[str], max_output_bytes: int) -> tuple[list[str], int | None]:
    frames = exec_relay.relay(
        runtime,
        handle,
        [QUERY_BIN, *args],
        timeout_seconds=QUERY_TIMEOUT_SECONDS,
        max_output_bytes=max_output_bytes,
    )
    result = await exec_relay.collect(frames)
    if result.get("error"):
        raise QueryError(502, "query_failed", str(result["error"]))
    if result.get("timed_out"):
        raise QueryError(504, "query_timed_out", f"no answer within {QUERY_TIMEOUT_SECONDS:.0f}s")
    if result.get("truncated"):
        raise QueryError(413, "query_output_too_large", "the workspace returned more than the server accepts")
    code = result.get("exit_code")
    if code in _MISSING_EXIT_CODES:
        raise QueryError(501, "query_unavailable", "this workspace's image has no warren-query; recreate it from a current image")
    return result.get("output", "").splitlines(), code


def _script_error(lines: list[str], code: int | None) -> QueryError:
    reason = next((ln[4:] for ln in lines if ln.startswith("ERR ")), "")
    if reason in ("excluded", "not found"):
        return QueryError(404, "not_found", "not found")
    if reason in ("symlink", "not a regular file"):
        return QueryError(400, "not_a_regular_file", "symbolic links and special files are not served")
    if reason == "not readable":
        return QueryError(403, "not_readable", "not readable by the workspace user")
    return QueryError(502, "query_failed", reason or f"warren-query exited {code}")


async def list_files(runtime: Any, handle: WorkspaceHandle) -> list[dict]:
    lines, code = await _run(runtime, handle, ["list", WORKSPACE_ROOT], _LIST_OUTPUT_BYTES)
    if code != 0 or not lines or lines[-1] != "END":
        raise _script_error(lines, code)
    files: dict[str, int] = {}
    for line in lines[:-1]:
        kind, _, rest = line.partition(" ")
        size, _, path = rest.partition(" ")
        if kind != "F" or not size.isdigit():
            continue
        try:
            validate_path(path)
        except QueryError:
            continue
        if is_excluded(path):
            continue
        files[path] = int(size)
        if len(files) > MAX_LIST_ENTRIES:
            raise QueryError(413, "too_many_files", f"more than {MAX_LIST_ENTRIES} files")
    dirs = {"/".join(p.split("/")[:i]) for p in files for i in range(1, p.count("/") + 1)}
    entries = [{"path": p, "size": s, "is_dir": False} for p, s in files.items()]
    entries += [{"path": d, "size": 0, "is_dir": True} for d in dirs]
    return sorted(entries, key=lambda e: e["path"])


async def read_file(runtime: Any, handle: WorkspaceHandle, path: str) -> bytes:
    validate_path(path)
    if is_excluded(path):
        raise QueryError(404, "not_found", "not found")
    lines, code = await _run(
        runtime, handle, ["read", WORKSPACE_ROOT, path, str(MAX_FILE_BYTES)], _FILE_OUTPUT_BYTES
    )
    if lines and lines[0].startswith("TOOBIG "):
        raise QueryError(413, "file_too_large", f"file exceeds {MAX_FILE_BYTES} bytes")
    if code != 0 or len(lines) < 2 or not lines[0].startswith("OK ") or lines[-1] != "END":
        raise _script_error(lines, code)
    try:
        data = base64.b64decode("".join(lines[1:-1]), validate=True)
    except (binascii.Error, ValueError):
        raise QueryError(502, "query_failed", "malformed file body") from None
    if len(data) > MAX_FILE_BYTES:
        raise QueryError(413, "file_too_large", f"file exceeds {MAX_FILE_BYTES} bytes")
    return data


async def diff(runtime: Any, handle: WorkspaceHandle) -> list[RepoDiff]:
    lines, code = await _run(runtime, handle, ["diff", WORKSPACE_ROOT, str(MAX_DIFF_BYTES)], _DIFF_OUTPUT_BYTES)
    if code != 0 or not lines or lines[-1] != "END":
        raise _script_error(lines, code)
    repos: list[RepoDiff] = []
    repo: str | None = None
    body: list[str] = []
    for line in lines[:-1]:
        if line.startswith("REPO "):
            repo, body = line[5:], []
        elif line == "ENDREPO" and repo is not None:
            try:
                raw = base64.b64decode("".join(body), validate=True)
            except (binascii.Error, ValueError):
                raw = b""
            if repo == "." or not is_excluded(repo):
                repos.append(
                    RepoDiff(
                        repo=repo,
                        diff=raw[:MAX_DIFF_BYTES].decode(errors="replace"),
                        truncated=len(raw) > MAX_DIFF_BYTES,
                    )
                )
            repo = None
        elif repo is not None:
            body.append(line)
    return repos
