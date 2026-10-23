#!/usr/bin/env python3
"""warren-docker-base entrypoint — emits NDJSON preflight events, supervises workspace app.

Design notes:
- Must NOT call os.execvp (Pitfall 8): entrypoint stays alive as PID 1 and blocks
  waiting for the workspace app; the sidecar continues as a daemon thread.
- emit() is the only stdout writer; uses json.dumps (no raw interpolation) and
  flush=True to ensure Podman buffers do not hold events (Pitfall 4 / T-04-04-02).
- Stale AF_UNIX socket removed before starting uvicorn (Pitfall 2 / T-04-04-03).
- Sidecar import wrapped in try/except: if warren_sidecar is not installed,
  sidecar_import_error is emitted and the entrypoint exits non-zero.
- asyncio is used only for the socket-ready poll (asyncio.sleep).  The workspace
  app subprocess is started synchronously after asyncio.run() returns, which
  avoids asyncio child-watcher compatibility issues on macOS Python 3.12.
"""
from __future__ import annotations

import asyncio
import json
import os
import pathlib
import re
import shlex
import subprocess
import sys
import threading
import time

_seq: int = 0


def emit(event: dict) -> None:
    """Write a NDJSON event line to stdout.

    Adds ts (ISO-8601 UTC) and seq (monotonic integer) fields.
    flush=True is mandatory — Podman / container runtimes buffer stdout.
    """
    global _seq
    event["ts"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    event["seq"] = _seq
    _seq += 1
    print(json.dumps(event), flush=True)


def fail(reason: str, detail: str = "") -> None:
    """Emit workspace_failed and exit non-zero."""
    emit({"type": "workspace_failed", "reason": reason, "detail": detail})
    sys.exit(1)


async def _preflight() -> str:
    """Run all preflight checks, start the sidecar, emit events.

    Returns the workspace app command to execute after the asyncio phase.
    Exits non-zero via fail() on any preflight error.
    """
    # ── D-05: workspace identity ──────────────────────────────────────────────
    workspace_id = os.environ.get("WARREN_WORKSPACE_ID")
    if not workspace_id:
        fail("missing_workspace_id")

    # ── D-05: worktree paths (colon-delimited, A2) ───────────────────────────
    worktree_paths_raw = os.environ.get("WARREN_WORKTREE_PATHS", "")
    worktree_paths = [p for p in worktree_paths_raw.split(":") if p]

    init_harness_dirs()

    # ── D-06 step 1: worktree_ready (per path) ───────────────────────────────
    for path in worktree_paths:
        if not os.path.isdir(path):
            fail("worktree_not_found", path)
        emit({"type": "worktree_ready", "path": path})

    # ── D-06 step 2: claude_md_ready ─────────────────────────────────────────
    claude_md_path = (
        os.path.join(worktree_paths[0], "CLAUDE.md")
        if worktree_paths
        else "/workspace/CLAUDE.md"
    )
    emit({"type": "claude_md_ready", "found": os.path.isfile(claude_md_path)})

    # ── D-06 step 3: start sidecar in daemon thread ───────────────────────────
    SOCK = "/tmp/warren-sidecar.sock"
    pathlib.Path(SOCK).unlink(missing_ok=True)  # remove stale socket (Pitfall 2)

    def _run_sidecar() -> None:
        """Start uvicorn serving warren_sidecar on a Unix-domain socket."""
        try:
            import structlog  # noqa: PLC0415
            import uvicorn  # noqa: PLC0415
            from warren_sidecar.app import app as sidecar_app  # noqa: PLC0415

            # Route all sidecar/structlog output to stderr so that entrypoint's
            # stdout remains clean NDJSON for Podman container.logs capture.
            structlog.configure(
                processors=[
                    structlog.dev.ConsoleRenderer(),
                ],
                wrapper_class=structlog.BoundLogger,
                logger_factory=structlog.PrintLoggerFactory(file=sys.stderr),
            )

            uvicorn.run(sidecar_app, uds=SOCK, log_level="warning")
        except ImportError as e:
            # If warren_sidecar is not installed emit workspace_failed and exit the
            # thread (sys.exit in a thread raises SystemExit, killing only the thread).
            emit({"type": "workspace_failed", "reason": "sidecar_import_error", "detail": str(e)})
            sys.exit(1)

    t = threading.Thread(target=_run_sidecar, daemon=True)
    t.start()

    # Wait for socket to appear — up to 2 seconds (T-04-04-03)
    for _ in range(20):
        if os.path.exists(SOCK):
            break
        await asyncio.sleep(0.1)
    else:
        fail("sidecar_socket_timeout", SOCK)

    # Audit finding 12: uvicorn leaves its uds socket 0o666 and the sidecar runs as
    # root. Restrict it, and keep the token (already read during the sidecar's
    # lifespan startup, which precedes the bind) out of the workspace app's env.
    # Nothing workspace-controlled has started yet.
    os.chmod(SOCK, 0o600)
    os.environ.pop("WARREN_SIDECAR_TOKEN", None)

    emit({"type": "sidecar_ready", "socket": SOCK})

    # ── D-06 step 4: workspace_ready ─────────────────────────────────────────
    emit({"type": "workspace_ready", "workspace_id": workspace_id})

    return os.environ.get("WARREN_APP", "bash")


_HARNESS_ROOT = "/var/lib/warren/harness"
_HARNESS_INIT = "/usr/local/bin/warren-harness-init"


def init_harness_dirs(init: str = _HARNESS_INIT, root: str = _HARNESS_ROOT) -> None:
    """AB1/AG3: the image's generated warren-harness-init keeps only each harness's
    declared persist paths (minus credential files) and rewrites warren's own
    generated config, e.g. a minimal .claude.json."""
    if not os.environ.get("WARREN_HARNESSES") or not os.path.isfile(init):
        return
    try:
        subprocess.run(["/bin/sh", init, root], timeout=60, check=True)
    except (OSError, subprocess.SubprocessError) as e:
        emit({"type": "harness_init_failed", "detail": str(e)})


def _build_argv(app_cmd: str) -> list[str]:
    """Build the subprocess argv for the workspace app.

    When there is no controlling TTY (server/Podman mode), wrap the app in a
    detached tmux session and block on it via `tmux wait-for` so the container
    stays alive until the session exits.  The user re-attaches with
    `tmux attach -t main`.

    When a TTY is present (local connect-mode), run the app directly.

    ``app_cmd`` is a single WARREN_APP string that may itself carry
    arguments (e.g. ``"claude --dangerously-skip-permissions"``) -- split it
    with ``shlex.split`` for the TTY path so it execs as argv ``["claude",
    "--dangerously-skip-permissions"]`` rather than one literal argv[0] that
    fails to find a binary by that whole name (audit 2026-10-16 #37). The
    no-TTY path keeps it as one string since it's handed to ``tmux`` inside
    an ``sh -c`` command, not exec'd directly.
    """
    if sys.stdin.isatty():
        return shlex.split(app_cmd)
    if os.environ.get("WARREN_SHELL_FIRST") == "1":
        # AG2a: `warren connect` runs the warren shell in tmux session `main`
        # (new-session -A), so leaving the shell or a harness never stops the container.
        return ["tail", "-f", "/dev/null"]
    # No TTY → server mode.
    # 1. Start the app in a detached tmux session named 'main'.
    # 2. Arrange for tmux to signal a wait channel 'done' when the session ends.
    # 3. Block on that channel so the entrypoint (and container) stay alive.
    # shlex.quote (not naive single-quote wrapping) protects against an
    # app_cmd value containing its own single quote, which would otherwise
    # break out of the 'tmux new-session ...' argument it's embedded in
    # (same injection class as audit P0 #12's shell-quoting fix elsewhere).
    quoted_app_cmd = shlex.quote(app_cmd)
    # UX-1: status-left marks the session itself (not just the shell's own
    # PROMPT/banner, which only render once at shell-start) so the ⬡ project/
    # template mark survives a `tmux attach -t main` reconnect too --
    # connect_via_ssh_podman_exec attaches to this exact session, with no
    # fresh shell-start to re-render a banner.
    # Audit U3: shlex.quote above only protects the outer shell -- tmux parses
    # the status-left STRING CONTENT itself for "#"-prefixed format sequences
    # (e.g. "#(cmd)" runs a shell command when the status line renders), a
    # completely separate escaping layer from the shell quoting shlex.quote
    # handles. WARREN_PROJECT/WARREN_TEMPLATE come from a project/template
    # name an authenticated (not necessarily admin) user can set, so a "#"
    # in either must be escaped as tmux's own literal-hash form ("##") before
    # shlex.quote ever sees it.
    def _tmux_escape(value: str) -> str:
        return value.replace("#", "##")

    status_left = shlex.quote(
        "⬡ "
        + _tmux_escape(os.environ.get("WARREN_PROJECT", ""))
        + "/"
        + _tmux_escape(os.environ.get("WARREN_TEMPLATE", ""))
        + " "
    )
    return [
        "sh", "-c",
        f"tmux new-session -d -s main {quoted_app_cmd} \\; "
        f"set-option -g status-left {status_left} \\; "
        f"set-hook -g session-closed 'wait-for -S done' && "
        f"tmux wait-for done",
    ]


_SESSION_ENV = "/etc/warren/session.env"
_SESSION_ENV_VARS = (
    "WARREN_HARNESSES", "WARREN_HARNESS_ROOT", "WARREN_HARNESS_DEFAULT",
    "WARREN_PROJECT", "WARREN_TEMPLATE", "WARREN_WORKSPACE_ID",
)
_SAFE_VALUE = re.compile(r"^[A-Za-z0-9 ._/:-]*$")


def write_session_env(path: str = _SESSION_ENV) -> None:
    """Copy the harness settings the warren shell reads into a root-owned file it
    sources when a `podman exec` session doesn't carry the container env."""
    lines = [
        f"{name}='{os.environ[name]}'"
        for name in _SESSION_ENV_VARS
        if name in os.environ and _SAFE_VALUE.match(os.environ[name])
    ]
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write("".join(f"{line}\n" for line in lines))
    except OSError as e:
        emit({"type": "session_env_unavailable", "detail": str(e)})


_SUPERVISOR = "/usr/local/bin/warren-agent-supervisor"


def start_agent_supervisor(path: str = _SUPERVISOR) -> subprocess.Popen | None:
    """AG2b: a `kind: agent` workspace's harness runs under warren's supervisor,
    alongside the shell in tmux session `main`, so attaching never takes it over."""
    if not os.environ.get("WARREN_AGENT_SPEC"):
        return None
    if not os.path.isfile(path):
        fail("agent_supervisor_missing", path)
    proc = subprocess.Popen([sys.executable, path])  # noqa: S603
    emit({"type": "agent_supervisor_started", "pid": proc.pid})
    return proc


if __name__ == "__main__":
    app_cmd = asyncio.run(_preflight())
    if os.environ.get("WARREN_SHELL_FIRST") == "1" and os.geteuid() == 0:
        write_session_env()
    start_agent_supervisor()

    # ── D-11: supervise workspace app (PID 1 stays alive) ────────────────────
    # Run synchronously after asyncio.run() returns so the daemon uvicorn thread
    # (and its own event loop) continues uninterrupted.
    argv = _build_argv(app_cmd)
    try:
        result = subprocess.run(argv)  # noqa: S603
    except (OSError, FileNotFoundError) as e:
        fail("workspace_app_not_found", f"{argv[0]}: {e}")
    else:
        sys.exit(result.returncode or 0)
