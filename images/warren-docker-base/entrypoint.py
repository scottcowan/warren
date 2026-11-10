#!/usr/bin/env python3
"""warren-docker-base entrypoint — emits NDJSON preflight events, supervises workspace app.

Design notes:
- Must NOT call os.execvp (Pitfall 8): entrypoint stays alive as PID 1 and blocks
  waiting for the workspace app; the sidecar's agent-state recorder runs as a
  daemon thread beside it.
- emit() is the only stdout writer; uses json.dumps (no raw interpolation) and
  flush=True to ensure Podman buffers do not hold events (Pitfall 4 / T-04-04-02).
- Sidecar import wrapped in try/except: if warren_sidecar is not installed,
  sidecar_import_error is emitted and the entrypoint exits non-zero.
- Root phase, then uid 1000: the image starts as container root (warren-docker-ssh-base's
  sshd needs it), does the few things that need root, then drops this very process to
  `warren` (uid/gid 1000) so the tmux server, harness init, agent supervisor, recorder and
  the app all run unprivileged. See `choose_workload_user` for when it does NOT drop.
"""
from __future__ import annotations

import json
import os
import re
import shlex
import subprocess
import sys
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


def _preflight() -> str:
    """Run all preflight checks, start the agent-state recorder, emit events.

    Returns the workspace app command to execute.
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

    # ── D-06 step 3: agent-state recorder (sidecar) in a daemon thread ───────
    # It tails the tmux pane for OSC 7501 state and writes osc-state.json, which
    # the server reads host-side. It serves nothing: the orchestrator never dials it.
    try:
        import structlog  # noqa: PLC0415
        from warren_sidecar.recorder import start_thread  # noqa: PLC0415
    except ImportError as e:
        fail("sidecar_import_error", str(e))
    # structlog output goes to stderr so stdout stays clean NDJSON for container logs.
    structlog.configure(
        processors=[structlog.dev.ConsoleRenderer()],
        wrapper_class=structlog.BoundLogger,
        logger_factory=structlog.PrintLoggerFactory(file=sys.stderr),
    )
    start_thread()

    # ── D-06 step 4: workspace_ready ─────────────────────────────────────────
    emit({"type": "workspace_ready", "workspace_id": workspace_id})

    return os.environ.get("WARREN_APP", "bash")


_HARNESS_ROOT = "/var/lib/warren/harness"
_WORKLOAD_UID = 1000
_WORKLOAD_GID = 1000
_WORKLOAD_HOME = "/home/warren"
_WORKLOAD_MARKER = "/etc/warren/workload"
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
    match_mount_owner(root)


def match_mount_owner(root: str) -> None:
    """Give what a still-root entrypoint wrote under a bind mount to the mount's owner.

    Only reached when the workload stays root (see choose_workload_user) over a mount
    owned by another non-root uid: rootful docker with a server uid other than 1000.
    Under rootless podman's `host` userns the dir is root-owned and this is a no-op, and
    under keep-id the entrypoint has dropped to uid 1000 (harness init then writes as the
    owner) so it never runs as root. Never follows a link.
    """
    if os.geteuid() != 0:
        return
    try:
        st = os.stat(root, follow_symlinks=False)
    except OSError:
        return
    if st.st_uid == 0 or not os.path.isdir(root) or os.path.islink(root):
        return
    uid, gid = st.st_uid, st.st_gid
    for top, dirs, files in os.walk(root, followlinks=False):
        for name in dirs + files:
            path = os.path.join(top, name)
            try:
                if os.lstat(path).st_uid != uid:
                    os.lchown(path, uid, gid)
            except OSError as e:
                emit({"type": "harness_chown_failed", "path": path, "detail": str(e)})
                return


def choose_workload_user(
    probe_paths: list[str],
    uid: int = _WORKLOAD_UID,
    env: dict[str, str] | None = None,
    stat=os.stat,  # noqa: ANN001
) -> bool:
    """Whether to drop from container root to `warren` (uid 1000) for the workload.

    Drop only when the bind mounts the server wrote are owned by that uid, i.e. under a
    keep-id userns (WARREN_PODMAN_USERNS, the default: the server's host user is uid 1000
    here), or when a rootful docker server's own uid happens to be 1000. Then uid 1000 can
    write the checkout and what it writes is the server user's on the host.

    Stay root when a mount is owned by root (podman `host` userns: the server's host user
    IS container root, and a uid-1000 workload would write as an unprivileged subuid the
    server can't read or delete), by any other uid (rootful docker with a server uid != 1000:
    chowning the checkout would take it away from that user), or when there is no mount
    to go by. WARREN_WORKLOAD_USER=root|warren overrides the probe.
    """
    env = os.environ if env is None else env
    forced = env.get("WARREN_WORKLOAD_USER", "")
    if forced in ("root", "warren"):
        return forced == "warren"
    for path in probe_paths:
        try:
            st = stat(path, follow_symlinks=False)
        except OSError:
            continue
        return st.st_uid == uid
    return False


def _probe_paths() -> list[str]:
    paths = [p for p in os.environ.get("WARREN_WORKTREE_PATHS", "").split(":") if p]
    paths.append(os.environ.get("WARREN_HARNESS_ROOT") or _HARNESS_ROOT)
    return paths


def drop_privileges(uid: int = _WORKLOAD_UID, gid: int = _WORKLOAD_GID, home: str = _WORKLOAD_HOME) -> None:
    """Become `warren` for good: clear supplementary groups, then gid, then uid.

    Order matters (setgroups/setgid need root). Everything started after this, in this
    process and its children, runs as uid 1000.
    """
    os.setgroups([])
    os.setgid(gid)
    os.setuid(uid)
    os.environ["HOME"] = home
    os.environ["USER"] = os.environ["LOGNAME"] = "warren"


def root_phase() -> None:
    """Everything that needs container root, then (usually) the drop to uid 1000.

    - /etc/warren/session.env for `warren shell` sessions that don't carry the container env;
    - /etc/warren/workload, which tells the image's tmux wrapper (and nothing else) that a
      `podman exec` session, which starts as root, must reach the workload's tmux server
      as the workload user;
    - the drop itself. Without it (host userns, other-owner docker mounts, or already
      non-root) the workload keeps running as root, as before.
    """
    if os.geteuid() != 0:
        return
    if os.environ.get("WARREN_SHELL_FIRST") == "1":
        write_session_env()
    if not choose_workload_user(_probe_paths()):
        return
    try:
        with open(_WORKLOAD_MARKER, "w", encoding="utf-8") as f:
            f.write(f"{_WORKLOAD_UID} {_WORKLOAD_GID} {_WORKLOAD_HOME} warren\n")
    except OSError as e:
        emit({"type": "workload_marker_unavailable", "detail": str(e)})
    try:
        drop_privileges()
    except OSError as e:
        fail("privilege_drop_failed", str(e))
    emit({"type": "workload_user", "user": "warren", "uid": _WORKLOAD_UID})


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
    root_phase()
    app_cmd = _preflight()
    start_agent_supervisor()

    # ── D-11: supervise workspace app (PID 1 stays alive) ────────────────────
    # The recorder thread (with its own event loop) keeps running beside it.
    argv = _build_argv(app_cmd)
    try:
        result = subprocess.run(argv)  # noqa: S603
    except (OSError, FileNotFoundError) as e:
        fail("workspace_app_not_found", f"{argv[0]}: {e}")
    else:
        sys.exit(result.returncode or 0)
