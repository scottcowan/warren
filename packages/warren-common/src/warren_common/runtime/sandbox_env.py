"""Shared host-environment allow-list for local sandboxed workspaces (audit
finding #4, 2026-10-16).

Before this existed, `warren connect`/`warren exec` (dispatch.py) and
SeatbeltRuntime.exec both merged the *entire* operator `os.environ` into the
sandboxed process — on top of (not instead of) the template's declared
secrets (`spec.env`/`env_snapshot`). Any AWS key, API token, or
`SSH_AUTH_SOCK` sitting in the operator's own shell reached every local
workspace, bypassing the template's secret allow-list and the AWS/SSH
opt-in model entirely.

`base_host_env()` is the only host state a local sandboxed process should
ever inherit unconditionally — just enough for a shell/app to start. Every
other variable the workspace needs (secrets, AWS profile, SSH_AUTH_SOCK,
terminal identity) is already captured explicitly into `spec.env` at
provision time (see `warren_cli.dispatch.provision_local`) and flows in via
`env_snapshot`, not via this allow-list.
"""
from __future__ import annotations

import os
import shlex
import tempfile
from pathlib import Path

#: Minimal host env a shell/app needs to start. Deliberately short — anything
#: a workspace legitimately needs beyond this (AWS_PROFILE, GITHUB_PAT,
#: TERM_PROGRAM, ...) is captured explicitly into spec.env at provision time
#: and arrives via env_snapshot, not through this allow-list.
BASE_ENV_ALLOWLIST: tuple[str, ...] = ("PATH", "HOME", "TERM", "LANG", "LC_ALL")

# Audit 2026-10-16 P2 #51 (bubblewrap) / S6 follow-up (nsjail): where the
# secret-bearing env file gets bind-mounted inside the sandbox, read back by
# the shell wrapper below before the real command ever runs. Shared by both
# local Linux runtimes (bubblewrap.py, nsjail.py) so the sourcing convention
# — and its shell-quoting — only has to be gotten right once.
ENV_MOUNT_DEST = "/run/warren-env"

# Sources the secret env file bind-mounted at ENV_MOUNT_DEST, then execs the
# real command -- $1 is the mount path, the rest ($@ after shift) is the real
# argv. Keeps actual secret VALUES out of this process's own argv (ps-visible
# to every user on the host via /proc/<pid>/cmdline) and, for nsjail, out of
# the long-lived nsjail.cfg file (replaced by a short-lived 0600 file that
# exists only for the duration of one exec() call).
ENV_SOURCE_SCRIPT = 'f="$1"; shift; set -a; . "$f"; set +a; exec "$@"'


def secret_service_paths() -> list[str]:
    """Host paths that reach the OS credential store holding the GitHub App key
    (AK1): the user runtime dir (session D-Bus socket, gnome-keyring control
    socket), libsecret's keyring files and the reserved key dir."""
    runtime_dir = os.environ.get("XDG_RUNTIME_DIR") or f"/run/user/{os.getuid()}"
    home = Path.home()
    return [
        runtime_dir,
        str(home / ".local" / "share" / "keyrings"),
        str(home / ".warren" / "github-app"),
    ]


def check_no_secret_service_mounts(host_paths: list[str]) -> None:
    """Refuse any mount that is, contains, or sits inside a secret-service path."""
    from warren_common.errors import TemplateDenied  # noqa: PLC0415

    denied = [os.path.abspath(p) for p in secret_service_paths()]
    for raw in host_paths:
        host = os.path.abspath(os.path.expanduser(raw))
        for d in denied:
            if host == d or host.startswith(d + os.sep) or d.startswith(host.rstrip(os.sep) + os.sep):
                raise TemplateDenied(
                    f"mount {raw!r} would expose {d} (OS credential store / session bus) to the sandbox"
                )


def host_mount_sources(spec) -> list[str]:
    """Every host path a local Linux sandbox binds from `spec`, for
    check_no_secret_service_mounts. The ssh agent socket is an exact-file bind
    and is exempt."""
    return [
        p
        for p in (
            spec.root_path,
            *(h for h, _ in spec.worktree_paths),
            *(h for h, _ in spec.reference_paths),
            *spec.ssh_key_paths,
            *(h for h, _, _ in spec.bind_mounts),
        )
        if p
    ]


def base_host_env() -> dict[str, str]:
    """Return the allow-listed subset of the *current* process's environment.

    Never returns the full `os.environ` — only `BASE_ENV_ALLOWLIST` keys that
    are actually set. Callers layer `env_snapshot`/`spec.env` on top of this.
    """
    return {k: v for k, v in ((k, os.environ.get(k)) for k in BASE_ENV_ALLOWLIST) if v}


def state_root() -> Path:
    """Base directory for out-of-tree sandbox state (audit finding #1):
    ``<state_root>/<workspace_id>/`` holds seatbelt's sandbox.sb/state.json
    and bwrap's state.json — deliberately never under a workspace's own
    root_path, which the sandboxed process itself can write to.

    ``WARREN_STATE_DIR`` overrides the default (``~/.warren/state``) — tests
    use this to avoid writing into the real operator home directory.
    """
    override = os.environ.get("WARREN_STATE_DIR")
    return Path(override) if override else Path.home() / ".warren" / "state"


def nsjail_secret_env_path(workspace_id: str) -> Path:
    """Deterministic host path for a workspace's ephemeral secrets env file.

    S6 follow-up (2026-10-17): nsjail's cfg is written once at provision time
    and reused by every later `exec()`, so the mount entry pointing at this
    path has to be fixed up front -- but the FILE itself is written fresh
    (and deleted) by each `exec()` call, same lifetime as bubblewrap's
    `env_file`. Lives under `state_root()`, never under a workspace's own
    `root_path` (which nsjail already bind-mounts rw into the jail), so the
    secrets file is never itself visible from inside the sandbox via any
    mount other than the single explicit `ENV_MOUNT_DEST` one.
    """
    return state_root() / workspace_id / "warren-env.sh"


def write_secret_env_file(env: dict[str, str], directory: Path) -> Path:
    """Write `env` to a 0600 temp file for sourcing at `ENV_MOUNT_DEST`.

    Audit 2026-10-16 P2 #51 (bubblewrap) / S6 follow-up (nsjail): keeps secret
    values off the sandboxing process's own argv/cfg file (see
    `ENV_SOURCE_SCRIPT`). `directory` should be a 0700 dir the sandboxed
    process cannot itself write to (e.g. the workspace's state_dir).
    """
    directory.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix="warren-env-", suffix=".sh", dir=str(directory))
    try:
        with os.fdopen(fd, "w") as f:
            for key, value in env.items():
                f.write(f"export {key}={shlex.quote(value)}\n")
        os.chmod(tmp_name, 0o600)
    except BaseException:
        os.unlink(tmp_name)
        raise
    return Path(tmp_name)
