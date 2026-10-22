"""
Pure SBPL profile builder for SeatbeltRuntime (RT-03d).

# sandbox-exec / SBPL approach informed by github.com/akitaonrails/ai-jail (GPL-3.0)

No I/O beyond resolving paths. `build_sbpl_profile(spec) -> SbplProfile`
produces a deny-default profile with the allow blocks required for a bash
shell to start on macOS 26+.

Host paths never appear in the profile text: each one is canonicalized with
realpath (AA3: seatbelt matches resolved paths, so `/tmp/x` must be written as
`/private/tmp/x`) and referenced as `(param "P_n")`, passed to sandbox-exec as
`-D P_n=<path>` (AE3).

SBPL is last-match-wins per subject/action pair; deny lines MUST come AFTER
any matching allow. The builder self-guards this invariant via
`_assert_deny_after_allow`.
"""
from __future__ import annotations

import os
import shutil
from dataclasses import dataclass, field
from pathlib import Path

from warren_common.github_tokens import credential_store_deny_paths
from warren_common.harness import grants_for_spec
from warren_common.runtime.base import WorkspaceSpec


def canonical_path(path: str) -> str:
    """realpath, rejecting characters that can't safely reach sandbox-exec."""
    if any(c in path for c in "\n\r\0"):
        raise ValueError("sandbox paths must not contain newlines or NUL")
    return os.path.realpath(os.path.expanduser(path))


@dataclass(frozen=True)
class SbplProfile:
    text: str
    params: dict[str, str] = field(default_factory=dict)


def sandbox_exec_param_args(params: dict[str, str]) -> list[str]:
    """`-D KEY=VALUE` arguments for sandbox-exec."""
    args: list[str] = []
    for key, value in params.items():
        args += ["-D", f"{key}={value}"]
    return args


class _Params:
    """Allocates one `(param ...)` per distinct canonical path."""

    def __init__(self) -> None:
        self.values: dict[str, str] = {}
        self._keys: dict[str, str] = {}

    def __call__(self, path: str) -> str:
        canon = canonical_path(path)
        key = self._keys.get(canon)
        if key is None:
            key = f"P_{len(self._keys)}"
            self._keys[canon] = key
            self.values[key] = canon
        return f'(param "{key}")'


_HEADER = "(version 1)\n(deny default)"

_PROCESS = """; Process operations
(allow process-exec)
(allow process-fork)
(allow process-info* (target same-sandbox))
(allow signal)
(allow sysctl-read)"""

_MACH_IPC = """; IPC and Mach — required for ANY macOS binary to start
(allow mach-lookup)
(allow mach-register)
(allow mach-host*)
(allow ipc-posix-shm-read-data)
(allow ipc-posix-shm-write-data)
(allow ipc-posix-shm-read-metadata)
(allow ipc-posix-shm-write-create)
(allow ipc-posix-sem)"""

_PTY_DEV = """; Pseudo-terminal — required for TTY / claude interactive
(allow pseudo-tty)
(allow file-ioctl)
(allow file-read* file-write* (literal "/dev/ptmx"))
(allow file-read* file-write* (regex #"^/dev/ttys[0-9]+"))

; Standard devices
(allow file-read-data (literal "/dev/null"))
(allow file-write* (literal "/dev/null"))
(allow file-write* (literal "/dev/zero"))
(allow file-write* (literal "/dev/random"))
(allow file-write* (literal "/dev/urandom"))
(allow file-read-data (literal "/dev/tty"))"""

_IOKIT = """; IOKit — power mgmt, hardware queries. Broad (no `iokit-user-client-class`
; filter) -- needed for basic power/battery/display queries many ordinary
; binaries make on start, and narrowing it to specific user-client classes
; risks breaking that without a concrete list of which classes are actually
; needed (S7, 2026-10-17: left as-is, documented as a residual grant rather
; than guessed at -- same reasoning as mach-lookup/mach-register below).
(allow iokit-open)

; distributed-notification-post (S7, 2026-10-17): assessed as NOT part of the
; appleevent-send/lsopen escape class -- it's one-way, no payload/command
; execution, and (unlike Apple Events) has no mechanism to make a listening
; process run arbitrary code. A listener reacting to a known notification
; name is a pre-existing design choice in whatever's listening, not something
; this grant lets a sandboxed process exploit beyond what any ordinary app on
; the system can already do. Left as-is.
(allow distributed-notification-post)

; Browser launch — required for AWS SSO and Claude Code OAuth, e.g. `open <url>`,
; which resolves and launches the default browser via LaunchServices (lsopen)
; alone; verified empirically (sandbox-exec, 2026-10-17) that this launches
; Chrome with no appleevent-send grant. appleevent-send used to be granted
; here too, but it lets a sandboxed process send Apple Events to ANY running
; app, not just a browser -- including Terminal/System Events, which accept
; Apple Events like "do shell script"/"keystroke" and would run them
; unsandboxed (audit finding #50). Removed as unnecessary for this grant's
; stated purpose.
;
; S7 (2026-10-17) follow-up: `lsopen` itself is STILL a confirmed escape --
; verified empirically that `open -a Terminal` under this exact profile
; launches Terminal.app outside the sandbox (same reachable-app-surface
; problem appleevent-send had, via a different API). Attempted narrowing with
; `(allow lsopen (appleevent-destination "..."))` (tried both the target
; app's own bundle id and the operator's actual default browser's bundle id)
; -- both made the LEGITIMATE `open <url>` browser-launch case fail with
; _LSOpenURLsWithCompletionHandler error -54 too, so whatever `lsopen`'s
; filter predicate actually keys on, it is not simply "destination bundle
; id" the way appleevent-send's filter is. Left unrestricted rather than ship
; a guessed filter that silently breaks AWS SSO/Claude OAuth login. This is a
; KNOWN, UNRESOLVED residual escape: a sandboxed process can launch an
; arbitrary app via `open -a <app>`. Narrowing it properly needs either the
; correct SBPL filter predicate for lsopen (undocumented in `man sandbox.sb`
; on this system) or replacing it with a warren-brokered open mechanism
; (sandboxed process requests a URL open over a control channel; warren's own
; unsandboxed CLI performs the actual `open` call).
(allow lsopen)"""

_NETWORK = """; Network — v1.0 full network (D-19)
(allow network-outbound)
(allow network-inbound)
(allow network-bind)
(allow system-socket)"""

# File reads: scoped allow-list (audit finding #2, 2026-10-16). `(allow
# file-read*)` used to be global here — ANY local workspace could read every
# OTHER workspace's state.json (whose env_snapshot holds decrypted secrets),
# ~/.ssh/id_*, ~/.aws/credentials, etc. Deny-by-default, allow-list up from
# there: just the system paths a working shell/app needs, plus (built
# per-workspace in `_file_reads`) this workspace's own root_path, worktrees,
# reference paths, and bind mounts.
#
# CRITICAL for macOS 26 Tahoe: dyld loader requires the literal "/" or every
# dynamically linked binary SIGABRTs before main. Do not remove.
_FILE_READS_BASE = """; File reads: deny-default scoped allow-list (finding #2) — see module docstring
(allow file-read* (literal "/"))
(allow file-read-metadata (literal "/etc"))
(allow file-read-metadata (literal "/var"))
(allow file-read-metadata (literal "/tmp"))
(allow file-read-metadata (literal "/opt"))
(allow file-read-metadata (literal "/private"))
(allow file-read-metadata (literal "/private/tmp"))
(allow file-read-metadata (literal "/private/var"))
(allow file-read-metadata (literal "/Users"))
(allow file-read* (subpath "/usr"))
(allow file-read* (subpath "/bin"))
(allow file-read* (subpath "/sbin"))
(allow file-read* (subpath "/System"))
(allow file-read* (subpath "/Library"))
(allow file-read* (subpath "/private/etc"))
(allow file-read* (subpath "/private/var/db/dyld"))
(allow file-read* (subpath "/opt/homebrew"))

; Xcode CLI tools shim (R2, 2026-10-17): `git`/`sh` resolve the active
; developer dir / shell through these symlinks on every invocation — without
; read access the shim fails before git ever starts.
(allow file-read* (subpath "/private/var/select/developer_dir"))
(allow file-read* (literal "/private/var/select/sh"))"""


def _file_reads(spec: WorkspaceSpec, p: _Params, extra_read_paths: list[str]) -> str:
    """Workspace-specific read scope: root_path, worktrees, reference clones,
    and bind mounts are all readable regardless of their write/readonly mode
    — readonly only ever restricts *write* access (finding #5), never read.
    """
    paths = [spec.root_path]
    paths += [host for host, _container in spec.worktree_paths]
    paths += [host for host, _container in spec.reference_paths]
    paths += [host for host, _container, _mode in spec.bind_mounts]
    paths += extra_read_paths
    return "\n".join(f"(allow file-read* (subpath {p(path)}))" for path in paths)


def _file_writes(spec: WorkspaceSpec, p: _Params, extra_write_paths: list[str]) -> str:
    """Workspace-specific write scope.

    Reference paths get a write grant only when they back a declared,
    non-readonly folder (finding #5). Host config dirs that dispatch adds as
    reference paths for bwrap/nsjail (~/.aws) are never granted
    write through this route. Worktrees are always rw by design (D-14) and
    live under root_path, already covered below.
    """
    lines = [
        "; File writes: workspace + system tmpdirs (readonly refs excluded — finding #5)",
        f"(allow file-write* (subpath {p(spec.root_path)}))",
        '(allow file-write* (subpath "/tmp"))',
        '(allow file-write* (subpath "/private/tmp"))',
        '(allow file-write* (subpath "/private/var/folders"))',
    ]

    writable_mounts = {f.mount for f in spec.folders if not f.readonly}
    for host_path, mount in spec.reference_paths:
        if mount in writable_mounts:
            lines.append(f"(allow file-write* (subpath {p(host_path)}))")

    for host, _container, mode in spec.bind_mounts:
        if mode == "ro":
            continue
        lines.append(f"(allow file-write* (subpath {p(host)}))")

    for extra in extra_write_paths:
        lines.append(f"(allow file-write* (subpath {p(extra)}))")
    return "\n".join(lines)


def _reference_git_denies(spec: WorkspaceSpec, p: _Params) -> str:
    """Write-protect `.git` hooks/config inside every reference clone (R4),
    regardless of the folder's own `readonly` setting: a planted
    `core.fsmonitor` or hook would run on the HOST the next time warren
    fetches that clone outside any workspace.

    AE1: the `.git` entry and the clone root itself are also protected from
    unlink/rename — otherwise `mv .git .git-x`, edit, `mv .git-x .git` sidesteps
    the path-based denies. `commondir` would redirect git to another
    config/hooks dir entirely.
    """
    lines = []
    for host, _container in spec.reference_paths:
        dot_git = os.path.join(host, ".git")
        lines.append(f"(deny file-write* (subpath {p(os.path.join(dot_git, 'hooks'))}))")
        for name in ("config", "commondir"):
            lines.append(f"(deny file-write* (literal {p(os.path.join(dot_git, name))}))")
        lines.append(f"(deny file-write* (literal {p(dot_git)}))")
        lines.append(f"(deny file-write-unlink (literal {p(host)}))")
    if not lines:
        return ""
    return "; Reference clone .git always write-protected (R4, AE1)\n" + "\n".join(lines)


def _readonly_denies(spec: WorkspaceSpec, p: _Params) -> str:
    """Write-deny every readonly folder and `ro` bind mount. Not granting write
    isn't enough: a path under /tmp, /private/tmp or /private/var/folders is
    writable through the system-tmpdir grants above. A path containing the
    workspace root is skipped, since denying it would deny the workspace itself."""
    root = canonical_path(spec.root_path)
    readonly_mounts = {f.mount for f in spec.folders if f.readonly}
    paths = [host for host, mount in spec.reference_paths if mount in readonly_mounts]
    paths += [host for host, _container, mode in spec.bind_mounts if mode == "ro"]
    lines = []
    for path in dict.fromkeys(paths):
        canon = canonical_path(path)
        if root == canon or root.startswith(canon.rstrip("/") + "/"):
            continue
        lines.append(f"(deny file-write* (subpath {p(path)}))")
    if not lines:
        return ""
    return "; Readonly folders and ro mounts, even under system tmpdirs\n" + "\n".join(lines)


def _assert_deny_after_allow(sections: list[str]) -> None:
    """Self-guard: any `(deny ...)` line (other than the header default) must
    come after every `(allow ...)` line. Raises RuntimeError on violation."""
    joined = "\n".join(sections)
    lines = joined.splitlines()
    last_allow = -1
    for i, ln in enumerate(lines):
        s = ln.strip()
        if s.startswith("(allow "):
            last_allow = i
    for i, ln in enumerate(lines):
        s = ln.strip()
        if s.startswith("(deny ") and not s.startswith("(deny default"):
            if i < last_allow:
                raise RuntimeError(
                    "SBPL ordering violation: deny at line "
                    f"{i} precedes allow at line {last_allow} (Pitfall 4)"
                )


# Read AND write for every workspace (finding #5 keeps this pattern honest —
# these are genuinely meant to be read-write, not folder-readonly subject to
# template declarations). Relative to $HOME.
_READ_WRITE_PATHS = (
    # npm / node caches
    ".npm",
    ".node_repl_history",
    # zsh history
    ".zsh_history",
    # general cache dir (W1: .zcompdump and oh-my-zsh's own cache are carved
    # back OUT of this broad grant below — everything else under ~/.cache
    # stays read-write)
    ".cache",
)

# Sourced or executed by the HOST's own unsandboxed shell, so always
# write-denied (relative to $HOME). W1 (2026-10-17): the host's interactive
# zsh sources ~/.zcompdump in `compinit`, and oh-my-zsh reads/execs plugin
# files out of ~/.cache/oh-my-zsh — a sandboxed process writing a malicious
# shell function into either gets it executed the next time the real user
# opens an ordinary terminal. Deny-write wins (last-match) over the broad
# ~/.cache grant; read stays allowed so a pre-existing compdump can be read
# as plain data. AA2: macOS /etc/zshrc_Apple_Terminal sources
# $SHELL_SESSION_FILE from ~/.zsh_sessions when Terminal restores a session.
_ZSH_HOST_SOURCED_CACHES = (".zcompdump", ".cache/oh-my-zsh", ".oh-my-zsh/cache")
_ZSH_HOST_EXEC_DENY_PATHS = (*_ZSH_HOST_SOURCED_CACHES, ".zsh_sessions")

def build_sbpl_profile(spec: WorkspaceSpec) -> SbplProfile:
    """Emit a deny-default SBPL profile for `spec`, plus its path parameters.

    Emission order matters (last-match-wins):
      header -> process -> mach/ipc -> pty/dev -> iokit -> network ->
      file-reads -> file-writes -> denies.

    Harness grants are the union over the template's harnesses (AG6): their
    install-read paths and their own per-workspace config dirs (AG3), with
    `readonly` entries write-denied. Every known harness's HOST config dir is
    write-denied and its credential files read-denied, whatever the template
    runs (AA1).
    """
    home = Path.home()
    p = _Params()
    grants = grants_for_spec(spec, home)

    extra_rw = [str(home / rel) for rel in _READ_WRITE_PATHS]
    extra_read_only: list[str] = list(grants.read)

    # AK3: the host's AWS config/SSO token cache is reachable only in `sso`
    # mode, and then narrowly — the token cache read-write for `aws sso login`,
    # config read-only (a writable ~/.aws/config could plant a
    # credential_process that runs on the HOST — finding #3), no credentials
    # file. `export` mode gets credentials from warren's host-side endpoint.
    aws = spec.aws
    if aws is not None and aws.mode == "sso":
        extra_rw.append(aws.sso_cache or str(home / ".aws" / "sso" / "cache"))
        extra_read_only.append(aws.config_file or str(home / ".aws" / "config"))

    # Z3 (2026-10-17): ssh key files are read-only and the agent socket
    # read-write (a live bidirectional connect), matching bubblewrap.py's
    # --ro-bind / nsjail_config.py's rw=False for the same paths.
    extra_write_only: list[str] = []
    extra_read_only += list(spec.ssh_key_paths)
    if spec.ssh_agent_sock:
        extra_write_only.append(spec.ssh_agent_sock)
        extra_read_only.append(spec.ssh_agent_sock)

    extra_read_only += [str(home / ".local" / "share" / "uv"), str(home / ".cache" / "uv")]
    # W1: .zcompdump / oh-my-zsh cache stay readable as plain data — only
    # WRITE is denied below.
    extra_read_only += [str(home / rel) for rel in _ZSH_HOST_SOURCED_CACHES]
    # Z2 follow-up: resolving a PATH entry under ~/.local/bin (e.g. `uv`)
    # needs read access to the directory entry itself.
    extra_read_only.append(str(home / ".local" / "bin"))
    # git reads its own global config before doing anything else (R2).
    extra_read_only.append(str(home / ".config" / "git"))
    extra_read_only.append(str(home / ".gitconfig"))
    extra_read_only.append(str(home / ".gitignore_global"))
    # git worktrees resolve refs/objects back to the bare `.git-store` they were
    # created from (R2) — read-only; writing here would let a sandboxed process
    # plant hooks/config that run on the HOST (same class as finding #3).
    extra_read_only.extend(spec.git_store_paths)
    # uv's binary dir — read-only, or a workspace could replace binaries that
    # then run on the HOST (finding #3).
    _uv = shutil.which("uv") or ""
    if _uv:
        extra_read_only.append(str(Path(_uv).parent))

    extra_writes = extra_rw + extra_write_only + list(grants.write)
    extra_reads = extra_rw + extra_read_only

    # Metadata-only (not content) on the home dir itself — git/realpath need to
    # stat() every ancestor of a nested path (R2). Content stays scoped to the
    # explicit allow-list (finding #2).
    _home_metadata = (
        f"(allow file-read-metadata (literal {p(str(home))}))\n"
        f"(allow file-read-metadata (subpath {p(str(home / '.warren'))}))"
    )

    deny_sections: list[str] = []
    if grants.readonly:
        deny_sections.append(
            "; Harness config that runs code or grants trust, read-only (AG1 readonly)\n"
            + "\n".join(f"(deny file-write* (subpath {p(path)}))" for path in grants.readonly)
        )
    deny_sections.append(
        "; Host config of every known harness always write-denied (AA1, AG6)\n"
        + "\n".join(f"(deny file-write* (subpath {p(path)}))" for path in grants.deny_write)
    )
    # Z4 follow-up, generalised: host harness credential files, both directions.
    deny_sections.append(
        "; Host harness credential files always read+write-denied (AG1 deny_read)\n"
        + "\n".join(f"(deny file-read* file-write* (literal {p(path)}))" for path in grants.deny_read)
    )
    deny_sections.append(
        "; Host-sourced shell files always write-denied (W1, AA2)\n"
        + "\n".join(
            f"(deny file-write* (subpath {p(str(home / rel))}))" for rel in _ZSH_HOST_EXEC_DENY_PATHS
        )
    )
    # `uv` can run sdist build scripts from ~/.cache/uv and `npx` executes
    # whatever sits under ~/.npm/_npx — both shared with the HOST's own
    # unsandboxed uv/npx (R4).
    deny_sections.append(
        "; HOST-executed cache subpaths always write-denied (R4)\n"
        + "\n".join(
            f"(deny file-write* (subpath {p(path)}))"
            for path in (str(home / ".cache" / "uv"), str(home / ".npm" / "_npx"))
        )
    )
    # AK1: the local GitHub App issuer keeps its private key in the OS
    # credential store. Deny the keychain/keyring files (so `security
    # find-generic-password` can't read the item from inside the sandbox) and
    # the reserved key-file path, both directions.
    deny_sections.append(
        "; GitHub App key: OS credential store + key path always denied (AK1)\n"
        + "\n".join(
            f"(deny file-read* file-write* (subpath {p(path)}))"
            for path in credential_store_deny_paths(home)
        )
    )
    ref_denies = _reference_git_denies(spec, p)
    if ref_denies:
        deny_sections.append(ref_denies)
    readonly_denies = _readonly_denies(spec, p)
    if readonly_denies:
        deny_sections.append(readonly_denies)

    sections = [
        _HEADER,
        _PROCESS,
        _MACH_IPC,
        _PTY_DEV,
        _IOKIT,
        _NETWORK,
        _FILE_READS_BASE,
        _home_metadata,
        _file_reads(spec, p, extra_reads),
        _file_writes(spec, p, extra_writes),
        *deny_sections,
    ]
    _assert_deny_after_allow(sections)
    return SbplProfile(text="\n\n".join(sections) + "\n", params=dict(p.values))
