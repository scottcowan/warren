"""GitManager -- server-side clone/pull for LIFE-03 (D-06, D-07, D-08).

D-06 requires a workspace's git worktree to be materialized by warren-server itself,
on node2, before the workspace is reported `running` -- never by the CLI on the
user's own machine. This module is where that materialization happens.

`_do_provision` (registry.py) is an `async def`, so a naive synchronous clone of a
large repository would stall the entire event loop and freeze every other in-flight
request for the clone's duration (04-RESEARCH.md Pitfall 4). Every GitPython call
here is therefore synchronous by nature but wrapped in `asyncio.to_thread` exactly
once at the method boundary -- the same discipline `runtime/podman.py` already
applies to every podman-py call. D-06's "synchronous, blocking provisioning" is
about workspace lifecycle ORDERING (the clone must complete before the workspace is
marked running), not a license to block the loop while it runs.

D-08: credentials come from a GitHub App installation token (`warren.git.github_app`),
never a stored PAT and never `warren.secrets`'s encrypted-at-rest secret store --
that store was explicitly declined for this purpose. The credential-bearing clone
URL is used only for the duration of a single clone/fetch call: it is never written
to the repo's persisted `.git/config` (the remote is always reset to the plain,
credential-free `repo_url` immediately afterward), and it is never logged. Every
exception message and log argument that might carry the embedded token is routed
through `_sanitize()` first -- this satisfies the "GitManager's deploy-key log
sanitization" convention already forward-referenced in `ssh_keys.py` and
`registry.py::issue_ssh_credential`.

GitPython (not a hand-rolled subprocess wrapper) is used because it was already
approved and pinned for this phase (04-01's package-legitimacy checkpoint,
pyproject.toml) -- it still shells out to the real `git` binary under the hood, it
just saves this module from hand-parsing git's CLI output/exit-code semantics for
auth failure vs. network failure vs. merge conflict (04-RESEARCH.md "Don't
Hand-Roll").
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import re
import shutil
import stat
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING
from urllib.parse import urlsplit, urlunsplit

import structlog
from git import GitCommandError, Repo
from git.exc import InvalidGitRepositoryError, NoSuchPathError

from warren_common.errors import ProvisionError
from warren_common.safe_git import (
    SafeGitError,
    SafeGitTimeout,
    drop_object_cache,
    read_repo_config,
    run_git,
    safe_git_env,
    shadow_git_dir,
)
from warren_common.turn_refs import (
    Snapshot,
    apply_snapshot,
    list_refs,
    resolve_snapshot,
    write_session_file,
)

if TYPE_CHECKING:
    from warren.git.github_app import GitHubAppCredentials

log = structlog.get_logger(__name__)

# A clone with no usable credential (no GitHub App, no per-folder ssh_key —
# e.g. a private HTTPS repo with no PAT support, a known gap) can hang
# indefinitely rather than fail fast: GIT_TERMINAL_PROMPT=0 is only ever set
# inside _askpass_env/_ssh_key_env, never for this bare case, and some
# environments have a credential helper that blocks on a network call of its
# own. Observed directly 2026-10-13: a multi-folder provision stuck for
# minutes on exactly this. A bounded timeout converts that hang into a
# GitError, which registry.py's per-folder loop already catches and skips.
_CLONE_TIMEOUT_S = 30.0
# Same bound per git invocation of a pull (fetch, merge, ...); the git process
# is killed on expiry, surfacing as GitPullError.
_PULL_TIMEOUT_S = _CLONE_TIMEOUT_S

# Matches an embedded installation-token credential in a GitHub App clone URL
# (`https://x-access-token:<token>@host/...`) so it can be stripped before any
# exception message or log argument is ever constructed. Every git failure's
# message may echo the remote URL verbatim (git writes it into its own error
# output), so this is applied unconditionally, not defensively.
_TOKEN_PATTERN = re.compile(r"x-access-token:[^@\s]*@")

# workspace_id must be a single, safe path component -- it is joined directly
# onto worktree_root (T-04-06-PT). Workspace ids are server-generated UUIDs in
# practice, but this validation does not depend on that remaining true.
_SAFE_WORKSPACE_ID = re.compile(r"^[A-Za-z0-9_-]+$")


def _sanitize(text: str) -> str:
    """Strip any `x-access-token:<...>@` credential segment from `text`."""
    return _TOKEN_PATTERN.sub("x-access-token:***@", text)


class GitError(ProvisionError):
    """A clone (or a workspace_id/path validation failure) could not complete."""

    reason = "git_clone_failed"


class GitPullError(ProvisionError):
    """A pull against an existing worktree could not complete."""

    reason = "git_pull_failed"


def _validate_workspace_id(workspace_id: str) -> None:
    if not workspace_id or not _SAFE_WORKSPACE_ID.match(workspace_id):
        raise GitError(f"unsafe workspace_id: {_sanitize(workspace_id)!r}")


# A FolderSpec.name is project-YAML-authored (trusted-ish, but still joined
# directly onto a filesystem path) -- dots are allowed (e.g. "my.music",
# "id.music.infra" are real repo names seen in practice) but a bare "." or
# ".." or anything containing a path separator is not.
_SAFE_FOLDER_NAME = re.compile(r"^[A-Za-z0-9_.-]+$")


def _validate_folder_name(name: str) -> None:
    if not name or name in (".", "..") or not _SAFE_FOLDER_NAME.match(name):
        raise GitError(f"unsafe folder name: {_sanitize(name)!r}")


_ASKPASS_SCRIPT = "#!/bin/sh\nprintf '%s\\n' \"$WARREN_GIT_ASKPASS_TOKEN\"\n"


def _url_with_askpass_username(repo_url: str) -> str:
    """Embed the fixed, non-secret "x-access-token" username in `repo_url`.

    "x-access-token" is GitHub Apps' well-known, public convention for the
    username half of an installation-token credential — it identifies the
    auth SCHEME, not a secret. Embedding only this (never the token itself)
    means git prompts for a password via GIT_ASKPASS but already knows the
    username, so exactly one askpass round-trip happens per operation.
    """
    parsed = urlsplit(repo_url)
    netloc = f"x-access-token@{parsed.netloc}"
    return urlunsplit((parsed.scheme, netloc, parsed.path, parsed.query, parsed.fragment))


@contextlib.contextmanager
def _askpass_env(token: str):
    """Yield a GIT_ASKPASS-based environment dict that supplies `token` to git
    as a password, without the token ever appearing in a URL, a process
    argument list, or any file git itself writes (issue #11).

    Writes a tiny, 0700, owner-only shell script to a private temp file that
    echoes the token from an environment variable it reads at invocation
    time — git executes this script as a subprocess only when it actually
    needs the credential, and the token passes through that subprocess's own
    environment, never through argv or a config file on disk. The script and
    its containing directory are removed unconditionally on exit, success or
    failure.
    """
    tmpdir = tempfile.mkdtemp(prefix="warren-askpass-")
    script_path = Path(tmpdir) / "askpass.sh"
    try:
        script_path.write_text(_ASKPASS_SCRIPT)
        os.chmod(script_path, stat.S_IRWXU)  # 0700 — owner rwx only
        yield {
            "GIT_ASKPASS": str(script_path),
            "GIT_TERMINAL_PROMPT": "0",
            "WARREN_GIT_ASKPASS_TOKEN": token,
        }
    finally:
        script_path.unlink(missing_ok=True)
        try:
            os.rmdir(tmpdir)
        except OSError:
            pass


# Scp-like (`git@host:path`) or explicit `ssh://` remote -- the two forms git
# itself accepts for an SSH transport.
_SSH_URL_RE = re.compile(r"^(?:ssh://|[\w.\-]+@[\w.\-]+:)")


def _is_ssh_url(repo_url: str) -> bool:
    """True for a remote git will clone over SSH rather than HTTPS."""
    return bool(_SSH_URL_RE.match(repo_url))


# Issue #10: a project-YAML-authored `url` is otherwise sent straight to a
# server-side `git clone` with no restriction on scheme or host -- SSRF
# against internal hosts, `file://`/bare-path clones of other repos on the
# server (git allows `protocol.file.allow=user` by default), and, once a
# GitHub App installation is wired in, that server-owned token being handed
# to an arbitrary attacker-chosen host. https/ssh are the only transports a
# legitimate folder spec ever needs.
_ALLOWED_CLONE_SCHEMES = frozenset({"https"})


def _validate_clone_url(repo_url: str) -> None:
    """Reject anything but an `https://` or SSH (`ssh://`/`git@host:path`) remote."""
    if _is_ssh_url(repo_url):
        return
    if urlsplit(repo_url).scheme not in _ALLOWED_CLONE_SCHEMES:
        raise GitError(f"unsupported clone url scheme: {_sanitize(repo_url)!r}")


# Defense in depth alongside `_validate_clone_url`: even if a URL smuggled a
# disallowed transport past that check (e.g. via a redirect git follows
# mid-clone, or a submodule URL this module never inspects), git itself
# refuses anything outside this list. `protocol.file.allow` defaults to
# "user", which is exactly the exposure issue #10 flags for `file://` clones.
_GIT_ALLOW_PROTOCOL_ENV = {"GIT_ALLOW_PROTOCOL": "https:ssh"}


@contextlib.contextmanager
def _ssh_key_env(key_value: str, known_hosts_path: Path):
    """Yield a GIT_SSH_COMMAND-based environment dict that supplies an SSH
    private key to git for one clone, without the key ever touching anywhere
    but a private 0600 temp file removed unconditionally on exit -- the SSH
    analog of `_askpass_env` above, for a `git@host:...`/`ssh://` remote
    instead of an HTTPS one (those two transports are mutually exclusive per
    URL, so callers pick exactly one of this or `_askpass_env`, never both).

    `IdentitiesOnly=yes` stops ssh from trying any other identity already
    loaded in an agent or `~/.ssh/config` first -- the wrong key silently
    succeeding against a different repo the operator also happens to have
    access to would be a confusing, silent misconfiguration.

    `known_hosts_path` is `GitManager.known_hosts_path`, a file under the same
    persistent `settings.data_dir` as `worktree_root` -- NOT ssh's default
    `~/$HOME/.ssh/known_hosts`, which lives on a container's ephemeral
    filesystem and resets on every restart. `StrictHostKeyChecking=accept-new`
    trusts a host's key on first contact but, unlike `=no`, still rejects a
    later host-key CHANGE -- pointing it at a persistent file is what makes
    that TOFU trust actually accumulate across restarts instead of every
    clone re-trusting on first contact again.
    """
    tmpdir = tempfile.mkdtemp(prefix="warren-sshkey-")
    key_path = Path(tmpdir) / "id_git"
    try:
        text = key_value if key_value.endswith("\n") else key_value + "\n"
        key_path.write_text(text)
        os.chmod(key_path, stat.S_IRUSR | stat.S_IWUSR)  # 0600 -- ssh refuses group/other-readable keys
        yield {
            "GIT_SSH_COMMAND": (
                f"ssh -i {key_path} -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new "
                f"-o UserKnownHostsFile={known_hosts_path}"
            ),
        }
    finally:
        key_path.unlink(missing_ok=True)
        try:
            os.rmdir(tmpdir)
        except OSError:
            pass


def _normalize_repo_url(url: str) -> str:
    """Normalize `url` for an origin-URL equality check (finding #25) --
    case-folded, with a trailing `.git` and trailing slash stripped, and any
    embedded userinfo (e.g. the non-secret `x-access-token@` username this
    module embeds for a credentialed HTTPS clone, see
    `_url_with_askpass_username`) dropped so a credentialed clone's stored
    origin still compares equal to the plain `repo_url` it was cloned from.
    """
    url = url.strip()
    if url.endswith(".git"):
        url = url[: -len(".git")]
    if _is_ssh_url(url):
        # scp-like/ssh remotes carry no embeddable credential in the URL
        # itself -- compared as-is (case-folded).
        return url.lower()
    parsed = urlsplit(url)
    netloc = parsed.netloc.rsplit("@", 1)[-1]
    path = parsed.path.rstrip("/")
    return f"{parsed.scheme}://{netloc}{path}".lower()


def _origin_url(path: Path) -> str | None:
    """`remote.origin.url` read as data -- the workspace can write this repo."""
    return read_repo_config(path / ".git", "remote.origin.url")


def _shadow_config(origin_url: str) -> list[tuple[str, str]]:
    return [
        ("remote.origin.url", origin_url),
        ("remote.origin.fetch", "+refs/heads/*:refs/remotes/origin/*"),
    ]


def _verify_existing_clone(path: Path, repo_url: str, shadow_root: Path) -> str | None:
    """Return `None` if `path` holds a complete clone whose origin matches
    `repo_url`; otherwise a short reason string (`"incomplete_clone"` or
    `"origin_mismatch"`) for the caller to act on. Synchronous -- callers run
    this via `asyncio.to_thread`, same discipline as every other git call in
    this module. The clone is workspace-writable, so HEAD is resolved through
    a shadow git dir (BB12), never the clone's own config.
    """
    try:
        origin_url = _origin_url(path)
        if origin_url is None:
            return "incomplete_clone"
        with shadow_git_dir(path / ".git", shadow_root, []) as shadow:
            # equivalent of `git rev-parse HEAD` -- raises on a
            # partial/corrupted clone with no resolvable HEAD.
            run_git("rev-parse", "--verify", "HEAD^{commit}", extra_env=shadow.env(), isolated=True)
    except Exception:
        return "incomplete_clone"
    if _normalize_repo_url(origin_url) != _normalize_repo_url(repo_url):
        return "origin_mismatch"
    return None


def _child_dirs(path: Path) -> list[Path]:
    try:
        with os.scandir(path) as entries:
            return [path / e.name for e in entries if e.is_dir(follow_symlinks=False)]
    except OSError:
        return []


class GitManager:
    """Clones and pulls per-workspace git worktrees under `worktree_root`."""

    def __init__(
        self,
        worktree_root: Path,
        credentials: "GitHubAppCredentials | None" = None,
    ) -> None:
        self.worktree_root = Path(worktree_root)
        self.credentials = credentials
        # Persisted alongside worktree_root (both live under settings.data_dir --
        # see app.py's `GitManager(worktree_root=settings.data_dir / "worktrees")`)
        # so TOFU host-key trust accumulates across restarts instead of resetting
        # every time a fresh ephemeral known_hosts file would (finding #49).
        self.known_hosts_path = self.worktree_root.parent / "ssh_known_hosts"
        self.known_hosts_path.parent.mkdir(parents=True, exist_ok=True)
        self.known_hosts_path.touch(exist_ok=True)
        os.chmod(self.known_hosts_path, stat.S_IRUSR | stat.S_IWUSR)
        # Warren-owned GIT_DIRs for host git against workspace-writable clones
        # (BB12); never mounted into a workspace.
        self.shadow_root = self.worktree_root.parent / "git-shadow"

    def worktree_path(self, workspace_id: str) -> Path:
        """Return `worktree_root / workspace_id`, after validating the id is safe."""
        _validate_workspace_id(workspace_id)
        return self.worktree_root / workspace_id

    async def remove_worktree(self, workspace_id: str) -> None:
        """Remove `workspace_id`'s entire worktree root from disk (finding #25),
        called from `registry.py`'s `destroy()` so a destroyed workspace's
        cloned repos -- PRIVATE repo clones included -- don't accumulate on
        disk forever: the single-repo clone and every multi-folder clone
        (`folders_root`, plus any legacy one nested in the root clone). A
        missing directory (never cloned, or already removed) is a silent
        no-op -- `destroy()` is idempotent and must stay that way.
        """
        roots = (self.worktree_path(workspace_id), self.folders_root(workspace_id))
        await asyncio.to_thread(self._drop_object_caches, roots)
        for path in roots:
            await asyncio.to_thread(shutil.rmtree, path, ignore_errors=True)

    def _drop_object_caches(self, roots: tuple[Path, Path]) -> None:
        root, folders = roots
        repos = [root, *_child_dirs(root), *_child_dirs(folders)]
        for repo in repos:
            drop_object_cache(repo / ".git", self.shadow_root)

    async def clone(
        self,
        workspace_id: str,
        repo_url: str,
        *,
        ref: str | None = None,
        ssh_key: str | None = None,
        pat: str | None = None,
    ) -> Path:
        """Clone `repo_url` into `worktree_path(workspace_id)`, returning that path.

        Idempotent: if the worktree already exists (has a `.git` directory), this
        is a no-op that returns the existing path without re-cloning or raising --
        a re-provision (`ensure_running`) must never destroy a user's working tree.

        `ssh_key` (a decrypted warren.secrets value, e.g. `WARREN_GIT_SSH_KEY` --
        resolved at provision time in registry.py, never persisted here) is only
        ever used when `repo_url` is itself an SSH remote (`_is_ssh_url`); it is
        silently ignored for an HTTPS remote.

        `pat` (a decrypted warren.secrets value, e.g. `GITHUB_PAT`) is a plain
        personal access token for an HTTPS remote -- the simpler, caller-supplied
        alternative to `self.credentials` (a GitHub App installation, which mints
        its own short-lived token instead of storing a long-lived one). When both
        `self.credentials` and `pat` could apply to the same HTTPS clone, `pat`
        wins -- it's the caller's own explicit secret, not warren-server's own
        app-wide fallback. The three credential mechanisms (ssh_key, pat,
        self.credentials) are mutually exclusive per clone: `ssh_key` only for an
        SSH remote, `pat`/`self.credentials` only for HTTPS, so a template
        declaring more than one ends up using whichever one `repo_url` actually
        needs.
        """
        path = self.worktree_path(workspace_id)
        return await self._clone_to_path(
            path, repo_url, ref=ref, ssh_key=ssh_key, pat=pat, log_id=workspace_id
        )

    def folders_root(self, workspace_id: str) -> Path:
        """`worktree_root / "<workspace_id>.folders"`: never mounted into a
        workspace, so no folder clone's directory is renamable from inside one
        (each is only ever a bind-mount root). A `.` can't occur in a valid
        workspace_id, so this never collides with another workspace's root."""
        _validate_workspace_id(workspace_id)
        return self.worktree_root / f"{workspace_id}.folders"

    def folder_worktree_path(self, workspace_id: str, folder_name: str) -> Path:
        """Where one repo of a multi-folder template is cloned (registry.py's
        per-folder loop): `folders_root(workspace_id) / folder_name`, or, for a
        workspace provisioned before that layout and not yet migrated, the
        legacy `worktree_path(workspace_id) / folder_name` (which `pull_at`
        refuses while it's nested in the root clone). Both components are
        validated as safe path segments.
        """
        _validate_folder_name(folder_name)
        path = self.folders_root(workspace_id) / folder_name
        legacy = self.worktree_path(workspace_id) / folder_name
        if not os.path.lexists(path) and os.path.lexists(legacy / ".git"):
            return legacy
        return path

    def _nested_in_root_clone(self, path: Path) -> bool:
        return path.parent.parent == self.worktree_root and os.path.lexists(path.parent / ".git")

    def _adopt_legacy_folder(self, legacy: Path) -> Path:
        """Move a legacy folder clone (nested in the root clone, so renamable
        from inside the workspace) under `folders_root`, returning its new
        path. Runs at provision time, before the workspace's container exists;
        the moved entry must be the same plain directory that was checked."""
        dest = self.worktree_root / f"{legacy.parent.name}.folders" / legacy.name
        if os.path.lexists(dest):
            return dest
        try:
            before = os.lstat(legacy)
        except FileNotFoundError:
            return dest
        if not stat.S_ISDIR(before.st_mode) or not os.path.lexists(legacy / ".git"):
            return dest
        dest.parent.mkdir(parents=True, exist_ok=True)
        os.rename(legacy, dest)
        after = os.lstat(dest)
        if not stat.S_ISDIR(after.st_mode) or (after.st_dev, after.st_ino) != (
            before.st_dev, before.st_ino
        ):
            if stat.S_ISDIR(after.st_mode):
                os.rename(dest, legacy)
            else:
                os.unlink(dest)
            raise GitError(f"legacy folder clone {legacy.name!r} was replaced during migration")
        log.info("git_folder_clone_migrated", dest=str(dest))
        return dest

    async def clone_into(
        self,
        dest: Path,
        repo_url: str,
        *,
        ref: str | None = None,
        ssh_key: str | None = None,
        pat: str | None = None,
    ) -> Path:
        """Clone `repo_url` directly into `dest`, for a caller (registry.py's
        multi-folder loop, via `folder_worktree_path`) managing its own
        per-repo directory layout rather than the single-repo-per-workspace
        convention `clone()`/`worktree_path()` assume. Same idempotent/
        credential/error-handling behavior as `clone()` -- this *is* `clone()`
        with the destination path decoupled from `workspace_id`. A legacy
        `dest` nested in the root clone is migrated under `folders_root` first;
        the returned path is the one to mount.
        """
        if self._nested_in_root_clone(dest):
            dest = await asyncio.to_thread(self._adopt_legacy_folder, dest)
        return await self._clone_to_path(
            dest, repo_url, ref=ref, ssh_key=ssh_key, pat=pat, log_id=str(dest)
        )

    async def _clone_to_path(
        self,
        path: Path,
        repo_url: str,
        *,
        ref: str | None,
        ssh_key: str | None,
        pat: str | None = None,
        log_id: str,
    ) -> Path:
        _validate_clone_url(repo_url)

        if (path / ".git").exists():
            # Finding #25: the old check stopped at "`.git` exists" -- a clone
            # that timed out (`_CLONE_TIMEOUT_S` above) leaves a partial
            # `.git` directory that this would have silently treated as a
            # complete, reusable clone forever, and never re-checked whether
            # the folder spec's `url` still matches what's actually on disk
            # (e.g. after a project's repo URL changes). Both are verified
            # before trusting the existing directory.
            problem = await asyncio.to_thread(
                _verify_existing_clone, path, repo_url, self.shadow_root
            )
            if problem is None:
                log.info("git_clone_skipped_existing", id=log_id)
                return path
            if problem == "origin_mismatch":
                # Never silently re-clone over a directory that might hold
                # legitimate local work just because its origin no longer
                # matches the current spec -- that's a real inconsistency
                # the caller must resolve, not something to paper over.
                raise GitError(
                    f"existing clone at {_sanitize(str(path))!r} has a "
                    f"different origin than the current url "
                    f"{_sanitize(repo_url)!r}"
                )
            # problem == "incomplete_clone": a never-completed clone can't
            # hold any real work worth preserving -- remove it and fall
            # through to clone fresh below.
            log.warning("git_clone_existing_incomplete_recloning", id=log_id)
            await asyncio.to_thread(shutil.rmtree, path, ignore_errors=True)

        # Issue #11: neither a GitHub App installation token nor a caller-
        # supplied PAT ever enters the clone URL or any argv/config git
        # touches. Only the fixed, non-secret "x-access-token" USERNAME is
        # embedded (so the origin URL git stores in .git/config permanently
        # is harmless even at rest); the actual token is supplied
        # per-invocation via GIT_ASKPASS, in that subprocess's own
        # environment only.
        clone_url = repo_url
        token: str | None = None
        use_ssh_key = ssh_key is not None and _is_ssh_url(repo_url)
        if not use_ssh_key and not _is_ssh_url(repo_url):
            if pat is not None:
                # Caller's own explicit secret (e.g. GITHUB_PAT) wins over
                # self.credentials -- a plain PAT needs no GitHub App
                # installation at all, and is the simpler, more common path.
                token = pat
                clone_url = _url_with_askpass_username(repo_url)
            elif self.credentials is not None and (
                urlsplit(repo_url).hostname == self.credentials.credential_host
            ):
                # Issue #10: the GitHub App installation token is warren-server's
                # own server-wide credential, not the caller's -- it must never
                # be handed to a host other than the one it was minted for, no
                # matter what host a project-YAML-authored `url` names.
                try:
                    token = await self.credentials.token()
                except Exception as e:  # GitHubAuthError and any credential failure
                    raise GitError(_sanitize(str(e))) from e
                clone_url = _url_with_askpass_username(repo_url)

        try:
            await asyncio.wait_for(
                asyncio.to_thread(
                    self._clone_sync, clone_url, path, ref, token, ssh_key if use_ssh_key else None
                ),
                timeout=_CLONE_TIMEOUT_S,
            )
        except asyncio.TimeoutError as e:
            # asyncio.TimeoutError IS builtin TimeoutError, which is itself an
            # OSError subclass in modern Python -- this branch MUST come
            # before `except OSError` below, or that catches it first with an
            # empty str(e) (TimeoutError() takes no message). The underlying
            # thread (and its git subprocess) keeps running in the executor
            # after this -- asyncio.wait_for cannot kill it, only stop
            # waiting. Acceptable: a bounded leak on an already-broken clone
            # beats blocking this provision (and every folder behind it)
            # forever.
            raise GitError(
                f"clone timed out after {_CLONE_TIMEOUT_S}s: {_sanitize(repo_url)}"
            ) from e
        except (GitCommandError, InvalidGitRepositoryError, NoSuchPathError, SafeGitError) as e:
            raise GitError(_sanitize(str(e))) from e
        except OSError as e:
            raise GitError(_sanitize(str(e))) from e

        log.info("git_clone_completed", id=log_id, ref=ref)
        return path

    def _clone_sync(
        self,
        clone_url: str,
        path: Path,
        ref: str | None,
        token: str | None,
        ssh_key: str | None = None,
    ) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        if ssh_key is not None:
            with _ssh_key_env(ssh_key, self.known_hosts_path) as env:
                Repo.clone_from(clone_url, str(path), env={**env, **_GIT_ALLOW_PROTOCOL_ENV, **safe_git_env(isolated=True)})
        elif token is not None:
            with _askpass_env(token) as env:
                Repo.clone_from(clone_url, str(path), env={**env, **_GIT_ALLOW_PROTOCOL_ENV, **safe_git_env(isolated=True)})
        else:
            # No credential at all (e.g. a private HTTPS repo with no PAT
            # support yet) -- still disable terminal prompts explicitly,
            # same as the askpass/ssh-key branches, so a missing credential
            # helper fails fast instead of blocking on a prompt that can
            # never be answered (this process has no attached terminal).
            Repo.clone_from(
                clone_url,
                str(path),
                env={"GIT_TERMINAL_PROMPT": "0", **_GIT_ALLOW_PROTOCOL_ENV, **safe_git_env(isolated=True)},
            )
        if ref:
            self._checkout_ref(path, clone_url, ref)

    def _checkout_ref(self, path: Path, clone_url: str, ref: str) -> None:
        with shadow_git_dir(
            path / ".git", self.shadow_root, _shadow_config(clone_url), work_tree=path
        ) as shadow:
            run_git("checkout", "-q", ref, extra_env=shadow.env(), isolated=True)

    async def pull(self, workspace_id: str) -> str:
        """Fetch and fast-forward the existing worktree, returning the new HEAD sha.

        Raises `GitPullError` if no worktree exists for `workspace_id` yet -- a pull
        never implicitly clones.
        """
        path = self.worktree_path(workspace_id)
        return await self.pull_at(path, log_id=workspace_id)

    async def pull_at(self, path: Path, *, log_id: str | None = None) -> str:
        """Fetch and fast-forward the worktree at an arbitrary `path`, for a
        caller (registry.py's multi-folder pull loop, via
        `folder_worktree_path`) managing its own per-repo directory layout
        rather than the single-repo-per-workspace convention `pull()`/
        `worktree_path()` assume. Same idempotent/credential/error-handling
        behavior as `pull()` -- this *is* `pull()` with the path decoupled
        from `workspace_id` (finding #26: a multi-folder workspace's folder
        clones live at `worktree_path(workspace_id)/folder_name`, not at
        `worktree_path(workspace_id)` itself, so pulling them needs this).
        """
        log_id = log_id if log_id is not None else str(path)
        if self._nested_in_root_clone(path):
            # The workspace can rename this directory (it's inside the root
            # clone's mount) while git checks out into it.
            raise GitPullError(
                f"folder clone {log_id} predates the isolated folder layout; "
                "re-provision the workspace to migrate it"
            )
        if not (path / ".git").exists():
            raise GitPullError(f"no worktree at {log_id}")

        token: str | None = None
        if self.credentials is not None:
            # Issue #10: same host pin as `_clone_to_path` -- the worktree's
            # origin was set at clone time from a project-YAML-authored `url`,
            # so it must be re-checked here too, not just assumed safe because
            # a worktree already exists for it.
            origin_url = await asyncio.to_thread(_origin_url, path) or ""
            if urlsplit(origin_url).hostname == self.credentials.credential_host:
                try:
                    token = await self.credentials.token()
                except Exception as e:
                    raise GitPullError(_sanitize(str(e))) from e

        try:
            sha = await asyncio.to_thread(self._pull_sync, path, token)
        except SafeGitTimeout as e:
            raise GitPullError(
                f"pull of {_sanitize(log_id)!r} timed out after {_PULL_TIMEOUT_S}s"
            ) from e
        except (GitCommandError, InvalidGitRepositoryError, NoSuchPathError, SafeGitError) as e:
            raise GitPullError(_sanitize(str(e))) from e
        except OSError as e:
            raise GitPullError(_sanitize(str(e))) from e

        log.info("git_pull_completed", id=log_id, commit=sha)
        return sha

    def _pull_sync(self, path: Path, token: str | None) -> str:
        """Fetch, then fast-forward-only merge — never `reset --hard` (issue #11).

        `reset --hard` discards any local commits or uncommitted changes in
        the worktree unconditionally, which contradicts this method's own
        "fast-forward" framing and silently destroys an agent's in-progress
        work the moment anything pulls. `merge --ff-only` does what the
        docstring above actually promises: it advances cleanly when possible
        and raises (surfacing as GitPullError) when it can't, rather than
        picking a side and deleting the other.

        No URL swapping here at all, unlike the old implementation — issue
        #11's "concurrent pulls" race came from two calls toggling the same
        shared `.git/config` origin URL back and forth. The origin URL for a
        credentialed repo already carries its permanent, non-secret
        "x-access-token" username from clone time (see `_url_with_askpass_username`)
        and is never rewritten again; only the actual token, supplied fresh
        per call via GIT_ASKPASS, ever needs to vary between calls.
        """
        origin_url = _origin_url(path)
        if not origin_url:
            raise GitPullError("worktree has no origin remote")
        try:
            _validate_clone_url(origin_url)
        except GitError as e:
            raise GitPullError(str(e)) from e
        with contextlib.ExitStack() as stack:
            shadow = stack.enter_context(shadow_git_dir(
                path / ".git", self.shadow_root, _shadow_config(origin_url), work_tree=path
            ))
            fetch_env = {**_GIT_ALLOW_PROTOCOL_ENV, **shadow.env()}
            if token is not None:
                fetch_env.update(stack.enter_context(_askpass_env(token)))

            def git(*args: str, env: dict[str, str] | None = None) -> str:
                return run_git(
                    *args, extra_env=env or shadow.env(), isolated=True, timeout=_PULL_TIMEOUT_S
                )

            git("fetch", "origin", env=fetch_env)
            target_branch = git("symbolic-ref", "--short", "HEAD").strip()
            git("merge", "--ff-only", f"origin/{target_branch}")
            return git("rev-parse", "HEAD").strip()

    async def list_turn_refs(self, path: Path, prefix: str) -> list[dict]:
        """HIST-09: refs under `prefix` in the clone at `path`."""
        try:
            return await asyncio.to_thread(list_refs, path / ".git", self.shadow_root, prefix)
        except SafeGitError as e:
            raise GitError(_sanitize(str(e))) from e

    async def resolve_turn_snapshot(self, path: Path, ref: str) -> Snapshot:
        """HIST-05/11: what a branch from `ref` in the clone at `path` starts from."""
        try:
            return await asyncio.to_thread(resolve_snapshot, path / ".git", self.shadow_root, ref)
        except SafeGitError as e:
            raise GitError(_sanitize(str(e))) from e

    async def apply_turn_snapshot(self, path: Path, snapshot: Snapshot, branch: str) -> str:
        """HIST-05: check `snapshot` out on `branch` in the fresh clone at `path`."""
        try:
            return await asyncio.to_thread(
                apply_snapshot, path / ".git", path, snapshot, branch, self.shadow_root
            )
        except (SafeGitError, OSError) as e:
            raise GitError(_sanitize(str(e))) from e

    async def write_turn_session(self, path: Path, workspace_id: str, session_id: str) -> None:
        """HIST-10: `.git/git-turn/session.json` in the clone at `path`."""
        await asyncio.to_thread(write_session_file, path / ".git", workspace_id, session_id=session_id)
