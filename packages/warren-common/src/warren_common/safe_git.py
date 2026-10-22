"""Hardened host-side git invocation.

Boundary (BB7/BB12): host git never reads a git config file a workspace can
write. Repo config can name arbitrary programs (`filter.<driver>.*` keyed by
names from .gitattributes, `diff.<driver>.textconv`, ...), so no list of `-c`
overrides can neutralise it; instead every call site does one of:

- runs against a git dir the workspace can't write (the bare `.git-store`s
  are never mounted writable), or
- runs through `shadow_git_dir`, which gives git a warren-owned GIT_DIR whose
  config warren writes from scratch; the workspace repo supplies only data
  (objects, refs, index, working tree), or
- doesn't run git at all.

On top of that, `safe_git_argv`/`safe_git_env` pin every fixed-name config
key that names a program (defence in depth). Locally the operator's own
system/global values for those keys are kept (they're outside every sandbox),
so e.g. the operator's credential helper still works; repo-scope values never
win. `isolated=True` (warren-server) ignores system/global config entirely;
its credentials come only from the GIT_ASKPASS/GIT_SSH_COMMAND env it sets.
"""

from __future__ import annotations

import contextlib
import functools
import os
import shutil
import stat
import subprocess
import tempfile
from collections.abc import Iterator, Mapping
from pathlib import Path

SAFE_GIT_CONFIG: tuple[tuple[str, str], ...] = (
    ("core.hooksPath", "/dev/null"),
    ("core.fsmonitor", "false"),
    ("protocol.ext.allow", "never"),
    ("core.sshCommand", "ssh"),
    ("core.askPass", ""),
    ("core.pager", "cat"),
    ("core.editor", ":"),
    ("sequence.editor", ":"),
    ("core.alternateRefsCommand", ""),
    ("diff.external", ""),
    ("gpg.program", "false"),
    ("gpg.ssh.program", "false"),
    ("gpg.x509.program", "false"),
    ("log.showSignature", "false"),
    ("merge.verifySignatures", "false"),
    ("submodule.recurse", "false"),
    ("fetch.recurseSubmodules", "false"),
    ("credential.helper", ""),  # resets the helper list; trusted ones re-added after
)

# Location env vars that would point git somewhere other than what the caller asked for.
_SCRUB_ENV = (
    "GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_OBJECT_DIRECTORY",
    "GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_COMMON_DIR", "GIT_NAMESPACE",
    "GIT_EXTERNAL_DIFF", "GIT_PAGER", "GIT_EDITOR", "GIT_SEQUENCE_EDITOR",
)

_OBJECT_ENV = ("GIT_OBJECT_DIRECTORY", "GIT_ALTERNATE_OBJECT_DIRECTORIES")


def object_scrubbed_environ() -> dict[str, str]:
    """os.environ without the object-location vars, for safe_git_argv callers
    that otherwise inherit the environment: object lookup stays the repo's own."""
    return {k: v for k, v in os.environ.items() if k not in _OBJECT_ENV}


_ISOLATED_ENV = {"GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull}


class SafeGitError(RuntimeError):
    """A hardened git run failed, or a repo isn't safe to operate on."""


def _trusted_cache_key() -> tuple[str | None, ...]:
    return tuple(os.environ.get(k) for k in (
        "HOME", "XDG_CONFIG_HOME", "GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM", "GIT_CONFIG_NOSYSTEM",
    ))


@functools.lru_cache(maxsize=8)
def _trusted_overrides(_key: tuple[str | None, ...]) -> tuple[tuple[str, str], ...]:
    """Operator-owned (system/global/built-in) values for the pinned keys."""
    env = {k: v for k, v in os.environ.items() if k not in _SCRUB_ENV}
    try:
        out = subprocess.run(
            ["git", "config", "--show-scope", "--includes", "--list", "-z"],
            capture_output=True, cwd="/", env=env, timeout=10,
        ).stdout.decode(errors="replace")
    except (OSError, subprocess.SubprocessError):
        return ()
    pinned = {k.lower() for k, _ in SAFE_GIT_CONFIG}
    fields = out.split("\0")
    single: dict[str, tuple[str, str]] = {}
    helpers: list[tuple[str, str]] = []
    for scope, entry in zip(fields[0::2], fields[1::2]):
        if scope not in ("system", "global", "unknown"):
            continue
        key, _, value = entry.partition("\n")
        lk = key.lower()
        if lk.startswith("credential.") and lk.endswith(".helper") and "=" not in key:
            helpers.append((key, value))
        elif lk in pinned and lk != "credential.helper":
            single[lk] = (key, value)
    return tuple(single.values()) + tuple(helpers)


def safe_git_config(*, isolated: bool = False) -> list[tuple[str, str]]:
    pairs = list(SAFE_GIT_CONFIG)
    if not isolated:
        pairs += _trusted_overrides(_trusted_cache_key())
    return pairs


def safe_git_argv(*args: str, git: str = "git", isolated: bool = False) -> list[str]:
    """`git -c k=v ... <args>` with the pinned config applied."""
    argv = [git]
    for key, value in safe_git_config(isolated=isolated):
        argv += ["-c", f"{key}={value}"]
    return argv + list(args)


def safe_git_env(
    base: Mapping[str, str] | None = None, *, isolated: bool = False
) -> dict[str, str]:
    """Env carrying the pinned config via GIT_CONFIG_COUNT (git >= 2.31), for
    callers such as GitPython that don't build the argv themselves.

    Returns only the overrides when `base` is None; otherwise `base` (minus
    location vars) merged with them, appending after any GIT_CONFIG_* entries
    already in `base`.
    """
    env: dict[str, str] = (
        {k: v for k, v in base.items() if k not in _SCRUB_ENV} if base is not None else {}
    )
    try:
        start = int(env.get("GIT_CONFIG_COUNT", "0"))
    except ValueError:
        start = 0
    pairs = safe_git_config(isolated=isolated)
    for i, (key, value) in enumerate(pairs, start=start):
        env[f"GIT_CONFIG_KEY_{i}"] = key
        env[f"GIT_CONFIG_VALUE_{i}"] = value
    env["GIT_CONFIG_COUNT"] = str(start + len(pairs))
    if isolated:
        env.update(_ISOLATED_ENV)
    return env


def run_git(
    *args: str,
    extra_env: Mapping[str, str] | None = None,
    isolated: bool = False,
    timeout: float | None = None,
) -> str:
    """Run hardened `git <args>` from `/`; return stdout or raise SafeGitError.

    `extra_env` (e.g. ShadowGitDir.env(), GIT_ASKPASS) is applied last.
    """
    full_env = safe_git_env(os.environ, isolated=isolated)
    full_env.update(extra_env or {})
    try:
        proc = subprocess.run(
            ["git", *args], capture_output=True, cwd="/", env=full_env, timeout=timeout,
        )
    except (OSError, subprocess.SubprocessError) as e:
        raise SafeGitError(f"git {args[:2]} failed: {e}") from e
    if proc.returncode != 0:
        tail = proc.stderr.decode(errors="replace")[:512]
        raise SafeGitError(f"git {list(args[:2])} failed rc={proc.returncode}: {tail}")
    return proc.stdout.decode(errors="replace")


def _require_dir(path: Path) -> None:
    try:
        st = os.lstat(path)
    except OSError as e:
        raise SafeGitError(f"{path} is missing") from e
    if not stat.S_ISDIR(st.st_mode):
        raise SafeGitError(f"{path} is not a plain directory")


def read_repo_config(git_dir: Path, key: str) -> str | None:
    """Read one value from `git_dir/config` as data (no includes, nothing run)."""
    _require_dir(git_dir)
    cfg = git_dir / "config"
    try:
        if not stat.S_ISREG(os.lstat(cfg).st_mode):
            return None
    except OSError:
        return None
    try:
        out = run_git("config", "--file", str(cfg), "--no-includes", "--get", key, isolated=True)
    except SafeGitError:
        return None
    return out.rstrip("\n")


# Metadata copied into (and back out of) a shadow git dir. Everything else in
# the workspace's git dir -- config, hooks, info/, commondir, modules/,
# worktrees/ -- is never read by host git.
_SHADOW_FILES = ("HEAD", "packed-refs", "shallow", "index", "ORIG_HEAD", "FETCH_HEAD")
# POSIX only (dir_fd reads); getattr keeps the module importable on Windows clients.
_NOFOLLOW_DIR = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)


def _read_tree(root_fd: int) -> dict[str, bytes]:
    """Regular files under the git dir's metadata names/refs, never following symlinks."""
    found: dict[str, bytes] = {}

    def read_at(dir_fd: int, name: str) -> bytes | None:
        try:
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dir_fd)
        except OSError:
            return None
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                return None
            with os.fdopen(os.dup(fd), "rb") as f:
                return f.read()
        finally:
            os.close(fd)

    for name in _SHADOW_FILES:
        data = read_at(root_fd, name)
        if data is not None:
            found[name] = data
    try:
        refs_fd = os.open("refs", _NOFOLLOW_DIR, dir_fd=root_fd)
    except OSError:
        return found
    try:
        for top, _dirs, files, fd in os.fwalk(".", dir_fd=refs_fd, follow_symlinks=False):
            rel = os.path.normpath(os.path.join("refs", top))
            for name in files:
                data = read_at(fd, name)
                if data is not None:
                    found[os.path.join(rel, name)] = data
    finally:
        os.close(refs_fd)
    return found


def _open_parent(root_fd: int, rel: str, *, create: bool) -> tuple[int, str]:
    parts = rel.split(os.sep)
    fd = os.dup(root_fd)
    try:
        for part in parts[:-1]:
            if create:
                with contextlib.suppress(FileExistsError):
                    os.mkdir(part, 0o755, dir_fd=fd)
            nfd = os.open(part, _NOFOLLOW_DIR, dir_fd=fd)
            os.close(fd)
            fd = nfd
    except OSError:
        os.close(fd)
        raise
    return fd, parts[-1]


def _write_back(root_fd: int, before: dict[str, bytes], after: dict[str, bytes]) -> None:
    for rel, data in after.items():
        if before.get(rel) == data:
            continue
        fd, name = _open_parent(root_fd, rel, create=True)
        try:
            tmp = f".{name}.warren-tmp"
            wfd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o644, dir_fd=fd)
            try:
                os.write(wfd, data)
            finally:
                os.close(wfd)
            os.replace(tmp, name, src_dir_fd=fd, dst_dir_fd=fd)
        finally:
            os.close(fd)
    for rel in before.keys() - after.keys():
        if not rel.startswith("refs" + os.sep):
            continue
        try:
            fd, name = _open_parent(root_fd, rel, create=False)
        except OSError:
            continue
        try:
            with contextlib.suppress(OSError):
                os.unlink(name, dir_fd=fd)
        finally:
            os.close(fd)


_ALTERNATES_FILES = ("alternates", "http-alternates")


def require_no_alternates(objects: Path) -> None:
    """Refuse an objects dir that declares alternates (BB12).

    Git follows `objects/info/alternates` (recursively) on every object lookup,
    so a workspace that writes one could make host git read -- and
    pull/checkout/branch copy into its own repo -- objects from another
    workspace's repo or any host path. warren never creates alternates in a
    repo it hands to a workspace, so any present are refused, never read.
    """
    info = objects / "info"
    try:
        st = os.lstat(info)
    except FileNotFoundError:
        return
    except OSError as e:
        raise SafeGitError(f"{info} is unreadable") from e
    if not stat.S_ISDIR(st.st_mode):
        raise SafeGitError(f"{info} is not a plain directory")
    for name in _ALTERNATES_FILES:
        try:
            os.lstat(info / name)
        except FileNotFoundError:
            continue
        except OSError as e:
            raise SafeGitError(f"{info / name} is unreadable") from e
        raise SafeGitError(
            f"{objects} depends on object alternates ({name}); refusing to read through it"
        )


def own_objects_dir(git_dir: Path) -> Path:
    """`git_dir/objects`, verified to be the repo's own plain directory (no
    symlink at it or among its entries, physically inside `git_dir`) with no
    alternates. The only object store host git is ever pointed at."""
    _require_dir(git_dir)
    objects = git_dir / "objects"
    _require_dir(objects)
    if os.path.dirname(os.path.realpath(objects)) != os.path.realpath(git_dir):
        raise SafeGitError(f"{objects} resolves outside {git_dir}")
    with os.scandir(objects) as entries:
        for child in entries:
            if child.is_symlink():
                raise SafeGitError(f"{objects} contains a symlink: {child.name}")
    require_no_alternates(objects)
    return objects


class ShadowGitDir:
    """A warren-owned GIT_DIR standing in for a workspace-writable one."""

    def __init__(self, path: Path, objects: Path, work_tree: Path | None) -> None:
        self.path = path
        self.objects = objects
        self.work_tree = work_tree

    def env(self) -> dict[str, str]:
        # GIT_ALTERNATE_OBJECT_DIRECTORIES is blanked so an inherited value can't
        # widen object lookup; a caller that deliberately borrows a vetted store
        # (own_objects_dir) sets it after this.
        env = {
            "GIT_DIR": str(self.path),
            "GIT_OBJECT_DIRECTORY": str(self.objects),
            "GIT_ALTERNATE_OBJECT_DIRECTORIES": "",
        }
        if self.work_tree is not None:
            env["GIT_WORK_TREE"] = str(self.work_tree)
        return env


@contextlib.contextmanager
def shadow_git_dir(
    real_git_dir: Path,
    shadow_root: Path,
    config: list[tuple[str, str]],
    *,
    work_tree: Path | None = None,
) -> Iterator[ShadowGitDir]:
    """Yield a ShadowGitDir whose config is exactly `config` (plus core
    format keys), with HEAD/refs/index copied in from `real_git_dir` and copied
    back on clean exit. `shadow_root` must be outside every sandbox's write
    scope. Objects are used in place (GIT_OBJECT_DIRECTORY): they're data. Only
    the repo's own objects dir is used; a repo with alternates is refused.
    """
    objects = own_objects_dir(real_git_dir)
    fmt = read_repo_config(real_git_dir, "extensions.objectformat")
    refstorage = read_repo_config(real_git_dir, "extensions.refstorage")
    if refstorage not in (None, "files"):
        raise SafeGitError(f"unsupported ref storage {refstorage!r} in {real_git_dir}")

    shadow_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    shadow = Path(tempfile.mkdtemp(prefix="shadow-", dir=shadow_root))
    root_fd = os.open(real_git_dir, _NOFOLLOW_DIR)
    try:
        before = _read_tree(root_fd)
        if "HEAD" not in before:
            raise SafeGitError(f"{real_git_dir} has no readable HEAD")
        for rel, data in before.items():
            dst = shadow / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            dst.write_bytes(data)
        (shadow / "refs" / "heads").mkdir(parents=True, exist_ok=True)
        (shadow / "objects").mkdir()
        cfg = str(shadow / "config")
        base = [
            ("core.repositoryformatversion", "1" if fmt else "0"),
            ("core.bare", "false" if work_tree is not None else "true"),
            ("core.logAllRefUpdates", "false"),
            ("gc.auto", "0"),
            ("maintenance.auto", "false"),
        ]
        if fmt:
            base.append(("extensions.objectformat", fmt))
        for key, value in base + list(config):
            run_git("config", "--file", cfg, "--add", key, value, isolated=True)
        yield ShadowGitDir(shadow, objects, work_tree)
        # Alternates planted while git ran: don't publish refs it produced.
        require_no_alternates(objects)
        _write_back(root_fd, before, _read_tree_path(shadow))
    finally:
        os.close(root_fd)
        shutil.rmtree(shadow, ignore_errors=True)


@contextlib.contextmanager
def readonly_shadow_git_dir(
    git_dir: Path,
    shadow_root: Path,
    *,
    common_dir: Path | None = None,
    work_tree: Path | None = None,
) -> Iterator[ShadowGitDir]:
    """`shadow_git_dir` for inspection only: nothing is copied back. Supports a linked
    worktree, whose HEAD/index live in `git_dir` and refs/objects in `common_dir`."""
    common = common_dir or git_dir
    _require_dir(git_dir)
    objects = own_objects_dir(common)
    fmt = read_repo_config(common, "extensions.objectformat")
    refstorage = read_repo_config(common, "extensions.refstorage")
    if refstorage not in (None, "files"):
        raise SafeGitError(f"unsupported ref storage {refstorage!r} in {common}")

    tree = _read_tree_path(common)
    if common != git_dir:
        own = _read_tree_path(git_dir)
        for name in ("HEAD", "index", "ORIG_HEAD"):
            tree.pop(name, None)
            if name in own:
                tree[name] = own[name]
    if "HEAD" not in tree:
        raise SafeGitError(f"{git_dir} has no readable HEAD")

    shadow_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    shadow = Path(tempfile.mkdtemp(prefix="shadow-ro-", dir=shadow_root))
    try:
        for rel, data in tree.items():
            dst = shadow / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            dst.write_bytes(data)
        (shadow / "refs" / "heads").mkdir(parents=True, exist_ok=True)
        (shadow / "objects").mkdir()
        cfg = str(shadow / "config")
        base = [
            ("core.repositoryformatversion", "1" if fmt else "0"),
            ("core.bare", "false" if work_tree is not None else "true"),
            ("core.logAllRefUpdates", "false"),
            ("gc.auto", "0"),
            ("maintenance.auto", "false"),
        ]
        if fmt:
            base.append(("extensions.objectformat", fmt))
        for key, value in base:
            run_git("config", "--file", cfg, "--add", key, value, isolated=True)
        yield ShadowGitDir(shadow, objects, work_tree)
    finally:
        shutil.rmtree(shadow, ignore_errors=True)


def _read_tree_path(path: Path) -> dict[str, bytes]:
    fd = os.open(path, _NOFOLLOW_DIR)
    try:
        return _read_tree(fd)
    finally:
        os.close(fd)
