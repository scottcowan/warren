"""Deliver a workspace's secrets to its ECS task through its own EFS volume.

Workspace secrets live only in warren's encrypted SQLite store. Right before each
RunTask the control plane decrypts exactly the template-declared secrets the owner
has and writes them into the workspace's access point, through its root mount of the
filesystem (WARREN_EFS_LOCAL_MOUNT_PATH):

    <mount>/workspaces/<id>/.warren/workspace.env   read by the workspace entrypoint
    <mount>/workspaces/<id>/.warren/git-init.env    read by warren-git-materialize

Inside the task that's /var/lib/warren/.warren/, outside the git working tree
(/var/lib/warren/workspace). Each consumer reads its file, deletes it, and only then
starts anything workspace-controlled. Nothing goes through RunTask overrides, which
DescribeTasks and CloudTrail record in plaintext.

The access point maps every client to uid/gid 1000, the workspace user, so
permissions (dir 0700, file 0400) can't stop that user reading a file; what protects
it is that no workspace process runs between the write and its consumption.

The volume is agent-writable, so the writer trusts nothing on it: every path
component is opened with O_NOFOLLOW relative to the previous directory fd, a
non-directory or symlink `.warren` is removed, and the file is written to a fresh
O_EXCL temp name and renamed into place.

Format, one secret per line, parsed without any shell evaluation:
    NAME=<base64 of the value>
NAME must be a portable environment variable name.
"""
from __future__ import annotations

import base64
import contextlib
import os
import re
import stat
import uuid
from typing import Iterator, Mapping

import structlog
from warren_common.errors import ProvisionError

log = structlog.get_logger(__name__)

SECRETS_DIR = ".warren"
WORKSPACE_FILE = "workspace.env"
GIT_INIT_FILE = "git-init.env"
CONTAINER_SECRETS_DIR = f"/var/lib/warren/{SECRETS_DIR}"

_ENV_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_WORKSPACE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]{0,63}$")
_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)


def is_env_name(name: str) -> bool:
    return bool(_ENV_NAME.match(name))


def encode(secrets: Mapping[str, str]) -> bytes:
    """Encode secrets as NAME=base64 lines; names that aren't env names are an error."""
    lines = []
    for name in sorted(secrets):
        if not is_env_name(name):
            raise ValueError(f"secret name {name!r} is not an environment variable name")
        value = base64.b64encode(secrets[name].encode("utf-8")).decode("ascii")
        lines.append(f"{name}={value}\n")
    return "".join(lines).encode("ascii")


def decode(data: bytes) -> dict[str, str]:
    """Inverse of encode(); malformed lines are skipped (mirrors the shell reader)."""
    out: dict[str, str] = {}
    for line in data.decode("ascii", errors="replace").splitlines():
        name, sep, value = line.partition("=")
        if not sep or not is_env_name(name) or not re.fullmatch(r"[A-Za-z0-9+/]*={0,2}", value):
            continue
        out[name] = base64.b64decode(value).decode("utf-8")
    return out


def _open_dir(name: str, dir_fd: int | None, *, create: bool, mode: int) -> int:
    try:
        return os.open(name, _DIR_FLAGS, dir_fd=dir_fd)
    except FileNotFoundError:
        if not create:
            raise
    os.mkdir(name, mode, dir_fd=dir_fd)
    return os.open(name, _DIR_FLAGS, dir_fd=dir_fd)


@contextlib.contextmanager
def _workspace_dir(local_mount: str, workspace_id: str, *, create: bool) -> Iterator[int]:
    if not _WORKSPACE_ID.match(workspace_id):
        raise ProvisionError(f"invalid workspace id {workspace_id!r}")
    fds: list[int] = []
    try:
        fds.append(os.open(local_mount, _DIR_FLAGS & ~os.O_NOFOLLOW))
        # The access point's root: EFS creates it 1000:1000 0700 on first mount, so
        # create it the same way when warren gets there first.
        fds.append(_open_dir("workspaces", fds[-1], create=create, mode=0o755))
        fds.append(_open_dir(workspace_id, fds[-1], create=create, mode=0o700))
        yield fds[-1]
    finally:
        for fd in reversed(fds):
            os.close(fd)


def _secrets_dir(ws_fd: int, *, create: bool) -> int:
    try:
        st = os.stat(SECRETS_DIR, dir_fd=ws_fd, follow_symlinks=False)
    except FileNotFoundError:
        st = None
    if st is not None and not stat.S_ISDIR(st.st_mode):
        # The workspace planted a symlink or file here; never write through it.
        os.unlink(SECRETS_DIR, dir_fd=ws_fd)
        st = None
    if st is None:
        if not create:
            raise FileNotFoundError(SECRETS_DIR)
        os.mkdir(SECRETS_DIR, 0o700, dir_fd=ws_fd)
    fd = os.open(SECRETS_DIR, _DIR_FLAGS, dir_fd=ws_fd)
    os.fchmod(fd, 0o700)
    return fd


def _unlink(name: str, dir_fd: int) -> None:
    with contextlib.suppress(FileNotFoundError):
        os.unlink(name, dir_fd=dir_fd)


def write_secrets(local_mount: str, workspace_id: str, files: Mapping[str, Mapping[str, str]]) -> None:
    """Write each `files[name]` (secrets mapping) atomically; an empty mapping removes
    that file instead, so a stale one never survives a relaunch."""
    with _workspace_dir(local_mount, workspace_id, create=True) as ws_fd:
        d = _secrets_dir(ws_fd, create=True)
        try:
            for filename, secrets in files.items():
                if not secrets:
                    _unlink(filename, d)
                    continue
                data = encode(secrets)
                tmp = f".{filename}.{uuid.uuid4().hex}.tmp"
                fd = os.open(
                    tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400, dir_fd=d
                )
                try:
                    with os.fdopen(fd, "wb", closefd=False) as fh:
                        fh.write(data)
                        fh.flush()
                        os.fsync(fd)
                    os.fchmod(fd, 0o400)
                finally:
                    os.close(fd)
                try:
                    os.rename(tmp, filename, src_dir_fd=d, dst_dir_fd=d)
                except BaseException:
                    _unlink(tmp, d)
                    raise
        finally:
            os.close(d)


def remove_secrets(local_mount: str, workspace_id: str) -> None:
    """Delete any delivered secrets files (and leftover temp files) for a workspace."""
    try:
        with _workspace_dir(local_mount, workspace_id, create=False) as ws_fd:
            try:
                d = _secrets_dir(ws_fd, create=False)
            except FileNotFoundError:
                return
            try:
                for name in os.listdir(d):
                    if name in (WORKSPACE_FILE, GIT_INIT_FILE) or name.endswith(".tmp"):
                        _unlink(name, d)
            finally:
                os.close(d)
    except FileNotFoundError:
        return
