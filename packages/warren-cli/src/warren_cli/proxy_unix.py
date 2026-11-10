"""Unix-socket listener helpers for ``warren proxy``.

A Unix socket authenticates by file permissions instead of a loopback port: the
socket is created 0600 in a 0700 directory owned by the current user, and each
accepted connection's peer uid is checked as well. Nothing here follows symlinks
or replaces anything but a stale socket this user owns.
"""

from __future__ import annotations

import hashlib
import os
import socket
import stat
import struct
import sys
from pathlib import Path

# sun_path is 104 bytes on macOS/BSD and 108 on Linux, including the NUL.
MAX_SOCKET_PATH = 100
_LOCAL_PEERCRED = 0x001  # macOS/BSD: getsockopt(SOL_LOCAL=0, LOCAL_PEERCRED) -> struct xucred


class UnixSocketError(OSError):
    """A socket path or directory that cannot be used safely (an OSError so the
    daemon records it like any other listen failure)."""


def supported() -> bool:
    return os.name != "nt" and hasattr(socket, "AF_UNIX") and hasattr(os, "getuid")


def _require_supported() -> None:
    if not supported():
        raise UnixSocketError("unix-socket listeners are not supported on this platform (use a TCP mapping)")


def default_run_dir() -> Path:
    return Path.home() / ".warren" / "run"


def default_socket_path(server: str, workspace: str, name: str, *, run_dir: Path | None = None) -> Path:
    """``<run dir>/<server>-<workspace>-<name>.sock``; a short hash of that name
    when the full path would not fit in ``sun_path``."""
    base = Path(run_dir) if run_dir is not None else default_run_dir()
    stem = f"{server}-{workspace}-{name}"
    path = base / f"{stem}.sock"
    if len(os.fsencode(path)) > MAX_SOCKET_PATH:
        path = base / f"{hashlib.sha256(stem.encode()).hexdigest()[:16]}.sock"
    if len(os.fsencode(path)) > MAX_SOCKET_PATH:
        raise UnixSocketError(f"socket path {path} is too long for a unix socket (max {MAX_SOCKET_PATH} bytes)")
    return path


def ensure_run_dir(path: Path | None = None) -> Path:
    """Create the run directory 0700 (parents default) and verify it is a real
    directory owned by this user; loosen nothing, tighten group/other bits."""
    _require_supported()
    d = Path(path) if path is not None else default_run_dir()
    d.parent.mkdir(parents=True, exist_ok=True)
    try:
        d.mkdir(mode=0o700)
    except FileExistsError:
        pass
    st = os.lstat(d)
    if stat.S_ISLNK(st.st_mode):
        raise UnixSocketError(f"refusing to use {d}: it is a symlink")
    if not stat.S_ISDIR(st.st_mode):
        raise UnixSocketError(f"{d} is not a directory")
    if st.st_uid != os.getuid():
        raise UnixSocketError(f"{d} is owned by uid {st.st_uid}, not this user ({os.getuid()})")
    if stat.S_IMODE(st.st_mode) != 0o700:
        os.chmod(d, 0o700)
    return d


def _clear_stale(path: str) -> None:
    """Remove ``path`` if it is a dead socket of this user; refuse anything else."""
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return
    if stat.S_ISLNK(st.st_mode):
        raise UnixSocketError(f"refusing to bind {path}: it is a symlink")
    if not stat.S_ISSOCK(st.st_mode):
        raise UnixSocketError(f"refusing to bind {path}: it exists and is not a socket")
    if st.st_uid != os.getuid():
        raise UnixSocketError(f"refusing to bind {path}: socket is owned by uid {st.st_uid}, not this user")
    probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        probe.settimeout(2)
        probe.connect(path)
    except (ConnectionRefusedError, FileNotFoundError):
        pass  # nobody listening: stale
    except OSError as exc:
        raise UnixSocketError(f"cannot tell whether {path} is in use: {exc}") from exc
    else:
        raise UnixSocketError(f"{path} is in use by a live listener (another warren proxy?)")
    finally:
        probe.close()
    os.unlink(path)


def bind_unix(path: Path | str) -> socket.socket:
    """Bind (not listen) a fresh 0600 Unix socket at ``path`` and return it.

    The umask is 0o177 around the bind so the socket never exists with wider
    permissions; afterwards it is lstat-verified (socket, 0600, our uid)."""
    _require_supported()
    p = os.fspath(path)
    if not os.path.isabs(p):
        raise UnixSocketError(f"socket path {p!r} must be absolute")
    if len(os.fsencode(p)) > MAX_SOCKET_PATH:
        raise UnixSocketError(f"socket path {p} is too long for a unix socket (max {MAX_SOCKET_PATH} bytes)")
    parent = os.path.dirname(p)
    if not os.path.isdir(parent):
        raise UnixSocketError(f"{parent} is not a directory (the socket's parent must exist)")
    _clear_stale(p)
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    old = os.umask(0o177)
    try:
        sock.bind(p)
    except OSError as exc:
        sock.close()
        raise UnixSocketError(f"could not bind {p}: {exc}") from exc
    finally:
        os.umask(old)
    try:
        st = os.lstat(p)
        if not stat.S_ISSOCK(st.st_mode) or stat.S_IMODE(st.st_mode) != 0o600 or st.st_uid != os.getuid():
            raise UnixSocketError(f"{p} was not created as an owner-only socket; refusing to use it")
    except BaseException:
        sock.close()
        try:
            os.unlink(p)
        except OSError:
            pass
        raise
    return sock


def peer_uid(sock: socket.socket) -> int | None:
    """The connected peer's effective uid, or None when it cannot be determined."""
    try:
        if hasattr(socket, "SO_PEERCRED") and sys.platform.startswith("linux"):
            data = sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
            return struct.unpack("3i", data)[1]
        if sys.platform == "darwin" or "bsd" in sys.platform:
            # struct xucred { u_int cr_version; uid_t cr_uid; ... }
            data = sock.getsockopt(0, _LOCAL_PEERCRED, 76)
            return struct.unpack_from("II", data)[1]
    except (OSError, struct.error):
        return None
    return None


def peer_allowed(sock: socket.socket) -> bool:
    """True only when the peer is provably this user (fails closed)."""
    return peer_uid(sock) == os.getuid()


def unlink_owned_socket(path: str) -> bool:
    """Remove ``path`` only if it is a socket (not a symlink) owned by this user;
    True when it was removed."""
    try:
        st = os.lstat(path)
    except OSError:
        return False
    if not stat.S_ISSOCK(st.st_mode) or st.st_uid != os.getuid():
        return False
    try:
        os.unlink(path)
    except OSError:
        return False
    return True
