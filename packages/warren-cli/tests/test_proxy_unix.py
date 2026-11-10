"""warren_cli.proxy_unix: socket path, run dir, hardened bind, peer-uid check."""

from __future__ import annotations

import os
import shutil
import socket
import stat
import tempfile
from pathlib import Path

import pytest

from warren_cli import proxy_unix

pytestmark = pytest.mark.skipif(not hasattr(socket, "AF_UNIX") or os.name == "nt", reason="unix sockets")


@pytest.fixture
def short(monkeypatch):
    """A short private dir: pytest's tmp_path can exceed sun_path on macOS."""
    d = Path(tempfile.mkdtemp(prefix="wu", dir="/tmp"))
    yield d
    shutil.rmtree(d, ignore_errors=True)


def test_default_socket_path_under_home_run_dir(short, monkeypatch):
    monkeypatch.setenv("HOME", str(short))
    p = proxy_unix.default_socket_path("srv", "ws1", "web")
    assert p == short / ".warren" / "run" / "srv-ws1-web.sock"


def test_default_socket_path_hashes_long_names_to_fit_sun_path(short):
    p = proxy_unix.default_socket_path("srv", "w" * 60, "n" * 60, run_dir=short / ("d" * 40))
    assert len(os.fsencode(p)) <= proxy_unix.MAX_SOCKET_PATH
    assert p.suffix == ".sock" and p.parent == short / ("d" * 40)
    # deterministic and distinct per input
    assert p == proxy_unix.default_socket_path("srv", "w" * 60, "n" * 60, run_dir=short / ("d" * 40))
    assert p != proxy_unix.default_socket_path("srv", "w" * 60, "m" * 60, run_dir=short / ("d" * 40))


def test_default_socket_path_rejects_a_too_deep_run_dir(short):
    with pytest.raises(proxy_unix.UnixSocketError, match="too long"):
        proxy_unix.default_socket_path("s", "w", "n", run_dir=short / ("d" * 120))


def test_ensure_run_dir_creates_0700(short):
    d = proxy_unix.ensure_run_dir(short / "a" / "run")
    assert stat.S_IMODE(os.lstat(d).st_mode) == 0o700


def test_ensure_run_dir_tightens_loose_mode_it_owns(short):
    d = short / "run"
    d.mkdir(mode=0o755)
    os.chmod(d, 0o755)
    proxy_unix.ensure_run_dir(d)
    assert stat.S_IMODE(os.lstat(d).st_mode) == 0o700


def test_ensure_run_dir_refuses_symlink(short):
    (short / "real").mkdir()
    (short / "run").symlink_to(short / "real")
    with pytest.raises(proxy_unix.UnixSocketError, match="symlink"):
        proxy_unix.ensure_run_dir(short / "run")


def test_ensure_run_dir_refuses_other_owner(short, monkeypatch):
    d = short / "run"
    d.mkdir()
    monkeypatch.setattr(os, "getuid", lambda: os.lstat(d).st_uid + 1)
    with pytest.raises(proxy_unix.UnixSocketError, match="owned by"):
        proxy_unix.ensure_run_dir(d)


def test_bind_unix_makes_a_0600_socket_and_restores_umask(short):
    old = os.umask(0o022)
    try:
        s = proxy_unix.bind_unix(short / "x.sock")
        assert os.umask(0o022) == 0o022
    finally:
        os.umask(old)
    try:
        st = os.lstat(short / "x.sock")
        assert stat.S_ISSOCK(st.st_mode) and stat.S_IMODE(st.st_mode) == 0o600 and st.st_uid == os.getuid()
    finally:
        s.close()


def test_bind_unix_replaces_a_stale_socket(short):
    p = short / "x.sock"
    dead = socket.socket(socket.AF_UNIX)
    dead.bind(str(p))
    dead.close()  # file stays, nobody listens
    assert p.exists()
    proxy_unix.bind_unix(p).close()


def test_bind_unix_refuses_a_live_socket(short):
    p = short / "x.sock"
    live = socket.socket(socket.AF_UNIX)
    live.bind(str(p))
    live.listen()
    try:
        with pytest.raises(proxy_unix.UnixSocketError, match="in use"):
            proxy_unix.bind_unix(p)
    finally:
        live.close()
    assert p.exists()


def test_bind_unix_refuses_regular_file_and_keeps_it(short):
    p = short / "x.sock"
    p.write_text("precious")
    with pytest.raises(proxy_unix.UnixSocketError, match="not a socket"):
        proxy_unix.bind_unix(p)
    assert p.read_text() == "precious"


def test_bind_unix_refuses_symlink_even_to_a_stale_socket(short):
    target = short / "t.sock"
    dead = socket.socket(socket.AF_UNIX)
    dead.bind(str(target))
    dead.close()
    link = short / "x.sock"
    link.symlink_to(target)
    with pytest.raises(proxy_unix.UnixSocketError, match="symlink"):
        proxy_unix.bind_unix(link)
    assert link.is_symlink() and target.exists()


def test_bind_unix_refuses_a_stale_socket_of_another_uid(short, monkeypatch):
    p = short / "x.sock"
    dead = socket.socket(socket.AF_UNIX)
    dead.bind(str(p))
    dead.close()
    monkeypatch.setattr(os, "getuid", lambda: os.lstat(p).st_uid + 1)
    with pytest.raises(proxy_unix.UnixSocketError, match="owned by"):
        proxy_unix.bind_unix(p)
    assert p.exists()


def test_bind_unix_rejects_relative_and_overlong_paths(short):
    with pytest.raises(proxy_unix.UnixSocketError, match="absolute"):
        proxy_unix.bind_unix(Path("rel.sock"))
    with pytest.raises(proxy_unix.UnixSocketError, match="too long"):
        proxy_unix.bind_unix(short / ("x" * 120))


def test_bind_unix_missing_parent_is_an_error(short):
    with pytest.raises(proxy_unix.UnixSocketError, match="directory"):
        proxy_unix.bind_unix(short / "nope" / "x.sock")


def test_peer_uid_of_a_socketpair_is_ours():
    a, b = socket.socketpair(socket.AF_UNIX)
    try:
        assert proxy_unix.peer_uid(a) == os.getuid()
        assert proxy_unix.peer_allowed(a)
    finally:
        a.close()
        b.close()


def test_peer_allowed_drops_other_uid_and_unknown(monkeypatch):
    s = object()
    monkeypatch.setattr(proxy_unix, "peer_uid", lambda sock: os.getuid() + 1)
    assert not proxy_unix.peer_allowed(s)
    monkeypatch.setattr(proxy_unix, "peer_uid", lambda sock: None)
    assert not proxy_unix.peer_allowed(s)  # fail closed


def test_unsupported_platform_is_a_clear_error(short, monkeypatch):
    monkeypatch.setattr(proxy_unix, "supported", lambda: False)
    with pytest.raises(proxy_unix.UnixSocketError, match="not supported on this platform"):
        proxy_unix.bind_unix(short / "x.sock")
    with pytest.raises(proxy_unix.UnixSocketError, match="not supported on this platform"):
        proxy_unix.ensure_run_dir(short / "run")
