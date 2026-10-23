"""network/egress.py host-network introspection unit tests (Phase 4 Plan 01/02, LIFE-02).

All behaviors are covered with monkeypatched `subprocess.run` — no real `/sys`, `podman`,
or `ip` binary is ever touched. `find_host_veth` and `read_egress_bytes` both shell out
through `podman unshare --rootless-netns` (see egress.py module docstring — corrected
2026-09-19 after live node2 verification showed the rootless bridge veth is invisible from
the operator's default network namespace), so tests assert against those exact argv shapes
rather than a plain `ip` call or a direct Python file read.
"""

from __future__ import annotations

import contextlib
import socketserver
import subprocess
import tempfile
import threading
from http.server import BaseHTTPRequestHandler
from pathlib import Path

import pytest

from warren.network.egress import (
    EgressUnavailable,
    find_host_veth,
    read_container_egress_bytes,
    read_container_egress_bytes_via_shim,
    read_egress_bytes,
)


def _fake_completed(*, returncode=0, stdout=b"", stderr=b""):
    return subprocess.CompletedProcess(args=["fake"], returncode=returncode, stdout=stdout, stderr=stderr)


_UNSHARE_LINK_PREFIX = ["podman", "unshare", "--rootless-netns", "ip", "-o", "link"]
_UNSHARE_CAT_PREFIX = ["podman", "unshare", "--rootless-netns", "sh", "-c"]


def test_read_egress_bytes_returns_tx_bytes_int(monkeypatch):
    def fake_run(args, **kwargs):
        assert args[:5] == _UNSHARE_CAT_PREFIX
        assert "tx_bytes" in args[5]
        return _fake_completed(stdout=b"123456\n")

    monkeypatch.setattr(subprocess, "run", fake_run)

    assert read_egress_bytes("veth0") == 123456


def test_read_egress_bytes_passes_a_timeout(monkeypatch):
    """Regression guard for audit 2026-10-16 #35: none of these subprocess.run
    calls had a timeout at all -- a hung podman call could stall the whole
    egress-monitoring loop indefinitely."""

    def fake_run(args, **kwargs):
        assert kwargs.get("timeout")
        return _fake_completed(stdout=b"1\n")

    monkeypatch.setattr(subprocess, "run", fake_run)

    read_egress_bytes("veth0")


def test_read_egress_bytes_timeout_raises_egress_unavailable(monkeypatch):
    def fake_run(args, **kwargs):
        raise subprocess.TimeoutExpired(cmd=args, timeout=kwargs.get("timeout", 10.0))

    monkeypatch.setattr(subprocess, "run", fake_run)

    with pytest.raises(EgressUnavailable):
        read_egress_bytes("veth0")


def test_read_egress_bytes_missing_interface_raises_egress_unavailable(monkeypatch):
    def fake_run(args, **kwargs):
        return _fake_completed(returncode=1, stderr=b"No such file or directory\n")

    monkeypatch.setattr(subprocess, "run", fake_run)

    with pytest.raises(EgressUnavailable):
        read_egress_bytes("veth-does-not-exist")


def test_find_host_veth_matches_iflink_index(monkeypatch):
    calls = []

    def fake_run(args, **kwargs):
        calls.append(args)
        if args[:2] == ["podman", "exec"]:
            return _fake_completed(stdout=b"13\n")
        if args[:6] == _UNSHARE_LINK_PREFIX:
            # A veth pair's `iflink` on either side reports the OTHER side's own ifindex.
            # The container's eth0 iflink is 13, so the host-side veth's own leading
            # index must be 13; its "@if2" suffix is the container's own eth0 index
            # (almost always 2) — irrelevant to matching, present only for realism.
            return _fake_completed(
                stdout=(
                    b"1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536\n"
                    b"13: veth1234abcd@if2: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500\n"
                )
            )
        raise AssertionError(f"unexpected subprocess args: {args}")

    monkeypatch.setattr(subprocess, "run", fake_run)

    assert find_host_veth("abc123") == "veth1234abcd"


def test_find_host_veth_matches_on_leading_index_not_trailing_marker(monkeypatch):
    """Regression guard (live node2 finding, 2026-09-19): a container's own eth0 is almost
    always ifindex 2, so nearly every host veth's line ends in "@if2" regardless of which
    container it belongs to. A decoy line that happens to end in "@if{iflink}" (the old,
    wrong matching rule) but whose own leading index is a DIFFERENT container's veth must
    NOT be picked — only the line whose leading index equals iflink is correct.
    """

    def fake_run(args, **kwargs):
        if args[:2] == ["podman", "exec"]:
            return _fake_completed(stdout=b"7\n")
        if args[:6] == _UNSHARE_LINK_PREFIX:
            return _fake_completed(
                stdout=(
                    # Decoy: some OTHER container's veth whose peer happens to be
                    # ifindex 7 — the old "@if{iflink}" substring match would wrongly
                    # pick this line.
                    b"9: veth-wrong-decoy@if7: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500\n"
                    # Correct: this line's own leading index (7) is the container's
                    # reported iflink.
                    b"7: veth-correct@if2: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500\n"
                )
            )
        raise AssertionError(f"unexpected subprocess args: {args}")

    monkeypatch.setattr(subprocess, "run", fake_run)

    assert find_host_veth("abc123") == "veth-correct"


def test_find_host_veth_raises_egress_unavailable_when_no_match(monkeypatch):
    def fake_run(args, **kwargs):
        if args[:2] == ["podman", "exec"]:
            return _fake_completed(stdout=b"13\n")
        if args[:6] == _UNSHARE_LINK_PREFIX:
            # pasta-default case: no veth pair exists at all
            return _fake_completed(stdout=b"1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536\n")
        raise AssertionError(f"unexpected subprocess args: {args}")

    monkeypatch.setattr(subprocess, "run", fake_run)

    with pytest.raises(EgressUnavailable):
        find_host_veth("abc123")


def test_find_host_veth_timeout_raises_egress_unavailable(monkeypatch):
    def fake_run(args, **kwargs):
        raise subprocess.TimeoutExpired(cmd=args, timeout=kwargs.get("timeout", 10.0))

    monkeypatch.setattr(subprocess, "run", fake_run)

    with pytest.raises(EgressUnavailable):
        find_host_veth("abc123")


def test_read_container_egress_bytes_reresolves_veth_every_call(monkeypatch):
    exec_calls = []

    def fake_run(args, **kwargs):
        if args[:2] == ["podman", "exec"]:
            exec_calls.append(args)
            return _fake_completed(stdout=b"13\n")
        if args[:6] == _UNSHARE_LINK_PREFIX:
            return _fake_completed(
                stdout=b"13: veth1234abcd@if2: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500\n"
            )
        if args[:5] == _UNSHARE_CAT_PREFIX:
            return _fake_completed(stdout=b"42\n")
        raise AssertionError(f"unexpected subprocess args: {args}")

    monkeypatch.setattr(subprocess, "run", fake_run)

    assert read_container_egress_bytes("abc123") == 42
    assert read_container_egress_bytes("abc123") == 42
    # find_host_veth (and its podman exec call) must run on every single call —
    # no caching of the resolved veth name across calls (Pitfall 2).
    assert len(exec_calls) == 2


class _ShimHandler(BaseHTTPRequestHandler):
    responses: dict[str, tuple[int, bytes]] = {}

    def address_string(self):  # pragma: no cover - matches production override
        return "unix"

    def do_GET(self):  # noqa: N802
        status, body = self.responses.get(self.path, (404, b'{"error": "not found"}'))
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):  # silence test output
        pass


@contextlib.contextmanager
def _running_shim(responses: dict[str, tuple[int, bytes]]):
    with tempfile.TemporaryDirectory() as tmpdir:
        socket_path = Path(tmpdir) / "shim.sock"

        handler = type("_Handler", (_ShimHandler,), {"responses": responses})
        server = socketserver.UnixStreamServer(str(socket_path), handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            yield socket_path
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)


def test_read_container_egress_bytes_via_shim_returns_tx_bytes():
    with _running_shim({"/egress/abc123": (200, b'{"tx_bytes": 999}')}) as socket_path:
        assert read_container_egress_bytes_via_shim("abc123", socket_path) == 999


def test_read_container_egress_bytes_via_shim_raises_on_non_200():
    with _running_shim({"/egress/abc123": (503, b'{"error": "unavailable"}')}) as socket_path:
        with pytest.raises(EgressUnavailable, match="HTTP 503"):
            read_container_egress_bytes_via_shim("abc123", socket_path)


def test_read_container_egress_bytes_via_shim_raises_on_malformed_body():
    with _running_shim({"/egress/abc123": (200, b"not json")}) as socket_path:
        with pytest.raises(EgressUnavailable, match="malformed"):
            read_container_egress_bytes_via_shim("abc123", socket_path)


def test_read_container_egress_bytes_via_shim_raises_when_socket_missing(tmp_path):
    missing_socket = tmp_path / "does-not-exist.sock"
    with pytest.raises(EgressUnavailable, match="failed to reach egress shim"):
        read_container_egress_bytes_via_shim("abc123", missing_socket)
