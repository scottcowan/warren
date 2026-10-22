#!/usr/bin/env python3
"""Native host-side egress shim for LIFE-02 (node2 finding, 2026-09-19).

Serves `warren.network.egress.read_container_egress_bytes` over a Unix socket so that
warren-server's idle reaper — running inside its own rootless container — can get an
egress byte count without needing `podman unshare --rootless-netns` to work nested.

WHY THIS EXISTS: a rootless container can never genuinely own the kernel-level subuid
range `podman unshare --rootless-netns` needs to build a second nested namespace layer.
Confirmed live on node2: `newuidmap: write to uid_map failed: Operation not permitted`,
reproduced under every combination of `--userns=host`/`keep-id` tried, plus explicitly
added SETUID/SETGID capabilities — none of it helps, because the check happens at the
real kernel level, which a nested rootless container's capability set cannot reach no
matter what is granted inside it. Only a process actually run by the real host user (not
nested in any container) can call `podman unshare --rootless-netns` successfully — hence
this script, run directly on node2 via systemd (see docs/warren-server-deploy.md).

Deliberately stdlib-only (http.server + socketserver), matching network/egress.py's own
"small, dependency-light, easy to replace" design goal (04-RESEARCH.md).

Run directly for local testing:
    python3 scripts/egress_shim.py --socket /run/user/1000/warren-egress-shim.sock

Systemd unit (see docs/warren-server-deploy.md) is the intended production entry point.
"""

from __future__ import annotations

import argparse
import json
import os
import socketserver
import sys
from http.server import BaseHTTPRequestHandler
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from warren.network.egress import EgressUnavailable, read_container_egress_bytes  # noqa: E402


class _UnixHTTPServer(socketserver.UnixStreamServer):
    allow_reuse_address = True


class _Handler(BaseHTTPRequestHandler):
    # BaseHTTPRequestHandler expects a (host, port) client_address tuple; a Unix socket's
    # peer has neither, so getpeername() raises and access-log formatting would blow up
    # without this override.
    def address_string(self) -> str:
        return "unix"

    def do_GET(self) -> None:  # noqa: N802
        prefix = "/egress/"
        if not self.path.startswith(prefix):
            self._send_json(404, {"error": f"unknown path {self.path!r}"})
            return

        container_id = self.path[len(prefix) :]
        if not container_id:
            self._send_json(400, {"error": "missing container_id"})
            return

        try:
            tx_bytes = read_container_egress_bytes(container_id)
        except EgressUnavailable as e:
            self._send_json(503, {"error": str(e)})
            return
        except Exception as e:  # defensive: never let an unexpected exception hang the conn
            self._send_json(500, {"error": f"unexpected error: {e}"})
            return

        self._send_json(200, {"tx_bytes": tx_bytes})

    def _send_json(self, status: int, payload: dict) -> None:
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt: str, *args: object) -> None:
        sys.stderr.write(f"{self.address_string()} - {fmt % args}\n")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--socket",
        default=os.environ.get(
            "WARREN_EGRESS_SHIM_SOCKET", "/run/user/1000/warren-egress-shim.sock"
        ),
        help="Unix socket path to listen on (default: %(default)s)",
    )
    args = parser.parse_args()

    socket_path = Path(args.socket)
    if socket_path.exists():
        socket_path.unlink()
    socket_path.parent.mkdir(parents=True, exist_ok=True)

    server = _UnixHTTPServer(str(socket_path), _Handler)
    # Bind-mounted into warren-server's container as a single UID (1000) bind mount, same
    # pattern as podman.sock — 0660 keeps it off other local users without needing 0666.
    os.chmod(socket_path, 0o660)
    print(f"warren-egress-shim listening on {socket_path}", file=sys.stderr)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        socket_path.unlink(missing_ok=True)


if __name__ == "__main__":
    main()
