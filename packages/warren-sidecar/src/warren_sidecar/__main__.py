"""warren-sidecar AF_UNIX socket entry point."""

from __future__ import annotations

import os
import socket
from pathlib import Path

import structlog
import uvicorn

from warren_sidecar.app import app
from warren_sidecar.config import SidecarSettings

log = structlog.get_logger(__name__)


def main() -> None:
    settings = SidecarSettings()
    # Stale socket guard (Pitfall 2): remove leftover socket from previous run
    Path(settings.socket_path).unlink(missing_ok=True)

    # Audit 2026-10-16 P2 #47: uvicorn's own `uds=` bind leaves the socket at
    # whatever the process umask produces (typically 0o755 or worse — world
    # connectable). The sidecar runs as root with no other access control on
    # this socket, so anything able to reach it could exec/read as root.
    # Bind and chmod it ourselves BEFORE uvicorn ever touches it, then hand
    # uvicorn the already-bound, already-restricted fd.
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.bind(settings.socket_path)
    os.chmod(settings.socket_path, 0o600)
    sock.listen()

    log.info("sidecar_starting", socket_path=settings.socket_path)
    uvicorn.run(app, fd=sock.fileno(), log_level="warning")


if __name__ == "__main__":
    main()
