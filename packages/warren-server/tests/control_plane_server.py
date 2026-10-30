"""AJ2: run the real warren-server app on 127.0.0.1 with the scripted runtime, for an
external process to drive over HTTP/MCP -- github.com/scottcowan/warren-examples'
acceptance tests, checking this repo out as a sibling directory (not a published
artifact; moved out of this repo's own examples/frameworks 2026-10-30).

    python -m tests.control_plane_server <port> <state-dir>

The reaper runs, so single-turn workspaces complete. HOME is <state-dir>/home.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from unittest.mock import patch


def main() -> None:
    port, state = int(sys.argv[1]), Path(sys.argv[2])
    home = state / "home"
    home.mkdir(parents=True, exist_ok=True)
    os.environ["HOME"] = str(home)

    from tests.control_plane import ScriptedRuntime, server_env_vars

    os.environ.update(server_env_vars(state, reaper=True))

    import uvicorn

    from warren.app import app

    with patch("warren.app.PodmanRuntime", return_value=ScriptedRuntime()):
        uvicorn.run(app, host="127.0.0.1", port=port, log_level="warning")


if __name__ == "__main__":
    main()
