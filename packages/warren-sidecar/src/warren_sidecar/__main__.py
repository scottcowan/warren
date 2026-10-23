"""warren-sidecar entry point: run the agent-state recorder in the foreground."""

from __future__ import annotations

import asyncio

from warren_sidecar.recorder import run


def main() -> None:
    asyncio.run(run())


if __name__ == "__main__":
    main()
