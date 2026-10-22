"""Subprocess bridge to the real `warren` CLI binary.

Every MCP tool shells out to the actual `warren` executable rather than
importing warren_cli's internals directly — this guarantees the MCP server
always behaves exactly like running the CLI by hand (same config resolution,
same error messages, same validation), with zero risk of a second code path
drifting from what a human operator actually gets.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass

# `warren new`'s own provisioning (routes/workspaces.py's POST /workspaces)
# can legitimately take up to 120s for a multi-folder template (see
# main.py's _provision_and_poll comment) — the default must exceed that
# with margin, or a real successful provision gets killed here at the old
# 30s mark while the underlying `warren` subprocess keeps running
# unreported (audit 2026-10-16 #29).
_DEFAULT_TIMEOUT = 150.0


class WarrenCLINotFound(RuntimeError):
    pass


class WarrenCLITimeout(RuntimeError):
    pass


@dataclass
class CLIResult:
    returncode: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.returncode == 0

    def as_dict(self) -> dict:
        return {"ok": self.ok, "stdout": self.stdout, "stderr": self.stderr}

    def json_or_raise(self) -> dict | list:
        """Parse stdout as JSON — for subcommands that print JSON on success.
        Raises RuntimeError (with stderr attached) on a non-zero exit."""
        if not self.ok:
            raise RuntimeError(self.stderr.strip() or f"warren exited {self.returncode}")
        return json.loads(self.stdout)


def _warren_binary() -> str:
    path = shutil.which("warren")
    if path is None:
        raise WarrenCLINotFound(
            "'warren' not found on PATH — warren-mcp must run in the same "
            "environment (uv workspace venv) as the warren CLI."
        )
    return path


def run_warren(args: list[str], *, timeout: float = _DEFAULT_TIMEOUT) -> CLIResult:
    binary = _warren_binary()
    try:
        proc = subprocess.run(
            [binary, *args],
            capture_output=True,
            text=True,
            timeout=timeout,
            stdin=subprocess.DEVNULL,  # never let a prompt block an MCP tool call
        )
    except subprocess.TimeoutExpired as exc:
        raise WarrenCLITimeout(
            f"warren {' '.join(args)!r} did not complete within {timeout}s"
        ) from exc
    return CLIResult(returncode=proc.returncode, stdout=proc.stdout, stderr=proc.stderr)
