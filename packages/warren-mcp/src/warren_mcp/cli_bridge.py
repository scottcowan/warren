"""Subprocess bridge to the real `warren` CLI binary.

Every MCP tool shells out to the actual `warren` executable rather than
importing warren_cli's internals directly — this guarantees the MCP server
always behaves exactly like running the CLI by hand (same config resolution,
same error messages, same validation), with zero risk of a second code path
drifting from what a human operator actually gets.

Environment (set in the MCP client's launch config):
  WARREN_MCP_BIN         absolute path of the warren executable (GUI-launched
                         clients often lack the shell PATH)
  WARREN_MCP_TIMEOUT     per-call timeout in seconds (default 150)
  WARREN_MCP_MAX_OUTPUT  chars of stdout / stderr kept per call (default 262144)
  AWS_PROFILE, AWS_REGION, AWS_*  pass through to the CLI and its `aws` calls
"""

from __future__ import annotations

import json
import os
import re
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
_DEFAULT_MAX_OUTPUT = 256 * 1024


def default_timeout() -> float:
    """Per-call subprocess timeout; WARREN_MCP_TIMEOUT (seconds) overrides."""
    try:
        value = float(os.environ.get("WARREN_MCP_TIMEOUT", ""))
    except ValueError:
        return _DEFAULT_TIMEOUT
    return value if value > 0 else _DEFAULT_TIMEOUT


def _max_output() -> int:
    try:
        value = int(os.environ.get("WARREN_MCP_MAX_OUTPUT", ""))
    except ValueError:
        return _DEFAULT_MAX_OUTPUT
    return value if value > 0 else _DEFAULT_MAX_OUTPUT


# (pattern, hint) — first match wins. Hints tell an MCP client what a human
# must do; the bridge never runs `aws sso login` itself (it needs a browser).
_HINTS: list[tuple[re.Pattern[str], str]] = [
    (
        re.compile(
            r"sso session .*expired|token has expired|unable to locate credentials|"
            r"expiredtoken|invalidclienttokenid|unable to refresh|error loading sso token|"
            r"credentials.*(expired|not found)",
            re.I,
        ),
        "AWS credentials are missing or expired. Ask the user to run "
        "`aws sso login --profile <profile>` in a terminal (the MCP launch config "
        "must pass the same AWS_PROFILE / AWS_REGION), then retry.",
    ),
    (
        re.compile(r"session-?manager-?plugin", re.I),
        "The AWS session-manager-plugin is not installed or not on PATH for the MCP "
        "server process; install it (needed for ECS Exec / tunnels) and retry.",
    ),
    (
        re.compile(r"pass --server|--server .*required|no remotes configured|non-interactive", re.I),
        "No warren server was selected. Pass the `server` argument or set "
        "WARREN_MCP_SERVER in the MCP launch config (see list_remotes).",
    ),
]


def failure_hint(stderr: str) -> str | None:
    for pattern, hint in _HINTS:
        if pattern.search(stderr):
            return hint
    return None


class WarrenCLINotFound(RuntimeError):
    pass


class WarrenCLITimeout(RuntimeError):
    pass


@dataclass
class CLIResult:
    returncode: int
    stdout: str
    stderr: str
    truncated: bool = False

    @property
    def ok(self) -> bool:
        return self.returncode == 0

    def as_dict(self) -> dict:
        out: dict = {"ok": self.ok, "stdout": self.stdout, "stderr": self.stderr}
        if self.truncated:
            out["truncated"] = True
        if not self.ok and (hint := failure_hint(self.stderr)):
            out["hint"] = hint
        return out

    def json_or_raise(self) -> dict | list:
        """Parse stdout as JSON — for subcommands that print JSON on success.
        Raises RuntimeError (with stderr attached) on a non-zero exit."""
        if not self.ok:
            raise RuntimeError(self.stderr.strip() or f"warren exited {self.returncode}")
        return json.loads(self.stdout)


def _warren_binary() -> str:
    override = os.environ.get("WARREN_MCP_BIN")
    if override:
        return override
    path = shutil.which("warren")
    if path is None:
        raise WarrenCLINotFound(
            "'warren' not found on PATH — warren-mcp must run in the same "
            "environment (uv workspace venv) as the warren CLI, or set "
            "WARREN_MCP_BIN to its absolute path."
        )
    return path


def _cap(text: str, limit: int) -> tuple[str, bool]:
    if len(text) <= limit:
        return text, False
    return text[:limit] + f"\n...[truncated {len(text) - limit} chars]", True


def _child_env() -> dict[str, str]:
    """The MCP client's env (AWS_PROFILE, AWS_REGION, AWS_* creds, WARREN_*)
    passes through; output is made non-interactive."""
    env = dict(os.environ)
    env.setdefault("NO_COLOR", "1")
    env["TERM"] = "dumb"
    env["AWS_PAGER"] = ""  # `aws` must never open a pager in a headless call
    return env


def run_warren(args: list[str], *, timeout: float | None = None) -> CLIResult:
    binary = _warren_binary()
    if timeout is None:
        timeout = default_timeout()
    try:
        proc = subprocess.run(
            [binary, *args],
            capture_output=True,
            text=True,
            timeout=timeout,
            stdin=subprocess.DEVNULL,  # never let a prompt block an MCP tool call
            env=_child_env(),
        )
    except subprocess.TimeoutExpired as exc:
        raise WarrenCLITimeout(
            f"warren {' '.join(args)!r} did not complete within {timeout}s"
        ) from exc
    except FileNotFoundError as exc:
        raise WarrenCLINotFound(f"cannot execute warren binary {binary!r}") from exc
    limit = _max_output()
    out, t1 = _cap(proc.stdout or "", limit)
    err, t2 = _cap(proc.stderr or "", limit)
    return CLIResult(returncode=proc.returncode, stdout=out, stderr=err, truncated=t1 or t2)
