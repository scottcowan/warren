"""Headless runs (`warren run`): the template's app run once on a prompt, its stdout kept.

A run is a single-turn workspace (AH2) whose app command is built here from the
template's `app` and the caller's prompt:

- claude: `claude -p --output-format json <prompt>` (the JSON result carries the final
  message, `is_error`, `session_id`, turn count and cost)
- codex:  `codex exec <prompt>`
- gemini: `gemini -p <prompt>`
- any other app: the prompt is appended as its last argument.

Flags the template's `app` already carries (e.g. `--dangerously-skip-permissions`) are
kept. stdin is /dev/null, so no harness waits on it. stdout goes to OUTPUT_PATH and the
exit code to EXIT_NAME beside it (the harness state dir: bind-mounted from the server's
data dir on podman/docker, on the volume on ECS), and stdout is echoed to the container
log afterwards. When that file can't be created the app still runs, with its output only
in the log.
"""

from __future__ import annotations

import shlex
from pathlib import PurePosixPath

OUTPUT_DIR = "/var/lib/warren/harness/.session"
OUTPUT_NAME = "run-output.txt"
OUTPUT_PATH = f"{OUTPUT_DIR}/{OUTPUT_NAME}"
# Path parts below the harness state dir (registry.completion.read_nofollow).
OUTPUT_REL = (".session", OUTPUT_NAME)
# The app's exit code, written next to the output. On podman/docker the server images run
# the app inside tmux, so the container's own exit code is tmux's, not the app's.
EXIT_NAME = "run-exit-code"
EXIT_REL = (".session", EXIT_NAME)
# How much of the output is echoed to the container log once the app exits.
LOG_TAIL_BYTES = 65536

_HEADLESS: dict[str, tuple[tuple[str, ...], tuple[str, ...]]] = {
    # name: (flags added unless already present, flags that mean "already headless")
    "claude": (("-p", "--output-format", "json"), ("-p", "--print")),
    "codex": (("exec",), ("exec", "e")),
    "gemini": (("-p",), ("-p", "--prompt")),
}


def _argv(app: str) -> list[str]:
    try:
        return shlex.split(app)
    except ValueError as exc:
        raise ValueError(f"app is not a valid command line: {exc}") from exc


def harness_of(app: str) -> str:
    """The known harness `app` runs ("" for any other program)."""
    argv = _argv(app or "")
    name = PurePosixPath(argv[0]).name if argv else ""
    return name if name in _HEADLESS else ""


_MARKER = "warren-run"


def run_harness(command: str) -> str:
    """The harness a headless_command() runs ("" for another program or not a run)."""
    prefix = f": {_MARKER} "
    if not command.startswith(prefix):
        return ""
    name = command[len(prefix):].split(";", 1)[0].strip()
    return name if name in _HEADLESS else ""


def headless_argv(app: str, prompt: str) -> list[str]:
    """`app` as argv with the harness's headless flags and the prompt appended."""
    argv = _argv(app)
    if not argv:
        raise ValueError("app is empty")
    harness = harness_of(app)
    if harness:
        add, already = _HEADLESS[harness]
        rest = argv[1:]
        if not any(flag in rest for flag in already):
            if harness == "codex":
                rest = [*add, *rest]
            else:
                rest = [*rest, *add]
        elif harness == "claude" and "--output-format" not in rest:
            rest = [*rest, "--output-format", "json"]
        argv = [argv[0], *rest]
    return [*argv, prompt]


def headless_command(app: str, prompt: str) -> str:
    """One shell command string (WARREN_APP / WARREN_APP_CMD) running the app headless,
    keeping its stdout in OUTPUT_PATH and exiting with the app's own exit code."""
    cmd = shlex.join(headless_argv(app, prompt)) + " < /dev/null"
    d = shlex.quote(OUTPUT_DIR)
    out = shlex.quote(OUTPUT_PATH)
    code = shlex.quote(f"{OUTPUT_DIR}/{EXIT_NAME}")
    # A no-op marker naming the harness, so the server can parse the output later
    # (run_harness) from the persisted app command alone.
    return (
        f": {_MARKER} {harness_of(app) or '-'}; "
        f"if mkdir -p {d} 2>/dev/null && : > {out} 2>/dev/null; then "
        f"{cmd} > {out}; rc=$?; echo $rc > {code}; tail -c {LOG_TAIL_BYTES} {out}; "
        f"else {cmd}; rc=$?; fi; exit $rc"
    )
