"""ecs-base's warren-session (AG2a): the warren shell in tmux session `main`, with
`warren connect --harness/--new` passed through. Runs the real script as a
non-root user against a fake tmux."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).parents[3] / "images" / "ecs-base" / "warren-session.sh"

pytestmark = pytest.mark.skipif(
    sys.platform == "win32" or os.geteuid() == 0, reason="runs the POSIX script as non-root"
)


def _run(tmp_path, *args, live=False):
    log = tmp_path / "tmux.log"
    tmux = tmp_path / "tmux"
    tmux.write_text(
        f'#!/bin/sh\necho "tmux $*" >> {log}\n[ "$1" = has-session ] && exit {0 if live else 1}\nexit 0\n'
    )
    tmux.chmod(0o755)
    script = tmp_path / "warren-session"
    script.write_text(SCRIPT.read_text().replace("/usr/bin/tmux", str(tmux)))
    script.chmod(0o755)
    r = subprocess.run(
        ["/bin/sh", str(script), *args], env={"HOME": str(tmp_path)}, capture_output=True, text=True, timeout=10
    )
    return r, (log.read_text().splitlines()[-1] if log.exists() else "")


def test_plain_connect_attaches_or_creates_main(tmp_path):
    r, last = _run(tmp_path, "zsh")
    assert r.returncode == 0, r.stderr
    assert last == "tmux new-session -A -s main -e WARREN_CONNECT=1 /bin/zsh"


def test_harness_on_live_session_opens_a_window(tmp_path):
    _, last = _run(tmp_path, "bash", "codex", "new", live=True)
    assert last == (
        "tmux new-window -t main -e WARREN_CONNECT=1 -e WARREN_CONNECT_HARNESS=codex "
        "-e WARREN_CONNECT_NEW=1 /bin/bash ; attach-session -t main"
    )


@pytest.mark.parametrize("bad", ["codex;id", "-e", "Codex", "a b"])
def test_rejects_bad_harness_names(tmp_path, bad):
    r, last = _run(tmp_path, "bash", bad)
    assert r.returncode == 2 and last == ""



ENTRYPOINT = SCRIPT.parent / "entrypoint.sh"
DOCKERFILE = SCRIPT.parent / "Dockerfile"


def test_entrypoint_runs_an_agent_under_the_supervisor_as_warren():
    """AG2b: the supervisor, not the harness, replaces WARREN_APP_CMD for agent workspaces."""
    text = ENTRYPOINT.read_text()
    root_phase_end = text.index("exec /sbin/su-exec warren:warren")
    agent = text.index('exec "$_py" /usr/local/bin/warren-agent-supervisor')
    assert root_phase_end < agent < text.index('exec sh -c "$WARREN_APP_CMD"')
    assert "agent_supervisor.py /usr/local/bin/warren-agent-supervisor" in DOCKERFILE.read_text()


def test_entrypoint_runs_the_baked_harness_init_as_warren():
    """AB1/AG3: the profile data lives in the image, not in RunTask overrides."""
    text = ENTRYPOINT.read_text()
    root_phase_end = text.index("exec /sbin/su-exec warren:warren")
    assert text.index("/usr/local/bin/warren-harness-init /var/lib/warren/harness") > root_phase_end
    assert "warren_harness_init.sh /usr/local/bin/warren-harness-init" in DOCKERFILE.read_text()
    assert "WARREN_HARNESS_PRUNE" not in text and "WARREN_HARNESS_DIRS" not in text
