"""`start_ssh_port_forward`/`start_orchestrator_port_forward` must drain
their subprocess's stdout/stderr pipes continuously, not just via
`communicate()` on the early-failure path (audit 2026-10-16 #35) -- a real
process writing enough to either pipe during normal operation could
otherwise fill the OS pipe buffer and stall.

These exercise a real subprocess that writes well past the typical 64KB
pipe buffer size, proving the drainer keeps up rather than relying on
`communicate()` (which these functions no longer call at all on success).
"""

from __future__ import annotations

import socket
import subprocess
import sys
import time

from warren_cli.dispatch import _start_pipe_drainers


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def test_drainer_keeps_up_with_a_chatty_subprocess_and_captures_tail_on_exit():
    # Writes 200k bytes to stderr (several times a typical 64KB pipe buffer)
    # then exits non-zero -- without draining, this write would block forever
    # and the process would never reach exit().
    script = (
        "import sys\n"
        "sys.stderr.write('line\\n' * 40000)\n"
        "sys.stderr.write('FINAL MARKER\\n')\n"
        "sys.exit(7)\n"
    )
    proc = subprocess.Popen(
        [sys.executable, "-c", script],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    stderr_tail = _start_pipe_drainers(proc)

    returncode = proc.wait(timeout=10)
    time.sleep(0.5)  # let the daemon drain threads finish reading past EOF

    assert returncode == 7
    assert "FINAL MARKER" in "".join(stderr_tail)
