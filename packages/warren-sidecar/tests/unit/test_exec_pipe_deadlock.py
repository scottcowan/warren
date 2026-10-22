"""Audit 2026-10-16 P1 #28: /exec must not deadlock on a large stderr write.

The old implementation drained stdout to EOF before even starting to read
stderr -- a command that writes more than its stderr pipe's OS buffer
(~64KB) while stdout isn't being read blocks forever trying to write more,
hanging this route indefinitely. Both streams must be read concurrently.
"""

from __future__ import annotations

import json

from fastapi.testclient import TestClient

from warren_sidecar.app import app

# Comfortably larger than every common OS pipe buffer size (64KB on Linux,
# 16KB on macOS) so a sequential stdout-then-stderr drain would hang on
# this write.
_LARGE_WRITE_BYTES = 200_000


def test_exec_large_stderr_does_not_deadlock(env_defaults, auth_headers):
    """A command writing well past the stderr pipe buffer, with nothing
    reading stdout concurrently, must still complete -- this would have
    hung indefinitely before the concurrent-read fix."""
    cmd = [
        "python3",
        "-c",
        (
            "import sys; sys.stderr.write('e' * "
            f"{_LARGE_WRITE_BYTES}); sys.stderr.flush()"
        ),
    ]
    with TestClient(app) as client:
        response = client.post("/exec", json={"cmd": cmd}, headers=auth_headers)

    assert response.status_code == 200
    lines = [line for line in response.text.splitlines() if line.strip()]
    events = [json.loads(line) for line in lines]
    exit_events = [e for e in events if e["type"] == "exec_exit"]
    assert exit_events
    assert exit_events[-1]["returncode"] == 0

    stderr_total = sum(
        len(e["content"]) for e in events if e.get("stream") == "stderr"
    )
    assert stderr_total == _LARGE_WRITE_BYTES


def test_exec_interleaves_stdout_and_stderr(env_defaults, auth_headers):
    cmd = [
        "python3",
        "-c",
        (
            "import sys; sys.stdout.write('out\\n'); sys.stdout.flush(); "
            "sys.stderr.write('err\\n'); sys.stderr.flush()"
        ),
    ]
    with TestClient(app) as client:
        response = client.post("/exec", json={"cmd": cmd}, headers=auth_headers)

    assert response.status_code == 200
    lines = [line for line in response.text.splitlines() if line.strip()]
    events = [json.loads(line) for line in lines]
    streams = {e["stream"] for e in events if e["type"] == "exec_output"}
    assert streams == {"stdout", "stderr"}
