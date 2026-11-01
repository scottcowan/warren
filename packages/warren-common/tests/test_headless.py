"""Headless runs: the app command built from a template's app and a prompt."""

from __future__ import annotations

import os
import shlex
import stat
import subprocess
from pathlib import Path

import pytest
from warren_common import headless


@pytest.mark.parametrize(
    ("app", "argv"),
    [
        ("claude", ["claude", "-p", "--output-format", "json", "P"]),
        ("claude --dangerously-skip-permissions", ["claude", "--dangerously-skip-permissions", "-p", "--output-format", "json", "P"]),
        ("claude -p", ["claude", "-p", "--output-format", "json", "P"]),
        ("claude -p --output-format stream-json --verbose", ["claude", "-p", "--output-format", "stream-json", "--verbose", "P"]),
        ("/usr/local/bin/codex --full-auto", ["/usr/local/bin/codex", "exec", "--full-auto", "P"]),
        ("codex exec", ["codex", "exec", "P"]),
        ("gemini", ["gemini", "-p", "P"]),
        ("./run-task.sh --fast", ["./run-task.sh", "--fast", "P"]),
    ],
)
def test_headless_argv(app, argv):
    assert headless.headless_argv(app, "P") == argv


def test_bad_app_is_rejected():
    with pytest.raises(ValueError):
        headless.headless_argv("", "P")
    with pytest.raises(ValueError):
        headless.headless_argv("claude 'unterminated", "P")


def test_run_harness_reads_the_marker():
    assert headless.run_harness(headless.headless_command("claude", "x")) == "claude"
    assert headless.run_harness(headless.headless_command("./task.sh", "x")) == ""
    assert headless.run_harness("claude -p hi") == ""


def _fake_app(tmp_path: Path, body: str) -> Path:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    tool = bin_dir / "claude"
    tool.write_text("#!/bin/sh\n" + body)
    tool.chmod(tool.stat().st_mode | stat.S_IXUSR)
    return bin_dir


def _run(cmd: str, bin_dir: Path) -> subprocess.CompletedProcess:
    env = {**os.environ, "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}"}
    return subprocess.run(["sh", "-c", cmd], env=env, capture_output=True, text=True, check=False)


def test_command_keeps_stdout_and_exit_code(tmp_path: Path, monkeypatch):
    out_dir = tmp_path / "harness" / ".session"
    monkeypatch.setattr(headless, "OUTPUT_DIR", str(out_dir))
    monkeypatch.setattr(headless, "OUTPUT_PATH", str(out_dir / "run-output.txt"))
    bin_dir = _fake_app(tmp_path, 'printf "%s|" "$@"; read x && echo "stdin:$x"; exit 4\n')

    prompt = "fix it; rm -rf / $(whoami) 'quoted'"
    proc = _run(headless.headless_command("claude", prompt), bin_dir)

    assert proc.returncode == 4
    saved = (out_dir / "run-output.txt").read_text()
    assert saved == f"-p|--output-format|json|{prompt}|"  # one argv, nothing read from stdin
    assert proc.stdout == saved  # echoed to the container log afterwards
    assert (out_dir / headless.EXIT_NAME).read_text() == "4\n"


def test_command_still_runs_when_the_output_file_cannot_be_created(tmp_path: Path, monkeypatch):
    blocker = tmp_path / "file"
    blocker.write_text("")
    monkeypatch.setattr(headless, "OUTPUT_DIR", str(blocker / "sub"))
    monkeypatch.setattr(headless, "OUTPUT_PATH", str(blocker / "sub" / "out.txt"))
    bin_dir = _fake_app(tmp_path, 'echo ran; exit 0\n')

    proc = _run(headless.headless_command("claude", "x"), bin_dir)

    assert proc.returncode == 0 and proc.stdout == "ran\n"


def test_command_is_one_shell_safe_string():
    cmd = headless.headless_command("claude", "a'b")
    assert shlex.split(cmd)[:3] == [":", "warren-run", "claude;"]
