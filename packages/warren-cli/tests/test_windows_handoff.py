"""AC1.2: interactive hand-offs exec on POSIX, run as a foreground child on Windows."""

from __future__ import annotations

import signal

import pytest
import typer


def test_hand_off_execs_on_posix(monkeypatch):
    from warren_cli import dispatch as d

    monkeypatch.setattr(d.winsupport.sys, "platform", "linux")
    calls = []

    def _execvp(file, argv):
        calls.append(("execvp", file, argv))
        raise SystemExit(0)

    def _execvpe(file, argv, env):
        calls.append(("execvpe", file, argv, env))
        raise SystemExit(0)

    monkeypatch.setattr(d.os, "execvp", _execvp)
    monkeypatch.setattr(d.os, "execvpe", _execvpe)
    monkeypatch.setattr(d.subprocess, "Popen", lambda *a, **k: pytest.fail("spawned on POSIX"))

    with pytest.raises(SystemExit):
        d._hand_off("/usr/bin/ssh", ["/usr/bin/ssh", "-t", "host"])
    with pytest.raises(SystemExit):
        d._hand_off("docker", ["docker", "exec"], {"PATH": "/bin"})
    assert calls == [
        ("execvp", "/usr/bin/ssh", ["/usr/bin/ssh", "-t", "host"]),
        ("execvpe", "docker", ["docker", "exec"], {"PATH": "/bin"}),
    ]


class _Proc:
    def __init__(self, rc, seen):
        self.rc = rc
        self.seen = seen

    def wait(self):
        self.seen["sigint_during_wait"] = signal.getsignal(signal.SIGINT)
        return self.rc


def _windows(monkeypatch, rc):
    from warren_cli import dispatch as d

    seen: dict = {}
    monkeypatch.setattr(d.winsupport.sys, "platform", "win32")
    monkeypatch.setattr(d.os, "execvp", lambda *a: pytest.fail("execvp on Windows"))
    monkeypatch.setattr(d.os, "execvpe", lambda *a: pytest.fail("execvpe on Windows"))

    def _popen(argv, env=None):
        seen["argv"] = argv
        seen["env"] = env
        seen["sigint_at_spawn"] = signal.getsignal(signal.SIGINT)
        return _Proc(rc, seen)

    monkeypatch.setattr(d.subprocess, "Popen", _popen)
    monkeypatch.setattr(
        d.shutil, "which", lambda name, path=None: f"C:\\Tools\\{name}.exe" if name == "aws" else None
    )
    return d, seen


def test_hand_off_runs_child_and_exits_with_its_code_on_windows(monkeypatch):
    d, seen = _windows(monkeypatch, 3)
    before = signal.getsignal(signal.SIGINT)
    with pytest.raises(typer.Exit) as exc:
        d._hand_off("aws", ["aws", "ssm", "start-session"])
    assert exc.value.exit_code == 3
    assert seen["argv"] == ["C:\\Tools\\aws.exe", "ssm", "start-session"]
    assert seen["sigint_during_wait"] is signal.SIG_IGN
    assert seen["sigint_at_spawn"] is not signal.SIG_IGN
    assert signal.getsignal(signal.SIGINT) is before


def test_hand_off_passes_env_on_windows(monkeypatch):
    d, seen = _windows(monkeypatch, 0)
    with pytest.raises(typer.Exit) as exc:
        d._hand_off("docker", ["docker", "exec", "-it", "c1", "bash"], {"PATH": "C:\\bin"})
    assert exc.value.exit_code == 0
    assert seen["argv"] == ["docker", "exec", "-it", "c1", "bash"]
    assert seen["env"] == {"PATH": "C:\\bin"}


def test_ssh_podman_connect_uses_hand_off_on_windows(monkeypatch):
    d, seen = _windows(monkeypatch, 130)
    monkeypatch.setattr(
        d.shutil, "which", lambda name, path=None: "C:\\Windows\\System32\\OpenSSH\\ssh.exe"
    )
    monkeypatch.setattr(d.winsupport.os, "listdir", lambda p: ["openssh-ssh-agent"])
    monkeypatch.delenv("SSH_AUTH_SOCK", raising=False)
    with pytest.raises(typer.Exit) as exc:
        d.connect_via_ssh_podman_exec("node2", "abc123")
    assert exc.value.exit_code == 130
    assert seen["argv"][0].endswith("ssh.exe")
    assert seen["argv"][1] == "-t"
    assert seen["env"]["SSH_AUTH_SOCK"] == "\\\\.\\pipe\\openssh-ssh-agent"


def test_tunnel_uses_hand_off_on_windows(monkeypatch):
    d, seen = _windows(monkeypatch, 0)
    monkeypatch.setattr(d.shutil, "which", lambda name, path=None: f"C:\\Tools\\{name}.exe")
    monkeypatch.setattr(d, "_resolve_ecs_container_runtime_id", lambda c, t: "rt-1")
    state = {
        "runtime_type": "ecs",
        "workspace_id": "ws-1",
        "ecs_cluster": "cl",
        "container_id": "arn:aws:ecs:eu-west-1:1:task/cl/abc",
    }
    with pytest.raises(typer.Exit) as exc:
        d._tunnel_via_execvp(state, remote_port=8420)
    assert exc.value.exit_code == 0
    assert seen["argv"][1:4] == ["ssm", "start-session", "--target"]
    assert seen["argv"][4] == "ecs:cl_abc_rt-1"


def test_credentials_endpoint_liveness_never_os_kills_on_windows(monkeypatch):
    from warren_cli import github_app

    monkeypatch.setattr(github_app.winsupport, "is_windows", lambda: True)
    monkeypatch.setattr(github_app.os, "kill", lambda *a: pytest.fail("os.kill sends CTRL_C_EVENT on Windows"))
    monkeypatch.setattr(github_app.winsupport, "windows_pid_alive", lambda pid: pid == 42)
    assert github_app._pid_alive(42) is True
    assert github_app._pid_alive(7) is False


def test_conftest_isolates_home_on_every_platform():
    import os
    from pathlib import Path

    assert Path.home() == Path(os.environ["HOME"])
    assert os.environ["USERPROFILE"] == os.environ["HOME"]
