"""AC1.4: ssh-agent resolution on Windows (OpenSSH named pipe)."""

from __future__ import annotations

import os
import sys

import pytest

import warren_common.winsupport as ws

_AGENT_PIPE = "\\\\.\\pipe\\openssh-ssh-agent"


@pytest.fixture
def windows(monkeypatch):
    pipes: list[str] = []
    monkeypatch.setattr(ws.sys, "platform", "win32")
    monkeypatch.setattr(ws.os, "listdir", lambda p: list(pipes) if p == ws.PIPE_PREFIX else [])
    return pipes


def test_existing_auth_sock_wins(tmp_path, windows):
    sock = tmp_path / "agent.sock"
    sock.write_text("")
    windows.append("openssh-ssh-agent")
    assert ws.ssh_agent_socket({"SSH_AUTH_SOCK": str(sock)}) == str(sock)


def test_windows_unset_auth_sock_uses_openssh_pipe(windows):
    windows.append("openssh-ssh-agent")
    assert ws.ssh_agent_socket({}) == _AGENT_PIPE


def test_windows_stale_posix_auth_sock_falls_back_to_pipe(windows):
    windows.append("openssh-ssh-agent")
    assert ws.ssh_agent_socket({"SSH_AUTH_SOCK": "/tmp/ssh-XXXX/agent.1"}) == _AGENT_PIPE


def test_windows_no_agent_running(windows):
    assert ws.ssh_agent_socket({}) is None


def test_posix_never_guesses_a_pipe(monkeypatch):
    monkeypatch.setattr(ws.sys, "platform", "linux")
    monkeypatch.setattr(ws.os, "listdir", lambda p: ["openssh-ssh-agent"])
    assert ws.ssh_agent_socket({}) is None
    assert ws.ssh_agent_socket({"SSH_AUTH_SOCK": "/nonexistent/agent"}) is None


def test_ssh_client_env_inherits_on_posix(monkeypatch):
    monkeypatch.setattr(ws.sys, "platform", "darwin")
    assert ws.ssh_client_env({"SSH_AUTH_SOCK": "/tmp/x"}) is None


def test_ssh_client_env_points_at_pipe_on_windows(windows):
    windows.append("openssh-ssh-agent")
    env = ws.ssh_client_env({"SSH_AUTH_SOCK": "/tmp/stale", "PATH": "C:\\bin"})
    assert env == {"SSH_AUTH_SOCK": _AGENT_PIPE, "PATH": "C:\\bin"}


def test_ssh_client_env_drops_stale_sock_without_agent(windows):
    env = ws.ssh_client_env({"SSH_AUTH_SOCK": "/tmp/stale", "PATH": "C:\\bin"})
    assert env == {"PATH": "C:\\bin"}


@pytest.mark.skipif(sys.platform != "win32", reason="real Win32 process query")
def test_windows_pid_alive_real():
    assert ws.windows_pid_alive(os.getpid()) is True
    assert ws.windows_pid_alive(0x7FFFFFF0) is False
