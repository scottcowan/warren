"""Wave 0 RED: dispatch.provision_local --connect handoff via os.execvp (Plan 05-05).

D-05: `connect` must call os.execvp AFTER asyncio.run has returned — NOT from
within an async coroutine — so the event loop's epoll/pipe fds don't leak
into the exec'd process.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

posix_exec_only = pytest.mark.skipif(
    sys.platform == "win32", reason="asserts the POSIX os.execvp hand-off; Windows covered by test_windows_handoff"
)



def _write_project_yaml(projects_dir: Path, name: str = "demo") -> Path:
    yaml_text = (
        f"name: {name}\n"
        "description: t\n"
        "repo: git@github.com:example/demo.git\n"
        "bare_path: /tmp/demo/.git-store\n"
        "docker_image: ghcr.io/example/base:latest\n"
        "templates:\n"
        "  claude:\n"
        "    description: agent\n"
        "    permission: write\n"
        "    app: claude\n"
    )
    path = projects_dir / f"{name}.yaml"
    path.write_text(yaml_text)
    return path


class _FakeState(dict):
    pass


@posix_exec_only
def test_provision_local_connect_calls_execvp_after_asyncio_run(
    tmp_path: Path, monkeypatch
):
    from warren_cli import dispatch

    projects_dir = tmp_path / "projects"
    projects_dir.mkdir()
    _write_project_yaml(projects_dir)

    order: list[str] = []
    execvp_args: list = []

    def _fake_execvpe(prog, argv, env):
        order.append("execvp")
        execvp_args.append((prog, list(argv)))
        # os.execvpe normally never returns; simulate by raising a marker.
        raise SystemExit(0)

    real_asyncio_run = dispatch.asyncio.run

    fake_state = _FakeState(
        runtime_type="nsjail",
        app="claude",
        workspace_id="ws-1",
        bind_mounts=[],
        ssh_key_paths=[],
        ssh_agent_sock=None,
    )
    (tmp_path / "nsjail-state").mkdir(exist_ok=True)
    (tmp_path / "nsjail-state" / "state.json").write_text(json.dumps(fake_state))
    fake_state["nsjail_state_dir"] = str(tmp_path / "nsjail-state")

    def _fake_asyncio_run(coro):
        order.append("asyncio.run")
        # Close the coroutine we're refusing to actually execute.
        try:
            coro.close()
        except Exception:
            pass
        return fake_state

    monkeypatch.setattr(dispatch.asyncio, "run", _fake_asyncio_run)
    # nsjail/docker/seatbelt now get an explicit allow-listed env via execvpe
    # (audit finding #4), not os.execvp inheriting the full operator os.environ.
    monkeypatch.setattr(os, "execvpe", _fake_execvpe)
    monkeypatch.setenv("WARREN_NSJAIL_PATH", "/usr/sbin/nsjail")

    from types import SimpleNamespace
    cfg = SimpleNamespace(
        defaults=SimpleNamespace(mode="local"),
        runtime=SimpleNamespace(type="nsjail"),
        images={},
    )
    with pytest.raises(SystemExit):
        dispatch.provision_local(
            "demo", "claude", projects_dir, connect=True, cfg=cfg, runtime=None
        )

    assert order == ["asyncio.run", "execvp"], (
        f"execvp must be called AFTER asyncio.run returns; got order={order!r}"
    )
    assert execvp_args, "os.execvp was not called"
    prog, argv = execvp_args[0]
    assert argv[0] == "nsjail" or Path(argv[0]).name == "nsjail"
    assert "--config" in argv
    assert argv[-2] == "--"
    # AG2a: a harness app still lands in the warren shell.
    assert argv[-1] == "bash"


@posix_exec_only
def test_execvp_called_with_flushed_stdio(tmp_path: Path, monkeypatch):
    from warren_cli import dispatch

    projects_dir = tmp_path / "projects"
    projects_dir.mkdir()
    _write_project_yaml(projects_dir)

    flushes: list[str] = []

    orig_stdout_flush = sys.stdout.flush
    orig_stderr_flush = sys.stderr.flush

    def _rec_stdout(*a, **kw):
        flushes.append("stdout")
        return orig_stdout_flush()

    def _rec_stderr(*a, **kw):
        flushes.append("stderr")
        return orig_stderr_flush()

    def _fake_execvpe(prog, argv, env):
        flushes.append("execvp")
        raise SystemExit(0)

    fake_state = _FakeState(
        runtime_type="nsjail",
        app="claude",
        workspace_id="ws-1",
        bind_mounts=[],
        ssh_key_paths=[],
        ssh_agent_sock=None,
    )
    (tmp_path / "nsjail-state").mkdir(exist_ok=True)
    (tmp_path / "nsjail-state" / "state.json").write_text(json.dumps(fake_state))
    fake_state["nsjail_state_dir"] = str(tmp_path / "nsjail-state")

    def _fake_asyncio_run(coro):
        try:
            coro.close()
        except Exception:
            pass
        return fake_state

    monkeypatch.setattr(dispatch.asyncio, "run", _fake_asyncio_run)
    monkeypatch.setattr(os, "execvpe", _fake_execvpe)
    monkeypatch.setattr(sys.stdout, "flush", _rec_stdout)
    monkeypatch.setattr(sys.stderr, "flush", _rec_stderr)
    monkeypatch.setenv("WARREN_NSJAIL_PATH", "/usr/sbin/nsjail")

    from types import SimpleNamespace
    cfg = SimpleNamespace(
        defaults=SimpleNamespace(mode="local"),
        runtime=SimpleNamespace(type="nsjail"),
        images={},
    )
    with pytest.raises(SystemExit):
        dispatch.provision_local(
            "demo", "claude", projects_dir, connect=True, cfg=cfg, runtime=None
        )

    exec_idx = flushes.index("execvp")
    assert "stdout" in flushes[:exec_idx], f"stdout not flushed before execvp: {flushes!r}"
    assert "stderr" in flushes[:exec_idx], f"stderr not flushed before execvp: {flushes!r}"


@posix_exec_only
def test_connect_via_execvp_docker():
    from warren_cli import dispatch
    calls = []
    import warren_cli.dispatch as d
    import sys as _sys
    orig_execvpe = d.os.execvpe
    try:
        def _fake(prog, argv, env):
            calls.append((prog, list(argv), env))
            raise SystemExit(0)
        d.os.execvpe = _fake
        with pytest.raises(SystemExit):
            d._connect_via_execvp({
                "runtime_type": "docker",
                "container_id": "abc123",
                "app": "bash",
                "workspace_id": "ws",
            })
    finally:
        d.os.execvpe = orig_execvpe
    prog, argv, env = calls[0]
    assert argv[0] == "docker"
    assert argv[1] == "exec"
    assert "-it" in argv
    assert "abc123" in argv
    assert argv[-1] == "bash"


@posix_exec_only
def test_connect_via_execvp_seatbelt(tmp_path):
    from warren_cli import dispatch
    calls = []
    import warren_cli.dispatch as d
    orig_execvpe = d.os.execvpe
    try:
        def _fake(prog, argv, env):
            calls.append((prog, list(argv), env))
            raise SystemExit(0)
        d.os.execvpe = _fake
        with pytest.raises(SystemExit):
            d._connect_via_execvp({
                "runtime_type": "seatbelt",
                "profile_path": str(tmp_path / "sandbox.sb"),
                "app": "bash",
                "workspace_id": "ws",
            })
    finally:
        d.os.execvpe = orig_execvpe
    prog, argv, env = calls[0]
    assert argv[0] == "/usr/bin/sandbox-exec"
    assert "-f" in argv
    assert argv[-1] == "bash"


@posix_exec_only
def test_connect_via_execvp_bwrap():
    from warren_cli import dispatch
    calls = []
    import warren_cli.dispatch as d
    orig_execvp = d.os.execvp
    try:
        def _fake(prog, argv):
            calls.append((prog, list(argv)))
            raise SystemExit(0)
        d.os.execvp = _fake
        with pytest.raises(SystemExit):
            d._connect_via_execvp({
                "runtime_type": "bwrap",
                "bwrap_path": "/usr/bin/bwrap",
                "bwrap_args": ["--die-with-parent", "--", "bash"],
                "app": "bash",
                "workspace_id": "ws",
            })
    finally:
        d.os.execvp = orig_execvp
    prog, argv = calls[0]
    assert argv[0] == "/usr/bin/bwrap"
    assert argv[-1] == "bash"


@posix_exec_only
def test_connect_via_execvp_env_is_allowlisted_not_full_os_environ(tmp_path, monkeypatch):
    """Audit finding #4: _connect_via_execvp used to mutate os.environ and
    call plain os.execvp, which inherits the WHOLE calling process's
    environment — any AWS key/API token sitting in the operator's own shell
    (never declared by the template) reached the sandboxed process on top of
    env_snapshot. nsjail/docker/seatbelt now get an explicit env via
    execvpe; only the base allow-list (PATH/HOME/TERM/LANG) plus
    env_snapshot may appear in it."""
    from warren_cli import dispatch as d

    monkeypatch.setenv("WARREN_TOTALLY_UNRELATED_HOST_SECRET", "leaked-if-broken")
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))

    captured: dict = {}

    def _fake_execvpe(prog, argv, env):
        captured["env"] = env
        raise SystemExit(0)

    monkeypatch.setattr(d.os, "execvpe", _fake_execvpe)

    with pytest.raises(SystemExit):
        d._connect_via_execvp({
            "runtime_type": "seatbelt",
            "profile_path": str(tmp_path / "sandbox.sb"),
            "app": "bash",
            "workspace_id": "ws",
            "env_snapshot": {"FOO": "bar"},
        })

    assert "WARREN_TOTALLY_UNRELATED_HOST_SECRET" not in captured["env"]
    assert captured["env"]["FOO"] == "bar"


_ECS_TASK = "arn:aws:ecs:us-east-1:123:task/cl/abc"


class _FakePopen:
    """Stands in for an interactive `aws ecs execute-command`; stderr is the only pipe."""

    def __init__(self, rc: int, stderr: str = ""):
        import io

        self._rc = rc
        self.stderr = io.StringIO(stderr)

    def wait(self):
        return self._rc


def _patch_ecs_exec(monkeypatch, *, agent_statuses=("RUNNING",), popen_results=((0, ""),)):
    """Fake which/describe-tasks/execute-command; returns (describe_calls, exec_calls, sleeps)."""
    import subprocess

    import warren_cli.dispatch as d

    monkeypatch.setattr(
        d.shutil, "which",
        lambda name: {"aws": "/usr/bin/aws", "session-manager-plugin": "/usr/bin/smp"}.get(name),
    )
    statuses = list(agent_statuses)
    describe_calls: list = []

    def _fake_run(argv, **kw):
        describe_calls.append(argv)
        status = statuses.pop(0) if len(statuses) > 1 else statuses[0]
        return subprocess.CompletedProcess(argv, 0, stdout=status + "\n", stderr="")

    results = list(popen_results)
    exec_calls: list = []

    def _fake_popen(argv, **kw):
        exec_calls.append(argv)
        return _FakePopen(*results.pop(0))

    sleeps: list = []
    monkeypatch.setattr(d.subprocess, "run", _fake_run)
    monkeypatch.setattr(d.subprocess, "Popen", _fake_popen)
    monkeypatch.setattr(d.time, "sleep", sleeps.append)
    return describe_calls, exec_calls, sleeps


def test_connect_ecs_execvp(monkeypatch):
    """ECS connect runs aws ecs execute-command into the workspace container and
    exits with its status."""
    import typer as typer_mod
    import warren_cli.dispatch as d

    _, exec_calls, _ = _patch_ecs_exec(monkeypatch)

    with pytest.raises(typer_mod.Exit) as exc:
        d._connect_via_execvp({
            "runtime_type": "ecs",
            "container_id": _ECS_TASK,
            "ecs_cluster": "my-cluster",
            "app": "bash",
            "workspace_id": "ws-ecs",
        })

    assert exc.value.exit_code == 0
    assert exec_calls == [[
        "/usr/bin/aws", "ecs", "execute-command",
        "--cluster", "my-cluster",
        "--task", _ECS_TASK,
        "--container", "workspace",
        "--interactive",
        "--command", d.ecs_session_command("bash"),
    ]]


def test_ecs_session_command_runs_root_owned_helper_by_absolute_path():
    """ECS Exec runs as root: the helper is never resolved via the task's PATH, and
    PATH is reset before anything else runs."""
    import shlex

    import warren_cli.dispatch as d

    argv = shlex.split(d.ecs_session_command("zsh"))
    assert argv[:2] == ["/bin/sh", "-c"]
    script = argv[2]
    assert script.startswith("PATH=/usr/sbin:/usr/bin:/sbin:/bin; export PATH;")
    assert script.endswith("exec /usr/local/bin/warren-session zsh - -")
    assert "command -v" not in script
    assert "for d in /usr/local/bin /usr/local /usr;" in script


def test_ecs_session_command_never_falls_back_to_a_root_shell():
    import shlex

    import warren_cli.dispatch as d

    script = shlex.split(d.ecs_session_command("bash"))[2]
    assert script.count("refusing to open a root shell") == 2
    assert script.count("exit 1") == 2
    # The only exec is the helper: no bare `exec bash` path.
    assert [part for part in script.split(";") if "exec" in part] == [" exec /usr/local/bin/warren-session bash - -"]


def test_ecs_session_command_mode_patterns_require_root_owned_non_writable():
    """The case patterns match `stat -c %u%A` output."""
    from fnmatch import fnmatchcase

    import warren_cli.dispatch as d

    helper, dirs = d._ECS_HELPER_MODE_OK, d._ECS_DIR_MODE_OK
    assert fnmatchcase("0-rwxr-xr-x", helper)
    assert fnmatchcase("0-rwx------", helper)
    assert not fnmatchcase("1000-rwxr-xr-x", helper)
    assert not fnmatchcase("0-rwxrwxr-x", helper)
    assert not fnmatchcase("0-rwxr-xrwx", helper)
    assert not fnmatchcase("0-rw-r--r--", helper)
    assert not fnmatchcase("", helper)
    assert fnmatchcase("0drwxr-xr-x", dirs)
    assert not fnmatchcase("0drwxrwxrwx", dirs)
    assert not fnmatchcase("1000drwxr-xr-x", dirs)
    assert not fnmatchcase("0-rwxr-xr-x", dirs)


def test_ecs_session_command_rejects_non_shell_values():
    """The shell is interpolated into a sh -c string; anything outside the
    known shells falls back to bash instead of reaching the task's shell."""
    import warren_cli.dispatch as d

    assert d.ecs_session_command("bash; rm -rf /") == d.ecs_session_command("bash")
    assert d.ecs_session_command("claude") == d.ecs_session_command("bash")


def test_connect_via_ecs_exec_waits_for_execute_command_agent(monkeypatch, capsys):
    import typer as typer_mod
    import warren_cli.dispatch as d

    describe_calls, exec_calls, sleeps = _patch_ecs_exec(
        monkeypatch, agent_statuses=("None", "PENDING", "RUNNING")
    )

    with pytest.raises(typer_mod.Exit):
        d.connect_via_ecs_exec("my-cluster", _ECS_TASK)

    assert len(describe_calls) == 3
    query = describe_calls[0][describe_calls[0].index("--query") + 1]
    assert "managedAgents[?name=='ExecuteCommandAgent']" in query
    assert "containers[?name=='workspace']" in query
    assert len(sleeps) == 2
    assert len(exec_calls) == 1
    assert "waiting for the ECS Exec agent" in capsys.readouterr().err


def test_connect_via_ecs_exec_agent_wait_is_bounded(monkeypatch, capsys):
    import typer as typer_mod
    import warren_cli.dispatch as d

    _, exec_calls, _ = _patch_ecs_exec(monkeypatch, agent_statuses=("PENDING",))
    clock = iter(range(0, 10_000, 50))
    monkeypatch.setattr(d.time, "monotonic", lambda: float(next(clock)))

    with pytest.raises(typer_mod.Exit) as exc:
        d.connect_via_ecs_exec("my-cluster", _ECS_TASK)

    assert exc.value.exit_code == 1
    assert not exec_calls
    err = " ".join(capsys.readouterr().err.split())
    assert "not ready after 120s" in err
    assert "PENDING" in err


def test_connect_via_ecs_exec_stopped_agent_errors(monkeypatch, capsys):
    import typer as typer_mod
    import warren_cli.dispatch as d

    _, exec_calls, _ = _patch_ecs_exec(monkeypatch, agent_statuses=("STOPPED",))

    with pytest.raises(typer_mod.Exit):
        d.connect_via_ecs_exec("my-cluster", _ECS_TASK)

    assert not exec_calls
    assert "has stopped" in " ".join(capsys.readouterr().err.split())


def test_connect_via_ecs_exec_retries_transient_agent_error(monkeypatch, capsys):
    import typer as typer_mod
    import warren_cli.dispatch as d

    transient = (
        "An error occurred (InvalidParameterException) when calling the ExecuteCommand operation: "
        "The execute command failed because execute command agent isn't running. Wait and try again.\n"
    )
    _, exec_calls, sleeps = _patch_ecs_exec(
        monkeypatch, popen_results=((254, transient), (254, transient), (0, ""))
    )

    with pytest.raises(typer_mod.Exit) as exc:
        d.connect_via_ecs_exec("my-cluster", _ECS_TASK)

    assert exc.value.exit_code == 0
    assert len(exec_calls) == 3
    assert sleeps == [2.0, 4.0]
    assert "execute command agent isn't running" in capsys.readouterr().err


def test_connect_via_ecs_exec_gives_up_after_bounded_retries(monkeypatch):
    import typer as typer_mod
    import warren_cli.dispatch as d

    transient = "TargetNotConnectedException: try again\n"
    _, exec_calls, sleeps = _patch_ecs_exec(
        monkeypatch, popen_results=[(254, transient)] * d.ECS_EXEC_ATTEMPTS
    )

    with pytest.raises(typer_mod.Exit) as exc:
        d.connect_via_ecs_exec("my-cluster", _ECS_TASK)

    assert exc.value.exit_code == 254
    assert len(exec_calls) == d.ECS_EXEC_ATTEMPTS
    assert sleeps == [2.0, 4.0, 8.0]


def test_connect_via_ecs_exec_does_not_retry_other_failures(monkeypatch):
    import typer as typer_mod
    import warren_cli.dispatch as d

    _, exec_calls, sleeps = _patch_ecs_exec(
        monkeypatch, popen_results=((255, "AccessDeniedException: not authorized\n"),)
    )

    with pytest.raises(typer_mod.Exit) as exc:
        d.connect_via_ecs_exec("my-cluster", _ECS_TASK)

    assert exc.value.exit_code == 255
    assert len(exec_calls) == 1
    assert not sleeps


def test_connect_via_ecs_exec_session_exit_status_is_not_retried(monkeypatch):
    """A user's shell exiting non-zero after a real session isn't an agent error."""
    import typer as typer_mod
    import warren_cli.dispatch as d

    _, exec_calls, _ = _patch_ecs_exec(monkeypatch, popen_results=((130, ""),))

    with pytest.raises(typer_mod.Exit) as exc:
        d.connect_via_ecs_exec("my-cluster", _ECS_TASK)

    assert exc.value.exit_code == 130
    assert len(exec_calls) == 1


@posix_exec_only
def test_connect_via_ecs_exec_missing_aws_cli_uses_ui_error(monkeypatch, capsys):
    import typer as typer_mod
    import warren_cli.dispatch as d

    monkeypatch.setattr(d.shutil, "which", lambda name: None)
    execs = []
    monkeypatch.setattr(d.os, "execvp", lambda *a: execs.append(a))

    with pytest.raises(typer_mod.Exit):
        d.connect_via_ecs_exec("my-cluster", "arn:aws:ecs:us-east-1:123:task/cl/abc")

    assert "aws CLI not found" in capsys.readouterr().err
    assert not execs


def test_connect_ecs_missing_aws_cli(monkeypatch):
    """ECS connect: typer.Exit raised when aws CLI not found."""
    import typer as typer_mod
    import warren_cli.dispatch as d

    orig_which = d.shutil.which

    def _fake_which(name):
        return None  # aws not found

    d.shutil.which = _fake_which
    try:
        with pytest.raises((SystemExit, typer_mod.Exit)):
            d._connect_via_execvp({
                "runtime_type": "ecs",
                "container_id": "arn:aws:ecs:us-east-1:123:task/cl/abc",
                "ecs_cluster": "my-cluster",
                "app": "bash",
                "workspace_id": "ws-ecs",
            })
    finally:
        d.shutil.which = orig_which


def test_connect_ecs_missing_ssm_plugin(monkeypatch):
    """ECS connect: typer.Exit raised when session-manager-plugin not found."""
    import typer as typer_mod
    import warren_cli.dispatch as d

    orig_which = d.shutil.which

    def _fake_which(name):
        if name == "aws":
            return "/usr/bin/aws"
        return None  # session-manager-plugin not found

    d.shutil.which = _fake_which
    try:
        with pytest.raises((SystemExit, typer_mod.Exit)):
            d._connect_via_execvp({
                "runtime_type": "ecs",
                "container_id": "arn:aws:ecs:us-east-1:123:task/cl/abc",
                "ecs_cluster": "my-cluster",
                "app": "bash",
                "workspace_id": "ws-ecs",
            })
    finally:
        d.shutil.which = orig_which


def _fake_describe_tasks_result(runtime_id: str = "1234567890abcdef1234567890abcdef"):
    import subprocess

    return subprocess.CompletedProcess(args=[], returncode=0, stdout=runtime_id + "\n", stderr="")


@posix_exec_only
def test_tunnel_ecs_execvp(monkeypatch):
    """ECS tunnel: os.execvp called with aws ssm start-session port-forward args."""
    import warren_cli.dispatch as d

    calls = []
    orig_execvp = d.os.execvp
    orig_which = d.shutil.which
    orig_run = d.subprocess.run

    def _fake_execvp(prog, argv):
        calls.append((prog, list(argv)))
        raise SystemExit(0)

    def _fake_which(name):
        if name == "aws":
            return "/usr/bin/aws"
        if name == "session-manager-plugin":
            return "/usr/local/bin/session-manager-plugin"
        return None

    def _fake_run(argv, **kwargs):
        assert argv[:3] == ["aws", "ecs", "describe-tasks"]
        return _fake_describe_tasks_result("runtimeid123")

    d.os.execvp = _fake_execvp
    d.shutil.which = _fake_which
    d.subprocess.run = _fake_run
    try:
        with pytest.raises(SystemExit):
            d._tunnel_via_execvp(
                {
                    "runtime_type": "ecs",
                    "container_id": "arn:aws:ecs:us-east-1:123:task/cl/abc",
                    "ecs_cluster": "my-cluster",
                    "workspace_id": "ws-ecs",
                },
                remote_port=8420,
            )
    finally:
        d.os.execvp = orig_execvp
        d.shutil.which = orig_which
        d.subprocess.run = orig_run

    assert calls, "os.execvp was not called"
    prog, argv = calls[0]
    assert prog == "/usr/bin/aws"
    assert argv[:3] == ["aws", "ssm", "start-session"]
    assert "--target" in argv
    target_idx = argv.index("--target")
    assert argv[target_idx + 1] == "ecs:my-cluster_abc_runtimeid123"
    assert "--document-name" in argv
    doc_idx = argv.index("--document-name")
    assert argv[doc_idx + 1] == "AWS-StartPortForwardingSession"
    assert "--parameters" in argv
    params_idx = argv.index("--parameters")
    assert argv[params_idx + 1] == "portNumber=8420,localPortNumber=8420"


@posix_exec_only
def test_tunnel_ecs_local_port_override(monkeypatch):
    """ECS tunnel: --local-port overrides the default (same as remote port)."""
    import warren_cli.dispatch as d

    calls = []
    orig_execvp = d.os.execvp
    orig_which = d.shutil.which
    orig_run = d.subprocess.run

    d.os.execvp = lambda prog, argv: (calls.append((prog, list(argv))), (_ for _ in ()).throw(SystemExit(0)))[1]
    d.shutil.which = lambda name: "/usr/bin/aws" if name == "aws" else "/usr/local/bin/session-manager-plugin"
    d.subprocess.run = lambda argv, **kwargs: _fake_describe_tasks_result("rtid")
    try:
        with pytest.raises(SystemExit):
            d._tunnel_via_execvp(
                {
                    "runtime_type": "ecs",
                    "container_id": "arn:aws:ecs:us-east-1:123:task/cl/abc",
                    "ecs_cluster": "my-cluster",
                    "workspace_id": "ws-ecs",
                },
                remote_port=8420,
                local_port=9000,
            )
    finally:
        d.os.execvp = orig_execvp
        d.shutil.which = orig_which
        d.subprocess.run = orig_run

    _, argv = calls[0]
    params_idx = argv.index("--parameters")
    assert argv[params_idx + 1] == "portNumber=8420,localPortNumber=9000"


def test_tunnel_non_ecs_runtime_rejected():
    """tunnel only applies to ecs — local runtimes don't need it."""
    import typer as typer_mod
    import warren_cli.dispatch as d

    with pytest.raises((SystemExit, typer_mod.Exit)):
        d._tunnel_via_execvp({"runtime_type": "docker", "workspace_id": "ws-1"}, remote_port=8420)


def test_tunnel_ecs_missing_aws_cli():
    """tunnel: typer.Exit raised when aws CLI not found."""
    import typer as typer_mod
    import warren_cli.dispatch as d

    orig_which = d.shutil.which
    d.shutil.which = lambda name: None
    try:
        with pytest.raises((SystemExit, typer_mod.Exit)):
            d._tunnel_via_execvp(
                {"runtime_type": "ecs", "container_id": "arn:x", "ecs_cluster": "c", "workspace_id": "w"},
                remote_port=8420,
            )
    finally:
        d.shutil.which = orig_which


def test_tunnel_describe_tasks_failure_surfaces_error():
    """tunnel: a describe-tasks failure raises typer.Exit rather than exec'ing a bad target."""
    import typer as typer_mod
    import warren_cli.dispatch as d

    orig_which = d.shutil.which
    orig_run = d.subprocess.run
    d.shutil.which = lambda name: "/usr/bin/aws" if name == "aws" else "/usr/local/bin/session-manager-plugin"
    d.subprocess.run = lambda argv, **kwargs: _fake_describe_tasks_result("None")
    try:
        with pytest.raises((SystemExit, typer_mod.Exit)):
            d._tunnel_via_execvp(
                {
                    "runtime_type": "ecs",
                    "container_id": "arn:aws:ecs:us-east-1:123:task/cl/abc",
                    "ecs_cluster": "my-cluster",
                    "workspace_id": "ws-ecs",
                },
                remote_port=8420,
            )
    finally:
        d.shutil.which = orig_which
        d.subprocess.run = orig_run


@posix_exec_only
@pytest.mark.parametrize("app,rc_name", [("bash", ".bashrc"), ("zsh", ".zshrc")])
def test_connect_ignores_host_claude_settings_env_and_keeps_rc_secret_free(
    tmp_path, monkeypatch, app, rc_name
):
    """BB6: the host ~/.claude/settings.json `env` block must not reach the
    sandbox, and no env/secret value may be written into workspace rc files."""
    import json as _json

    from warren_cli import dispatch as d

    fake_home = tmp_path / "home"
    (fake_home / ".claude").mkdir(parents=True)
    (fake_home / ".claude" / "settings.json").write_text(
        _json.dumps({"env": {"HOST_ONLY_TOKEN": "host-settings-secret"}})
    )
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: fake_home))
    monkeypatch.setenv("HOME", str(fake_home))
    ws = tmp_path / "ws"
    ws.mkdir()

    captured: dict = {}

    def _fake_execvpe(prog, argv, env):
        captured["env"] = env
        raise SystemExit(0)

    monkeypatch.setattr(d.os, "execvpe", _fake_execvpe)

    with pytest.raises(SystemExit):
        d._connect_via_execvp({
            "runtime_type": "seatbelt",
            "profile_path": str(tmp_path / "sandbox.sb"),
            "app": app,
            "workspace_id": "ws",
            "root_path": str(ws),
            "env_snapshot": {"TEMPLATE_SECRET": "template-secret-value"},
        })

    assert "HOST_ONLY_TOKEN" not in captured["env"]
    assert captured["env"]["TEMPLATE_SECRET"] == "template-secret-value"
    rc_text = (ws / rc_name).read_text()
    assert "host-settings-secret" not in rc_text
    assert "template-secret-value" not in rc_text
    assert "HOST_ONLY_TOKEN" not in rc_text


@pytest.mark.parametrize(
    "app,rc_name,other_rc", [("bash", ".bashrc", ".zshrc"), ("zsh", ".zshrc", ".bashrc")]
)
@posix_exec_only
def test_connect_rewrites_old_rc_files_with_exports(tmp_path, monkeypatch, app, rc_name, other_rc):
    """BB13: rc files written by an older warren (with `export KEY=secret`
    lines) are regenerated from scratch on connect, not kept."""
    from warren_cli import dispatch as d

    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path / "home"))
    ws = tmp_path / "ws"
    ws.mkdir()
    old = "# warren workspace {} — minimal\nexport OLD_SECRET='old-secret-value'\n"
    (ws / rc_name).write_text(old.format(rc_name))
    (ws / other_rc).write_text(old.format(other_rc))
    victim = tmp_path / "victim"
    victim.write_text("host file")
    dyn = ws / (".warren_dynamic.zsh" if app == "zsh" else ".warren_dynamic.bash")
    dyn.symlink_to(victim)

    def _fake_execvpe(prog, argv, env):
        raise SystemExit(0)

    monkeypatch.setattr(d.os, "execvpe", _fake_execvpe)
    with pytest.raises(SystemExit):
        d._connect_via_execvp({
            "runtime_type": "seatbelt",
            "profile_path": str(tmp_path / "sandbox.sb"),
            "app": app,
            "workspace_id": "ws",
            "root_path": str(ws),
            "env_snapshot": {"TEMPLATE_SECRET": "template-secret-value"},
        })

    rc_text = (ws / rc_name).read_text()
    assert "old-secret-value" not in rc_text
    assert "OLD_SECRET" not in rc_text
    assert "WARREN_CLI=" in rc_text
    assert "alias warren=" not in rc_text
    assert not (ws / other_rc).exists()
    assert victim.read_text() == "host file"
    assert not dyn.is_symlink()


class _TTY:
    def __init__(self, tty: bool = True):
        self.buf = ""
        self._tty = tty

    def isatty(self):
        return self._tty

    def write(self, s):
        self.buf += s

    def flush(self):
        pass


def test_set_terminal_title_writes_osc0_with_labels(monkeypatch):
    from warren_cli import dispatch

    monkeypatch.delenv("WARREN_NO_TERMINAL_TITLE", raising=False)
    out = _TTY()
    dispatch.set_terminal_title("proj", "develop.claude", "abcdef1234567890", stream=out)
    assert out.buf == "\x1b]0;warren: proj/develop.claude (abcdef12)\x07"


def test_set_terminal_title_strips_control_bytes(monkeypatch):
    from warren_cli import dispatch

    monkeypatch.delenv("WARREN_NO_TERMINAL_TITLE", raising=False)
    out = _TTY()
    dispatch.set_terminal_title("p\x07\x1b]0;evil", "t", "ws", stream=out)
    inner = out.buf[len("\x1b]0;"):-1]
    assert "\x07" not in inner and "\x1b" not in inner


def test_set_terminal_title_noop_off_tty_or_opted_out(monkeypatch):
    from warren_cli import dispatch

    out = _TTY(tty=False)
    dispatch.set_terminal_title("p", "t", "ws", stream=out)
    assert out.buf == ""
    monkeypatch.setenv("WARREN_NO_TERMINAL_TITLE", "1")
    out = _TTY()
    dispatch.set_terminal_title("p", "t", "ws", stream=out)
    assert out.buf == ""


@posix_exec_only
def test_connect_via_execvp_sets_title_before_exec(monkeypatch):
    import warren_cli.dispatch as d

    titles = []
    monkeypatch.setattr(d, "set_terminal_title", lambda *a, **kw: titles.append(a))

    def _fake(prog, argv, env):
        raise SystemExit(0)

    monkeypatch.setattr(d.os, "execvpe", _fake)
    with pytest.raises(SystemExit):
        d._connect_via_execvp({
            "runtime_type": "docker", "container_id": "abc", "app": "bash",
            "workspace_id": "ws-1", "project": "proj", "intent": "develop",
        })
    assert titles == [("proj", "develop", "ws-1")]


@posix_exec_only
def test_connect_via_execvp_passes_seed_prompt_to_supporting_app(monkeypatch):
    import warren_cli.dispatch as d

    calls = []

    def _fake(prog, argv, env):
        calls.append(list(argv))
        raise SystemExit(0)

    monkeypatch.setattr(d.os, "execvpe", _fake)
    base = {"runtime_type": "docker", "container_id": "abc", "workspace_id": "ws"}
    with pytest.raises(SystemExit):
        d._connect_via_execvp({**base, "app": "gemini", "seed_prompt": "fix the build"})
    with pytest.raises(SystemExit):
        d._connect_via_execvp({**base, "app": "bash", "seed_prompt": "fix the build"})
    with pytest.raises(SystemExit):
        d._connect_via_execvp({**base, "app": "claude", "seed_prompt": "fix the build"})
    assert calls[0][-3:] == ["gemini", "-i", "fix the build"]
    assert calls[1][-1] == "bash"
    # AG2a: a harness app gets the shell; the shell hands the seed to the harness.
    assert calls[2][-1] == "bash"


def test_ecs_session_command_passes_harness_and_new():
    import shlex

    import warren_cli.dispatch as d

    script = shlex.split(d.ecs_session_command("zsh", harness="codex", new=True))[2]
    assert script.endswith("exec /usr/local/bin/warren-session zsh codex new")
    script = shlex.split(d.ecs_session_command("bash", harness="codex; reboot"))[2]
    assert script.endswith("exec /usr/local/bin/warren-session bash - -")


@posix_exec_only
def test_connect_via_ssh_podman_exec_runs_the_warren_shell_in_tmux(monkeypatch):
    import shlex

    import warren_cli.dispatch as d
    from warren_common.harness_shell import TMUX_SESSION_SCRIPT

    captured = {}

    def _fake_execvp(prog, argv):
        captured["argv"] = list(argv)
        raise SystemExit(0)

    monkeypatch.setattr("warren_cli.dispatch.shutil.which", lambda name: "/usr/bin/ssh")
    monkeypatch.setattr("warren_cli.dispatch.os.execvp", _fake_execvp)
    with pytest.raises(SystemExit):
        d.connect_via_ssh_podman_exec("node2", "ctr", shell="zsh", harness="claude", new=False)
    remote = shlex.split(captured["argv"][-1])
    assert remote[:5] == ["podman", "exec", "-it", "--", "ctr"]
    assert remote[5:8] == ["/bin/sh", "-c", TMUX_SESSION_SCRIPT]
    assert remote[8:] == ["warren-session", "zsh", "claude", "-"]


def _shell_first_state(tmp_path, app="claude", harnesses=("claude", "codex")):
    ws = tmp_path / "ws"
    ws.mkdir()
    root = tmp_path / "state" / "harness"
    root.mkdir(parents=True)
    return {
        "runtime_type": "seatbelt",
        "profile_path": str(tmp_path / "sandbox.sb"),
        "app": app,
        "harnesses": list(harnesses),
        "harness_root": str(root),
        "workspace_id": "ws-1",
        "root_path": str(ws),
        "env_snapshot": {},
    }


@posix_exec_only
def test_local_connect_opens_warren_shell_with_harness_commands(tmp_path, monkeypatch):
    """AG2a: a local user workspace always gets the warren shell; harnesses are
    commands in it and --harness/--new are passed to it."""
    from warren_cli import dispatch as d
    from warren_common import harness_shell

    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path / "home"))
    monkeypatch.setattr(d, "_prepare_local_harness_dirs", lambda *a, **kw: None)
    captured = {}

    def _fake_execvpe(prog, argv, env):
        captured.update(argv=list(argv), env=dict(env))
        raise SystemExit(0)

    monkeypatch.setattr(d.os, "execvpe", _fake_execvpe)
    state = _shell_first_state(tmp_path)
    with pytest.raises(SystemExit):
        d._connect_via_execvp(state, harness="codex", new=True)

    assert captured["argv"][-1] == "bash"
    env = captured["env"]
    assert env["WARREN_HARNESSES"] == "claude codex"
    assert env["WARREN_HARNESS_DEFAULT"] == "claude"
    assert env["WARREN_HARNESS_ROOT"] == state["harness_root"]
    assert env["WARREN_CONNECT"] == "1"
    assert env["WARREN_CONNECT_HARNESS"] == "codex"
    assert env["WARREN_CONNECT_NEW"] == "1"
    ws = Path(state["root_path"])
    assert (ws / ".warren_harness.sh").read_text() == harness_shell.asset_text()
    assert (ws / ".bashrc").read_text().rstrip().endswith('source "$HOME/.warren_harness.sh"')


@posix_exec_only
def test_local_connect_rejects_harness_not_in_template(tmp_path, monkeypatch):
    from warren_cli import dispatch as d

    monkeypatch.setattr(d, "_prepare_local_harness_dirs", lambda *a, **kw: None)
    monkeypatch.setattr(d.os, "execvpe", lambda *a: pytest.fail("must not exec"))
    import typer

    with pytest.raises(typer.Exit):
        d._connect_via_execvp(_shell_first_state(tmp_path, harnesses=("claude",)), harness="pi")
