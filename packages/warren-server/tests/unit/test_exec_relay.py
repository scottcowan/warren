"""#59: exec relay bounds, and the podman/ECS exec_stream backends (no real socket/AWS)."""

from __future__ import annotations

import asyncio
import json
import struct
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from warren import exec_relay
from warren_common.runtime.base import ExecExit, ExecUnavailable, WorkspaceHandle

_HANDLE = WorkspaceHandle(workspace_id="ws-1", runtime_id="cid", root_path="")


class _Runtime:
    def __init__(self, gen):
        self._gen = gen
        self.closed = False

    async def exec_stream(self, handle, argv):
        try:
            async for item in self._gen():
                yield item
        finally:
            self.closed = True


async def _run(runtime, **kw) -> list[dict]:
    kw.setdefault("timeout_seconds", 5)
    kw.setdefault("max_output_bytes", 1024)
    return [f async for f in exec_relay.relay(runtime, _HANDLE, ["x"], **kw)]


@pytest.mark.asyncio
async def test_timeout_stops_the_stream():
    async def gen():
        yield b"started\n"
        await asyncio.sleep(30)
        yield ExecExit(0)

    runtime = _Runtime(gen)
    frames = await _run(runtime, timeout_seconds=0.2)
    assert frames[0] == {"type": "output", "data": "started\n"}
    assert frames[-1]["timed_out"] is True
    assert frames[-1]["exit_code"] is None
    assert runtime.closed


@pytest.mark.asyncio
async def test_split_utf8_is_reassembled():
    async def gen():
        yield "é".encode()[:1]
        yield "é".encode()[1:]
        yield ExecExit(0)

    frames = await _run(_Runtime(gen))
    assert "".join(f["data"] for f in frames if f["type"] == "output") == "é"


@pytest.mark.asyncio
async def test_unavailable_exec_becomes_an_error_frame():
    async def gen():
        raise ExecUnavailable("no plugin")
        yield b""

    (frame,) = await _run(_Runtime(gen))
    assert frame["error"] == "no plugin"
    assert frame["exit_code"] is None


@pytest.mark.asyncio
async def test_collect_folds_frames():
    async def gen():
        yield b"a"
        yield b"b"
        yield ExecExit(2)

    result = await exec_relay.collect(exec_relay.relay(_Runtime(gen), _HANDLE, ["x"], timeout_seconds=5, max_output_bytes=10))
    assert result["output"] == "ab"
    assert result["exit_code"] == 2


def test_bounded_timeout():
    s = SimpleNamespace(exec_default_timeout_seconds=60.0, exec_max_timeout_seconds=600.0)
    assert exec_relay.bounded_timeout(s, None) == 60.0
    assert exec_relay.bounded_timeout(s, 5000) == 600.0


@pytest.mark.parametrize("argv", [[], [""], ["a"] * 257, ["a\x00b"], ["a" * 9000]])
def test_validate_argv_rejects(argv):
    with pytest.raises(ValueError):
        exec_relay.validate_argv(argv)


def _frame(payload: bytes, stream: int = 1) -> bytes:
    return struct.pack(">BxxxL", stream, len(payload)) + payload


@pytest.mark.asyncio
async def test_podman_exec_stream_uses_the_exec_api_and_reports_exit_code():
    import io

    from warren.runtime.podman import PodmanRuntime

    runtime = PodmanRuntime.__new__(PodmanRuntime)
    container = MagicMock()
    container.id = "cid"
    started = MagicMock()
    started.raw = io.BytesIO(_frame(b"out\n") + _frame(b"err\n", 2))
    created = MagicMock()
    created.json.return_value = {"Id": "exec-1"}
    container.client.post.side_effect = [created, started]
    container.client.get.return_value.json.return_value = {"ExitCode": 3}
    runtime._client = MagicMock()
    runtime._client.containers.get.return_value = container

    items = [i async for i in runtime.exec_stream(_HANDLE, ["sh", "-c", "echo out; echo err >&2; exit 3"])]

    assert items == [b"out\n", b"err\n", ExecExit(3)]
    create_call, start_call = container.client.post.call_args_list
    assert create_call.args[0] == "/containers/cid/exec"
    body = json.loads(create_call.kwargs["data"])
    assert body["Cmd"] == ["sh", "-c", "echo out; echo err >&2; exit 3"]
    assert body["Tty"] is False and body["AttachStdin"] is False
    assert start_call.args[0] == "/exec/exec-1/start"
    container.client.get.assert_called_once_with("/exec/exec-1/json")
    started.close.assert_called_once()


class _FakeProc:
    def __init__(self, lines: list[bytes]):
        self.returncode = None
        self.killed = False

        async def _lines():
            for line in lines:
                yield line

        self.stdout = _lines()

    async def wait(self):
        self.returncode = 0
        return 0

    def kill(self):
        self.killed = True


@pytest.mark.asyncio
async def test_ecs_exec_stream_runs_execute_command_and_parses_sentinel(monkeypatch):
    from warren.runtime import ecs as ecs_mod

    runtime = ecs_mod.ECSRuntime(
        server_id="s", settings=SimpleNamespace(ecs_cluster="warren-cluster", aws_region="eu-west-1")
    )
    client = MagicMock()
    client.describe_tasks.return_value = {
        "tasks": [{"containers": [{"name": "workspace", "runtimeId": "rt-1"}]}]
    }
    client.execute_command.return_value = {"session": {"sessionId": "sess", "streamUrl": "wss://x", "tokenValue": "t"}}
    client.meta.endpoint_url = "https://ecs.eu-west-1.amazonaws.com"
    runtime._ecs = client
    monkeypatch.setattr(ecs_mod.shutil, "which", lambda name: "/usr/bin/session-manager-plugin")
    monkeypatch.setattr(ecs_mod.secrets, "token_hex", lambda n: "abc")
    spawned: dict = {}

    async def _spawn(*args, **kwargs):
        spawned["args"] = args
        return _FakeProc([
            b"\r\n",
            b"Starting session with SessionId: sess\r\n",
            b"hello\r\n",
            b"__WARREN_EXIT_abc__4\r\n",
            b"Exiting session with sessionId: sess.\r\n",
        ])

    monkeypatch.setattr(ecs_mod.asyncio, "create_subprocess_exec", _spawn)
    task_arn = "arn:aws:ecs:eu-west-1:1:task/warren-cluster/tid"
    handle = WorkspaceHandle(workspace_id="ws-1", runtime_id=task_arn, root_path="")

    items = [i async for i in runtime.exec_stream(handle, ["echo", "it's"])]

    assert items == [b"\n", b"hello\n", ExecExit(4)]
    kwargs = client.execute_command.call_args.kwargs
    assert kwargs["task"] == task_arn and kwargs["container"] == "workspace" and kwargs["interactive"] is True
    assert kwargs["command"].startswith("sh -c ") and "__WARREN_EXIT_abc__$?" in kwargs["command"]
    args = spawned["args"]
    assert args[0] == "/usr/bin/session-manager-plugin"
    assert json.loads(args[5]) == {"Target": "ecs:warren-cluster_tid_rt-1"}


@pytest.mark.asyncio
async def test_ecs_exec_stream_without_plugin_is_unavailable(monkeypatch):
    from warren.runtime import ecs as ecs_mod

    runtime = ecs_mod.ECSRuntime(server_id="s", settings=SimpleNamespace(ecs_cluster="c"))
    monkeypatch.setattr(ecs_mod.shutil, "which", lambda name: None)
    with pytest.raises(ExecUnavailable):
        async for _ in runtime.exec_stream(_HANDLE, ["id"]):
            pass
