"""workspace_query: fixed argv over the runtime's exec channel, strict parsing of
untrusted output, path validation and caps."""

from __future__ import annotations

import base64

import pytest
from warren import workspace_query as wq
from warren_common.runtime.base import WorkspaceHandle
from warren_common.runtime.fake import FakeRuntime

_HANDLE = WorkspaceHandle(workspace_id="ws-a", runtime_id="c-ws-a", root_path="")


def _runtime(output: str | bytes, code: int = 0) -> FakeRuntime:
    rt = FakeRuntime("test")
    data = output.encode() if isinstance(output, str) else output
    rt.exec_handler = lambda ws, argv: ([data], code)
    return rt


def _b64(data: bytes) -> str:
    return base64.encodebytes(data).decode()


async def test_list_runs_the_fixed_query_argv_and_parses_entries():
    rt = _runtime(
        "F 5 a.txt\nF 7 src/lib/m.py\nF 3 main/with space.txt\n"
        "F 9 .env\nF 9 cfg/.env.local\nF 1 node_modules/x.js\nF 1 .git/config\n"
        "F 1 ../escape\nF 1 /etc/passwd\nF x bad-size\nD 4 dir\ngarbage\nEND\n"
    )
    entries = await wq.list_files(rt, _HANDLE)
    assert rt.exec_calls == [("ws-a", ["/usr/local/bin/warren-query", "list", "/workspace"])]
    assert entries == [
        {"path": "a.txt", "size": 5, "is_dir": False},
        {"path": "main", "size": 0, "is_dir": True},
        {"path": "main/with space.txt", "size": 3, "is_dir": False},
        {"path": "src", "size": 0, "is_dir": True},
        {"path": "src/lib", "size": 0, "is_dir": True},
        {"path": "src/lib/m.py", "size": 7, "is_dir": False},
    ]


async def test_list_without_end_marker_is_an_error():
    with pytest.raises(wq.QueryError) as ei:
        await wq.list_files(_runtime("F 5 a.txt\n"), _HANDLE)
    assert ei.value.status == 502


async def test_list_entry_cap(monkeypatch):
    monkeypatch.setattr(wq, "MAX_LIST_ENTRIES", 2)
    with pytest.raises(wq.QueryError) as ei:
        await wq.list_files(_runtime("F 1 a\nF 1 b\nF 1 c\nEND\n"), _HANDLE)
    assert ei.value.status == 413


async def test_output_over_the_cap_is_refused(monkeypatch):
    monkeypatch.setattr(wq, "_LIST_OUTPUT_BYTES", 16)
    with pytest.raises(wq.QueryError) as ei:
        await wq.list_files(_runtime("F 1 " + "a" * 64 + "\nEND\n"), _HANDLE)
    assert ei.value.status == 413


@pytest.mark.parametrize("hostile", ["$(id)", "a; rm -rf ~", "`id`", "a b|c", "-rf", "'quote\"", "a*b"])
async def test_read_passes_the_path_as_one_argv_item(hostile):
    rt = _runtime(f"OK 2\n{_b64(b'hi')}END\n")
    assert await wq.read_file(rt, _HANDLE, hostile) == b"hi"
    assert rt.exec_calls == [
        ("ws-a", ["/usr/local/bin/warren-query", "read", "/workspace", hostile, str(wq.MAX_FILE_BYTES)])
    ]


@pytest.mark.parametrize(
    "bad",
    ["", "/etc/passwd", "../x", "a/../../b", "a//b", "./a", "a/.", "a/", "a\nb", "a\x00b", "a\rb", "x" * 1025],
)
async def test_read_rejects_invalid_paths_without_running_anything(bad):
    rt = _runtime("never")
    with pytest.raises(wq.QueryError) as ei:
        await wq.read_file(rt, _HANDLE, bad)
    assert ei.value.status == 400
    assert rt.exec_calls == []


@pytest.mark.parametrize("excluded", [".env", "cfg/.env.prod", ".git/config", "node_modules/a.js", "x/.venv/y", "__pycache__/m.pyc"])
async def test_read_refuses_excluded_paths_without_running_anything(excluded):
    rt = _runtime("never")
    with pytest.raises(wq.QueryError) as ei:
        await wq.read_file(rt, _HANDLE, excluded)
    assert ei.value.status == 404
    assert rt.exec_calls == []


@pytest.mark.parametrize(
    ("output", "code", "status"),
    [
        ("TOOBIG 2000000\n", 7, 413),
        ("ERR symlink\n", 6, 400),
        ("ERR not a regular file\n", 6, 400),
        ("ERR excluded\n", 4, 404),
        ("ERR not found\n", 5, 404),
        ("ERR not readable\n", 8, 403),
        ("ERR cannot drop privileges\n", 125, 502),
        ("sh: warren-query: not found\n", 127, 501),
        ("OK 2\n!!!not-base64!!!\nEND\n", 0, 502),
    ],
)
async def test_read_maps_script_outcomes(output, code, status):
    with pytest.raises(wq.QueryError) as ei:
        await wq.read_file(_runtime(output, code), _HANDLE, "a.txt")
    assert ei.value.status == status


async def test_read_refuses_a_body_over_the_cap_even_if_the_script_lies(monkeypatch):
    monkeypatch.setattr(wq, "MAX_FILE_BYTES", 4)
    with pytest.raises(wq.QueryError) as ei:
        await wq.read_file(_runtime(f"OK 4\n{_b64(b'12345')}END\n"), _HANDLE, "a.txt")
    assert ei.value.status == 413


async def test_read_tolerates_tty_line_endings():
    body = _b64(b"x" * 200).replace("\n", "\r\n")
    assert await wq.read_file(_runtime(f"OK 200\r\n{body}END\r\n"), _HANDLE, "a.txt") == b"x" * 200


async def test_diff_parses_repos_and_flags_truncation(monkeypatch):
    monkeypatch.setattr(wq, "MAX_DIFF_BYTES", 8)
    out = (
        f"REPO .\n{_b64(b'small')}ENDREPO\n"
        f"REPO sub/app\n{_b64(b'0123456789')}ENDREPO\n"
        f"REPO node_modules/x\n{_b64(b'nope')}ENDREPO\n"
        "END\n"
    )
    rt = _runtime(out)
    repos = await wq.diff(rt, _HANDLE)
    assert rt.exec_calls == [("ws-a", ["/usr/local/bin/warren-query", "diff", "/workspace", "8"])]
    assert repos == [
        wq.RepoDiff(repo=".", diff="small", truncated=False),
        wq.RepoDiff(repo="sub/app", diff="01234567", truncated=True),
    ]


async def test_exec_channel_failure_is_502():
    from warren_common.runtime.base import ExecUnavailable

    rt = FakeRuntime("test")

    def _boom(ws, argv):
        raise ExecUnavailable("no plugin")

    rt.exec_handler = _boom
    with pytest.raises(wq.QueryError) as ei:
        await wq.list_files(rt, _HANDLE)
    assert ei.value.status == 502
