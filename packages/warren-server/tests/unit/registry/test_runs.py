"""Headless runs: the runs store, result assembly and parsing (registry/runs.py)."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from warren.registry import runs
from warren.registry.store import open_db

T0 = datetime(2026, 11, 1, 12, 0, tzinfo=UTC)


@pytest.fixture
async def store(sqlite_path):
    db = await open_db(sqlite_path)
    yield runs.RunStore(db)
    await db.close()


async def _create(store, run_id, owner="alice", started=T0, timeout=None):
    await store.create(run_id=run_id, owner_id=owner, project="p", template="t",
                       timeout_seconds=timeout, started_at=started)


# --- store -------------------------------------------------------------------------


async def test_create_get_finish_roundtrip(store):
    await _create(store, "r1", timeout=60)
    run = await store.get("r1")
    assert run["status"] == "running" and run["timeout_seconds"] == 60
    assert run["started_at"] == "2026-11-01T12:00:00Z" and run["result"] is None

    assert await store.finish("r1", status="succeeded", result={"x": 1}, ended_at=T0 + timedelta(seconds=5))
    run = await store.get("r1")
    assert run["status"] == "succeeded" and run["result"] == {"x": 1}
    assert run["ended_at"] == "2026-11-01T12:00:05Z"
    # A finished run is never overwritten (a late timeout, a second completion).
    assert not await store.finish("r1", status="failed", result={"x": 2})
    assert (await store.get("r1"))["result"] == {"x": 1}


async def test_create_is_idempotent_and_finish_rejects_running(store):
    await _create(store, "r1", owner="alice")
    await _create(store, "r1", owner="mallory")
    assert (await store.get("r1"))["owner_id"] == "alice"
    with pytest.raises(ValueError):
        await store.finish("r1", status="running", result={})


async def test_list_is_owner_scoped_newest_first(store):
    await _create(store, "a1", owner="alice", started=T0)
    await _create(store, "a2", owner="alice", started=T0 + timedelta(minutes=1))
    await _create(store, "b1", owner="bob")
    assert [r["run_id"] for r in await store.list("alice")] == ["a2", "a1"]
    assert {r["run_id"] for r in await store.list(None)} == {"a1", "a2", "b1"}


async def test_prune_by_age_and_per_owner_count_keeps_running(store):
    for i in range(4):
        await _create(store, f"a{i}", started=T0 + timedelta(minutes=i))
        await store.finish(f"a{i}", status="succeeded", result={}, ended_at=T0 + timedelta(minutes=i))
    await _create(store, "old", owner="bob", started=T0 - timedelta(days=40))
    await store.finish("old", status="failed", result={}, ended_at=T0 - timedelta(days=40))
    await _create(store, "live", owner="bob", started=T0 - timedelta(days=40))

    removed = await store.prune(retention_seconds=30 * 86400, max_per_owner=2, now=T0 + timedelta(hours=1))

    assert removed == 3
    assert {r["run_id"] for r in await store.list(None)} == {"a3", "a2", "live"}


# --- parsing -----------------------------------------------------------------------


def test_parse_numstat_handles_binary_and_renames():
    raw = "3\t1\tsrc/a.py\0-\t-\tlogo.png\0" "0\t0\t\0old.txt\0new.txt\0"
    assert runs.parse_numstat(raw) == {
        "src/a.py": (3, 1), "logo.png": (None, None), "new.txt": (0, 0),
    }


def test_parse_status_reads_xy_and_skips_rename_source():
    raw = " M src/a.py\0?? notes.md\0R  new.txt\0old.txt\0 D gone.txt\0"
    assert runs.parse_status(raw) == [
        (" M", "src/a.py"), ("??", "notes.md"), ("R ", "new.txt"), (" D", "gone.txt"),
    ]


def test_summarize_repo_merges_files_and_ignores_run_bookkeeping():
    summary = runs.summarize_repo({
        "mount": "app", "base_branch": "main", "branch": "warren/fix", "head": "h1", "base": "b1",
        "numstat": "3\t1\tsrc/a.py\0" "0\t4\tgone.txt\0",
        "status": " D gone.txt\0?? new.md\0?? .warren/verdict.json\0",
        "remote": "h1",
    })
    assert summary["diffstat"] == {"files": 3, "insertions": 3, "deletions": 5}
    assert [(f["path"], f["status"]) for f in summary["changed_files"]] == [
        ("gone.txt", "deleted"), ("new.md", "untracked"), ("src/a.py", "modified"),
    ]
    assert summary["remote_branch"] == "origin/warren/fix" and summary["pushed"] is True
    assert summary["is_clean"] is False
    clean = runs.summarize_repo({"mount": "", "branch": "main", "head": "h", "remote": "other",
                                 "status": "?? .warren/verdict.json\0"})
    assert clean["is_clean"] is True and clean["pushed"] is False and clean["changed_files"] == []


def test_summarize_repo_caps_changed_files():
    numstat = "".join(f"1\t0\tf{i:04d}\0" for i in range(runs.MAX_CHANGED_FILES + 5))
    summary = runs.summarize_repo({"mount": "", "numstat": numstat})
    assert len(summary["changed_files"]) == runs.MAX_CHANGED_FILES
    assert summary["changed_files_truncated"] is True
    assert summary["diffstat"]["files"] == runs.MAX_CHANGED_FILES + 5


def test_parse_claude_json_output():
    out = json.dumps({
        "type": "result", "subtype": "success", "is_error": False, "result": "Fixed it. PR: https://github.com/o/r/pull/7",
        "num_turns": 4, "total_cost_usd": 0.12, "session_id": "abc-123", "usage": {"input_tokens": 9},
    })
    message, harness = runs.parse_harness_output(out, "claude")
    assert message.startswith("Fixed it.")
    assert harness == {"subtype": "success", "is_error": False, "num_turns": 4,
                       "total_cost_usd": 0.12, "session_id": "abc-123"}


def test_parse_claude_stream_json_takes_last_result_line():
    lines = [json.dumps({"type": "assistant", "message": {}}), json.dumps({"type": "result", "result": "done", "is_error": True})]
    message, harness = runs.parse_harness_output("\n".join(lines) + "\n", "claude")
    assert message == "done" and harness == {"is_error": True}


def test_parse_plain_output_is_the_summary():
    assert runs.parse_harness_output("  all good\n", "codex") == ("all good", None)
    assert runs.parse_harness_output("not json", "claude") == ("not json", None)
    assert runs.parse_harness_output("", "claude") == (None, None)


def test_find_pr_urls_dedupes_and_caps():
    text = "https://github.com/o/r/pull/1 and https://github.com/o/r/pull/1 https://gitlab.com/g/s/p/-/merge_requests/2"
    assert runs.find_pr_urls(text, None) == [
        "https://github.com/o/r/pull/1", "https://gitlab.com/g/s/p/-/merge_requests/2",
    ]
    many = " ".join(f"https://github.com/o/r/pull/{i}" for i in range(20))
    assert len(runs.find_pr_urls(many)) == runs.MAX_PR_URLS


@pytest.mark.parametrize(
    ("exit_code", "harness", "timed_out", "status"),
    [
        (0, None, False, "succeeded"),
        (2, None, False, "failed"),
        (None, None, False, "failed"),
        (0, {"is_error": True}, False, "failed"),
        (0, None, True, "timed_out"),
    ],
)
def test_run_status(exit_code, harness, timed_out, status):
    assert runs.run_status(exit_code=exit_code, harness_result=harness, timed_out=timed_out) == status


def test_transcript_pointer_only_for_a_safe_claude_session():
    assert runs.transcript_pointer("claude", {"session_id": "abc-1"}, "efs")["retained"] is True
    assert runs.transcript_pointer("claude", {"session_id": "abc-1"}, "")["retained"] is False
    assert runs.transcript_pointer("claude", {"session_id": "../etc"}, "") is None
    assert runs.transcript_pointer("codex", {"session_id": "abc"}, "") is None


def test_build_result_shape():
    ws = SimpleNamespace(workspace_id="r1", project="p", intent="t", created_at=T0)
    status, result = runs.build_result(
        run={"started_at": "2026-11-01T12:00:00Z"}, workspace=ws,
        event={"exit_code": 0, "verdict": {"pr": "https://github.com/o/r/pull/9"}, "capture_errors": ["a"]},
        repos_raw=[{"mount": "", "branch": "main", "head": "h"}], output='{"type":"result","result":"ok"}',
        harness="claude", storage="", source="control-plane", errors=["b"], timed_out=False,
        ended_at=T0 + timedelta(seconds=90),
    )
    assert status == "succeeded"
    assert result["schema"] == "warren.run.result/v1"
    assert result["duration_seconds"] == 90 and result["ended_at"] == "2026-11-01T12:01:30Z"
    assert result["final_message"] == "ok"
    assert result["pull_requests"] == ["https://github.com/o/r/pull/9"]
    assert result["capture_errors"] == ["a", "b"]
    assert result["git"][0]["branch"] == "main"
