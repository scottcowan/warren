"""`warren run`: start a headless run, wait for it with a fake clock, read its result."""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest
import respx
from typer.testing import CliRunner
from warren_cli.commands import run as run_cmd
from warren_cli.main import app

runner = CliRunner()
BASE = "http://test.local"
RUN_ID = "0a1b2c3d-1111-2222-3333-444455556666"
RESULT = {
    "schema": "warren.run.result/v1", "run_id": RUN_ID, "status": "succeeded", "exit_code": 0,
    "project": "demo", "template": "fix", "started_at": "2026-11-01T12:00:00Z",
    "ended_at": "2026-11-01T12:03:00Z", "final_message": "Added the flag.",
    "git": [{"mount": "code/app", "branch": "warren/fix", "diffstat": {"files": 1, "insertions": 2, "deletions": 0},
             "changed_files": [{"path": "a.py", "status": "modified"}], "pushed": True,
             "remote_branch": "origin/warren/fix"}],
    "pull_requests": ["https://github.com/acme/app/pull/12"], "capture_errors": [],
}


@pytest.fixture
def cfg(tmp_path: Path) -> Path:
    path = tmp_path / "config.toml"
    path.write_text(f'[remotes.node2]\nurl = "{BASE}"\nauth_token = "tok-xyz"\n')
    return path


class FakeTime:
    def __init__(self) -> None:
        self.now = 0.0
        self.sleeps: list[float] = []

    def clock(self) -> float:
        return self.now

    async def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += seconds


@pytest.fixture
def fake_time(monkeypatch) -> FakeTime:
    t = FakeTime()
    monkeypatch.setattr(run_cmd, "_clock", t.clock)
    monkeypatch.setattr(run_cmd, "_sleep", t.sleep)
    return t


def _invoke(cfg: Path, *args: str):
    return runner.invoke(app, ["run", *args, "--server", "node2", "--config", str(cfg)])


def _started(status="running"):
    return httpx.Response(202, json={"run_id": RUN_ID, "status": status, "project": "demo", "template": "fix"})


def test_start_prints_the_run_id_without_waiting(cfg):
    with respx.mock(base_url=BASE) as m:
        post = m.post("/runs").mock(return_value=_started())
        result = _invoke(cfg, "demo/fix", "--prompt", "add a flag", "--timeout", "600")
    assert result.exit_code == 0, result.output
    assert result.stdout.strip() == RUN_ID
    body = json.loads(post.calls[0].request.content)
    assert body["project"] == "demo" and body["template"] == "fix" and body["prompt"] == "add a flag"
    assert body["timeout_seconds"] == 600 and body["operationId"].startswith("cli-run-")
    assert post.calls[0].request.headers["Authorization"] == "Bearer tok-xyz"


def test_start_json_and_prompt_file(cfg, tmp_path):
    prompt = tmp_path / "task.md"
    prompt.write_text("multi\nline task\n")
    with respx.mock(base_url=BASE) as m:
        post = m.post("/runs").mock(return_value=_started())
        result = _invoke(cfg, "fix", "--project", "demo", "--prompt-file", str(prompt), "--json")
    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)["run_id"] == RUN_ID
    assert json.loads(post.calls[0].request.content)["prompt"] == "multi\nline task\n"


@pytest.mark.parametrize(
    "args",
    [
        ["demo/fix"],
        ["demo/fix", "--prompt", "x", "--prompt-file", "f"],
        ["justatemplate", "--prompt", "x"],
        ["demo/fix", "--prompt", "   "],
    ],
)
def test_start_argument_errors(cfg, args):
    with respx.mock(base_url=BASE, assert_all_called=False) as m:
        post = m.post("/runs")
        result = _invoke(cfg, *args)
    assert result.exit_code == 2
    assert not post.called


def test_wait_polls_with_the_fake_clock_and_prints_the_result(cfg, fake_time):
    statuses = iter(["running", "running", "succeeded"])
    with respx.mock(base_url=BASE) as m:
        m.post("/runs").mock(return_value=_started())
        status = m.get(f"/runs/{RUN_ID}").mock(
            side_effect=lambda req: httpx.Response(200, json={"run_id": RUN_ID, "status": next(statuses)})
        )
        m.get(f"/runs/{RUN_ID}/result").mock(return_value=httpx.Response(200, json=RESULT))
        result = _invoke(cfg, "demo/fix", "--prompt", "x", "--wait", "--poll-interval", "15")
    assert result.exit_code == 0, result.output
    assert status.call_count == 3
    assert fake_time.sleeps == [15.0, 15.0]
    out = result.stdout
    assert "succeeded" in out and "Added the flag." in out
    assert "warren/fix  1 files +2 -0, pushed to origin/warren/fix" in out
    assert "pull request: https://github.com/acme/app/pull/12" in out


def test_wait_json_and_failure_exit_codes(cfg, fake_time):
    for final, code in (("failed", 1), ("timed_out", 124)):
        with respx.mock(base_url=BASE) as m:
            m.post("/runs").mock(return_value=_started())
            m.get(f"/runs/{RUN_ID}").mock(return_value=httpx.Response(200, json={"status": final}))
            m.get(f"/runs/{RUN_ID}/result").mock(return_value=httpx.Response(200, json={**RESULT, "status": final}))
            result = _invoke(cfg, "demo/fix", "--prompt", "x", "--wait", "--json")
        assert result.exit_code == code
        assert json.loads(result.stdout)["status"] == final
    assert fake_time.sleeps == []


def test_wait_timeout_leaves_the_run_going(cfg, fake_time):
    with respx.mock(base_url=BASE) as m:
        m.post("/runs").mock(return_value=_started())
        status = m.get(f"/runs/{RUN_ID}").mock(return_value=httpx.Response(200, json={"status": "running"}))
        result = _invoke(cfg, "demo/fix", "--prompt", "x", "--wait", "--poll-interval", "10", "--wait-timeout", "35")
    assert result.exit_code == run_cmd.EXIT_STILL_RUNNING
    assert status.call_count == 4 and fake_time.now == 30.0  # polls at 0, 10, 20, 30
    assert "still running" in result.output


def test_wait_rides_out_a_dropped_connection(cfg, fake_time):
    responses = iter([httpx.ConnectError("reset"), httpx.Response(200, json={"status": "succeeded"})])

    def _status(req):
        item = next(responses)
        if isinstance(item, Exception):
            raise item
        return item

    with respx.mock(base_url=BASE) as m:
        m.post("/runs").mock(return_value=_started())
        m.get(f"/runs/{RUN_ID}").mock(side_effect=_status)
        m.get(f"/runs/{RUN_ID}/result").mock(return_value=httpx.Response(200, json=RESULT))
        result = _invoke(cfg, "demo/fix", "--prompt", "x", "--wait")
    assert result.exit_code == 0, result.output
    assert len(fake_time.sleeps) == 1


def test_start_error_is_reported(cfg):
    with respx.mock(base_url=BASE) as m:
        m.post("/runs").mock(return_value=httpx.Response(
            422, json={"detail": {"error": "single_turn_requires_app", "detail": "needs an app"}}
        ))
        result = _invoke(cfg, "demo/observe", "--prompt", "x")
    assert result.exit_code == 1
    assert "needs an app" in result.output


def test_status_and_result_resolve_a_prefix(cfg):
    with respx.mock(base_url=BASE) as m:
        m.get("/runs").mock(return_value=httpx.Response(200, json=[{"run_id": RUN_ID}, {"run_id": "ffff"}]))
        m.get(f"/runs/{RUN_ID}").mock(return_value=httpx.Response(200, json={
            "run_id": RUN_ID, "project": "demo", "template": "fix", "status": "failed", "exit_code": 3,
        }))
        m.get(f"/runs/{RUN_ID}/result").mock(return_value=httpx.Response(200, json={**RESULT, "status": "failed"}))
        status = _invoke(cfg, "status", "0a1b")
        result = _invoke(cfg, "result", "0a1b", "--json")
    assert status.exit_code == 0 and "failed  exit 3" in status.stdout
    assert result.exit_code == 1 and json.loads(result.stdout)["git"][0]["mount"] == "code/app"


def test_result_of_a_running_run_and_a_forbidden_one(cfg):
    with respx.mock(base_url=BASE) as m:
        m.get(f"/runs/{RUN_ID}/result").mock(return_value=httpx.Response(200, json={"run_id": RUN_ID, "status": "running"}))
        running = _invoke(cfg, "result", RUN_ID)
    assert running.exit_code == run_cmd.EXIT_STILL_RUNNING
    with respx.mock(base_url=BASE) as m:
        m.get(f"/runs/{RUN_ID}/result").mock(return_value=httpx.Response(403, json={"detail": "not run owner"}))
        denied = _invoke(cfg, "result", RUN_ID)
    assert denied.exit_code == 1 and "not run owner" in denied.output


def test_list(cfg):
    with respx.mock(base_url=BASE) as m:
        listing = m.get("/runs").mock(return_value=httpx.Response(200, json=[{
            "run_id": RUN_ID, "project": "demo", "template": "fix", "status": "succeeded",
            "exit_code": 0, "started_at": "2026-11-01T12:00:00Z",
        }]))
        result = _invoke(cfg, "list", "--all")
    assert result.exit_code == 0, result.output
    assert "0a1b2c3d" in result.stdout and "demo/fix" in result.stdout
    assert listing.calls[0].request.url.params["all"] == "true"
