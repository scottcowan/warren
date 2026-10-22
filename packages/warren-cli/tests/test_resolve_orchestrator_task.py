"""`_resolve_orchestrator_task_arn` ECS task selection (audit 2026-10-16 #35):
during a rolling deploy, more than one task can briefly have
desiredStatus=RUNNING -- this must prefer a task whose lastStatus is
actually RUNNING over blindly taking taskArns[0]."""

from __future__ import annotations

import json
import subprocess
from unittest.mock import patch

from warren_cli.dispatch import _resolve_orchestrator_task_arn


def _completed(stdout: str = "", returncode: int = 0) -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr="")


def test_single_candidate_returned_without_describe_call():
    with patch("warren_cli.dispatch.subprocess.run") as mock_run:
        mock_run.return_value = _completed(json.dumps(["arn:aws:ecs:us-east-1:1:task/c/only"]))
        arn = _resolve_orchestrator_task_arn("cluster", "service")
    assert arn == "arn:aws:ecs:us-east-1:1:task/c/only"
    assert mock_run.call_count == 1


def test_multiple_candidates_prefers_task_with_running_last_status():
    """The draining old task and the new live task both show up in
    list-tasks during a rolling deploy -- describe-tasks must be consulted
    to pick the one that's actually running, not taskArns[0]."""
    draining_arn = "arn:aws:ecs:us-east-1:1:task/c/draining-old"
    live_arn = "arn:aws:ecs:us-east-1:1:task/c/live-new"

    def _run(argv, **kw):
        if argv[2] == "list-tasks":
            # taskArns[0] is the DRAINING task -- the old (wrong) code would
            # have returned this one.
            return _completed(json.dumps([draining_arn, live_arn]))
        assert argv[2] == "describe-tasks"
        return _completed(
            json.dumps(
                [
                    {"arn": draining_arn, "lastStatus": "DEACTIVATING"},
                    {"arn": live_arn, "lastStatus": "RUNNING"},
                ]
            )
        )

    with patch("warren_cli.dispatch.subprocess.run", side_effect=_run):
        arn = _resolve_orchestrator_task_arn("cluster", "service")
    assert arn == live_arn


def test_describe_tasks_failure_falls_back_to_first_candidate():
    first_arn = "arn:aws:ecs:us-east-1:1:task/c/first"

    def _run(argv, **kw):
        if argv[2] == "list-tasks":
            return _completed(json.dumps([first_arn, "arn:aws:ecs:us-east-1:1:task/c/second"]))
        return _completed(returncode=1)

    with patch("warren_cli.dispatch.subprocess.run", side_effect=_run):
        arn = _resolve_orchestrator_task_arn("cluster", "service")
    assert arn == first_arn


def test_no_running_tasks_raises_runtime_error():
    with patch("warren_cli.dispatch.subprocess.run") as mock_run:
        mock_run.return_value = _completed(json.dumps([]))
        try:
            _resolve_orchestrator_task_arn("cluster", "service")
        except RuntimeError as e:
            assert "no running task found" in str(e)
        else:
            raise AssertionError("expected RuntimeError")
