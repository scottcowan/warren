"""warren_cli.gh against a fake `gh` (no network)."""

from __future__ import annotations

import json
import subprocess

import pytest

from warren_cli import gh


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("git@github.com:acme/app.git", "acme/app"),
        ("https://github.com/acme/app", "acme/app"),
        ("https://github.com/acme/app.git", "acme/app"),
        ("ssh://git@github.com/acme/my.repo.git", "acme/my.repo"),
        ("git@gitlab.com:acme/app.git", None),
        ("", None),
        (None, None),
    ],
)
def test_github_repo(url, expected):
    assert gh.github_repo(url) == expected


def _fake_gh(monkeypatch, responses: dict):
    """responses: {tuple(args): (returncode, stdout, stderr)}."""
    calls = []
    monkeypatch.setattr(gh.shutil, "which", lambda name: "/usr/bin/gh")

    def _run(argv, **kw):
        args = tuple(argv[1:])
        calls.append(args)
        rc, out, err = responses[args]
        return subprocess.CompletedProcess(argv, rc, out, err)

    monkeypatch.setattr(gh.subprocess, "run", _run)
    return calls


def test_pr_state(monkeypatch):
    _fake_gh(monkeypatch, {
        ("pr", "view", "feat/x", "--repo", "acme/app", "--json", "state"): (0, '{"state": "MERGED"}', ""),
        ("pr", "view", "feat/y", "--repo", "acme/app", "--json", "state"): (
            1, "", 'no pull requests found for branch "feat/y"'
        ),
    })
    assert gh.pr_state("acme/app", "feat/x") == "MERGED"
    assert gh.pr_state("acme/app", "feat/y") is None


def test_pr_state_other_errors_raise(monkeypatch):
    _fake_gh(monkeypatch, {
        ("pr", "view", "b", "--repo", "acme/app", "--json", "state"): (1, "", "HTTP 401: Bad credentials"),
    })
    with pytest.raises(gh.GhError):
        gh.pr_state("acme/app", "b")


def _runs(*runs):
    return json.dumps({"total_count": len(runs), "check_runs": [
        {"status": s, "conclusion": c} for s, c in runs
    ]})


def test_newest_green_commit_skips_red_pending_and_unchecked(monkeypatch):
    commits = json.dumps([{"sha": "c4"}, {"sha": "c3"}, {"sha": "c2"}, {"sha": "c1"}])
    _fake_gh(monkeypatch, {
        ("api", "repos/acme/app/commits?sha=main&per_page=20"): (0, commits, ""),
        ("api", "repos/acme/app/commits/c4/check-runs?per_page=100"): (
            0, _runs(("in_progress", None), ("completed", "success")), ""
        ),
        ("api", "repos/acme/app/commits/c3/check-runs?per_page=100"): (
            0, _runs(("completed", "failure"), ("completed", "success")), ""
        ),
        ("api", "repos/acme/app/commits/c2/check-runs?per_page=100"): (0, _runs(), ""),
        ("api", "repos/acme/app/commits/c1/check-runs?per_page=100"): (
            0, _runs(("completed", "success"), ("completed", "skipped")), ""
        ),
    })
    assert gh.newest_green_commit("acme/app", "main") == "c1"


def test_missing_gh_binary(monkeypatch):
    monkeypatch.setattr(gh.shutil, "which", lambda name: None)
    with pytest.raises(gh.GhError, match="gh CLI not found"):
        gh.pr_state("acme/app", "b")
