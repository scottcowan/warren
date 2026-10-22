"""Thin wrappers over the operator's own `gh` CLI (PR state, CI check-runs)."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from typing import Any
from urllib.parse import quote

_GITHUB_URL_RE = re.compile(
    r"^(?:git@github\.com:|ssh://git@github\.com/|https://github\.com/)"
    r"(?P<owner>[A-Za-z0-9_.-]+)/(?P<repo>[A-Za-z0-9_.-]+?)(?:\.git)?/?$"
)
_GREEN_CONCLUSIONS = frozenset({"success", "neutral", "skipped"})


class GhError(RuntimeError):
    pass


def github_repo(url: str | None) -> str | None:
    """`owner/repo` for a GitHub remote URL, else None."""
    m = _GITHUB_URL_RE.match(url or "")
    return f"{m['owner']}/{m['repo']}" if m else None


def _gh(*args: str) -> Any:
    gh = shutil.which("gh")
    if not gh:
        raise GhError("gh CLI not found on PATH (https://cli.github.com)")
    r = subprocess.run([gh, *args], capture_output=True, text=True, check=False)
    if r.returncode != 0:
        raise GhError(r.stderr.strip() or f"gh {args[0]} failed")
    return json.loads(r.stdout or "null")


def pr_state(repo: str, branch: str) -> str | None:
    """"OPEN"/"MERGED"/"CLOSED" for the PR whose head is `branch`, None if there is none."""
    try:
        data = _gh("pr", "view", branch, "--repo", repo, "--json", "state")
    except GhError as exc:
        if "no pull requests found" in str(exc).lower():
            return None
        raise
    return (data or {}).get("state")


def _commit_is_green(repo: str, sha: str) -> bool:
    data = _gh("api", f"repos/{repo}/commits/{sha}/check-runs?per_page=100")
    runs = (data or {}).get("check_runs") or []
    return bool(runs) and all(
        r.get("status") == "completed" and r.get("conclusion") in _GREEN_CONCLUSIONS for r in runs
    )


def newest_green_commit(repo: str, branch: str, *, limit: int = 20) -> str | None:
    """Newest of the last `limit` commits on `branch` whose check-runs all passed."""
    commits = _gh("api", f"repos/{repo}/commits?sha={quote(branch, safe='')}&per_page={limit}") or []
    for commit in commits:
        sha = commit.get("sha")
        if sha and _commit_is_green(repo, sha):
            return sha
    return None
