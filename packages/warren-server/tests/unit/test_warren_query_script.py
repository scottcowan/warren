"""assets/warren_query.sh, run directly against a temp workspace (as the test user, so
the privilege drop is skipped). The image smoke tests cover the dropped-to user."""

from __future__ import annotations

import base64
import os
import shutil
import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).parents[3] / "warren-common" / "src" / "warren_common" / "assets" / "warren_query.sh"


def _gnu_or_busybox_stat() -> bool:
    try:
        return subprocess.run(["stat", "-c", "%s", "/"], capture_output=True).returncode == 0
    except OSError:
        return False


pytestmark = pytest.mark.skipif(
    os.name != "posix" or shutil.which("git") is None or not _gnu_or_busybox_stat() or os.geteuid() == 0,
    reason="needs POSIX sh, git and stat -c, run as a non-root user",
)


def _q(*args: str) -> subprocess.CompletedProcess:
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin")}
    return subprocess.run(["sh", str(SCRIPT), *args], capture_output=True, text=True, env=env, timeout=60)


def _git(cwd: Path, *args: str) -> None:
    env = {"PATH": os.environ.get("PATH", ""), "HOME": str(cwd), "GIT_CONFIG_NOSYSTEM": "1"}
    subprocess.run(
        ["git", "-c", "user.email=t@t", "-c", "user.name=t", *args], cwd=cwd, check=True, env=env, capture_output=True
    )


@pytest.fixture
def workspace(tmp_path: Path) -> Path:
    root = tmp_path / "workspace"
    repo = root / "main"
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_text("TOPSECRET")
    repo.mkdir(parents=True)
    _git(repo, "init", "-q")
    (repo / "a.txt").write_text("hello\n")
    (repo / "sub").mkdir()
    (repo / "sub" / "b.txt").write_text("x\n")
    (repo / ".gitignore").write_text("*.log\nbuild/\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "init")
    (repo / "a.txt").write_text("hello\nchanged\n")
    (repo / "x.log").write_text("TOPSECRET")
    (repo / "build").mkdir()
    (repo / "build" / "o.txt").write_text("TOPSECRET")
    (repo / ".env").write_text("TOPSECRET")
    (repo / "node_modules").mkdir()
    (repo / "node_modules" / "m.js").write_text("TOPSECRET")
    (repo / "link.txt").symlink_to(outside / "secret.txt")
    (repo / "linkdir").symlink_to(outside, target_is_directory=True)
    (root / "top.txt").write_text("top")
    (root / "plain").mkdir()
    (root / "plain" / "p.txt").write_text("p")
    (root / "plain" / "escape").symlink_to(outside, target_is_directory=True)
    return root


def test_list_honours_exclusions_and_skips_symlinks(workspace):
    out = _q("list", str(workspace))
    assert out.returncode == 0, out.stderr
    lines = out.stdout.splitlines()
    assert lines[-1] == "END"
    paths = {ln.split(" ", 2)[2] for ln in lines[:-1]}
    assert paths == {"top.txt", "plain/p.txt", "main/a.txt", "main/sub/b.txt", "main/.gitignore"}
    assert "F 14 main/a.txt" in lines


def test_tracked_file_under_a_dir_swapped_for_a_symlink_is_not_listed(workspace):
    repo = workspace / "main"
    shutil.rmtree(repo / "sub")
    (repo / "sub").symlink_to(workspace.parent / "outside", target_is_directory=True)
    paths = {ln.split(" ", 2)[2] for ln in _q("list", str(workspace)).stdout.splitlines()[:-1]}
    assert not any(p.startswith("main/sub") for p in paths)


def test_read_returns_base64_body(workspace):
    out = _q("read", str(workspace), "main/a.txt", "100")
    lines = out.stdout.splitlines()
    assert out.returncode == 0 and lines[0] == "OK 14" and lines[-1] == "END"
    assert base64.b64decode("".join(lines[1:-1])) == b"hello\nchanged\n"


@pytest.mark.parametrize(
    ("rel", "code", "reason"),
    [
        ("main/link.txt", 6, "ERR symlink"),
        ("main/linkdir/secret.txt", 6, "ERR symlink"),
        ("plain/escape/secret.txt", 6, "ERR symlink"),
        ("main/.env", 4, "ERR excluded"),
        ("main/x.log", 4, "ERR excluded"),
        ("main/build/o.txt", 4, "ERR excluded"),
        ("main/node_modules/m.js", 4, "ERR excluded"),
        ("main/nope.txt", 5, "ERR not found"),
        ("main/sub", 6, "ERR not a regular file"),
    ],
)
def test_read_refusals(workspace, rel, code, reason):
    out = _q("read", str(workspace), rel, "100")
    assert (out.returncode, out.stdout.strip()) == (code, reason)
    assert "TOPSECRET" not in out.stdout


def test_read_over_the_cap(workspace):
    out = _q("read", str(workspace), "main/a.txt", "3")
    assert (out.returncode, out.stdout.strip()) == (7, "TOOBIG 14")


def test_diff_per_repo(workspace):
    out = _q("diff", str(workspace), "100000")
    lines = out.stdout.splitlines()
    assert out.returncode == 0 and lines[0] == "REPO main" and lines[-2:] == ["ENDREPO", "END"]
    diff = base64.b64decode("".join(lines[1:-2])).decode()
    assert "+changed" in diff


def test_hostile_repo_config_does_not_run_commands(workspace, tmp_path):
    marker = tmp_path / "ran"
    repo = workspace / "main"
    _git(repo, "config", "core.fsmonitor", f"touch {marker}; false")
    _git(repo, "config", "diff.external", f"touch {marker}")
    (repo / ".gitattributes").write_text("*.txt diff=evil\n")
    _git(repo, "config", "diff.evil.textconv", f"touch {marker}; cat")
    assert _q("diff", str(workspace), "100000").returncode == 0
    assert _q("list", str(workspace)).returncode == 0
    assert not marker.exists()
