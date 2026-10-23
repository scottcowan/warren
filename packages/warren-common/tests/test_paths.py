"""BB1: mount validation and workspace containment checks."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from pydantic import ValidationError

from warren_common.models import FolderSpec
from warren_common.paths import PathEscapeError, ensure_within


@pytest.mark.parametrize(
    "mount,expected",
    [
        ("code/repo", "code/repo"),
        ("./code//repo/", "code/repo"),
        ("wiki", "wiki"),
    ],
)
def test_folder_mount_normalised(mount, expected):
    f = FolderSpec(name="f", type="local-path", mount=mount, path="/x")
    assert f.mount == expected


@pytest.mark.parametrize(
    "mount",
    ["", "   ", ".", "/etc", "~/Documents", "~", "..", "../../Documents",
     "a/../../b", "code/../..", "\\abs"],
)
def test_folder_mount_rejects_escapes(mount):
    with pytest.raises(ValidationError):
        FolderSpec(name="f", type="local-path", mount=mount, path="/x")


def test_ensure_within_accepts_nested(tmp_path: Path):
    root = tmp_path / "ws"
    root.mkdir()
    assert ensure_within(root, root / "a" / "b") == (root / "a" / "b").resolve()


@pytest.mark.parametrize("rel", ["../x", "a/../../x"])
def test_ensure_within_rejects_dotdot(tmp_path: Path, rel):
    root = tmp_path / "ws"
    root.mkdir()
    with pytest.raises(PathEscapeError):
        ensure_within(root, root / rel)


def test_ensure_within_rejects_absolute_and_root(tmp_path: Path):
    root = tmp_path / "ws"
    root.mkdir()
    with pytest.raises(PathEscapeError):
        ensure_within(root, root / "/etc")
    with pytest.raises(PathEscapeError):
        ensure_within(root, root)
    assert ensure_within(root, root, allow_root=True) == root.resolve()


def test_ensure_within_rejects_symlinked_parent(tmp_path: Path):
    root = tmp_path / "ws"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (root / "link").symlink_to(outside)
    with pytest.raises(PathEscapeError):
        ensure_within(root, root / "link" / "child")


@pytest.mark.parametrize(
    "wid", ["aaaaaaaa-1111-2222-3333-444444444444", "aaaa", "ws-1", "ws_1"]
)
def test_workspace_id_accepted(wid):
    from warren_common.paths import validate_workspace_id

    assert validate_workspace_id(wid) == wid


@pytest.mark.parametrize(
    "wid",
    ["", ".", "..", "/etc", "/var/victim", "../x", "a/b", "a\\b", "~", "-rf",
     " ws", "ws\n", "a" * 65, "C:x"],
)
def test_workspace_id_rejected(wid):
    from warren_common.paths import UnsafeWorkspaceIdError, validate_workspace_id

    with pytest.raises(UnsafeWorkspaceIdError):
        validate_workspace_id(wid)


@pytest.mark.skipif(sys.platform == "win32", reason="symlink creation needs privilege on Windows")
def test_workspace_child_rejects_symlink(tmp_path: Path):
    from warren_common.paths import workspace_child

    root = tmp_path / "root"
    root.mkdir()
    (root / "ws-1").symlink_to(tmp_path)
    with pytest.raises(PathEscapeError):
        workspace_child(root, "ws-1")
    (root / "ws-2").mkdir()
    assert workspace_child(root, "ws-2") == root / "ws-2"


@pytest.mark.skipif(sys.platform == "win32", reason="symlink creation needs privilege on Windows")
def test_ensure_private_dir(tmp_path: Path):
    import os

    from warren_common.paths import ensure_private_dir

    d = tmp_path / "d"
    assert ensure_private_dir(d) == d
    d.mkdir(mode=0o700)
    assert ensure_private_dir(d) == d
    link = tmp_path / "link"
    link.symlink_to(d)
    with pytest.raises(PathEscapeError):
        ensure_private_dir(link)
    if os.name != "nt":
        os.chmod(d, 0o777)
        with pytest.raises(PathEscapeError):
            ensure_private_dir(d)


def test_state_dir_helpers_reject_unsafe_ids(tmp_path: Path, monkeypatch):
    from warren_common.runtime import bubblewrap, nsjail, seatbelt
    from warren_common.runtime.sandbox_env import nsjail_secret_env_path, workspace_state_dir

    monkeypatch.setenv("WARREN_STATE_DIR", str(tmp_path / "state"))
    for fn in (workspace_state_dir, nsjail_secret_env_path, nsjail._state_dir_for,
               seatbelt._state_dir_for, bubblewrap._state_dir_for):
        with pytest.raises(PathEscapeError):
            fn("../../victim")
    assert workspace_state_dir("ws-1") == tmp_path / "state" / "ws-1"
