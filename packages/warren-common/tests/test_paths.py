"""BB1: mount validation and workspace containment checks."""

from __future__ import annotations

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
