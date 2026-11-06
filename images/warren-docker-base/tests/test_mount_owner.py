"""`match_mount_owner`: under a keep-id userns the harness dir is owned by uid 1000, and
what the root entrypoint's harness init wrote there is handed to that owner."""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path

_ENTRYPOINT_PATH = Path(__file__).parent.parent / "entrypoint.py"
_spec = importlib.util.spec_from_file_location("warren_entrypoint_owner", _ENTRYPOINT_PATH)
_entrypoint = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_entrypoint)


def _tree(tmp_path: Path) -> Path:
    root = tmp_path / "harness"
    (root / "claude" / "projects").mkdir(parents=True)
    (root / "claude" / "settings.json").write_text("{}")
    (root / "link").symlink_to("/etc/passwd")
    return root


def _fake_stat(owner_uid: int, real_lstat):
    class _St:
        def __init__(self, st, uid):
            self.st_uid, self.st_gid, self.st_mode = uid, uid, st.st_mode

    def stat(path, *, follow_symlinks=True):
        return _St(real_lstat(path), owner_uid)

    def lstat(path):
        return _St(real_lstat(path), 0)  # "written by container root"

    return stat, lstat


def test_chowns_to_the_mount_owner_without_following_links(tmp_path, monkeypatch):
    root = _tree(tmp_path)
    stat, lstat = _fake_stat(1000, os.lstat)
    chowned: list[tuple[str, int, int]] = []
    monkeypatch.setattr(_entrypoint.os, "geteuid", lambda: 0)
    monkeypatch.setattr(_entrypoint.os, "stat", stat)
    monkeypatch.setattr(_entrypoint.os, "lstat", lstat)
    monkeypatch.setattr(_entrypoint.os, "lchown", lambda p, u, g: chowned.append((p, u, g)))
    monkeypatch.setattr(_entrypoint.os, "chown", lambda *a, **k: (_ for _ in ()).throw(AssertionError("chown follows links")))

    _entrypoint.match_mount_owner(str(root))

    got = sorted(os.path.relpath(p, root) for p, _, _ in chowned)
    assert got == ["claude", "claude/projects", "claude/settings.json", "link"]
    assert {(u, g) for _, u, g in chowned} == {(1000, 1000)}


def test_root_owned_mount_is_left_alone(tmp_path, monkeypatch):
    """podman's default mapping (WARREN_PODMAN_USERNS=host): the server user is root here."""
    root = _tree(tmp_path)
    stat, _ = _fake_stat(0, os.lstat)
    monkeypatch.setattr(_entrypoint.os, "geteuid", lambda: 0)
    monkeypatch.setattr(_entrypoint.os, "stat", stat)
    monkeypatch.setattr(_entrypoint.os, "lchown", lambda *a: (_ for _ in ()).throw(AssertionError("chowned")))
    _entrypoint.match_mount_owner(str(root))


def test_not_root_does_nothing(tmp_path, monkeypatch):
    root = _tree(tmp_path)
    monkeypatch.setattr(_entrypoint.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(_entrypoint.os, "lchown", lambda *a: (_ for _ in ()).throw(AssertionError("chowned")))
    _entrypoint.match_mount_owner(str(root))
    _entrypoint.match_mount_owner(str(tmp_path / "missing"))
