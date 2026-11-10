"""The root phase and the drop to `warren` (uid 1000): who the workload runs as, and which
root-only actions still happen first."""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

_ENTRYPOINT_PATH = Path(__file__).parent.parent / "entrypoint.py"
_spec = importlib.util.spec_from_file_location("warren_entrypoint_workload", _ENTRYPOINT_PATH)
_ep = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_ep)


def _stat_owned_by(uid: int):
    return lambda path, follow_symlinks=True: SimpleNamespace(st_uid=uid)


@pytest.mark.parametrize(
    ("owner", "drops"),
    [
        (1000, True),  # podman keep-id: the server user is uid 1000 here
        (0, False),  # podman host userns: the server user is container root
        (501, False),  # rootful docker, server uid != 1000: don't take the checkout away
    ],
)
def test_drops_only_over_mounts_owned_by_uid_1000(monkeypatch, owner, drops):
    assert _ep.choose_workload_user(["/workspace/repo"], env={}, stat=_stat_owned_by(owner)) is drops


def test_first_existing_probe_path_decides(monkeypatch):
    def stat(path, follow_symlinks=True):
        if path == "/missing":
            raise FileNotFoundError(path)
        return SimpleNamespace(st_uid=1000)

    assert _ep.choose_workload_user(["/missing", "/var/lib/warren/harness"], env={}, stat=stat) is True


def test_no_mount_to_go_by_stays_root(monkeypatch):
    def stat(*a, **k):
        raise FileNotFoundError

    assert _ep.choose_workload_user(["/nope"], env={}, stat=stat) is False


def test_env_override(monkeypatch):
    env = {"WARREN_WORKLOAD_USER": "root"}
    assert _ep.choose_workload_user(["/w"], env=env, stat=_stat_owned_by(1000)) is False
    env = {"WARREN_WORKLOAD_USER": "warren"}
    assert _ep.choose_workload_user(["/w"], env=env, stat=_stat_owned_by(0)) is True


def test_drop_order_groups_then_gid_then_uid(monkeypatch):
    calls: list[tuple] = []
    monkeypatch.setattr(_ep.os, "setgroups", lambda g: calls.append(("setgroups", tuple(g))))
    monkeypatch.setattr(_ep.os, "setgid", lambda g: calls.append(("setgid", g)))
    monkeypatch.setattr(_ep.os, "setuid", lambda u: calls.append(("setuid", u)))
    monkeypatch.setattr(_ep.os, "environ", {})
    _ep.drop_privileges()
    assert calls == [("setgroups", ()), ("setgid", 1000), ("setuid", 1000)]
    assert _ep.os.environ["HOME"] == "/home/warren"
    assert _ep.os.environ["USER"] == _ep.os.environ["LOGNAME"] == "warren"


def _root_phase_env(monkeypatch, tmp_path: Path, *, owner: int, shell_first: bool):
    """Run root_phase as 'root' with every privileged call recorded instead of made."""
    events: list[str] = []
    marker = tmp_path / "workload"
    session_env = tmp_path / "session.env"
    monkeypatch.setattr(_ep, "_WORKLOAD_MARKER", str(marker))
    monkeypatch.setattr(_ep, "write_session_env", lambda: (events.append("session_env"), session_env.write_text("x")))
    monkeypatch.setattr(_ep, "drop_privileges", lambda: events.append("drop"))
    monkeypatch.setattr(_ep, "emit", lambda e: events.append(f"emit:{e['type']}"))
    monkeypatch.setattr(_ep.os, "geteuid", lambda: 0)
    monkeypatch.setattr(_ep.os, "environ", {"WARREN_SHELL_FIRST": "1"} if shell_first else {})
    monkeypatch.setattr(_ep, "choose_workload_user", lambda paths: owner == 1000)
    return events, marker


def test_keep_id_root_phase_writes_root_files_then_drops(monkeypatch, tmp_path):
    events, marker = _root_phase_env(monkeypatch, tmp_path, owner=1000, shell_first=True)
    _ep.root_phase()
    # The root-only writes happen before the drop; nothing root-only is left for after it.
    assert events == ["session_env", "drop", "emit:workload_user"]
    assert marker.read_text() == "1000 1000 /home/warren warren\n"


def test_host_userns_root_phase_keeps_root_and_writes_no_marker(monkeypatch, tmp_path):
    events, marker = _root_phase_env(monkeypatch, tmp_path, owner=0, shell_first=True)
    _ep.root_phase()
    assert events == ["session_env"]
    assert not marker.exists()


def test_not_root_does_nothing(monkeypatch, tmp_path):
    events, marker = _root_phase_env(monkeypatch, tmp_path, owner=1000, shell_first=True)
    monkeypatch.setattr(_ep.os, "geteuid", lambda: 1000)
    _ep.root_phase()
    assert events == [] and not marker.exists()


def test_failed_drop_is_fatal_not_a_silent_root_workload(monkeypatch, tmp_path):
    events, _ = _root_phase_env(monkeypatch, tmp_path, owner=1000, shell_first=False)

    def boom():
        raise PermissionError("nope")

    monkeypatch.setattr(_ep, "drop_privileges", boom)
    with pytest.raises(SystemExit):
        _ep.root_phase()
    assert "emit:workspace_failed" in events


def test_dockerfile_creates_the_user_and_labels_the_image():
    text = (Path(__file__).parent.parent / "Dockerfile").read_text()
    assert "useradd -u 1000 -g warren" in text
    assert 'LABEL dev.warren.workload-uid="1000"' in text
    # No USER: sshd (docker-ssh-base) needs root at start; the entrypoint drops.
    assert not any(line.startswith("USER ") for line in text.splitlines())
    assert os.path.isfile(Path(__file__).parent.parent / "warren-tmux.sh")
