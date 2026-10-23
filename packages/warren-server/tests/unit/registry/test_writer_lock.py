"""Audit #10: a single fenced SQLite writer per data dir."""

from __future__ import annotations

import subprocess
import sys
import threading
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from warren.registry import store
from warren.registry.store import WriterLockHeld, acquire_writer_lock, resolve_journal_mode


def test_second_writer_lock_fails_fast(tmp_path):
    db_file = tmp_path / "warren.db"
    first = acquire_writer_lock(db_file)
    try:
        with pytest.raises(WriterLockHeld):
            acquire_writer_lock(db_file)
    finally:
        first.release()
    acquire_writer_lock(db_file).release()


def test_writer_lock_is_exclusive_across_processes(tmp_path):
    db_file = tmp_path / "warren.db"
    lock = acquire_writer_lock(db_file)
    try:
        probe = subprocess.run(
            [
                sys.executable,
                "-c",
                "import sys; from warren.registry.store import acquire_writer_lock, WriterLockHeld\n"
                "try:\n    acquire_writer_lock(sys.argv[1])\nexcept WriterLockHeld:\n    sys.exit(3)\n",
                str(db_file),
            ],
            capture_output=True,
            timeout=60,
        )
    finally:
        lock.release()
    assert probe.returncode == 3, probe.stderr


def test_zero_wait_fails_fast(tmp_path):
    db_file = tmp_path / "warren.db"
    holder = acquire_writer_lock(db_file)
    try:
        start = time.monotonic()
        with pytest.raises(WriterLockHeld):
            acquire_writer_lock(db_file, wait_s=0)
        assert time.monotonic() - start < 0.5
    finally:
        holder.release()


def test_wait_times_out_with_writer_lock_held(tmp_path):
    db_file = tmp_path / "warren.db"
    holder = acquire_writer_lock(db_file)
    try:
        start = time.monotonic()
        with pytest.raises(WriterLockHeld):
            acquire_writer_lock(db_file, wait_s=0.8)
        assert 0.7 <= time.monotonic() - start < 3
    finally:
        holder.release()


def test_wait_acquires_once_the_holder_releases(tmp_path):
    db_file = tmp_path / "warren.db"
    holder = acquire_writer_lock(db_file)
    releaser = threading.Timer(0.6, holder.release)
    releaser.start()
    try:
        start = time.monotonic()
        lock = acquire_writer_lock(db_file, wait_s=10)
        assert 0.5 <= time.monotonic() - start < 5
        lock.release()
    finally:
        releaser.join()


def test_release_is_idempotent(tmp_path):
    lock = acquire_writer_lock(tmp_path / "warren.db")
    lock.release()
    lock.release()


def test_lock_creates_private_data_dir(tmp_path):
    data_dir = tmp_path / "fresh"
    acquire_writer_lock(data_dir / "warren.db").release()
    assert (data_dir.stat().st_mode & 0o777) == 0o700


@pytest.mark.parametrize(
    ("fstype", "expected"),
    [("nfs4", "DELETE"), ("nfs", "DELETE"), ("ext4", "WAL"), ("overlay", "WAL"), ("", "WAL")],
)
def test_auto_journal_mode_avoids_wal_on_network_filesystems(tmp_path, fstype, expected):
    with patch.object(store, "_filesystem_type", return_value=fstype):
        assert resolve_journal_mode(tmp_path) == expected


def test_explicit_journal_mode_overrides_detection(tmp_path):
    with patch.object(store, "_filesystem_type", return_value="nfs4"):
        assert resolve_journal_mode(tmp_path, "wal") == "WAL"
    with patch.object(store, "_filesystem_type", return_value="ext4"):
        assert resolve_journal_mode(tmp_path, "delete") == "DELETE"


def test_filesystem_type_uses_longest_matching_mount(tmp_path):
    tmp_path = tmp_path.resolve()
    mounts = (
        "overlay / overlay rw 0 0\n"
        f"fs-1.efs:/ {tmp_path} nfs4 rw 0 0\n"
        f"tmpfs {tmp_path}x tmpfs rw 0 0\n"
    )
    with patch.object(store.Path, "read_text", return_value=mounts):
        assert store._filesystem_type(tmp_path / "warren.db") == "nfs4"
        assert store._filesystem_type(tmp_path.parent) == "overlay"


async def test_open_db_uses_delete_journal_on_network_filesystem(tmp_path):
    with patch.object(store, "_filesystem_type", return_value="nfs4"):
        db = await store.open_db(tmp_path / "warren.db")
    try:
        async with db.execute("PRAGMA journal_mode") as cur:
            assert (await cur.fetchone())[0] == "delete"
    finally:
        await db.close()


async def test_second_server_on_same_data_dir_refuses_to_start(monkeypatch, tmp_path):
    monkeypatch.setenv("WARREN_SECRET_KEY", "x" * 32)
    monkeypatch.setenv("WARREN_BOOTSTRAP_TOKEN", "test-bootstrap-token000000000000")
    monkeypatch.setenv("WARREN_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("WARREN_PODMAN_SOCKET", str(tmp_path / "podman.sock"))
    monkeypatch.setenv("WARREN_SERVER_ID", "test-server")
    monkeypatch.setenv("WARREN_REAPER_ENABLED", "0")
    monkeypatch.setenv("WARREN_WRITER_LOCK_WAIT_S", "0")
    registry = MagicMock()
    registry.reconcile_from_disk = AsyncMock()

    with (
        patch("warren.app.run_preflight", AsyncMock()),
        patch("warren.app.WorkspaceRegistry", return_value=registry),
        patch("warren.app.PodmanRuntime"),
    ):
        from warren.app import app, lifespan

        async with lifespan(app):
            with pytest.raises(WriterLockHeld):
                async with lifespan(app):
                    pass
        async with lifespan(app):
            pass
