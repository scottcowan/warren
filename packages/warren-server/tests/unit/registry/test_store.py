"""WorkspaceStore CRUD unit tests against a tempfile SQLite DB (Pitfall #13)."""

from __future__ import annotations

import os
import stat
import sys
from pathlib import Path

import aiosqlite
import pytest

from warren.registry.store import WorkspaceStore, open_db


@pytest.mark.asyncio
async def test_insert_and_get_roundtrip(sqlite_path: str):
    store = await WorkspaceStore.open(sqlite_path)
    await store.insert(
        workspace_id="ws-1",
        project="p",
        intent="i",
        image="img:latest",
        root_path="/tmp/ws-1",
        server_instance="s1",
        status="provisioning",
    )
    row = await store.get("ws-1")
    assert row is not None
    assert row.workspace_id == "ws-1"
    assert row.project == "p"
    assert row.status == "provisioning"
    assert row.server_instance == "s1"


@pytest.mark.asyncio
async def test_get_missing_returns_none(sqlite_path: str):
    store = await WorkspaceStore.open(sqlite_path)
    assert await store.get("nope") is None


@pytest.mark.asyncio
async def test_update_status(sqlite_path: str):
    store = await WorkspaceStore.open(sqlite_path)
    await store.insert(
        workspace_id="ws-u",
        project="p",
        intent="i",
        image="img",
        root_path="/tmp/ws-u",
        server_instance="s1",
        status="provisioning",
    )
    await store.update_status("ws-u", "running")
    row = await store.get("ws-u")
    assert row.status == "running"


@pytest.mark.asyncio
async def test_list_non_terminal_filters_by_status(sqlite_path: str):
    store = await WorkspaceStore.open(sqlite_path)
    for wid, status in [
        ("ws-run", "running"),
        ("ws-prov", "provisioning"),
        ("ws-stopping", "stopping"),
        ("ws-unknown", "unknown"),
        ("ws-stopped", "stopped"),
        ("ws-failed", "failed"),
    ]:
        await store.insert(
            workspace_id=wid,
            project="p",
            intent="i",
            image="img",
            root_path=f"/tmp/{wid}",
            server_instance="s1",
            status=status,
        )
    rows = await store.list_non_terminal()
    ids = {r.workspace_id for r in rows}
    assert ids == {"ws-run", "ws-prov", "ws-stopping", "ws-unknown"}


@pytest.mark.asyncio
async def test_insert_with_ssh_port_and_owner_id_roundtrips(sqlite_path: str):
    store = await WorkspaceStore.open(sqlite_path)
    await store.insert(
        workspace_id="ws-ssh",
        project="p",
        intent="i",
        image="img",
        root_path="/tmp/ws-ssh",
        server_instance="s1",
        status="provisioning",
        ssh_port=30017,
        owner_id="u-1",
    )
    row = await store.get("ws-ssh")
    assert row is not None
    assert row.ssh_port == 30017
    assert row.owner_id == "u-1"


@pytest.mark.asyncio
async def test_insert_without_ssh_port_or_owner_id_defaults_to_none(sqlite_path: str):
    store = await WorkspaceStore.open(sqlite_path)
    await store.insert(
        workspace_id="ws-none",
        project="p",
        intent="i",
        image="img",
        root_path="/tmp/ws-none",
        server_instance="s1",
        status="provisioning",
    )
    row = await store.get("ws-none")
    assert row is not None
    assert row.ssh_port is None
    assert row.owner_id is None


@pytest.mark.asyncio
async def test_insert_with_idle_ttl_seconds_roundtrips(sqlite_path: str):
    store = await WorkspaceStore.open(sqlite_path)
    await store.insert(
        workspace_id="ws-ttl",
        project="p",
        intent="i",
        image="img",
        root_path="/tmp/ws-ttl",
        server_instance="s1",
        status="provisioning",
        idle_ttl_seconds=1800.0,
    )
    row = await store.get("ws-ttl")
    assert row is not None
    assert row.idle_ttl_seconds == 1800.0


@pytest.mark.asyncio
async def test_insert_without_idle_ttl_seconds_defaults_to_none(sqlite_path: str):
    store = await WorkspaceStore.open(sqlite_path)
    await store.insert(
        workspace_id="ws-ttl-none",
        project="p",
        intent="i",
        image="img",
        root_path="/tmp/ws-ttl-none",
        server_instance="s1",
        status="provisioning",
    )
    row = await store.get("ws-ttl-none")
    assert row is not None
    assert row.idle_ttl_seconds is None


@pytest.mark.asyncio
async def test_open_db_migrates_pre_idle_ttl_seconds_schema(tmp_path):
    """A database created by the previous schema (no idle_ttl_seconds) self-migrates
    on open_db(), same as the owner_id migration below."""
    import aiosqlite

    db_path = tmp_path / "pre_idle_ttl.db"
    old_schema = """
    CREATE TABLE workspaces (
        workspace_id     TEXT PRIMARY KEY,
        project          TEXT NOT NULL,
        intent           TEXT NOT NULL,
        image            TEXT NOT NULL,
        root_path        TEXT NOT NULL,
        container_id     TEXT,
        status           TEXT NOT NULL,
        server_instance  TEXT NOT NULL,
        labels_json      TEXT NOT NULL DEFAULT '{}',
        created_at       TEXT NOT NULL,
        updated_at       TEXT NOT NULL,
        ssh_port         INTEGER,
        owner_id         TEXT
    );
    """
    db = await aiosqlite.connect(str(db_path))
    await db.executescript(old_schema)
    await db.commit()
    await db.close()

    store = await WorkspaceStore.open(str(db_path))
    await store.insert(
        workspace_id="ws-migrated",
        project="p",
        intent="i",
        image="img",
        root_path="/tmp/ws-migrated",
        server_instance="s1",
        status="provisioning",
        idle_ttl_seconds=900.0,
    )
    row = await store.get("ws-migrated")
    assert row is not None
    assert row.idle_ttl_seconds == 900.0
    await store.close()


@pytest.mark.asyncio
async def test_update_ssh_port(sqlite_path: str):
    store = await WorkspaceStore.open(sqlite_path)
    await store.insert(
        workspace_id="ws-port",
        project="p",
        intent="i",
        image="img",
        root_path="/tmp/ws-port",
        server_instance="s1",
        status="provisioning",
        ssh_port=30017,
    )
    before = await store.get("ws-port")
    await store.update_ssh_port("ws-port", 30020)
    row = await store.get("ws-port")
    assert row is not None
    assert row.ssh_port == 30020
    assert row.updated_at >= before.updated_at


@pytest.mark.asyncio
async def test_list_all_and_list_non_terminal_roundtrip_ssh_port_and_owner_id(
    sqlite_path: str,
):
    store = await WorkspaceStore.open(sqlite_path)
    await store.insert(
        workspace_id="ws-list",
        project="p",
        intent="i",
        image="img",
        root_path="/tmp/ws-list",
        server_instance="s1",
        status="running",
        ssh_port=30021,
        owner_id="u-2",
    )
    all_rows = {r.workspace_id: r for r in await store.list_all()}
    non_terminal_rows = {r.workspace_id: r for r in await store.list_non_terminal()}
    assert all_rows["ws-list"].ssh_port == 30021
    assert all_rows["ws-list"].owner_id == "u-2"
    assert non_terminal_rows["ws-list"].ssh_port == 30021
    assert non_terminal_rows["ws-list"].owner_id == "u-2"


@pytest.mark.asyncio
async def test_open_db_migrates_pre_owner_id_schema(tmp_path):
    """A database created by the previous schema (no owner_id) self-migrates on open_db()."""
    db_path = tmp_path / "old-schema.sqlite3"
    old_db = await aiosqlite.connect(str(db_path), isolation_level=None)
    await old_db.executescript(
        """
        CREATE TABLE IF NOT EXISTS workspaces (
            workspace_id     TEXT PRIMARY KEY,
            project          TEXT NOT NULL,
            intent           TEXT NOT NULL,
            image            TEXT NOT NULL,
            root_path        TEXT NOT NULL,
            container_id     TEXT,
            status           TEXT NOT NULL,
            server_instance  TEXT NOT NULL,
            labels_json      TEXT NOT NULL DEFAULT '{}',
            created_at       TEXT NOT NULL,
            updated_at       TEXT NOT NULL
        );
        """
    )
    await old_db.close()

    db = await open_db(str(db_path))
    store = WorkspaceStore(db)
    await store.insert(
        workspace_id="ws-migrated",
        project="p",
        intent="i",
        image="img",
        root_path="/tmp/ws-migrated",
        server_instance="s1",
        status="provisioning",
        owner_id="u-3",
    )
    row = await store.get("ws-migrated")
    assert row is not None
    assert row.owner_id == "u-3"
    await store.close()


@pytest.mark.asyncio
@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permission bits only")
async def test_open_db_creates_data_dir_with_0700_when_new(tmp_path: Path):
    """Audit #44: a data dir this call creates is chmod'd 0700."""
    data_dir = tmp_path / "fresh-data-dir"
    assert not data_dir.exists()
    db = await open_db(data_dir / "warren.db")
    try:
        mode = stat.S_IMODE(data_dir.stat().st_mode)
        assert mode == 0o700
    finally:
        await db.close()


@pytest.mark.asyncio
@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permission bits only")
async def test_open_db_does_not_chmod_preexisting_data_dir(tmp_path: Path):
    """Audit #44: an operator's pre-existing data dir keeps whatever perms it already
    had -- open_db must never force 0700 onto a directory it didn't create."""
    data_dir = tmp_path / "preexisting-data-dir"
    data_dir.mkdir(mode=0o750)
    os.chmod(data_dir, 0o750)  # mkdir's mode is umask-affected; set it explicitly
    db = await open_db(data_dir / "warren.db")
    try:
        mode = stat.S_IMODE(data_dir.stat().st_mode)
        assert mode == 0o750
    finally:
        await db.close()


@pytest.mark.asyncio
@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permission bits only")
async def test_open_db_chmods_db_file_to_0600(tmp_path: Path):
    """Audit #44: the DB file (holds Fernet-encrypted secrets + hashed auth tokens) is
    chmod'd 0600 on every open_db call, correcting a looser pre-existing mode too."""
    db_path = tmp_path / "warren.db"
    db = await open_db(db_path)
    await db.close()

    os.chmod(db_path, 0o644)  # simulate a looser mode from an older version

    db2 = await open_db(db_path)
    try:
        mode = stat.S_IMODE(db_path.stat().st_mode)
        assert mode == 0o600
    finally:
        await db2.close()


@pytest.mark.asyncio
async def test_open_db_scrubs_legacy_plaintext_env_from_spec_json(sqlite_path: str):
    """Audit V3: a row's spec_json snapshotted before the R1 fix can still carry a
    plaintext "env" key (every declared secret's decrypted value, sitting outside the
    Fernet-encrypted secrets store it was meant to live in exclusively). Reopening the
    DB (the same open_db() call every server startup makes) must strip it."""
    import json

    store = await WorkspaceStore.open(sqlite_path)
    await store.insert(
        workspace_id="ws-legacy",
        project="p",
        intent="i",
        image="img:latest",
        root_path="/tmp/ws-legacy",
        server_instance="s1",
        status="provisioning",
        spec_json=json.dumps(
            {"secret_names": ["API_KEY"], "env": {"API_KEY": "sk-plaintext-secret"}}
        ),
    )
    await store.close()

    store2 = await WorkspaceStore.open(sqlite_path)
    try:
        row = await store2.get("ws-legacy")
        assert row is not None
        data = json.loads(row.spec_json)
        assert "env" not in data
        assert data["secret_names"] == ["API_KEY"]
    finally:
        await store2.close()


@pytest.mark.asyncio
async def test_open_db_scrub_is_noop_for_rows_without_env(sqlite_path: str):
    """A row with no "env" key (the post-R1 shape) must pass through untouched."""
    import json

    store = await WorkspaceStore.open(sqlite_path)
    await store.insert(
        workspace_id="ws-clean",
        project="p",
        intent="i",
        image="img:latest",
        root_path="/tmp/ws-clean",
        server_instance="s1",
        status="provisioning",
        spec_json=json.dumps({"secret_names": ["API_KEY"]}),
    )
    await store.close()

    store2 = await WorkspaceStore.open(sqlite_path)
    try:
        row = await store2.get("ws-clean")
        assert row is not None
        assert json.loads(row.spec_json) == {"secret_names": ["API_KEY"]}
    finally:
        await store2.close()



def _insert_kwargs(i: int, owner: str) -> dict:
    return dict(
        workspace_id=f"ws-{owner}-{i}",
        project="p",
        intent="i",
        image="img",
        root_path="",
        server_instance="s1",
        status="provisioning",
        owner_id=owner,
    )


async def test_insert_caps_are_atomic_under_concurrency(sqlite_path: str):
    """Finding 11: list-then-insert let concurrent creates overshoot max_workspaces."""
    import asyncio

    from warren.registry.store import CapacityExhausted

    store = await WorkspaceStore.open(sqlite_path)
    results = await asyncio.gather(
        *(store.insert(**_insert_kwargs(i, "alice"), max_total=6, max_per_owner=3) for i in range(12)),
        *(store.insert(**_insert_kwargs(i, "bob"), max_total=6, max_per_owner=6) for i in range(12)),
        return_exceptions=True,
    )
    errors = [r for r in results if isinstance(r, BaseException)]
    assert all(isinstance(e, CapacityExhausted) for e in errors)
    rows = await store.list_non_terminal()
    assert len(rows) == 6
    assert len([w for w in rows if w.owner_id == "alice"]) <= 3
    await store.close()


async def test_insert_cap_scope_and_terminal_rows(sqlite_path: str):
    from warren.registry.store import CapacityExhausted

    store = await WorkspaceStore.open(sqlite_path)
    await store.insert(**_insert_kwargs(0, "alice"), max_total=2, max_per_owner=1)
    with pytest.raises(CapacityExhausted) as owner_exc:
        await store.insert(**_insert_kwargs(1, "alice"), max_total=2, max_per_owner=1)
    assert owner_exc.value.scope == "owner"
    await store.insert(**_insert_kwargs(0, "bob"), max_total=2, max_per_owner=1)
    with pytest.raises(CapacityExhausted) as server_exc:
        await store.insert(**_insert_kwargs(0, "carol"), max_total=2, max_per_owner=1)
    assert server_exc.value.scope == "server"
    await store.update_status("ws-alice-0", "destroyed")
    await store.insert(**_insert_kwargs(2, "alice"), max_total=2, max_per_owner=1)
    await store.close()


@pytest.mark.asyncio
async def test_open_db_drops_legacy_stored_sidecar_tokens(sqlite_path: str):
    """Audit finding 12 follow-up: a previous release stored every workspace's sidecar
    token (live, reaped and destroyed rows alike). Reopening the DB removes them all,
    including from the file's freed pages."""
    store = await WorkspaceStore.open(sqlite_path)
    await store._db.execute("ALTER TABLE workspaces ADD COLUMN sidecar_token_enc BLOB")
    for ws, status in (("ws-live", "running"), ("ws-reaped", "stopped"), ("ws-gone", "destroyed")):
        await store.insert(
            workspace_id=ws, project="p", intent="i", image="img", root_path="",
            server_instance="s1", status=status,
        )
        await store._db.execute(
            "UPDATE workspaces SET sidecar_token_enc = ? WHERE workspace_id = ?",
            (f"LEGACY-SIDECAR-TOKEN-{ws}".encode(), ws),
        )
    await store.close()

    store2 = await WorkspaceStore.open(sqlite_path)
    try:
        async with store2._db.execute("PRAGMA table_info(workspaces)") as cur:
            assert "sidecar_token_enc" not in {row[1] for row in await cur.fetchall()}
        assert (await store2.get("ws-gone")).status == "destroyed"
    finally:
        await store2.close()
    for path in Path(sqlite_path).parent.glob(Path(sqlite_path).name + "*"):
        assert b"LEGACY-SIDECAR-TOKEN" not in path.read_bytes()
