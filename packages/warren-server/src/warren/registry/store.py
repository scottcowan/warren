"""aiosqlite-backed WorkspaceStore with WAL + PRAGMAs (D-05, Pitfall #12)."""

from __future__ import annotations

import json
import os
import socket
import sqlite3
import stat
import time
from datetime import datetime, timezone
from pathlib import Path

import aiosqlite
import structlog
from warren.registry.models import Workspace, WorkspaceStatus

log = structlog.get_logger(__name__)

_SCHEMA_SQL = (Path(__file__).parent / "schema.sql").read_text()

_NON_TERMINAL = ("provisioning", "running", "stopping", "unknown")

# Columns that may be missing on an already-deployed database because they were added
# to schema.sql after that database's file was first created. `CREATE TABLE IF NOT
# EXISTS` never retroactively adds columns to an existing table, so `_ensure_columns()`
# below performs an idempotent `ALTER TABLE ... ADD COLUMN` migration on every open_db()
# call for any entry here that `PRAGMA table_info` doesn't already report. Keyed by
# table, since this same open_db()/migration path is shared by WorkspaceStore and
# AuthStore (both live in this one SQLite file).
_EXPECTED_COLUMNS: dict[str, dict[str, str]] = {
    "workspaces": {
        "ssh_port": "INTEGER",
        "owner_id": "TEXT",
        "idle_ttl_seconds": "REAL",
        # Audit 2026-10-16 P0 #7: the fully-resolved extra spec (env/secret_names/
        # folders/app/ssh_key_paths/ssh_agent_sock/docker_networks/ecs_cpu/ecs_memory/
        # efs_retention_days/aws/scope -- the last two added by audit R11),
        # snapshotted at provision time so ensure_running can reprovision a
        # lost/reaped container faithfully instead of as a bare shell.
        "spec_json": "TEXT",
    },
    "users": {
        # Issue #11: nullable-timestamp "disabled" flag, matching the existing
        # revoked_at/expires_at convention rather than a plain boolean column.
        "disabled_at": "TEXT",
    },
    "tokens": {
        # Issue #11: records which token minted this one, so a revoked token's lineage
        # could in principle be traced/revoked together later. Cascading revocation
        # itself is not implemented yet -- a reasonable follow-up, not blocking.
        "created_by_token_id": "TEXT",
    },
    "workspace_tokens": {
        # AI8/AJ2: a reservation token may provision its (not yet existing) workspace once.
        "provision_grant": "INTEGER NOT NULL DEFAULT 0",
    },
}


async def _ensure_columns(db: aiosqlite.Connection) -> None:
    """Idempotently add any columns in `_EXPECTED_COLUMNS` missing from their table.

    Required, not optional: schema.sql's `CREATE TABLE IF NOT EXISTS` never alters an
    already-existing table, so an already-deployed database would otherwise silently
    never gain new nullable columns like `owner_id`, and every owner_id-bearing SELECT
    would raise `sqlite3.OperationalError` on that host.
    """
    for table, columns in _EXPECTED_COLUMNS.items():
        async with db.execute(f"PRAGMA table_info({table})") as cur:
            rows = await cur.fetchall()
        existing = {row[1] for row in rows}
        for column, sql_type in columns.items():
            if column not in existing:
                await db.execute(f"ALTER TABLE {table} ADD COLUMN {column} {sql_type}")


async def _scrub_legacy_plaintext_env(db: aiosqlite.Connection) -> None:
    """Audit V3: a row's `spec_json` snapshotted before the R1 fix (which
    removed "env" from _SPEC_EXTRA_FIELDS in registry.py) can still carry a
    plaintext "env" key -- every declared secret's decrypted value, sitting
    at rest in this database outside the Fernet-encrypted secrets store it
    was supposed to live in exclusively. Idempotent one-time scrub: strip
    "env" from every stored spec_json that still has it. Safe to run on
    every open_db() call -- a row with no "env" key is a no-op, and this
    never touches the secrets table itself (rotation/deletion there is
    unaffected either way).
    """
    async with db.execute(
        "SELECT workspace_id, spec_json FROM workspaces WHERE spec_json IS NOT NULL"
    ) as cur:
        rows = await cur.fetchall()
    for workspace_id, spec_json in rows:
        try:
            data = json.loads(spec_json)
        except (TypeError, ValueError):
            continue
        if not isinstance(data, dict) or "env" not in data:
            continue
        del data["env"]
        await db.execute(
            "UPDATE workspaces SET spec_json = ? WHERE workspace_id = ?",
            (json.dumps(data), workspace_id),
        )


async def _drop_stored_sidecar_tokens(db: aiosqlite.Connection) -> None:
    """Audit finding 12 follow-up: an earlier release stored every workspace's
    sidecar token (Fernet-encrypted) in `workspaces.sidecar_token_enc`, including
    destroyed rows', for a server->sidecar call that never existed. Tokens now live
    only in each container's env, so drop the column -- or, on an SQLite too old for
    DROP COLUMN, null it -- with secure_delete so the freed pages are zeroed.
    """
    async with db.execute("PRAGMA table_info(workspaces)") as cur:
        if "sidecar_token_enc" not in {row[1] for row in await cur.fetchall()}:
            return
    await db.execute("PRAGMA secure_delete=ON")
    try:
        await db.execute("ALTER TABLE workspaces DROP COLUMN sidecar_token_enc")
    except aiosqlite.OperationalError:
        await db.execute("UPDATE workspaces SET sidecar_token_enc = NULL")
    await db.execute("PRAGMA wal_checkpoint(TRUNCATE)")


_NETWORK_FS_TYPES = frozenset({"nfs", "nfs4", "efs", "cifs", "smb3", "smbfs", "9p", "fuse.sshfs"})


class WriterLockHeld(RuntimeError):
    """Another warren-server process already owns this database."""


class WriterLock:
    """Audit #10: an exclusive advisory lock on `<db>.lock`, held for the server's
    lifetime so a rolling deployment (or a second task) sharing the same data dir
    on EFS can never become a second SQLite writer. flock(2) is emulated with a
    whole-file POSIX lock on Linux NFS clients, which EFS (NFSv4) enforces across
    hosts; a crashed holder's lock is released when its NFS lease expires."""

    def __init__(self, path: Path, fd: int) -> None:
        self.path = path
        self._fd: int | None = fd

    def release(self) -> None:
        if self._fd is None:
            return
        import fcntl

        try:
            fcntl.flock(self._fd, fcntl.LOCK_UN)
        finally:
            os.close(self._fd)
            self._fd = None


def acquire_writer_lock(db_file: str | Path, wait_s: float = 0.0) -> WriterLock:
    """Take the single-writer lock for `db_file`, retrying with backoff for up to
    `wait_s` seconds (0 = fail fast), then raise WriterLockHeld. Waiting matters on
    Fargate + EFS: a just-stopped task's NFSv4 lock lingers until its lease expires,
    and a task that exits at startup counts toward the deployment circuit breaker.
    Blocking -- call from a thread inside the event loop."""
    import fcntl

    lock_path = Path(f"{db_file}.lock")
    if not lock_path.parent.exists():
        lock_path.parent.mkdir(parents=True)
        os.chmod(lock_path.parent, stat.S_IRWXU)  # 0700, same as open_db
    fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, stat.S_IRUSR | stat.S_IWUSR)
    deadline = time.monotonic() + max(wait_s, 0.0)
    delay = 0.25
    while True:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            break
        except OSError as exc:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                os.close(fd)
                raise WriterLockHeld(
                    f"{lock_path} is held by another warren-server process; refusing to "
                    f"open {db_file} as a second writer"
                ) from exc
            log.warning("writer_lock_waiting", lock_path=str(lock_path), remaining_s=round(remaining, 1))
            time.sleep(min(delay, remaining))
            delay = min(delay * 2, 5.0)
    os.ftruncate(fd, 0)
    os.write(fd, f"{os.getpid()} {socket.gethostname()}\n".encode())
    return WriterLock(lock_path, fd)


def _filesystem_type(path: Path) -> str:
    """fstype of the mount containing `path`, from /proc/self/mounts; "" if unknown."""
    try:
        mounts = Path("/proc/self/mounts").read_text().splitlines()
    except OSError:
        return ""
    target = os.path.realpath(path)
    best, fstype = "", ""
    for line in mounts:
        fields = line.split()
        if len(fields) < 3:
            continue
        mount_point = fields[1].replace("\\040", " ")
        inside = target == mount_point or target.startswith(mount_point.rstrip("/") + "/")
        if inside and len(mount_point) >= len(best):
            best, fstype = mount_point, fields[2]
    return fstype


def resolve_journal_mode(data_dir: Path, setting: str = "auto") -> str:
    """WAL needs a shared-memory index that network filesystems can't provide
    safely, so "auto" falls back to DELETE when data_dir is on NFS/EFS."""
    if setting in ("wal", "delete"):
        return setting.upper()
    return "DELETE" if _filesystem_type(data_dir) in _NETWORK_FS_TYPES else "WAL"


async def open_db(path: str | Path, journal_mode: str = "auto") -> aiosqlite.Connection:
    """Open an aiosqlite connection in autocommit mode (WAL, or DELETE on a network
    filesystem -- see resolve_journal_mode) and apply schema.

    Audit 2026-10-16 P2 #44: the DB holds Fernet-encrypted secrets and hashed
    auth tokens, so its permissions matter. The data directory is only chmod'd
    0700 when this call is the one creating it -- an operator's pre-existing
    directory (with its own, possibly deliberately different, permissions) is
    never forced. The DB file itself is chmod'd 0600 every time, since a file
    left world/group-readable by an older version of this code (or a careless
    `cp`) should be corrected on the next startup, not just on first creation.
    """
    data_dir = Path(path).parent
    created_data_dir = not data_dir.exists()
    data_dir.mkdir(parents=True, exist_ok=True)
    if created_data_dir:
        os.chmod(data_dir, stat.S_IRWXU)  # 0700

    db = await aiosqlite.connect(str(path), isolation_level=None)
    await db.execute(f"PRAGMA journal_mode={resolve_journal_mode(data_dir, journal_mode)}")
    await db.execute("PRAGMA synchronous=NORMAL")
    await db.execute("PRAGMA foreign_keys=ON")
    await db.execute("PRAGMA busy_timeout=5000")
    await db.executescript(_SCHEMA_SQL)
    await _ensure_columns(db)
    await _scrub_legacy_plaintext_env(db)
    await _drop_stored_sidecar_tokens(db)

    os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)  # 0600
    return db


class CapacityExhausted(Exception):
    """An insert refused because it would exceed max_workspaces (`scope="server"`) or
    max_workspaces_per_user (`scope="owner"`)."""

    def __init__(self, scope: str, limit: int) -> None:
        super().__init__(f"{scope} workspace limit ({limit}) reached")
        self.scope = scope
        self.limit = limit


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _row_to_workspace(row: aiosqlite.Row | tuple) -> Workspace:
    (
        workspace_id,
        project,
        intent,
        image,
        root_path,
        container_id,
        status,
        server_instance,
        labels_json,
        created_at,
        updated_at,
        ssh_port,
        owner_id,
        idle_ttl_seconds,
        spec_json,
    ) = row
    return Workspace(
        workspace_id=workspace_id,
        project=project,
        intent=intent,
        image=image,
        root_path=root_path,
        container_id=container_id,
        status=status,
        server_instance=server_instance,
        labels=json.loads(labels_json or "{}"),
        created_at=datetime.fromisoformat(created_at),
        updated_at=datetime.fromisoformat(updated_at),
        ssh_port=ssh_port,
        owner_id=owner_id,
        idle_ttl_seconds=idle_ttl_seconds,
        spec_json=spec_json,
    )


class WorkspaceStore:
    """CRUD wrapper around the workspaces table."""

    def __init__(self, db: aiosqlite.Connection) -> None:
        self._db = db

    @classmethod
    async def open(cls, path: str | Path) -> "WorkspaceStore":
        db = await open_db(path)
        return cls(db)

    async def close(self) -> None:
        await self._db.close()

    async def insert(
        self,
        *,
        workspace_id: str,
        project: str,
        intent: str,
        image: str,
        root_path: str,
        server_instance: str,
        status: WorkspaceStatus,
        container_id: str | None = None,
        labels: dict[str, str] | None = None,
        ssh_port: int | None = None,
        owner_id: str | None = None,
        idle_ttl_seconds: float | None = None,
        spec_json: str | None = None,
        max_total: int | None = None,
        max_per_owner: int | None = None,
    ) -> None:
        """Insert a row. With `max_total`/`max_per_owner`, the non-terminal count check and
        the insert are one SQL statement, so concurrent creates can't overshoot either cap
        (SQLite takes the write lock before the statement's reads)."""
        now = _utcnow_iso()
        placeholders = ",".join("?" * len(_NON_TERMINAL))
        cursor = await self._db.execute(
            f"""
            INSERT INTO workspaces (
                workspace_id, project, intent, image, root_path,
                container_id, status, server_instance, labels_json,
                created_at, updated_at, ssh_port, owner_id, idle_ttl_seconds,
                spec_json
            ) SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
            WHERE (? IS NULL OR (SELECT COUNT(*) FROM workspaces WHERE status IN ({placeholders})) < ?)
              AND (? IS NULL OR (
                  SELECT COUNT(*) FROM workspaces WHERE status IN ({placeholders}) AND owner_id IS ?
              ) < ?)
            """,
            (
                workspace_id,
                project,
                intent,
                image,
                root_path,
                container_id,
                status,
                server_instance,
                json.dumps(labels or {}),
                now,
                now,
                ssh_port,
                owner_id,
                idle_ttl_seconds,
                spec_json,
                max_total,
                *_NON_TERMINAL,
                max_total,
                max_per_owner,
                *_NON_TERMINAL,
                owner_id,
                max_per_owner,
            ),
        )
        if cursor.rowcount == 0:
            active = await self.list_non_terminal()
            if max_total is not None and len(active) >= max_total:
                raise CapacityExhausted("server", max_total)
            raise CapacityExhausted("owner", max_per_owner or 0)

    async def get(self, workspace_id: str) -> Workspace | None:
        async with self._db.execute(
            """
            SELECT workspace_id, project, intent, image, root_path,
                   container_id, status, server_instance, labels_json,
                   created_at, updated_at, ssh_port, owner_id, idle_ttl_seconds,
                   spec_json
            FROM workspaces WHERE workspace_id = ?
            """,
            (workspace_id,),
        ) as cur:
            row = await cur.fetchone()
        if row is None:
            return None
        return _row_to_workspace(row)

    async def update_status(self, workspace_id: str, status: WorkspaceStatus) -> None:
        await self._db.execute(
            "UPDATE workspaces SET status = ?, updated_at = ? WHERE workspace_id = ?",
            (status, _utcnow_iso(), workspace_id),
        )
        if status != "stopped":
            await self.clear_idle_stopped(workspace_id)

    async def mark_idle_stopped(self, workspace_id: str) -> None:
        await self._db.execute(
            "INSERT OR REPLACE INTO idle_stops (workspace_id, stopped_at) VALUES (?, ?)",
            (workspace_id, _utcnow_iso()),
        )

    async def clear_idle_stopped(self, workspace_id: str) -> None:
        await self._db.execute("DELETE FROM idle_stops WHERE workspace_id = ?", (workspace_id,))

    async def list_idle_stopped(self) -> list[tuple[str, datetime]]:
        async with self._db.execute("SELECT workspace_id, stopped_at FROM idle_stops") as cur:
            rows = await cur.fetchall()
        return [(wid, datetime.fromisoformat(at)) for wid, at in rows]

    async def mark_running(self, workspace_id: str, container_id: str) -> None:
        """Status `running` and its runtime id in one write, so no row is ever
        running without one (AM2 replay treats such a row as never launched)."""
        await self._db.execute(
            "UPDATE workspaces SET status = 'running', container_id = ?, updated_at = ? WHERE workspace_id = ?",
            (container_id, _utcnow_iso(), workspace_id),
        )
        await self.clear_idle_stopped(workspace_id)

    async def update_container_id(
        self, workspace_id: str, container_id: str | None
    ) -> None:
        await self._db.execute(
            "UPDATE workspaces SET container_id = ?, updated_at = ? WHERE workspace_id = ?",
            (container_id, _utcnow_iso(), workspace_id),
        )

    async def update_image(self, workspace_id: str, image: str) -> None:
        await self._db.execute(
            "UPDATE workspaces SET image = ?, updated_at = ? WHERE workspace_id = ?",
            (image, _utcnow_iso(), workspace_id),
        )

    async def update_ssh_port(self, workspace_id: str, port: int) -> None:
        await self._db.execute(
            "UPDATE workspaces SET ssh_port = ?, updated_at = ? WHERE workspace_id = ?",
            (port, _utcnow_iso(), workspace_id),
        )

    async def list_non_terminal(self) -> list[Workspace]:
        placeholders = ",".join("?" * len(_NON_TERMINAL))
        async with self._db.execute(
            f"""
            SELECT workspace_id, project, intent, image, root_path,
                   container_id, status, server_instance, labels_json,
                   created_at, updated_at, ssh_port, owner_id, idle_ttl_seconds,
                   spec_json
            FROM workspaces WHERE status IN ({placeholders})
            """,
            _NON_TERMINAL,
        ) as cur:
            rows = await cur.fetchall()
        return [_row_to_workspace(r) for r in rows]

    async def list_all(self) -> list[Workspace]:
        async with self._db.execute(
            """
            SELECT workspace_id, project, intent, image, root_path,
                   container_id, status, server_instance, labels_json,
                   created_at, updated_at, ssh_port, owner_id, idle_ttl_seconds,
                   spec_json
            FROM workspaces ORDER BY created_at DESC
            """
        ) as cur:
            rows = await cur.fetchall()
        return [_row_to_workspace(r) for r in rows]


class LaunchAttemptStore:
    """AI3: persisted ECS launch identity per workspace (ecs_launch_attempts)."""

    def __init__(self, db: aiosqlite.Connection) -> None:
        self._db = db

    async def get(self, workspace_id: str) -> dict[str, str] | None:
        async with self._db.execute(
            """
            SELECT generation, fingerprint, task_definition_arn, client_token
            FROM ecs_launch_attempts WHERE workspace_id = ?
            """,
            (workspace_id,),
        ) as cur:
            row = await cur.fetchone()
        if row is None:
            return None
        generation, fingerprint, task_definition_arn, client_token = row
        return {
            "generation": generation,
            "fingerprint": fingerprint,
            "task_definition_arn": task_definition_arn,
            "client_token": client_token,
        }

    async def put(self, workspace_id: str, attempt: dict[str, str]) -> None:
        await self._db.execute(
            """
            INSERT OR REPLACE INTO ecs_launch_attempts (
                workspace_id, generation, fingerprint, task_definition_arn,
                client_token, created_at
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                workspace_id,
                attempt["generation"],
                attempt["fingerprint"],
                attempt["task_definition_arn"],
                attempt["client_token"],
                _utcnow_iso(),
            ),
        )

    async def delete(self, workspace_id: str) -> None:
        await self._db.execute(
            "DELETE FROM ecs_launch_attempts WHERE workspace_id = ?", (workspace_id,)
        )


class OperationStore:
    """AM2: client operation receipts (operations), one per principal + operation id."""

    def __init__(self, db: aiosqlite.Connection) -> None:
        self._db = db

    async def create(
        self, *, principal: str, operation_id: str, kind: str, request_hash: str, workspace_id: str
    ) -> bool:
        """Record an `accepted` operation; False if this principal already has one with that id."""
        now = _utcnow_iso()
        try:
            await self._db.execute(
                """
                INSERT INTO operations (
                    principal, operation_id, kind, request_hash, stage, workspace_id,
                    created_at, updated_at
                ) VALUES (?, ?, ?, ?, 'accepted', ?, ?, ?)
                """,
                (principal, operation_id, kind, request_hash, workspace_id, now, now),
            )
        except sqlite3.IntegrityError:
            return False
        return True

    async def get(self, principal: str, operation_id: str) -> dict[str, str] | None:
        async with self._db.execute(
            """
            SELECT operation_id, kind, request_hash, stage, workspace_id, created_at, updated_at
            FROM operations WHERE principal = ? AND operation_id = ?
            """,
            (principal, operation_id),
        ) as cur:
            row = await cur.fetchone()
        if row is None:
            return None
        keys = ("operation_id", "kind", "request_hash", "stage", "workspace_id", "created_at", "updated_at")
        return dict(zip(keys, row))

    async def delete(self, principal: str, operation_id: str) -> None:
        await self._db.execute(
            "DELETE FROM operations WHERE principal = ? AND operation_id = ?", (principal, operation_id)
        )

    async def set_stage(self, principal: str, operation_id: str, stage: str) -> None:
        await self._db.execute(
            "UPDATE operations SET stage = ?, updated_at = ? WHERE principal = ? AND operation_id = ?",
            (stage, _utcnow_iso(), principal, operation_id),
        )
