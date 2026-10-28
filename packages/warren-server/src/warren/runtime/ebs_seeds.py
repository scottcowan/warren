"""Per-owner bare-repo seed snapshots for EBS workspaces (WARREN_ECS_EBS_BARE_SEEDS).

Fargate attaches one EBS volume per task, so an owner's repo cache can't be a second
volume. Instead each owner gets one EBS *seed snapshot* holding bare mirrors of the repos
their EBS workspaces use (`.warren-bares/<host>/<path>.git`, see seed_key). A new EBS
workspace volume is created from its owner's seed instead of empty, and git-init
(images/ecs-base/git-materialize.sh) clones each folder locally from it, fetching only
the delta with the owner's credentials, then deletes the seed from the volume.

    which repos     the union of the git folders of the owner's non-destroyed EBS
                    workspaces (registry rows), cached in ecs_ebs_seed_repos with the
                    secret names that fetch them. A repo no workspace uses any more is
                    kept WARREN_ECS_EBS_SEED_REPO_TTL_DAYS after it was released, then
                    dropped at the next refresh; a seed with no repos is deleted.
    create          launch from the owner's completed seed (sizeInGiB = max(configured,
                    seed size)) and set WARREN_GIT_SEEDED=1 for git-init, or empty as
                    before. A seed that is missing, lacks one of the workspace's repos,
                    or is older than the refresh interval queues a background refresh;
                    the create never waits for it.
    refresh         single-flight per owner (refreshing_since). `git ls-remote` with
                    the owner's own credentials first: when every recorded ref SHA still
                    matches and the seed holds exactly the wanted repos, nothing runs.
                    Otherwise a seed-refresh task (git-init container only, volume from
                    the current seed or empty, a sealed blob with only that owner's
                    credentials for the listed repos) mirrors the repos; once it stops
                    the control plane snapshots its volume, deletes the volume, and
                    promotes the snapshot when it completes. The replaced snapshot is
                    deleted after a grace period (a launch may be creating from it).
    sweep           refreshes stale seeds, promotes completed ones, drops expired repos,
                    deletes empty seeds and this server's orphaned seed volumes and
                    snapshots (warren=true + warren.server_instance + warren.storage=
                    ebs-seed), each owner under its lock.

Isolation: only the control plane picks a launch's snapshotId, and only from the seed row
of the workspace's authenticated owner (spec.owner_id, set by create_workspace from the
caller's verified identity), re-checked against the snapshot's own tags (owner, server,
storage=ebs-seed, completed). A seed is only ever written by its owner's refresh task with
that owner's credentials; a workspace's own snapshots are always workspace snapshots
(storage=ebs). Workspace tasks have no EC2 permissions.
"""
from __future__ import annotations

import asyncio
import contextlib
import hashlib
import json
import re
import time
import uuid
from collections.abc import Awaitable, Callable, Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import structlog
from warren.runtime.ebs import (
    STORAGE_SEED,
    TAG_ECS_CREATED,
    TAG_STORAGE,
    VOLUME_NAME,
    EBSVolumes,
    _tags,
    _ts,
)
from warren.runtime.ecs_git import (
    EFS_MOUNT_PATH,
    GIT_INIT_CONTAINER,
    GIT_INIT_ENTRYPOINT,
    git_folder_refs,
)
from warren.runtime.ecs_kms_secrets import BLOB_ENV, seal_with_kms
from warren.runtime.efs import TAG_MANAGED, TAG_OWNER_ID, TAG_SERVER_INSTANCE
from warren_common.errors import ProvisionError

log = structlog.get_logger(__name__)

SEED_DIR = f"{EFS_MOUNT_PATH}/.warren-bares"
TASK_KIND = "seed-refresh"
# git-materialize.sh refresh-seed: some repos failed, the others are mirrored.
EXIT_PARTIAL = 3
MAX_SEED_REPOS = 64
MAX_BRANCHES_PER_REPO = 16
# A replaced seed snapshot is kept this long: a RunTask may still be creating from it.
SUPERSEDED_GRACE_SECONDS = 3600.0
MAX_OVERRIDES_BYTES = 8192

_URL_CHARS = re.compile(r"^[A-Za-z0-9._~:/@+-]+$")
_KEY_CHARS = re.compile(r"^[a-z0-9._/-]+$")
_SCHEME = re.compile(r"^(https|ssh|file)://(.*)$")
_OWNER_RE = re.compile(r"^[A-Za-z0-9._:@+=/-]{1,256}$")
_SHA_RE = re.compile(r"^[0-9a-f]{40}([0-9a-f]{24})?$")


def seed_key(url: str) -> str | None:
    """`<host>/<path>` of a repo's seed bare, lowercased, without scheme, userinfo or a
    trailing .git; None when the URL has no safe key (a port, odd characters, ...).
    Must match git-materialize.sh's seed_key (a unit test runs both)."""
    if not url or not _URL_CHARS.match(url):
        return None
    m = _SCHEME.match(url)
    if m:
        first, sep, rest = m.group(2).partition("/")
        k = first.rsplit("@", 1)[-1] + sep + rest
    elif "://" in url:
        return None
    elif ":" in url:
        first, _, rest = url.partition(":")
        k = first.rsplit("@", 1)[-1] + "/" + rest
    else:
        return None
    k = k.lstrip("/").removesuffix("/").removesuffix(".git").lower()
    if not k or not _KEY_CHARS.match(k) or "//" in k or k.endswith("/"):
        return None
    parts = k.split("/")
    if len(parts) < 2 or any(p.startswith((".", "-")) or p.endswith(".git") for p in parts):
        return None
    return k


def valid_owner(owner_id: str) -> bool:
    return bool(owner_id) and bool(_OWNER_RE.match(owner_id))


@dataclass(frozen=True)
class SeedRepo:
    """One git folder's repo, as the seed sees it."""

    key: str
    url: str
    kind: str
    cred_kind: str
    cred_secret: str
    branch: str


@dataclass(frozen=True)
class SeedSnapshot:
    snapshot_id: str
    size_gib: int


@dataclass
class OwnerUnion:
    """What an owner's non-destroyed EBS workspaces reference (newest workspace first)."""

    repos: list[SeedRepo] = field(default_factory=list)
    image: str = ""
    storage_key: str = ""


def seed_repos_from_folders(folders: Iterable[Any]) -> list[SeedRepo]:
    out: list[SeedRepo] = []
    for ref in git_folder_refs(list(folders)):
        key = seed_key(ref.url)
        if key:
            out.append(
                SeedRepo(
                    key=key, url=ref.url, kind=ref.kind, cred_kind=ref.cred_kind,
                    cred_secret=ref.cred_secret, branch=ref.branch,
                )
            )
    return out


def live_union(workspaces: Iterable[Any]) -> dict[str, OwnerUnion]:
    """Per owner, the repos of their non-destroyed EBS workspaces. Each workspace counts
    only toward the owner recorded in its own persisted spec (the authenticated
    secret-resolution owner), so one owner's workspaces never add to another's seed."""
    from warren.registry.registry import deserialize_spec_extra
    from warren.runtime.ebs import storage_from_extra

    out: dict[str, OwnerUnion] = {}
    for ws in workspaces:
        if getattr(ws, "status", "") == "destroyed":
            continue
        try:
            extra = deserialize_spec_extra(getattr(ws, "spec_json", None))
        except Exception:
            continue
        if storage_from_extra(extra) != "ebs":
            continue
        owner = extra.get("owner_id") or ""
        if not isinstance(owner, str) or not valid_owner(owner):
            continue
        union = out.setdefault(
            owner, OwnerUnion(image=getattr(ws, "image", "") or "", storage_key=extra.get("storage_key") or "")
        )
        union.repos.extend(seed_repos_from_folders(extra.get("folders") or []))
    return out


def _iso(t: float) -> str:
    return datetime.fromtimestamp(t, UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _epoch(value: Any) -> float | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=UTC).timestamp()
    except ValueError:
        return None


def _keys(raw: Any) -> list[str]:
    try:
        data = json.loads(raw) if isinstance(raw, str) else []
    except ValueError:
        return []
    return [k for k in data if isinstance(k, str)] if isinstance(data, list) else []


def _is_https(url: str) -> bool:
    return url.startswith("https://")


def ls_remote_sync(
    url: str, token: str | None, refs: list[str], *, allow_protocol: str = "https", timeout: float = 30.0
) -> dict[str, str]:
    """`git ls-remote` of `refs` on `url` from the control plane. The token reaches git
    only through GIT_ASKPASS in the child's environment (warren.git.manager's
    _askpass_env), never argv, a URL or a log line; git runs with warren's pinned safe
    config, no system/global config, and only `allow_protocol` transports."""
    from warren.git.manager import _askpass_env, _url_with_askpass_username
    from warren_common.safe_git import run_git

    env = {"GIT_ALLOW_PROTOCOL": allow_protocol, "GIT_TERMINAL_PROMPT": "0"}
    with contextlib.ExitStack() as stack:
        target = url
        if token:
            env.update(stack.enter_context(_askpass_env(token)))
            target = _url_with_askpass_username(url)
        out = run_git(
            "ls-remote", "--upload-pack=git-upload-pack", "--", target, *refs,
            extra_env=env, isolated=True, timeout=timeout,
        )
    shas: dict[str, str] = {}
    for line in out.splitlines():
        sha, _, ref = line.partition("\t")
        if ref in refs and _SHA_RE.match(sha):
            shas[ref] = sha
    return shas


class BareSeeds:
    """The owner seed lifecycle (module docstring). Wired by app.py onto ECSRuntime.seeds
    when WARREN_ECS_EBS_BARE_SEEDS is set and EBS storage is configured."""

    def __init__(
        self,
        runtime: Any,
        ebs: EBSVolumes,
        settings: Any,
        store: Any,
        *,
        ls_remote: Callable[..., dict[str, str]] | None = None,
        now: Callable[[], float] = time.time,
        sleep: Callable[[float], Awaitable[Any]] = asyncio.sleep,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._rt = runtime
        self._ebs = ebs
        self._settings = settings
        self.store = store
        self._ls_remote = ls_remote or ls_remote_sync
        self._now = now
        self._sleep = sleep
        self._clock = clock
        self._locks: dict[str, asyncio.Lock] = {}
        self._tasks: dict[str, asyncio.Task] = {}
        self._task_def_cache: dict[str, str] = {}
        # async () -> {owner_id: OwnerUnion}, wired by app.py over the registry rows.
        self.live_repos: Callable[[], Awaitable[dict[str, OwnerUnion]]] | None = None

    # ------------------------------------------------------------------
    # Identity, tags, settings
    # ------------------------------------------------------------------

    @property
    def server_id(self) -> str:
        return self._rt.server_id

    @property
    def _prefix(self) -> str:
        return getattr(self._rt, "_resource_prefix", "warren") or "warren"

    @property
    def started_by(self) -> str:
        """Distinct from the workspaces' startedBy, so the orphan sweep (which lists by
        startedBy) never sees a seed-refresh task."""
        return f"{self._prefix}-seed-{self.server_id[:16]}"[:36]

    def pseudo_id(self, owner_id: str) -> str:
        """The KMS encryption-context id of an owner's refresh task's secrets envelope."""
        digest = hashlib.sha256(f"{self.server_id}\0{owner_id}".encode()).hexdigest()
        return f"seed-{digest[:32]}"

    def seed_tags(self, owner_id: str) -> list[tuple[str, str]]:
        return [
            (TAG_MANAGED, "true"),
            (TAG_SERVER_INSTANCE, self.server_id),
            (TAG_STORAGE, STORAGE_SEED),
            (TAG_OWNER_ID, owner_id),
        ]

    def task_tags(self, owner_id: str) -> list[dict[str, str]]:
        p = self._prefix
        return [
            {"key": f"{p}.server_instance", "value": self.server_id},
            {"key": f"{p}.owner_id", "value": owner_id},
            {"key": f"{p}.task_kind", "value": TASK_KIND},
        ]

    def _setting(self, name: str, default: Any) -> Any:
        value = getattr(self._settings, name, None)
        return default if value is None or value == "" else value

    @property
    def _ttl(self) -> float:
        return float(self._setting("ecs_ebs_seed_repo_ttl_days", 30.0)) * 86400.0

    @property
    def _interval(self) -> float:
        return float(self._setting("ecs_ebs_seed_refresh_interval_seconds", 86400.0))

    @property
    def _timeout(self) -> float:
        return float(self._setting("ecs_ebs_seed_refresh_timeout_seconds", 1800.0))

    @property
    def _poll(self) -> float:
        return float(self._setting("ecs_ebs_poll_interval_seconds", 5.0))

    @property
    def _detach_wait(self) -> float:
        return float(self._setting("ecs_ebs_detach_wait_seconds", 180.0))

    def _claim_stale_before(self, now: float) -> str:
        # A claim older than any refresh can take belongs to a crashed server.
        return _iso(now - 2 * self._timeout - self._detach_wait - 60.0)

    def _busy(self, seed: dict | None, now: float) -> bool:
        since = _epoch((seed or {}).get("refreshing_since"))
        return since is not None and _iso(since) >= self._claim_stale_before(now)

    def _lock(self, owner_id: str) -> asyncio.Lock:
        lock = self._locks.get(owner_id)
        if lock is None:
            lock = self._locks[owner_id] = asyncio.Lock()
        return lock

    def _stale(self, seed: dict | None) -> bool:
        verified = _epoch((seed or {}).get("verified_at"))
        return verified is None or self._now() - verified >= self._interval

    # ------------------------------------------------------------------
    # The owner's repo union
    # ------------------------------------------------------------------

    async def _live_for(self, owner_id: str) -> OwnerUnion:
        if self.live_repos is None:
            return OwnerUnion()
        return (await self.live_repos()).get(owner_id) or OwnerUnion()

    async def _reconcile(self, owner_id: str, live: list[SeedRepo], used: list[SeedRepo]) -> list[dict]:
        """Bring ecs_ebs_seed_repos in line with the union: live repos (and the ones a
        create is about to use) are current; others are released, then dropped after the
        TTL. Returns the repos the seed should hold, most recently used first."""
        now = self._now()
        now_iso = _iso(now)
        rows = {
            r["repo_key"]: {k: v for k, v in r.items() if k != "owner_id"}
            for r in await self.store.repos(owner_id)
        }
        used_keys = {r.key for r in used}
        by_key: dict[str, list[SeedRepo]] = {}
        for repo in [*live, *used]:
            by_key.setdefault(repo.key, []).append(repo)
        for key, refs in by_key.items():
            row = rows.get(key)
            latest = refs[-1]
            branches = sorted(set(row["branches"] if row else []) | {r.branch for r in refs})
            if len(branches) > MAX_BRANCHES_PER_REPO:
                newest = {r.branch for r in refs}
                branches = sorted(newest | set(sorted(set(branches) - newest)[: max(0, MAX_BRANCHES_PER_REPO - len(newest))]))
            new = {
                "repo_key": key, "url": latest.url, "kind": latest.kind,
                "cred_kind": latest.cred_kind, "cred_secret": latest.cred_secret,
                "branches": branches, "ref_shas": (row or {}).get("ref_shas") or {},
                "last_used_at": now_iso if key in used_keys or row is None else row["last_used_at"],
                "released_at": None,
            }
            if row != new:
                await self.store.put_repo(owner_id, new)
            rows[key] = new
        for key, row in list(rows.items()):
            if key in by_key:
                continue
            released = _epoch(row.get("released_at"))
            if released is None:
                released = now
                row = {**row, "released_at": now_iso}
                await self.store.put_repo(owner_id, row)
                rows[key] = row
            if now - released >= self._ttl:
                await self.store.delete_repo(owner_id, key)
                del rows[key]
                log.info("ebs_seed_repo_dropped", owner_id=owner_id, repo=key)
        return sorted(rows.values(), key=lambda r: (r["last_used_at"], r["repo_key"]), reverse=True)

    # ------------------------------------------------------------------
    # Create path
    # ------------------------------------------------------------------

    async def _usable(self, owner_id: str, seed: dict | None) -> SeedSnapshot | None:
        """The owner's completed seed snapshot, only if its own tags say it is this
        owner's seed on this server."""
        snapshot_id = (seed or {}).get("snapshot_id")
        if not snapshot_id:
            return None
        snap = await self._ebs._snapshot(snapshot_id)
        if snap is None or snap.get("State") != "completed":
            return None
        tags = _tags(snap)
        if (
            tags.get(TAG_MANAGED) != "true"
            or tags.get(TAG_SERVER_INSTANCE) != self.server_id
            or tags.get(TAG_STORAGE) != STORAGE_SEED
            or tags.get(TAG_OWNER_ID) != owner_id
        ):
            log.warning("ebs_seed_snapshot_not_owners", owner_id=owner_id, snapshot_id=snapshot_id)
            return None
        size = int(snap.get("VolumeSize") or (seed or {}).get("size_gib") or 0)
        return SeedSnapshot(snapshot_id=snapshot_id, size_gib=size)

    async def prepare_launch(self, spec: Any, *, image: str) -> SeedSnapshot | None:
        """For a new EBS workspace with git folders: record its repos in the owner's
        union, return the owner's seed to create its volume from (None: empty volume),
        and queue a refresh when the seed is missing, lacks a repo or is stale. Keyed by
        spec.owner_id only (the authenticated owner); never raises into the create."""
        owner_id = getattr(spec, "owner_id", "") or ""
        if not valid_owner(owner_id):
            return None
        used = seed_repos_from_folders(spec.folders)
        if not used:
            return None
        async with self._lock(owner_id):
            live = await self._live_for(owner_id)
            rows = await self._reconcile(owner_id, live.repos, used)
            seed = await self.store.get_seed(owner_id)
            snap = await self._usable(owner_id, seed)
            if image and (seed or {}).get("image") != image:
                await self.store.update_seed(
                    owner_id, image=image, storage_key=getattr(spec, "storage_key", "") or ""
                )
        in_seed = set(_keys((seed or {}).get("repo_keys"))) if snap else set()
        wanted = {r["repo_key"] for r in rows}
        if snap is None or not {r.key for r in used} <= in_seed or in_seed != wanted or self._stale(seed):
            self.queue_refresh(owner_id)
        if snap is not None:
            log.info("ebs_seed_used", workspace_id=spec.workspace_id, snapshot_id=snap.snapshot_id)
        return snap

    def queue_refresh(self, owner_id: str) -> asyncio.Task:
        """Start the owner's refresh in the background unless one is running here."""
        task = self._tasks.get(owner_id)
        if task is not None and not task.done():
            return task
        task = asyncio.create_task(self._refresh_logged(owner_id))
        self._tasks[owner_id] = task
        return task

    async def aclose(self) -> None:
        """Cancel in-flight refreshes (shutdown). A cancelled refresh's claim goes stale
        and its leftover volume/snapshot is cleaned up by a later sweep."""
        tasks = [t for t in self._tasks.values() if not t.done()]
        for task in tasks:
            task.cancel()
        for task in tasks:
            with contextlib.suppress(BaseException):
                await task

    async def _refresh_logged(self, owner_id: str) -> str:
        try:
            return await self.refresh(owner_id)
        except asyncio.CancelledError:
            raise
        except Exception:
            log.exception("ebs_seed_refresh_failed", owner_id=owner_id)
            return "failed"

    # ------------------------------------------------------------------
    # Refresh
    # ------------------------------------------------------------------

    async def refresh(self, owner_id: str) -> str:
        """One single-flight refresh of the owner's seed. Returns "busy" (another one
        holds it), "deleted", "current" (SHA check: nothing moved), "refreshed",
        "pending" (snapshot still completing; the sweep promotes it) or "failed"."""
        if not valid_owner(owner_id):
            return "failed"
        now = self._now()
        if not await self.store.claim_refresh(owner_id, _iso(now), self._claim_stale_before(now)):
            return "busy"
        result, error = "failed", None
        try:
            result, error = await self._refresh_claimed(owner_id)
        except Exception as exc:
            code = (getattr(exc, "response", None) or {}).get("Error", {}).get("Code", "")
            error = f"{type(exc).__name__}{': ' + code if code else ''}"
            log.warning("ebs_seed_refresh_error", owner_id=owner_id, error=error)
        finally:
            if result != "deleted":
                await self.store.update_seed(owner_id, refreshing_since=None, last_error=error)
        log.info("ebs_seed_refresh", owner_id=owner_id, result=result, error=error)
        return result

    async def _refresh_claimed(self, owner_id: str) -> tuple[str, str | None]:
        async with self._lock(owner_id):
            live = await self._live_for(owner_id)
            rows = await self._reconcile(owner_id, live.repos, [])
            seed = await self.store.get_seed(owner_id) or {}
            if not rows:
                await self._delete_seed(owner_id, seed)
                return "deleted", None
            snap = await self._usable(owner_id, seed)
        rows = rows[:MAX_SEED_REPOS]

        names = sorted({r["cred_secret"] for r in rows if r["cred_kind"] in ("pat", "ssh")})
        values: dict[str, str] = {}
        if names and getattr(self._rt, "secret_values", None) is not None:
            got = await self._rt.secret_values(owner_id, names) or {}
            values = {k: v for k, v in got.items() if k in names and isinstance(v, str) and v}

        current = await self._remote_shas(rows, values)
        in_seed = set(_keys(seed.get("repo_keys"))) if snap else set()
        keys = [r["repo_key"] for r in rows]
        if snap is not None and in_seed == set(keys) and all(
            current.get(r["repo_key"]) and current[r["repo_key"]] == r["ref_shas"] for r in rows
        ):
            await self.store.update_seed(owner_id, verified_at=_iso(self._now()))
            return "current", None

        image = (
            getattr(self._settings, "ecs_git_init_image", "") or seed.get("image") or live.image or ""
        )
        if not image:
            return "failed", "no git-init image known for this owner yet"
        task_arn, keys = await self._run_task(owner_id, rows, values, snap, image, seed.get("storage_key") or "")
        exit_code = await self._wait_stopped(task_arn)
        volume = await self._task_volume(owner_id, task_arn)
        if volume is None:
            return "failed", "the seed-refresh task left no volume to snapshot"
        volume_id = volume["VolumeId"]
        if exit_code not in (0, EXIT_PARTIAL):
            await self._ebs._delete_volume(volume_id)
            return "failed", f"the seed-refresh task exited {exit_code}"
        snapshot_id = await self._ebs.create_tagged_snapshot(
            volume_id, self.seed_tags(owner_id), f"warren bare seed {self.pseudo_id(owner_id)}"
        )
        await self._ebs._delete_volume(volume_id)
        if snapshot_id is None:
            return "failed", "the seed-refresh volume disappeared before its snapshot"
        # SHAs from before the task ran: the mirrors are at least that new. A partial
        # refresh records none, so the next check refreshes again.
        shas = {k: current.get(k) or {} for k in keys} if exit_code == 0 else {}
        await self.store.update_seed(
            owner_id,
            pending_snapshot_id=snapshot_id,
            pending_size_gib=int(volume.get("Size") or 0) or None,
            pending_repo_keys=json.dumps(keys),
            pending_ref_shas=json.dumps(shas, sort_keys=True),
        )
        log.info("ebs_seed_snapshot_started", owner_id=owner_id, snapshot_id=snapshot_id, repos=len(keys))
        partial = None if exit_code == 0 else "some repos could not be fetched"
        deadline = self._clock() + self._timeout
        while True:
            async with self._lock(owner_id):
                state = await self._promote(owner_id)
            if state == "promoted":
                return "refreshed", partial
            if state != "pending":
                return "failed", "the new seed snapshot failed"
            if self._clock() >= deadline:
                return "pending", partial
            await self._sleep(self._poll)

    async def _remote_shas(self, rows: list[dict], values: dict[str, str]) -> dict[str, dict[str, str] | None]:
        """Each repo's current ref SHAs per `git ls-remote` with the owner's own token
        (https only; None when unknown, which always refreshes)."""
        out: dict[str, dict[str, str] | None] = {}
        for row in rows:
            key, url = row["repo_key"], row["url"]
            if not _is_https(url):
                out[key] = None
                continue
            token = values.get(row["cred_secret"]) if row["cred_kind"] == "pat" else None
            refs = ["HEAD", *(f"refs/heads/{b}" for b in row["branches"])]
            try:
                out[key] = await asyncio.to_thread(self._ls_remote, url, token, refs)
            except Exception as exc:
                log.info("ebs_seed_ls_remote_failed", repo=key, error=type(exc).__name__)
                out[key] = None
        return out

    def _records(self, rows: list[dict], values: dict[str, str]) -> tuple[str, set[str]]:
        records: list[str] = []
        used: set[str] = set()
        for row in rows:
            key, url = row["repo_key"], row["url"]
            if seed_key(url) != key or any(c in url for c in "\t\n\r "):
                continue
            cred_kind, cred = row["cred_kind"], row["cred_secret"]
            if cred_kind not in ("pat", "ssh") or cred not in values:
                cred_kind, cred = "none", "-"
            else:
                used.add(cred)
            records.append("\t".join([key, url, cred_kind, cred]))
        return "\n".join(records), used

    async def _task_definition(self, image: str) -> str:
        p = self._prefix
        region = getattr(self._settings, "aws_region", "us-east-1") or "us-east-1"
        register_kwargs: dict[str, Any] = {
            "family": f"{p}-seed-refresh",
            "networkMode": "awsvpc",
            "requiresCompatibilities": ["FARGATE"],
            "cpu": str(getattr(self._rt, "_default_cpu", "256")),
            "memory": str(getattr(self._rt, "_default_memory", "512")),
            "containerDefinitions": [
                {
                    # Named git-init: the secrets envelope is sealed for that container.
                    "name": GIT_INIT_CONTAINER,
                    "image": image,
                    "essential": True,
                    "entryPoint": [GIT_INIT_ENTRYPOINT],
                    "command": [],
                    "mountPoints": [
                        {"containerPath": EFS_MOUNT_PATH, "sourceVolume": VOLUME_NAME, "readOnly": False}
                    ],
                    "logConfiguration": {
                        "logDriver": "awslogs",
                        "options": {
                            "awslogs-group": f"/{p}/{self.server_id}",
                            "awslogs-region": region,
                            "awslogs-stream-prefix": TASK_KIND,
                            "awslogs-create-group": "false",
                        },
                    },
                }
            ],
            "volumes": [{"name": VOLUME_NAME, "configuredAtLaunch": True}],
            "tags": [{"key": f"{p}.server_instance", "value": self.server_id}],
        }
        execution_role = getattr(self._settings, "ecs_task_execution_role_arn", "") or ""
        task_role = getattr(self._settings, "ecs_task_role_arn", "") or ""
        if execution_role:
            register_kwargs["executionRoleArn"] = execution_role
        if task_role:
            register_kwargs["taskRoleArn"] = task_role
        cache_key = json.dumps(register_kwargs, sort_keys=True)
        arn = self._task_def_cache.get(cache_key)
        if arn is None:
            ecs = self._rt._ensure_clients()
            resp = await asyncio.to_thread(ecs.register_task_definition, **register_kwargs)
            arn = resp["taskDefinition"]["taskDefinitionArn"]
            self._task_def_cache[cache_key] = arn
        return arn

    async def _overrides(self, owner_id: str, rows: list[dict], values: dict[str, str]) -> tuple[dict, list[str]]:
        """RunTask overrides for git-init, dropping the least recently used repos until
        they fit ECS's limit. Only the credentials the listed repos need are sealed."""
        region = getattr(self._settings, "aws_region", "us-east-1") or "us-east-1"
        key_id = getattr(self._settings, "ecs_secrets_kms_key_id", "") or ""
        pseudo = self.pseudo_id(owner_id)
        while rows:
            records, used = self._records(rows, values)
            env = [
                {"name": "WARREN_GIT_MODE", "value": "refresh-seed"},
                {"name": "WARREN_GIT_SEED_REPOS", "value": records},
                {"name": "WARREN_WORKSPACE_ID", "value": pseudo},
            ]
            known_hosts = getattr(self._settings, "ecs_git_known_hosts", "") or ""
            if known_hosts:
                env.append({"name": "WARREN_GIT_KNOWN_HOSTS", "value": known_hosts})
            if used:
                blob = await seal_with_kms(
                    self._rt._kms, key_id, {n: values[n] for n in sorted(used)},
                    workspace_id=pseudo, container=GIT_INIT_CONTAINER, region=region,
                )
                env.append({"name": BLOB_ENV, "value": blob})
            overrides = {"containerOverrides": [{"name": GIT_INIT_CONTAINER, "environment": env}]}
            if len(json.dumps(overrides, separators=(",", ":"))) <= MAX_OVERRIDES_BYTES:
                keys = [line.split("\t", 1)[0] for line in records.splitlines()]
                return overrides, keys
            rows = rows[:-1]
        raise ProvisionError("the seed-refresh overrides don't fit ECS's limit")

    async def _run_task(
        self, owner_id: str, rows: list[dict], values: dict[str, str],
        snap: SeedSnapshot | None, image: str, storage_key: str,
    ) -> tuple[str, list[str]]:
        ecs = self._rt._ensure_clients()
        await self._rt._ensure_log_group(f"/{self._prefix}/{self.server_id}")
        task_def = await self._task_definition(image)
        overrides, keys = await self._overrides(owner_id, rows, values)
        configured = int(self._setting("ecs_ebs_size_gib", 20))
        volume_config = self._ebs.volume_configuration(
            self.pseudo_id(owner_id),
            owner_id=owner_id,
            snapshot_id=snap.snapshot_id if snap else None,
            size_gib=max(configured, snap.size_gib) if snap else configured,
            tags=self.seed_tags(owner_id),
        )
        placement = self._rt._ebs_placement(storage_key)
        assign_public_ip = "ENABLED" if getattr(self._settings, "ecs_assign_public_ip", False) else "DISABLED"
        resp = await asyncio.to_thread(
            ecs.run_task,
            cluster=getattr(self._settings, "ecs_cluster", "") or "",
            taskDefinition=task_def,
            launchType="FARGATE",
            networkConfiguration={
                "awsvpcConfiguration": {
                    "subnets": list(getattr(self._settings, "ecs_subnet_ids", None) or []),
                    "securityGroups": list(placement.security_group_ids),
                    "assignPublicIp": assign_public_ip,
                }
            },
            overrides=overrides,
            enableExecuteCommand=False,
            tags=self.task_tags(owner_id),
            startedBy=self.started_by,
            clientToken=uuid.uuid4().hex,
            volumeConfigurations=[volume_config],
        )
        failures = resp.get("failures") or []
        tasks = resp.get("tasks") or []
        if failures or not tasks:
            reason = failures[0].get("reason", "unknown") if failures else "no task"
            raise ProvisionError(f"seed-refresh run_task failed: {reason}")
        arn = tasks[0]["taskArn"]
        log.info("ebs_seed_refresh_task", owner_id=owner_id, task_arn=arn, repos=len(keys))
        return arn, keys

    async def _wait_stopped(self, task_arn: str) -> int | None:
        """git-init's exit code once the task stops; past the refresh timeout the task is
        stopped (its exit code then fails the refresh)."""
        ecs = self._rt._ensure_clients()
        cluster = getattr(self._settings, "ecs_cluster", "") or ""
        deadline = self._clock() + self._timeout
        stop_sent = False
        while True:
            desc = await asyncio.to_thread(ecs.describe_tasks, cluster=cluster, tasks=[task_arn])
            task = (desc.get("tasks") or [{}])[0]
            if task.get("lastStatus") == "STOPPED":
                for container in task.get("containers") or []:
                    if container.get("name") == GIT_INIT_CONTAINER:
                        code = container.get("exitCode")
                        return code if isinstance(code, int) else None
                return None
            if self._clock() >= deadline:
                if stop_sent:
                    raise TimeoutError("the seed-refresh task did not stop")
                log.warning("ebs_seed_refresh_timeout", task_arn=task_arn)
                with contextlib.suppress(Exception):
                    await asyncio.to_thread(
                        ecs.stop_task, cluster=cluster, task=task_arn, reason="warren seed refresh timeout"
                    )
                stop_sent = True
                deadline = self._clock() + self._detach_wait
            await self._sleep(self._poll)

    async def _task_volume(self, owner_id: str, task_arn: str) -> dict | None:
        """The refresh task's retained volume once it is `available`."""
        deadline = self._clock() + self._detach_wait
        while True:
            vols = [
                v for v in await self._ebs.volumes(storage=STORAGE_SEED)
                if _tags(v).get(TAG_OWNER_ID) == owner_id and _tags(v).get(TAG_ECS_CREATED) == task_arn
            ]
            if vols and vols[0].get("State") == "available":
                return vols[0]
            if vols and vols[0].get("State") in ("deleting", "deleted", "error"):
                return None
            if self._clock() >= deadline:
                return None  # the sweep deletes it once it detaches
            await self._sleep(self._poll)

    async def _promote(self, owner_id: str) -> str:
        """Make a completed pending snapshot the owner's seed: "none", "pending",
        "promoted" or "failed". Call under the owner's lock."""
        seed = await self.store.get_seed(owner_id) or {}
        pending_id = seed.get("pending_snapshot_id")
        if not pending_id:
            return "none"
        snap = await self._ebs._snapshot(pending_id)
        tags = _tags(snap) if snap else {}
        ours = tags.get(TAG_OWNER_ID) == owner_id and tags.get(TAG_STORAGE) == STORAGE_SEED
        state = (snap or {}).get("State", "error") if ours else "error"
        if state == "pending":
            return "pending"
        clear = {
            "pending_snapshot_id": None, "pending_size_gib": None,
            "pending_repo_keys": None, "pending_ref_shas": None,
        }
        if state != "completed":
            if snap is not None and ours:
                await self._ebs._delete_snapshot(pending_id)
            await self.store.update_seed(owner_id, **clear, last_error="the new seed snapshot failed")
            return "failed"
        old, previous = seed.get("snapshot_id"), seed.get("previous_snapshot_id")
        if previous and previous not in (pending_id, old):
            await self._ebs._delete_snapshot(previous)
        now_iso = _iso(self._now())
        keys = _keys(seed.get("pending_repo_keys"))
        await self.store.update_seed(
            owner_id,
            **clear,
            snapshot_id=pending_id,
            size_gib=seed.get("pending_size_gib") or snap.get("VolumeSize"),
            repo_keys=json.dumps(keys),
            created_at=now_iso,
            verified_at=now_iso,
            previous_snapshot_id=old if old and old != pending_id else None,
            superseded_at=now_iso if old and old != pending_id else None,
        )
        try:
            shas = json.loads(seed.get("pending_ref_shas") or "{}")
        except ValueError:
            shas = {}
        for key in keys:
            value = shas.get(key) if isinstance(shas, dict) else None
            await self.store.set_ref_shas(owner_id, key, value if isinstance(value, dict) else None)
        log.info("ebs_seed_promoted", owner_id=owner_id, snapshot_id=pending_id, replaced=old)
        return "promoted"

    async def _delete_seed(self, owner_id: str, seed: dict) -> None:
        for name in ("snapshot_id", "pending_snapshot_id", "previous_snapshot_id"):
            if seed.get(name):
                await self._ebs._delete_snapshot(seed[name])
        await self.store.delete_seed(owner_id)
        log.info("ebs_seed_deleted", owner_id=owner_id)

    # ------------------------------------------------------------------
    # Sweep
    # ------------------------------------------------------------------

    async def sweep(self, *, min_age_seconds: float = 900.0) -> dict[str, int]:
        """One pass: union reconcile + TTL, promotions, grace deletes, empty seeds,
        stale refreshes, then this server's orphaned seed volumes/snapshots."""
        stats = {
            "refreshes_queued": 0, "promoted": 0, "seeds_deleted": 0,
            "snapshots_deleted": 0, "volumes_deleted": 0,
        }
        live_all = await self.live_repos() if self.live_repos is not None else {}
        owners = set(live_all) | set(await self.store.repo_owners())
        owners |= {s["owner_id"] for s in await self.store.list_seeds()}
        for owner_id in sorted(o for o in owners if valid_owner(o)):
            try:
                await self._sweep_owner(owner_id, live_all.get(owner_id) or OwnerUnion(), stats)
            except Exception:
                log.exception("ebs_seed_sweep_owner_failed", owner_id=owner_id)
        try:
            await self._sweep_orphans(min_age_seconds, stats)
        except Exception:
            log.exception("ebs_seed_sweep_orphans_failed")
        return stats

    async def _sweep_owner(self, owner_id: str, union: OwnerUnion, stats: dict[str, int]) -> None:
        now = self._now()
        async with self._lock(owner_id):
            rows = await self._reconcile(owner_id, union.repos, [])
            seed = await self.store.get_seed(owner_id)
            busy = self._busy(seed, now)
            if seed and not busy:
                if seed.get("pending_snapshot_id") and await self._promote(owner_id) == "promoted":
                    stats["promoted"] += 1
                seed = await self.store.get_seed(owner_id) or {}
                superseded = _epoch(seed.get("superseded_at"))
                if seed.get("previous_snapshot_id") and (
                    superseded is None or now - superseded >= SUPERSEDED_GRACE_SECONDS
                ):
                    await self._ebs._delete_snapshot(seed["previous_snapshot_id"])
                    await self.store.update_seed(owner_id, previous_snapshot_id=None, superseded_at=None)
                    stats["snapshots_deleted"] += 1
            if not rows:
                if seed and not busy:
                    await self._delete_seed(owner_id, seed)
                    stats["seeds_deleted"] += 1
                return
            if union.image and not (seed or {}).get("image"):
                await self.store.update_seed(owner_id, image=union.image, storage_key=union.storage_key)
            seed = await self.store.get_seed(owner_id) or {}
        if busy:
            return
        in_seed = set(_keys(seed.get("repo_keys"))) if seed.get("snapshot_id") else None
        if in_seed is None or in_seed != {r["repo_key"] for r in rows} or self._stale(seed):
            self.queue_refresh(owner_id)
            stats["refreshes_queued"] += 1

    async def _sweep_orphans(self, min_age_seconds: float, stats: dict[str, int]) -> None:
        now = self._now()
        seeds = {s["owner_id"]: s for s in await self.store.list_seeds()}

        def running(owner_id: str) -> bool:
            task = self._tasks.get(owner_id)
            return (task is not None and not task.done()) or self._busy(seeds.get(owner_id), now)

        for vol in await self._ebs.volumes(storage=STORAGE_SEED):
            if vol.get("State") != "available" or now - _ts(vol.get("CreateTime")) < min_age_seconds:
                continue
            if running(_tags(vol).get(TAG_OWNER_ID, "")):
                continue
            if await self._ebs._delete_volume(vol["VolumeId"]):
                stats["volumes_deleted"] += 1
        for snap in await self._ebs.snapshots(storage=STORAGE_SEED):
            owner_id = _tags(snap).get(TAG_OWNER_ID, "")
            seed = seeds.get(owner_id) or {}
            referenced = {
                seed.get(n) for n in ("snapshot_id", "pending_snapshot_id", "previous_snapshot_id")
            }
            if snap["SnapshotId"] in referenced or now - _ts(snap.get("StartTime")) < min_age_seconds:
                continue
            if running(owner_id):
                continue
            await self._ebs._delete_snapshot(snap["SnapshotId"])
            stats["snapshots_deleted"] += 1
