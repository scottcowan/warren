"""git_write: scoped, short-lived GitHub write tokens for agent workspaces.

Fake GitHub (httpx.MockTransport behind a real GitHubAppMinter with a generated key),
fake KMS, fake exec. No AWS, no GitHub.
"""

from __future__ import annotations

import io
import itertools
import json
import os
import tarfile
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest
import structlog
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import HTTPException

from warren.git.write_tokens import (
    REFRESH_MARGIN_SECONDS,
    TOKENS_SECRET,
    GitWriteError,
    GitWriteTokens,
    encode_tokens,
    refresh_once,
)
from warren.registry.registry import serialize_spec_extra
from warren_common.github_tokens import GIT_WRITE_PERMISSIONS, GitHubAppMinter
from warren_common.models import FolderSpec, ProjectConfig
from warren_common.runtime.base import ExecExit, WorkspaceHandle, WorkspaceSpec
from warren_common.runtime.fake import FakeRuntime
from warren_common.templates import resolve_template

T0 = 1_900_000_000.0


@pytest.fixture(scope="module")
def pem() -> bytes:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )


class FakeGitHub:
    """Records every request; mints ghs_tok<N>, expiring 1h after `clock.now`."""

    def __init__(self, clock) -> None:
        self.clock = clock
        self.calls: list[httpx.Request] = []
        self.minted: list[str] = []
        self.revoked: list[str] = []
        self.fail_mint = False
        self._n = itertools.count(1)

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.calls.append(request)
        path = request.url.path
        if path.startswith("/repos/") and path.endswith("/installation"):
            owner = path.split("/")[2]
            return httpx.Response(200, json={"id": {"acme": 11, "other": 22}.get(owner, 99)})
        if path.endswith("/access_tokens"):
            if self.fail_mint:
                return httpx.Response(500)
            token = f"ghs_tok{next(self._n):04d}aaaaaaaaaaaaaaaaaaaa"
            self.minted.append(token)
            from datetime import datetime, timezone

            exp = datetime.fromtimestamp(self.clock.now + 3600, tz=timezone.utc).isoformat()
            return httpx.Response(201, json={"token": token, "expires_at": exp})
        if path == "/installation/token" and request.method == "DELETE":
            self.revoked.append(request.headers["Authorization"].removeprefix("Bearer "))
            return httpx.Response(204)
        return httpx.Response(404)

    def mint_bodies(self) -> list[tuple[str, dict]]:
        return [(r.url.path, json.loads(r.content)) for r in self.calls if r.url.path.endswith("/access_tokens")]


class Clock:
    def __init__(self) -> None:
        self.now = T0

    def __call__(self) -> float:
        return self.now


@pytest.fixture
def gh(pem):
    clock = Clock()
    fake = FakeGitHub(clock)
    minter = GitHubAppMinter("123", lambda: pem, transport=httpx.MockTransport(fake.handler), clock=clock)
    fake.manager = GitWriteTokens(minter, clock=clock)
    return fake


def _folder(url, type_="git-worktree", readonly=False, mount="code/x"):
    return FolderSpec(name=mount.replace("/", "-"), type=type_, url=url, mount=mount, readonly=readonly)


FOLDERS = [
    _folder("https://github.com/acme/app.git", mount="code/app"),
    _folder("git@github.com:Acme/api.git", mount="code/api"),
    _folder("https://github.com/acme/docs.git", type_="git-clone", mount="refs/docs"),
    _folder("https://github.com/acme/locked.git", readonly=True, mount="code/locked"),
    _folder("https://github.com/other/lib.git", mount="code/lib"),
    _folder("https://gitlab.com/acme/elsewhere.git", mount="code/gl"),
]


# --- scoping ----------------------------------------------------------------


async def test_mint_scopes_to_the_writable_repos_with_only_contents_and_prs(gh):
    issued = await gh.manager.mint("ws-1", FOLDERS)
    assert set(issued) == {"acme", "other"}
    bodies = dict(gh.mint_bodies())
    assert bodies["/app/installations/11/access_tokens"] == {
        "repositories": ["api", "app"],
        "permissions": {"contents": "write", "pull_requests": "write"},
    }
    assert bodies["/app/installations/22/access_tokens"] == {
        "repositories": ["lib"],
        "permissions": {"contents": "write", "pull_requests": "write"},
    }
    for _, body in bodies.items():
        assert set(body["permissions"]) == {"contents", "pull_requests"}
        assert not {"administration", "workflows", "secrets"} & set(body["permissions"])
    assert GIT_WRITE_PERMISSIONS == {"contents": "write", "pull_requests": "write"}


async def test_each_workspace_gets_its_own_token_never_the_minter_cache(gh):
    a = await gh.manager.mint("ws-a", FOLDERS[:1])
    b = await gh.manager.mint("ws-b", FOLDERS[:1])
    assert a["acme"].token != b["acme"].token


async def test_mint_refuses_a_template_with_nothing_to_push(gh):
    with pytest.raises(GitWriteError):
        await gh.manager.mint("ws-1", [FOLDERS[2], FOLDERS[3], FOLDERS[5]])
    assert gh.mint_bodies() == []


async def test_partial_mint_failure_revokes_what_was_minted(gh, pem):
    calls = {"n": 0}
    orig = gh.handler

    def handler(request):
        if request.url.path.endswith("/access_tokens"):
            calls["n"] += 1
            if calls["n"] == 2:
                return httpx.Response(500)
        return orig(request)

    minter = GitHubAppMinter("123", lambda: pem, transport=httpx.MockTransport(handler), clock=gh.clock)
    with pytest.raises(GitWriteError):
        await GitWriteTokens(minter, clock=gh.clock).mint("ws-1", FOLDERS)
    assert gh.revoked == gh.minted and len(gh.minted) == 1


def test_encode_tokens_validates_owner_and_token_shape():
    assert encode_tokens({"acme": "ghs_" + "a" * 36}) == "acme ghs_" + "a" * 36 + "\n"
    with pytest.raises(GitWriteError):
        encode_tokens({"ac me": "ghs_" + "a" * 36})
    with pytest.raises(GitWriteError):
        encode_tokens({"acme": "ghs_x\nother ghs_y"})


# --- refresh schedule ---------------------------------------------------------


class InstallRecorder:
    def __init__(self) -> None:
        self.installs: list[tuple[str, dict[str, str]]] = []
        self.drops: list[str] = []
        self.fail = False

    async def install_git_tokens(self, handle, tokens):
        if self.fail:
            raise RuntimeError("exec failed")
        self.installs.append((handle.workspace_id, dict(tokens)))

    async def drop_git_tokens(self, handle):
        self.drops.append(handle.workspace_id)


async def test_refresh_is_due_ten_minutes_before_the_earliest_expiry(gh):
    m = gh.manager
    assert m.due("ws-1")  # nothing held yet: mint now
    m.hold("ws-1", await m.mint("ws-1", FOLDERS))
    assert m.next_refresh_at("ws-1") == T0 + 3600 - REFRESH_MARGIN_SECONDS
    gh.clock.now = T0 + 3600 - REFRESH_MARGIN_SECONDS - 1
    assert not m.due("ws-1")
    gh.clock.now = T0 + 3600 - REFRESH_MARGIN_SECONDS
    assert m.due("ws-1")


async def test_refresh_delivers_then_revokes_the_superseded_tokens(gh):
    m = gh.manager
    first = await m.mint("ws-1", FOLDERS[:1])
    m.hold("ws-1", first)
    rt = InstallRecorder()
    await m.refresh("ws-1", FOLDERS[:1], rt, WorkspaceHandle("ws-1", "task", ""))
    new = m.held("ws-1")["acme"].token
    assert rt.installs == [("ws-1", {"acme": new})]
    assert gh.revoked == [first["acme"].token]


async def test_failed_delivery_revokes_the_new_token_and_keeps_the_old(gh):
    m = gh.manager
    first = await m.mint("ws-1", FOLDERS[:1])
    m.hold("ws-1", first)
    rt = InstallRecorder()
    rt.fail = True
    with pytest.raises(GitWriteError):
        await m.refresh("ws-1", FOLDERS[:1], rt, WorkspaceHandle("ws-1", "task", ""))
    assert m.held("ws-1")["acme"].token == first["acme"].token
    assert gh.revoked == [gh.minted[-1]]


def _row(workspace_id, status="running", git_write=True, folders=FOLDERS[:1], container="task"):
    spec = WorkspaceSpec(
        workspace_id=workspace_id, project="p", intent="t", image="i", root_path="",
        folders=list(folders), git_write=git_write,
    )
    return SimpleNamespace(
        workspace_id=workspace_id, status=status, container_id=container, root_path="",
        owner_id="u1", spec_json=serialize_spec_extra(spec),
    )


class FakeRegistry:
    def __init__(self, rows, runtime) -> None:
        self.rows = {r.workspace_id: r for r in rows}
        self.runtime = runtime
        self.store = SimpleNamespace(list_non_terminal=self._list, get=self._get)
        import asyncio

        self._locks: dict[str, asyncio.Lock] = {}

    async def _list(self):
        return [r for r in self.rows.values() if r.status in ("provisioning", "running", "stopping", "unknown")]

    async def _get(self, workspace_id):
        return self.rows.get(workspace_id)

    async def _lock_for(self, workspace_id):
        import asyncio

        return self._locks.setdefault(workspace_id, asyncio.Lock())


async def test_refresh_loop_only_touches_running_git_write_workspaces(gh):
    rt = InstallRecorder()
    reg = FakeRegistry(
        [_row("ws-on"), _row("ws-off", git_write=False), _row("ws-prov", status="provisioning")], rt
    )
    await refresh_once(reg, gh.manager)
    assert [w for w, _ in rt.installs] == ["ws-on"]
    # Not due again until 10 minutes before expiry.
    gh.clock.now = T0 + 60
    await refresh_once(reg, gh.manager)
    assert len(rt.installs) == 1
    gh.clock.now = T0 + 3600 - REFRESH_MARGIN_SECONDS
    await refresh_once(reg, gh.manager)
    assert len(rt.installs) == 2
    assert gh.revoked == [rt.installs[0][1]["acme"]]


async def test_refresh_loop_revokes_workspaces_that_stopped_behind_its_back(gh):
    rt = InstallRecorder()
    reg = FakeRegistry([_row("ws-1")], rt)
    await refresh_once(reg, gh.manager)
    token = gh.manager.held("ws-1")["acme"].token
    reg.rows["ws-1"].status = "failed"
    await refresh_once(reg, gh.manager)
    assert gh.revoked == [token]
    assert gh.manager.held_ids() == set()


# --- revoke on stop / destroy (real registry) ----------------------------------


class GitWriteFakeRuntime(FakeRuntime, InstallRecorder):
    def __init__(self) -> None:
        FakeRuntime.__init__(self, server_id="test")
        InstallRecorder.__init__(self)
        self.launch_tokens: list[dict[str, str]] = []

    async def provision(self, spec):
        self.launch_tokens.append(dict(spec.git_tokens))
        return await super().provision(spec)


async def _provisioned(sqlite_path, gh, workspace_id="ws-1"):
    from warren.registry.registry import WorkspaceRegistry
    from warren.registry.store import WorkspaceStore

    store = await WorkspaceStore.open(sqlite_path)
    rt = GitWriteFakeRuntime()
    registry = WorkspaceRegistry(runtime=rt, store=store, server_id="test")
    registry.git_write_tokens = gh.manager
    spec = WorkspaceSpec(
        workspace_id=workspace_id, project="p", intent="t", image="i", root_path="",
        folders=FOLDERS[:1], git_write=True, owner_id="u1",
    )
    await store.insert(
        workspace_id=workspace_id, project="p", intent="t", image="i", root_path="",
        server_instance="test", status="provisioning", owner_id="u1", spec_json=serialize_spec_extra(spec),
    )
    await registry._do_provision(workspace_id, spec)
    return registry, rt, spec


async def test_launch_hands_the_token_to_the_runtime_and_holds_it(sqlite_path, gh):
    registry, rt, spec = await _provisioned(sqlite_path, gh)
    assert (await registry.store.get("ws-1")).status == "running"
    assert rt.launch_tokens == [{"acme": gh.minted[0]}]
    assert gh.manager.held("ws-1")["acme"].token == gh.minted[0]
    assert spec.git_tokens == {}  # transient, cleared after the launch
    assert gh.minted[0] not in (await registry.store.get("ws-1")).spec_json


async def test_stop_drops_the_file_and_revokes(sqlite_path, gh):
    registry, rt, _ = await _provisioned(sqlite_path, gh)
    await registry.stop("ws-1")
    assert rt.drops == ["ws-1"]
    assert gh.revoked == [gh.minted[0]]
    assert gh.manager.held_ids() == set()


async def test_destroy_drops_the_file_and_revokes(sqlite_path, gh):
    registry, rt, _ = await _provisioned(sqlite_path, gh)
    await registry.destroy("ws-1")
    assert rt.drops == ["ws-1"]
    assert gh.revoked == [gh.minted[0]]
    assert (await registry.store.get("ws-1")).status == "destroyed"


async def test_failed_launch_revokes_the_minted_token(sqlite_path, gh):
    from warren.registry.registry import WorkspaceRegistry
    from warren.registry.store import WorkspaceStore
    from warren_common.errors import ProvisionError

    store = await WorkspaceStore.open(sqlite_path)
    rt = GitWriteFakeRuntime()
    rt.provision = AsyncMock(side_effect=ProvisionError("boom"))
    registry = WorkspaceRegistry(runtime=rt, store=store, server_id="test")
    registry.git_write_tokens = gh.manager
    spec = WorkspaceSpec(
        workspace_id="ws-1", project="p", intent="t", image="i", root_path="",
        folders=FOLDERS[:1], git_write=True,
    )
    await store.insert(
        workspace_id="ws-1", project="p", intent="t", image="i", root_path="",
        server_instance="test", status="provisioning",
    )
    await registry._do_provision("ws-1", spec)
    assert (await store.get("ws-1")).status == "failed"
    assert gh.revoked == gh.minted and len(gh.minted) == 1
    assert gh.manager.held_ids() == set()


async def test_github_outage_does_not_fail_the_launch(sqlite_path, gh):
    gh.fail_mint = True
    registry, rt, _ = await _provisioned(sqlite_path, gh)
    assert (await registry.store.get("ws-1")).status == "running"
    assert rt.launch_tokens == [{}]


# --- opt-in validation ----------------------------------------------------------


def _request(manager, runtime):
    registry = SimpleNamespace(git_write_tokens=manager, runtime=runtime)
    return SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(registry=registry)))


def test_git_write_rejected_without_a_github_app():
    from warren.routes.workspaces import _require_git_write

    with pytest.raises(HTTPException) as exc:
        _require_git_write(_request(None, InstallRecorder()), FOLDERS)
    assert exc.value.status_code == 422
    assert exc.value.detail["error"] == "template_denied"
    assert "GitHub App" in exc.value.detail["detail"]


def test_git_write_rejected_on_a_runtime_that_cannot_deliver(gh):
    from warren.routes.workspaces import _require_git_write

    with pytest.raises(HTTPException) as exc:
        _require_git_write(_request(gh.manager, FakeRuntime(server_id="s")), FOLDERS)
    assert "can't deliver" in exc.value.detail["detail"]


def test_git_write_rejected_on_ecs_without_the_kms_key(gh):
    from warren.routes.workspaces import _require_git_write
    from warren.runtime.ecs import ECSRuntime

    rt = ECSRuntime(server_id="s", settings=SimpleNamespace(ecs_secrets_kms_key_id=""))
    with pytest.raises(HTTPException) as exc:
        _require_git_write(_request(gh.manager, rt), FOLDERS)
    assert "WARREN_ECS_SECRETS_KMS_KEY_ID" in exc.value.detail["detail"]


def test_git_write_rejected_with_nothing_to_push(gh):
    from warren.routes.workspaces import _require_git_write

    with pytest.raises(HTTPException) as exc:
        _require_git_write(_request(gh.manager, InstallRecorder()), [FOLDERS[2]])
    assert "git-worktree" in exc.value.detail["detail"]


def test_git_write_allowed_with_an_app_and_a_capable_runtime(gh):
    from warren.routes.workspaces import _require_git_write

    _require_git_write(_request(gh.manager, InstallRecorder()), FOLDERS)


def test_git_write_is_off_by_default_and_inherited_by_templates():
    root = ProjectConfig.model_validate(
        {"name": "p", "git_write": True, "templates": {"dev": {}, "ro": {"git_write": False}}}
    )
    assert ProjectConfig().git_write is False
    assert resolve_template(root, "dev", validate=False).git_write is True
    assert resolve_template(root, "ro", validate=False).git_write is False


# --- the token never reaches logs or command arguments ----------------------------


class FakeKms:
    def __init__(self) -> None:
        self.key = os.urandom(32)
        self.contexts: list[dict] = []

    def generate_data_key(self, KeyId, KeySpec, EncryptionContext):  # noqa: N803
        self.contexts.append(EncryptionContext)
        return {"Plaintext": self.key, "CiphertextBlob": b"wrapped-key"}


def _ecs_runtime(kms):
    from warren.runtime.ecs import ECSRuntime

    rt = ECSRuntime(
        server_id="s",
        settings=SimpleNamespace(ecs_secrets_kms_key_id="alias/warren", aws_region="us-east-1"),
    )
    rt._kms = kms
    rt._ensure_clients = MagicMock()
    rt.argvs = []

    async def fake_exec(handle, argv):
        rt.argvs.append(list(argv))
        yield b"warren-git-token: installed 1\n"
        yield ExecExit(0)

    rt.exec_stream = fake_exec
    return rt


async def test_ecs_refresh_puts_only_ciphertext_in_the_exec_command(gh):
    from warren.runtime.ecs_kms_secrets import open_envelope

    kms = FakeKms()
    rt = _ecs_runtime(kms)
    rows = [_row("ws-1")]
    with structlog.testing.capture_logs() as logs:
        gh.manager.hold("ws-1", await gh.manager.mint("ws-1", FOLDERS[:1]))  # launch
        await refresh_once(FakeRegistry(rows, rt), gh.manager)  # not due
        gh.clock.now = T0 + 3600 - REFRESH_MARGIN_SECONDS
        await refresh_once(FakeRegistry(rows, rt), gh.manager)
        gh.clock.now = T0 + 2 * (3600 - REFRESH_MARGIN_SECONDS)
        await refresh_once(FakeRegistry(rows, rt), gh.manager)
        await gh.manager.revoke("ws-1", runtime=rt, handle=WorkspaceHandle("ws-1", "task", ""))
    assert len(gh.minted) == 3
    assert gh.revoked == gh.minted
    install = [a for a in rt.argvs if a[-1] == "install-envelope"]
    assert len(install) == 2
    for token, argv in zip(gh.minted[1:], install):
        joined = " ".join(argv)
        assert not any(t in joined for t in gh.minted)
        blob = next(a.split("=", 1)[1] for a in argv if a.startswith("WARREN_SECRETS_BLOB="))
        opened = open_envelope(blob, kms.key, workspace_id="ws-1", container="workspace")
        assert opened == {TOKENS_SECRET: f"acme {token}\n"}
    assert rt.argvs[-1] == ["/usr/local/bin/warren-git-token", "remove"]
    assert kms.contexts == [{"warren:workspace_id": "ws-1", "warren:container": "workspace"}] * 2
    actions = {e.get("action") for e in logs}
    assert {"git_write_token.mint", "git_write_token.refresh", "git_write_token.revoke"} <= actions
    dumped = repr(logs)
    assert not any(t in dumped for t in gh.minted)
    revokes = [e for e in logs if e.get("action") == "git_write_token.revoke"]
    assert all(e["repositories"] == ["app"] and e["workspace_id"] == "ws-1" for e in revokes)


async def test_ecs_launch_puts_the_token_in_the_workspace_secrets_not_git_init():
    from warren.runtime.ecs import ECSRuntime, Placement

    rt = ECSRuntime(server_id="s", settings=SimpleNamespace(ecs_secrets_kms_key_id="k"))
    rt._preflight_ok = True
    volume = MagicMock()
    volume.attach = AsyncMock()
    volume.last_access_point_id = "fsap-1"
    rt._placement_for_spec = lambda spec: Placement(volume, "fs-1", "/mnt/efs", [])
    rt._register_and_run = AsyncMock(return_value=WorkspaceHandle("ws-1", "task", ""))
    token = "ghs_" + "b" * 36
    spec = WorkspaceSpec(
        workspace_id="ws-1", project="p", intent="t", image="i", root_path="",
        folders=FOLDERS[:1], git_write=True, git_tokens={"acme": token},
    )
    await rt.provision(spec)
    args = rt._register_and_run.await_args.args
    delivered, git_plan = args[5], args[6]
    assert delivered[TOKENS_SECRET] == f"acme {token}\n"
    assert TOKENS_SECRET not in git_plan.init_secret_names
    assert token not in git_plan.folders_env
    assert token not in repr(spec)


async def test_podman_writes_tokens_with_put_archive_not_exec_args():
    from warren.runtime.podman import PodmanRuntime

    rt = PodmanRuntime.__new__(PodmanRuntime)
    container = MagicMock()
    rt._client = MagicMock()
    rt._client.containers.get.return_value = container
    argvs = []

    async def fake_exec(handle, argv):
        argvs.append(list(argv))
        yield ExecExit(0)

    rt.exec_stream = fake_exec
    token = "ghs_" + "c" * 36
    with structlog.testing.capture_logs() as logs:
        await rt.install_git_tokens(WorkspaceHandle("ws-1", "cid", ""), {"acme": token})
        await rt.drop_git_tokens(WorkspaceHandle("ws-1", "cid", ""))
    kwargs = container.put_archive.call_args.kwargs
    assert kwargs["path"] == "/run"
    with tarfile.open(fileobj=io.BytesIO(kwargs["data"])) as tar:
        members = {m.name: m for m in tar.getmembers()}
        assert members["warren-git"].isdir() and members["warren-git"].mode == 0o755
        f = members["warren-git/acme"]
        assert (f.mode, f.uid, f.gid) == (0o600, 1000, 1000)
        assert tar.extractfile(f).read() == (token + "\n").encode()
    assert argvs == [["chown", "1000:1000", "/run/warren-git/acme"], ["rm", "-rf", "/run/warren-git"]]
    assert not any(token in " ".join(a) for a in argvs)
    assert token not in repr(logs)
