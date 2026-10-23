"""Lifespan wiring — Plan 01-05 Task 1 (RED then GREEN)."""

from __future__ import annotations

import asyncio
import subprocess
import sys
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


@pytest.fixture
def tmp_data_dir():
    with tempfile.TemporaryDirectory() as d:
        yield Path(d)


@pytest.fixture
def env_defaults(monkeypatch, tmp_data_dir):
    monkeypatch.setenv("WARREN_SECRET_KEY", "x" * 32)
    monkeypatch.setenv("WARREN_BOOTSTRAP_TOKEN", "test-bootstrap-token000000000000")
    monkeypatch.setenv("WARREN_DATA_DIR", str(tmp_data_dir))
    monkeypatch.setenv("WARREN_PODMAN_SOCKET", str(tmp_data_dir / "podman.sock"))
    monkeypatch.setenv("WARREN_SERVER_ID", "test-server")
    yield


@pytest.mark.asyncio
async def test_lifespan_populates_app_state(env_defaults):
    """Lifespan startup must set app.state.settings/runtime/registry after steps 1-6."""
    fake_registry_reconcile = AsyncMock()
    fake_registry_instance = MagicMock()
    fake_registry_instance.reconcile_from_disk = fake_registry_reconcile

    with (
        patch("warren.app.run_preflight", AsyncMock()) as preflight,
        patch("warren.app.WorkspaceRegistry", return_value=fake_registry_instance) as reg_cls,
        patch("warren.app.PodmanRuntime") as runtime_cls,
    ):
        from warren.app import app, lifespan

        async with lifespan(app):
            preflight.assert_awaited_once()
            fake_registry_reconcile.assert_awaited_once()
            assert app.state.settings is not None
            assert app.state.runtime is runtime_cls.return_value
            assert app.state.registry is fake_registry_instance


@pytest.mark.asyncio
async def test_lifespan_wires_git_manager_for_podman(env_defaults, tmp_data_dir):
    """GitManager was never instantiated anywhere in production -- every
    server-side worktree clone path (registry.py's _do_provision) was dead
    code on a real podman/docker deployment despite being fully implemented
    and tested. runtime_type defaults to podman in these tests."""
    fake_registry_reconcile = AsyncMock()
    fake_registry_instance = MagicMock()
    fake_registry_instance.reconcile_from_disk = fake_registry_reconcile

    with (
        patch("warren.app.run_preflight", AsyncMock()),
        patch("warren.app.WorkspaceRegistry", return_value=fake_registry_instance) as reg_cls,
        patch("warren.app.PodmanRuntime"),
    ):
        from warren.app import app, lifespan
        from warren.git.manager import GitManager

        async with lifespan(app):
            pass

    git_manager = reg_cls.call_args.kwargs["git_manager"]
    assert isinstance(git_manager, GitManager)
    assert git_manager.worktree_root == tmp_data_dir / "worktrees"


@pytest.mark.asyncio
async def test_lifespan_wires_github_app_credentials_when_configured(
    env_defaults, monkeypatch, tmp_data_dir
):
    """#58: GitManager must receive a GitHubAppCredentials instance built from
    settings when the GitHub App env vars are set, or github_app.py's auth
    implementation is never actually exercised in production."""
    key_path = tmp_data_dir / "github-app.pem"
    key_path.write_text("fake-pem")
    monkeypatch.setenv("WARREN_GITHUB_APP_ID", "12345")
    monkeypatch.setenv("WARREN_GITHUB_APP_INSTALLATION_ID", "67890")
    monkeypatch.setenv("WARREN_GITHUB_APP_PRIVATE_KEY_PATH", str(key_path))

    fake_registry = MagicMock()
    fake_registry.reconcile_from_disk = AsyncMock()

    with (
        patch("warren.app.run_preflight", AsyncMock()),
        patch("warren.app.WorkspaceRegistry", return_value=fake_registry) as reg_cls,
        patch("warren.app.PodmanRuntime"),
    ):
        from warren.app import app, lifespan
        from warren.git.github_app import GitHubAppCredentials

        async with lifespan(app):
            pass

    git_manager = reg_cls.call_args.kwargs["git_manager"]
    assert isinstance(git_manager.credentials, GitHubAppCredentials)
    assert git_manager.credentials.app_id == "12345"
    assert git_manager.credentials.installation_id == "67890"
    assert git_manager.credentials.private_key_path == key_path


@pytest.mark.asyncio
async def test_lifespan_omits_github_app_credentials_when_unconfigured(env_defaults):
    """No GitHub App env vars set -- GitManager must fall back to
    credentials=None (plain PAT/SSH-only behavior), not raise or half-wire."""
    fake_registry = MagicMock()
    fake_registry.reconcile_from_disk = AsyncMock()

    with (
        patch("warren.app.run_preflight", AsyncMock()),
        patch("warren.app.WorkspaceRegistry", return_value=fake_registry) as reg_cls,
        patch("warren.app.PodmanRuntime"),
    ):
        from warren.app import app, lifespan

        async with lifespan(app):
            pass

    git_manager = reg_cls.call_args.kwargs["git_manager"]
    assert git_manager.credentials is None


@pytest.mark.asyncio
async def test_lifespan_omits_git_manager_for_ecs(env_defaults, monkeypatch):
    """ECS tasks run on a different host entirely -- a host-side clone on this
    process would never reach them, so git_manager stays None for that runtime."""
    monkeypatch.setenv("WARREN_RUNTIME_TYPE", "ecs")
    fake_registry_reconcile = AsyncMock()
    fake_registry_instance = MagicMock()
    fake_registry_instance.reconcile_from_disk = fake_registry_reconcile
    fake_runtime = MagicMock()
    fake_runtime.preflight = AsyncMock()

    with (
        patch("warren.app.WorkspaceRegistry", return_value=fake_registry_instance) as reg_cls,
        patch("warren.runtime.ecs.ECSRuntime", return_value=fake_runtime),
    ):
        from warren.app import app, lifespan

        async with lifespan(app):
            pass

    assert reg_cls.call_args.kwargs["git_manager"] is None


@pytest.mark.asyncio
async def test_lifespan_reconcile_timeout_is_non_fatal(env_defaults):
    """asyncio.TimeoutError from reconcile must be caught; startup must complete."""

    async def slow_reconcile():
        await asyncio.sleep(10)

    fake_registry = MagicMock()
    fake_registry.reconcile_from_disk = slow_reconcile

    with (
        patch("warren.app.run_preflight", AsyncMock()),
        patch("warren.app.WorkspaceRegistry", return_value=fake_registry),
        patch("warren.app.PodmanRuntime"),
        patch("warren.app._RECONCILE_TIMEOUT_S", 0.01),
    ):
        from warren.app import app, lifespan

        async with lifespan(app):
            assert app.state.registry is fake_registry


@pytest.mark.asyncio
async def test_lifespan_starts_and_cancels_reaper(env_defaults):
    """Lifespan must spawn a reaper task on startup and cancel it on shutdown."""
    fake_registry = MagicMock()
    fake_registry.reconcile_from_disk = AsyncMock()

    async def _forever_reaper(*args, **kwargs):
        try:
            while True:
                await asyncio.sleep(3600)
        except asyncio.CancelledError:
            raise

    with (
        patch("warren.app.run_preflight", AsyncMock()),
        patch("warren.app.WorkspaceRegistry", return_value=fake_registry),
        patch("warren.app.PodmanRuntime"),
        patch("warren.app.run_reaper", side_effect=_forever_reaper),
    ):
        from warren.app import app, lifespan

        async with lifespan(app):
            await asyncio.sleep(0.01)
            task = app.state.reaper_task
            assert task is not None
            assert not task.done()

        # After lifespan exits, task must be cancelled cleanly.
        assert app.state.reaper_task.cancelled() or app.state.reaper_task.done()


@pytest.mark.asyncio
async def test_lifespan_reaper_disabled_via_env(env_defaults, monkeypatch):
    """WARREN_REAPER_ENABLED=0 skips spawning the reaper task."""
    monkeypatch.setenv("WARREN_REAPER_ENABLED", "0")
    fake_registry = MagicMock()
    fake_registry.reconcile_from_disk = AsyncMock()

    with (
        patch("warren.app.run_preflight", AsyncMock()),
        patch("warren.app.WorkspaceRegistry", return_value=fake_registry),
        patch("warren.app.PodmanRuntime"),
        patch("warren.app.run_reaper") as reaper,
    ):
        from warren.app import app, lifespan

        async with lifespan(app):
            assert app.state.reaper_task is None
            reaper.assert_not_called()


@pytest.mark.asyncio
async def test_lifespan_starts_and_cancels_idle_reaper(env_defaults):
    """Lifespan must spawn an idle-reaper task on startup and cancel it on shutdown."""
    fake_registry = MagicMock()
    fake_registry.reconcile_from_disk = AsyncMock()

    async def _forever_idle_reaper(*args, **kwargs):
        try:
            while True:
                await asyncio.sleep(3600)
        except asyncio.CancelledError:
            raise

    with (
        patch("warren.app.run_preflight", AsyncMock()),
        patch("warren.app.WorkspaceRegistry", return_value=fake_registry),
        patch("warren.app.PodmanRuntime"),
        patch(
            "warren.registry.idle_reaper.run_idle_reaper",
            side_effect=_forever_idle_reaper,
        ),
    ):
        from warren.app import app, lifespan

        async with lifespan(app):
            await asyncio.sleep(0.01)
            task = app.state.idle_reaper_task
            assert task is not None
            assert isinstance(task, asyncio.Task)
            assert not task.done()

        # After lifespan exits, task must be cancelled cleanly.
        assert app.state.idle_reaper_task.cancelled() or app.state.idle_reaper_task.done()


@pytest.mark.asyncio
async def test_lifespan_idle_reaper_disabled_via_settings(env_defaults, monkeypatch):
    """WARREN_IDLE_REAPER_ENABLED=0 skips spawning the idle-reaper task."""
    monkeypatch.setenv("WARREN_IDLE_REAPER_ENABLED", "0")
    fake_registry = MagicMock()
    fake_registry.reconcile_from_disk = AsyncMock()

    with (
        patch("warren.app.run_preflight", AsyncMock()),
        patch("warren.app.WorkspaceRegistry", return_value=fake_registry),
        patch("warren.app.PodmanRuntime"),
        patch("warren.registry.idle_reaper.run_idle_reaper") as idle_reaper,
    ):
        from warren.app import app, lifespan

        async with lifespan(app):
            assert app.state.idle_reaper_task is None
            idle_reaper.assert_not_called()


@pytest.mark.asyncio
async def test_lifespan_passes_bridge_name_to_podman_runtime(env_defaults):
    """PodmanRuntime construction must thread egress_bridge_name from settings."""
    fake_registry = MagicMock()
    fake_registry.reconcile_from_disk = AsyncMock()

    with (
        patch("warren.app.run_preflight", AsyncMock()),
        patch("warren.app.WorkspaceRegistry", return_value=fake_registry),
        patch("warren.app.PodmanRuntime") as runtime_cls,
    ):
        from warren.app import app, lifespan

        async with lifespan(app):
            _, kwargs = runtime_cls.call_args
            assert kwargs["egress_bridge_name"] == app.state.settings.egress_bridge_name
            assert kwargs["ssh_publish_host"] == app.state.settings.ssh_publish_host == "127.0.0.1"


@pytest.mark.asyncio
async def test_lifespan_idle_reaper_spawn_failure_is_non_fatal(env_defaults):
    """A create_task failure spawning the idle reaper must not prevent lifespan from yielding."""
    fake_registry = MagicMock()
    fake_registry.reconcile_from_disk = AsyncMock()

    with (
        patch("warren.app.run_preflight", AsyncMock()),
        patch("warren.app.WorkspaceRegistry", return_value=fake_registry),
        patch("warren.app.PodmanRuntime"),
        patch("warren.app.asyncio.create_task", side_effect=RuntimeError("boom")),
    ):
        from warren.app import app, lifespan

        async with lifespan(app):
            assert app.state.idle_reaper_task is None


@pytest.mark.asyncio
async def test_docker_runtime_is_implemented():
    """DockerRuntime is now fully implemented (05b-03). Verify it instantiates cleanly."""
    from warren_common.runtime.base import RuntimeConfig
    from warren_common.runtime.docker import DockerRuntime

    rt = DockerRuntime(RuntimeConfig(type="docker"))
    # DockerRuntime methods are real implementations (not stubs) — just verify the class
    # has the expected async methods from the ContainerRuntime Protocol.
    import inspect
    for method in ("provision", "start", "stop", "destroy", "exec", "status"):
        assert hasattr(rt, method), f"DockerRuntime missing method: {method}"
        assert inspect.iscoroutinefunction(getattr(rt, method)) or inspect.isasyncgenfunction(getattr(rt, method)), \
            f"DockerRuntime.{method} is not async"


@pytest.mark.asyncio
async def test_lifespan_ecs(env_defaults, monkeypatch):
    """When WARREN_RUNTIME_TYPE=ecs, lifespan instantiates ECSRuntime (not PodmanRuntime)."""
    monkeypatch.setenv("WARREN_RUNTIME_TYPE", "ecs")

    from warren.runtime.ecs import ECSRuntime

    fake_registry = MagicMock()
    fake_registry.reconcile_from_disk = AsyncMock()

    with (
        patch("warren.runtime.ecs.ECSRuntime.preflight", AsyncMock()),
        patch("warren.app.WorkspaceRegistry", return_value=fake_registry),
    ):
        from warren.app import app, lifespan

        async with lifespan(app):
            assert isinstance(app.state.runtime, ECSRuntime), (
                f"Expected ECSRuntime, got {type(app.state.runtime)}"
            )
            assert app.state.ecs_orphan_sweep_task is not None


@pytest.mark.asyncio
async def test_lifespan_ecs_orphan_sweep_disabled_by_zero_interval(env_defaults, monkeypatch):
    monkeypatch.setenv("WARREN_RUNTIME_TYPE", "ecs")
    monkeypatch.setenv("WARREN_ECS_ORPHAN_SWEEP_INTERVAL_SECONDS", "0")

    fake_registry = MagicMock()
    fake_registry.reconcile_from_disk = AsyncMock()

    with (
        patch("warren.runtime.ecs.ECSRuntime.preflight", AsyncMock()),
        patch("warren.app.WorkspaceRegistry", return_value=fake_registry),
    ):
        from warren.app import app, lifespan

        async with lifespan(app):
            assert app.state.ecs_orphan_sweep_task is None


@pytest.mark.asyncio
async def test_lifespan_wires_auth_store(env_defaults):
    """After lifespan startup, app.state.auth_store is an AuthStore instance."""
    fake_registry = MagicMock()
    fake_registry.reconcile_from_disk = AsyncMock()

    with (
        patch("warren.app.run_preflight", AsyncMock()),
        patch("warren.app.WorkspaceRegistry", return_value=fake_registry),
        patch("warren.app.PodmanRuntime"),
    ):
        from warren.app import app, lifespan
        from warren.auth.store import AuthStore

        async with lifespan(app):
            assert isinstance(app.state.auth_store, AuthStore)


@pytest.mark.asyncio
async def test_lifespan_bootstrap_creates_one_admin(env_defaults):
    """With WARREN_BOOTSTRAP_TOKEN set and a fresh data dir, one admin exists after startup."""
    fake_registry = MagicMock()
    fake_registry.reconcile_from_disk = AsyncMock()

    with (
        patch("warren.app.run_preflight", AsyncMock()),
        patch("warren.app.WorkspaceRegistry", return_value=fake_registry),
        patch("warren.app.PodmanRuntime"),
    ):
        from warren.app import app, lifespan

        async with lifespan(app):
            users = await app.state.auth_store.list_users()
            assert len(users) == 1
            assert users[0].is_admin is True


@pytest.mark.asyncio
async def test_lifespan_bootstrap_is_idempotent(env_defaults):
    """Entering lifespan twice against the same WARREN_DATA_DIR leaves exactly one admin."""
    fake_registry = MagicMock()
    fake_registry.reconcile_from_disk = AsyncMock()

    with (
        patch("warren.app.run_preflight", AsyncMock()),
        patch("warren.app.WorkspaceRegistry", return_value=fake_registry),
        patch("warren.app.PodmanRuntime"),
    ):
        from warren.app import app, lifespan

        async with lifespan(app):
            pass

        async with lifespan(app):
            users = await app.state.auth_store.list_users()
            assert len(users) == 1


@pytest.mark.asyncio
async def test_lifespan_bootstrap_skipped_without_token(env_defaults, monkeypatch):
    """With WARREN_BOOTSTRAP_TOKEN unset, lifespan still completes with zero users."""
    monkeypatch.delenv("WARREN_BOOTSTRAP_TOKEN", raising=False)
    fake_registry = MagicMock()
    fake_registry.reconcile_from_disk = AsyncMock()

    with (
        patch("warren.app.run_preflight", AsyncMock()),
        patch("warren.app.WorkspaceRegistry", return_value=fake_registry),
        patch("warren.app.PodmanRuntime"),
    ):
        from warren.app import app, lifespan

        async with lifespan(app):
            users = await app.state.auth_store.list_users()
            assert users == []


def test_dry_run_exits_zero(tmp_path, monkeypatch):
    """`python -m warren --dry-run` runs the lifespan startup and exits 0."""
    env = {
        "WARREN_SECRET_KEY": "x" * 32,
        "WARREN_BOOTSTRAP_TOKEN": "test-bootstrap-token000000000000",
        "WARREN_DATA_DIR": str(tmp_path),
        "WARREN_PODMAN_SOCKET": str(tmp_path / "podman.sock"),
        "WARREN_SERVER_ID": "test-server",
        "PYTHONPATH": str(Path(__file__).parents[2] / "src"),
        "WARREN_DRY_RUN_SKIP_PREFLIGHT": "1",
        "PATH": "/usr/bin:/bin",
    }
    result = subprocess.run(
        [sys.executable, "-m", "warren", "--dry-run"],
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, f"stdout={result.stdout} stderr={result.stderr}"


def test_main_configures_logging_before_serving(monkeypatch):
    """`main()` must call `configure_logging()` before `uvicorn.run`/`_dry_run`.

    Real bug: nothing ever called it, so structlog ran on its own unconfigured
    default the whole time -- which auto-detects `rich` (pulled in transitively
    via the `typer` dependency, never actually imported by this package) and
    renders any `exc_info=True` call as a Rich traceback with `show_locals`,
    printing full secret values (e.g. an SSH private key passed to GitManager)
    in plaintext to container logs, bypassing `redact_secrets` entirely.
    """
    from warren import __main__ as main_module

    calls: list[str] = []
    monkeypatch.setattr(main_module, "configure_logging", lambda: calls.append("configure_logging"))
    monkeypatch.setattr(main_module.uvicorn, "run", lambda *a, **kw: calls.append("uvicorn.run"))
    monkeypatch.setattr(sys, "argv", ["warren"])

    main_module.main()

    assert calls == ["configure_logging", "uvicorn.run"]
