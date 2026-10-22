"""_resolve_image() declarative-build wiring tests (LIFE-04, D-09).

`warren-common`'s `ProjectConfig` (a separate repo) does not yet surface a
`containerfile` attribute -- `_resolve_image()` reads it defensively via
`getattr(..., "containerfile", None)` so this stays a no-op until that
field lands there. These tests patch `warren_common.loader.ProjectLoader.load`
and `warren.routes.workspaces.resolve_template` directly to return fake
project/template configs carrying a `containerfile` attribute, exercising
the wiring `_resolve_image()` itself owns without waiting on the upstream
field or depending on real template-inheritance resolution (covered
separately by warren-common's test_templates.py).
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest
from fastapi import HTTPException, Request

from warren.routes.workspaces import ProvisionRequest, _resolve_image


def _project_cfg(
    *,
    template_containerfile: str | None = None,
    project_containerfile: str | None = None,
    docker_image: str = "localhost/warren-base:latest",
    ecs_image: str = "localhost/warren-ecs-base:latest",
) -> tuple[SimpleNamespace, SimpleNamespace]:
    """Return (project_cfg, template_cfg) fakes — template_cfg is what
    `resolve_template()` is patched to return."""
    template_cfg = SimpleNamespace(
        docker_image=docker_image, containerfile=template_containerfile, ecs_image=ecs_image
    )
    project_cfg = SimpleNamespace(
        docker_image=docker_image,
        containerfile=project_containerfile,
    )
    return project_cfg, template_cfg


def _make_request(
    *,
    image_build_enabled: bool,
    runtime=None,
    runtime_type: str = "podman",
    ecs_default_image: str = "",
) -> Request:
    settings = SimpleNamespace(
        projects_dir=Path("/does/not/matter"),
        image_build_enabled=image_build_enabled,
        image_build_memory="2g",
        image_build_cpus=2.0,
        runtime_type=runtime_type,
        ecs_default_image=ecs_default_image,
        # Audit Z12: this file's fixtures use fake custom images unrelated to the
        # sanctioning feature itself (covered separately in test_workspaces.py) --
        # allow-list them so _server_sanctioned_image doesn't drop them to the
        # ProjectConfig default and mask what each test actually exercises.
        allowed_images=[
            "localhost/warren-base:latest",
            "ghcr.io/scottcowan/warren-base-ecs:latest",
            "localhost/warren-ecs-base:latest",
        ],
    )
    app_state = SimpleNamespace(settings=settings, runtime=runtime)
    app = SimpleNamespace(state=app_state)
    user = SimpleNamespace(user_id="user-1", username="demo", is_admin=False)
    scope = {"type": "http", "app": app, "state": {"user": user}}
    return Request(scope)


def _body(project: str = "demo", template: str = "dev") -> ProvisionRequest:
    return ProvisionRequest(project=project, template=template)


@pytest.mark.asyncio
async def test_declared_containerfile_builds_and_returns_tag():
    fake_runtime = SimpleNamespace(
        supports_image_build=True,
        build_image=AsyncMock(return_value="localhost/warren-project-demo:abc123"),
    )
    request = _make_request(image_build_enabled=True, runtime=fake_runtime)
    project_cfg, template_cfg = _project_cfg(template_containerfile="Containerfile")

    with (
        patch("warren_common.loader.ProjectLoader.load_effective", return_value=project_cfg),
        patch("warren.routes.workspaces.resolve_template", return_value=template_cfg),
        patch(
            "warren.routes.workspaces.resolve_build_spec",
            return_value=SimpleNamespace(tag="localhost/warren-project-demo:abc123"),
        ),
    ):
        image = await _resolve_image(_body(), request)

    assert image == "localhost/warren-project-demo:abc123"
    fake_runtime.build_image.assert_called_once()


@pytest.mark.asyncio
async def test_build_disabled_returns_422_image_build_disabled():
    fake_runtime = SimpleNamespace(supports_image_build=True, build_image=AsyncMock())
    request = _make_request(image_build_enabled=False, runtime=fake_runtime)
    project_cfg, template_cfg = _project_cfg(template_containerfile="Containerfile")

    with (
        patch("warren_common.loader.ProjectLoader.load_effective", return_value=project_cfg),
        patch("warren.routes.workspaces.resolve_template", return_value=template_cfg),
    ):
        with pytest.raises(HTTPException) as ei:
            await _resolve_image(_body(), request)

    assert ei.value.status_code == 422
    assert ei.value.detail["error"] == "image_build_disabled"
    fake_runtime.build_image.assert_not_called()


@pytest.mark.asyncio
async def test_traversal_path_returns_422_with_no_absolute_host_path(tmp_path):
    fake_runtime = SimpleNamespace(supports_image_build=True, build_image=AsyncMock())
    request = _make_request(image_build_enabled=True, runtime=fake_runtime)
    project_cfg, template_cfg = _project_cfg(template_containerfile="../../../etc/shadow")

    with (
        patch("warren_common.loader.ProjectLoader.load_effective", return_value=project_cfg),
        patch("warren.routes.workspaces.resolve_template", return_value=template_cfg),
    ):
        with pytest.raises(HTTPException) as ei:
            await _resolve_image(_body(), request)

    assert ei.value.status_code == 422
    assert ei.value.detail["error"] == "containerfile_invalid"
    detail_text = str(ei.value.detail)
    assert str(tmp_path) not in detail_text
    fake_runtime.build_image.assert_not_called()


@pytest.mark.asyncio
async def test_no_containerfile_declared_uses_existing_tag_lookup():
    fake_runtime = SimpleNamespace(supports_image_build=True, build_image=AsyncMock())
    request = _make_request(image_build_enabled=True, runtime=fake_runtime)
    project_cfg, template_cfg = _project_cfg()

    with (
        patch("warren_common.loader.ProjectLoader.load_effective", return_value=project_cfg),
        patch("warren.routes.workspaces.resolve_template", return_value=template_cfg),
    ):
        image = await _resolve_image(_body(), request)

    assert image == "localhost/warren-base:latest"
    fake_runtime.build_image.assert_not_called()


@pytest.mark.asyncio
async def test_runtime_without_build_capability_falls_back_to_tag_lookup():
    # A runtime lacking `supports_image_build` entirely, e.g. FakeRuntime/ECSRuntime.
    fake_runtime = SimpleNamespace()
    request = _make_request(image_build_enabled=True, runtime=fake_runtime)
    project_cfg, template_cfg = _project_cfg(template_containerfile="Containerfile")

    with (
        patch("warren_common.loader.ProjectLoader.load_effective", return_value=project_cfg),
        patch("warren.routes.workspaces.resolve_template", return_value=template_cfg),
    ):
        image = await _resolve_image(_body(), request)

    assert image == "localhost/warren-base:latest"


@pytest.mark.asyncio
async def test_ecs_runtime_uses_ecs_image_override_when_set():
    request = _make_request(image_build_enabled=True, runtime_type="ecs")
    project_cfg, template_cfg = _project_cfg(
        docker_image="localhost/warren-base:latest",
        ecs_image="ghcr.io/scottcowan/warren-base-ecs:latest",
    )

    with (
        patch("warren_common.loader.ProjectLoader.load_effective", return_value=project_cfg),
        patch("warren.routes.workspaces.resolve_template", return_value=template_cfg),
    ):
        image = await _resolve_image(_body(), request)

    assert image == "ghcr.io/scottcowan/warren-base-ecs:latest"


@pytest.mark.asyncio
async def test_ecs_runtime_uses_its_own_default_not_docker_image():
    """When a template doesn't override `ecs_image`, ECS gets its own default
    (the Alpine-based ecs-base image), never the docker_image default — the
    two fields are independent, not a fallback chain."""
    request = _make_request(image_build_enabled=True, runtime_type="ecs")
    project_cfg, template_cfg = _project_cfg(docker_image="localhost/warren-base:latest")

    with (
        patch("warren_common.loader.ProjectLoader.load_effective", return_value=project_cfg),
        patch("warren.routes.workspaces.resolve_template", return_value=template_cfg),
    ):
        image = await _resolve_image(_body(), request)

    assert image == "localhost/warren-ecs-base:latest"
    assert image != "localhost/warren-base:latest"


@pytest.mark.asyncio
async def test_ecs_default_image_setting_used_when_template_never_overrode_ecs_image():
    """Audit V1: WARREN_ECS_DEFAULT_IMAGE lets a deployment point every
    workspace that never set its own ecs_image at that deployment's own
    published image, without editing every project YAML."""
    from warren_common.models import ProjectConfig

    request = _make_request(
        image_build_enabled=True,
        runtime_type="ecs",
        ecs_default_image="123456789012.dkr.ecr.us-east-1.amazonaws.com/warren-ecs:prod",
    )
    # ecs_image left at ProjectConfig's own hardcoded default -- the template never
    # overrode it.
    project_cfg, template_cfg = _project_cfg(
        docker_image="localhost/warren-base:latest",
        ecs_image=ProjectConfig.model_fields["ecs_image"].default,
    )

    with (
        patch("warren_common.loader.ProjectLoader.load_effective", return_value=project_cfg),
        patch("warren.routes.workspaces.resolve_template", return_value=template_cfg),
    ):
        image = await _resolve_image(_body(), request)

    assert image == "123456789012.dkr.ecr.us-east-1.amazonaws.com/warren-ecs:prod"


@pytest.mark.asyncio
async def test_ecs_default_image_setting_never_overrides_explicit_template_ecs_image():
    """An explicit per-project/template ecs_image always wins over the
    server-level default, even when the default is set."""
    request = _make_request(
        image_build_enabled=True,
        runtime_type="ecs",
        ecs_default_image="123456789012.dkr.ecr.us-east-1.amazonaws.com/warren-ecs:prod",
    )
    project_cfg, template_cfg = _project_cfg(
        docker_image="localhost/warren-base:latest",
        ecs_image="ghcr.io/scottcowan/warren-base-ecs:latest",
    )

    with (
        patch("warren_common.loader.ProjectLoader.load_effective", return_value=project_cfg),
        patch("warren.routes.workspaces.resolve_template", return_value=template_cfg),
    ):
        image = await _resolve_image(_body(), request)

    assert image == "ghcr.io/scottcowan/warren-base-ecs:latest"


@pytest.mark.asyncio
async def test_podman_runtime_ignores_ecs_image_override():
    request = _make_request(image_build_enabled=True, runtime_type="podman")
    project_cfg, template_cfg = _project_cfg(
        docker_image="localhost/warren-base:latest",
        ecs_image="ghcr.io/scottcowan/warren-base-ecs:latest",
    )

    with (
        patch("warren_common.loader.ProjectLoader.load_effective", return_value=project_cfg),
        patch("warren.routes.workspaces.resolve_template", return_value=template_cfg),
    ):
        image = await _resolve_image(_body(), request)

    assert image == "localhost/warren-base:latest"
