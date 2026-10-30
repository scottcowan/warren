"""ECS workspace storage mode on the provisioning route: the deployment default
(WARREN_ECS_WORKSPACE_STORAGE), a template's `ecs_storage` override (only for a mode
the deployment has configured), the mode recorded on the spec, and EBS workspaces not
needing a WARREN_ECS_OWNER_STORAGE entry. Plus the lifespan wiring."""

from __future__ import annotations

import asyncio
import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from tests.unit.routes.test_workspaces import _make_fake_registry, env_defaults  # noqa: F401

ROLE = "arn:aws:iam::123456789012:role/warren-ecs-infra"
KEY = "arn:aws:kms:us-east-1:123456789012:key/0000-1111"
_AWS = {"X-AWS-STS-Signed-Request": '{"url": "https://sts.amazonaws.com/"}'}


def _project(template: dict):
    from warren_common.models import ProjectConfig

    return ProjectConfig.model_validate(
        {"name": "demo", "docker_image": "ghcr.io/scottcowan/warren-base:latest", "templates": {"t": template}}
    )


def _post(monkeypatch, auth_headers, template: dict, env: dict, principal: str = "alice"):
    monkeypatch.setenv("WARREN_RUNTIME_TYPE", "ecs")
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    fake_registry = _make_fake_registry()

    async def verify(signed, audience, patterns, on_verified_arn=None):
        on_verified_arn(f"arn:aws:sts::123456789012:assumed-role/AWSReservedSSO_Dev_0123abcd/{principal}")
        return "deadbeef" * 4

    from warren.app import app

    with (
        patch("warren_common.loader.ProjectLoader.load_effective", return_value=_project(template)),
        patch("warren.app.WorkspaceRegistry", return_value=fake_registry),
        patch("warren.runtime.ecs.ECSRuntime", return_value=MagicMock()),
        patch("warren.auth.aws_identity.verify_signed_caller_identity", AsyncMock(side_effect=verify)),
        patch("warren.registry.efs_reaper.run_efs_reaper", AsyncMock()),
        patch("warren.registry.ebs_sweep.run_ebs_sweep", AsyncMock()),
    ):
        with TestClient(app, headers={**auth_headers, **_AWS}) as client:
            app.state.registry = fake_registry
            resp = client.post("/workspaces", json={"project": "demo", "template": "t"})
    spec = fake_registry._do_provision.call_args.args[1] if fake_registry._do_provision.call_args else None
    return resp, spec


EBS = {"WARREN_ECS_EBS_INFRA_ROLE_ARN": ROLE, "WARREN_ECS_SECRETS_KMS_KEY_ID": KEY}
EFS = {"WARREN_EFS_ID": "fs-0aaaaaaaaaaaaaaa1"}


@pytest.mark.parametrize("template, env, mode", [
    ({}, {}, "efs"),  # default, unchanged for existing deployments
    ({}, {**EBS, "WARREN_ECS_WORKSPACE_STORAGE": "ebs"}, "ebs"),
    ({"ecs_storage": "ebs"}, {**EBS, **EFS}, "ebs"),
    ({"ecs_storage": "efs"}, {**EBS, **EFS, "WARREN_ECS_WORKSPACE_STORAGE": "ebs"}, "efs"),
])
def test_mode_is_resolved_and_recorded_on_the_spec(env_defaults, monkeypatch, auth_headers, template, env, mode):  # noqa: F811
    resp, spec = _post(monkeypatch, auth_headers, template, env)
    assert resp.status_code == 202, resp.text
    assert spec.ecs_storage == mode


@pytest.mark.parametrize("template, env, needle", [
    ({"ecs_storage": "ebs"}, EFS, "WARREN_ECS_EBS_INFRA_ROLE_ARN"),
    ({"ecs_storage": "ebs"}, {**EFS, "WARREN_ECS_EBS_INFRA_ROLE_ARN": ROLE}, "WARREN_ECS_SECRETS_KMS_KEY_ID"),
    ({"ecs_storage": "efs"}, {}, "WARREN_EFS_ID"),
])
def test_override_for_an_unconfigured_mode_is_template_denied(env_defaults, monkeypatch, auth_headers, template, env, needle):  # noqa: F811,E501
    resp, spec = _post(monkeypatch, auth_headers, template, env)
    assert resp.status_code == 422
    assert resp.json()["detail"]["error"] == "template_denied"
    assert needle in resp.json()["detail"]["detail"]
    assert spec is None


def test_ebs_workspace_needs_no_owner_storage_entry(env_defaults, monkeypatch, auth_headers):  # noqa: F811
    storage = {"alice": {"efs_id": "fs-0aaaaaaaaaaaaaaa1", "security_group_ids": ["sg-0aaaaaaaaaaaaaaa1"],
                         "local_mount_path": "/mnt/warren-efs/alice"}}
    env = {**EBS, "WARREN_ECS_OWNER_STORAGE": json.dumps(storage)}
    resp, spec = _post(monkeypatch, auth_headers, {"ecs_storage": "ebs"}, env, principal="mallory")
    assert resp.status_code == 202, resp.text
    assert spec.ecs_storage == "ebs" and spec.storage_key == ""
    resp, spec = _post(monkeypatch, auth_headers, {"ecs_storage": "ebs"}, env, principal="alice")
    assert spec.storage_key == "alice"  # keeps their own security groups
    resp, _ = _post(monkeypatch, auth_headers, {}, env, principal="mallory")
    assert resp.status_code == 403  # an EFS workspace still needs the entry


def test_template_field_merges_like_other_ecs_scalars():
    from warren_common.models import ProjectConfig
    from warren_common.templates import resolve_template

    cfg = ProjectConfig.model_validate(
        {"name": "p", "ecs_storage": "ebs", "templates": {"a": {"templates": {"b": {"ecs_storage": "efs"}}}}}
    )
    assert resolve_template(cfg, "a").ecs_storage == "ebs"
    assert resolve_template(cfg, "a.b").ecs_storage == "efs"
    with pytest.raises(Exception):
        ProjectConfig.model_validate({"name": "p", "ecs_storage": "s3"})


def test_volume_errors_map_to_retryable_503_and_409():
    from warren.routes.workspaces import _provision_http_error
    from warren.runtime.ebs import WorkspaceVolumeLost, WorkspaceVolumeNotReady

    err = _provision_http_error(WorkspaceVolumeNotReady("x", retry_after_seconds=7))
    assert err.status_code == 503 and err.headers == {"Retry-After": "7"}
    assert _provision_http_error(WorkspaceVolumeLost("y")).status_code == 409


async def test_lifespan_wires_ebs_storage_and_its_sweep(monkeypatch, tmp_path):
    monkeypatch.setenv("WARREN_SECRET_KEY", "x" * 32)
    monkeypatch.setenv("WARREN_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("WARREN_SERVER_ID", "test-server")
    monkeypatch.setenv("WARREN_RUNTIME_TYPE", "ecs")
    monkeypatch.setenv("WARREN_REAPER_ENABLED", "0")
    monkeypatch.setenv("WARREN_ECS_WORKSPACE_STORAGE", "ebs")
    for k, v in EBS.items():
        monkeypatch.setenv(k, v)
    registry = MagicMock()
    registry.reconcile_from_disk = AsyncMock()
    swept: list = []

    async def fake_sweep(reg, *, interval_seconds, min_age_seconds):
        swept.append((reg, interval_seconds, min_age_seconds))

    with (
        patch("warren.runtime.ecs.ECSRuntime.preflight", AsyncMock()),
        patch("warren.app.WorkspaceRegistry", return_value=registry),
        patch("warren.registry.ebs_sweep.run_ebs_sweep", fake_sweep),
    ):
        from warren.app import app, lifespan
        from warren.registry.store import EbsSnapshotStore

        async with lifespan(app):
            await asyncio.sleep(0)
            rt = app.state.runtime
            assert rt.ebs is not None
            assert isinstance(rt.ebs.snapshot_store, EbsSnapshotStore)
            assert rt.storage_of is not None
            assert await rt.storage_of("missing") is None
    assert swept == [(registry, 900.0, 900.0)]
