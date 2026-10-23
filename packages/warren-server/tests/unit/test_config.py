"""WarrenSettings unit tests (Plan 07-01 Wave 0).

Tests for ECS settings fields appended here as xfail stubs; they turn green
once Plan 07-02 Task 1 adds the ECS fields to WarrenSettings.
"""

from __future__ import annotations

from pathlib import Path

import pytest


def test_ecs_settings(monkeypatch):
    """WarrenSettings with WARREN_ECS_CLUSTER env var populates ecs_cluster field.

    Also verifies WARREN_ECS_CPU and WARREN_ECS_MEMORY populate ecs_cpu and ecs_memory.
    Plan 07-02 GREEN — ECS fields now present in WarrenSettings.
    """
    monkeypatch.setenv("WARREN_SECRET_KEY", "x" * 32)
    monkeypatch.setenv("WARREN_ECS_CLUSTER", "my-cluster")
    monkeypatch.setenv("WARREN_ECS_CPU", "512")
    monkeypatch.setenv("WARREN_ECS_MEMORY", "1024")

    from warren.config import WarrenSettings

    settings = WarrenSettings()
    assert settings.ecs_cluster == "my-cluster"
    assert settings.ecs_cpu == "512"
    assert settings.ecs_memory == "1024"


@pytest.mark.parametrize("prefix", ["", " ", "a/b", "-x", "x y", "x" * 33, "a.b"])
def test_ecs_resource_prefix_must_be_a_non_empty_family_prefix(monkeypatch, prefix):
    # It is the leading "<prefix>-" of every workspace task-definition family and the
    # first SSM path segment, so IAM can scope task-definition/<prefix>-*.
    from pydantic import ValidationError

    from warren.config import WarrenSettings

    monkeypatch.setenv("WARREN_SECRET_KEY", "x" * 32)
    monkeypatch.setenv("WARREN_ECS_RESOURCE_PREFIX", prefix)
    with pytest.raises(ValidationError):
        WarrenSettings()


def test_ecs_resource_prefix_accepts_family_safe_values(monkeypatch):
    from warren.config import WarrenSettings
    from warren.runtime.ecs import _slug

    monkeypatch.setenv("WARREN_SECRET_KEY", "x" * 32)
    monkeypatch.setenv("WARREN_ECS_RESOURCE_PREFIX", "acme_wr-1")
    settings = WarrenSettings()
    assert _slug("ghcr.io/org/img:1.2", settings.ecs_resource_prefix) == "acme_wr-1-org-img-1-2"


def test_allowed_docker_networks_defaults_empty(monkeypatch):
    """R24: unset means NO networks pass the allow-list -- fail closed, not
    'everything allowed', matching github_app_allowed_repos' posture."""
    monkeypatch.setenv("WARREN_SECRET_KEY", "x" * 32)

    from warren.config import WarrenSettings

    settings = WarrenSettings()
    assert settings.allowed_docker_networks == []


def test_allowed_docker_networks_comma_separated_from_env(monkeypatch):
    monkeypatch.setenv("WARREN_SECRET_KEY", "x" * 32)
    monkeypatch.setenv("WARREN_ALLOWED_DOCKER_NETWORKS", "net-a,net-b")

    from warren.config import WarrenSettings

    settings = WarrenSettings()
    assert settings.allowed_docker_networks == ["net-a", "net-b"]


def test_allowed_docker_networks_json_array_from_env(monkeypatch):
    monkeypatch.setenv("WARREN_SECRET_KEY", "x" * 32)
    monkeypatch.setenv("WARREN_ALLOWED_DOCKER_NETWORKS", '["net-a", "net-b"]')

    from warren.config import WarrenSettings

    settings = WarrenSettings()
    assert settings.allowed_docker_networks == ["net-a", "net-b"]


def test_allowed_images_defaults_empty(monkeypatch):
    """Z12: unset means no image outside what the server-wide file (or the
    model's own hardcoded default) already sanctions may be used by a
    user-scoped project -- fail closed, same posture as allowed_docker_networks."""
    monkeypatch.setenv("WARREN_SECRET_KEY", "x" * 32)

    from warren.config import WarrenSettings

    settings = WarrenSettings()
    assert settings.allowed_images == []


def test_allowed_images_comma_separated_from_env(monkeypatch):
    monkeypatch.setenv("WARREN_SECRET_KEY", "x" * 32)
    monkeypatch.setenv("WARREN_ALLOWED_IMAGES", "registry.example.com/a:latest,registry.example.com/b:latest")

    from warren.config import WarrenSettings

    settings = WarrenSettings()
    assert settings.allowed_images == [
        "registry.example.com/a:latest",
        "registry.example.com/b:latest",
    ]


def test_efs_local_mount_path_from_env(monkeypatch):
    """R13: WARREN_EFS_LOCAL_MOUNT_PATH must actually populate efs_local_mount_path --
    this is the env var the three IaC paths (terraform/main.tf's
    efs_delete_workspace_data_on_destroy, cdk/warren_stack.py's parameter of the same
    name, and setup.sh's root-access-point prompt) now wire up so efs_reaper.py's
    opt-in "actually delete workspace data" feature is reachable from a real
    deployment, instead of being dead code nothing ever set.
    """
    monkeypatch.setenv("WARREN_SECRET_KEY", "x" * 32)
    monkeypatch.setenv("WARREN_EFS_LOCAL_MOUNT_PATH", "/mnt/warren-efs-root")

    from warren.config import WarrenSettings

    settings = WarrenSettings()
    assert settings.efs_local_mount_path == "/mnt/warren-efs-root"


def test_efs_local_mount_path_defaults_empty(monkeypatch):
    """Default (unset) stays empty -- the reaper logs the data as orphaned rather than
    attempting to delete it, matching this feature's original/safe behavior."""
    monkeypatch.setenv("WARREN_SECRET_KEY", "x" * 32)

    from warren.config import WarrenSettings

    settings = WarrenSettings()
    assert settings.efs_local_mount_path == ""


def test_host_data_dir_defaults_to_none(monkeypatch):
    monkeypatch.setenv("WARREN_SECRET_KEY", "x" * 32)

    from warren.config import WarrenSettings

    assert WarrenSettings().host_data_dir is None


def test_host_data_dir_populated_from_env(monkeypatch):
    monkeypatch.setenv("WARREN_SECRET_KEY", "x" * 32)
    monkeypatch.setenv(
        "WARREN_HOST_DATA_DIR", "/mnt/storage/containers-storage/volumes/warren-data/_data"
    )

    from warren.config import WarrenSettings

    settings = WarrenSettings()
    assert settings.host_data_dir == Path(
        "/mnt/storage/containers-storage/volumes/warren-data/_data"
    )


def test_ecs_settings_defaults(monkeypatch):
    """WarrenSettings defaults give ecs_cpu='256' and ecs_memory='512'."""
    monkeypatch.setenv("WARREN_SECRET_KEY", "x" * 32)

    from warren.config import WarrenSettings

    settings = WarrenSettings()
    assert settings.ecs_cpu == "256"
    assert settings.ecs_memory == "512"


def test_ecs_assign_public_ip_default(monkeypatch):
    """WarrenSettings defaults ecs_assign_public_ip to False (Templates A/C behavior)."""
    monkeypatch.setenv("WARREN_SECRET_KEY", "x" * 32)

    from warren.config import WarrenSettings

    settings = WarrenSettings()
    assert settings.ecs_assign_public_ip is False


def test_ecs_assign_public_ip_enabled(monkeypatch):
    """WARREN_ECS_ASSIGN_PUBLIC_IP=true sets ecs_assign_public_ip to True (Template B)."""
    monkeypatch.setenv("WARREN_SECRET_KEY", "x" * 32)
    monkeypatch.setenv("WARREN_ECS_ASSIGN_PUBLIC_IP", "true")

    from warren.config import WarrenSettings

    settings = WarrenSettings()
    assert settings.ecs_assign_public_ip is True


def test_ecs_assign_public_ip_disabled_explicit(monkeypatch):
    """WARREN_ECS_ASSIGN_PUBLIC_IP=false explicitly sets ecs_assign_public_ip to False."""
    monkeypatch.setenv("WARREN_SECRET_KEY", "x" * 32)
    monkeypatch.setenv("WARREN_ECS_ASSIGN_PUBLIC_IP", "false")

    from warren.config import WarrenSettings

    settings = WarrenSettings()
    assert settings.ecs_assign_public_ip is False


def test_ecs_subnet_ids_from_env(monkeypatch):
    """WARREN_ECS_SUBNET_IDS as JSON array parses to a proper list[str].

    pydantic-settings v2 requires JSON-encoded values for list[str] fields.
    Plain comma-separated strings (e.g. 'subnet-aaa,subnet-bbb') are NOT split
    and would produce a one-element list — the setup.sh wizard now outputs JSON.
    """
    monkeypatch.setenv("WARREN_SECRET_KEY", "x" * 32)
    monkeypatch.setenv("WARREN_ECS_SUBNET_IDS", '["subnet-aaa","subnet-bbb"]')

    from warren.config import WarrenSettings

    s = WarrenSettings()
    assert s.ecs_subnet_ids == ["subnet-aaa", "subnet-bbb"]


def test_ecs_security_group_ids_from_env(monkeypatch):
    """WARREN_ECS_SECURITY_GROUP_IDS as JSON array parses to a proper list[str]."""
    monkeypatch.setenv("WARREN_SECRET_KEY", "x" * 32)
    monkeypatch.setenv("WARREN_ECS_SECURITY_GROUP_IDS", '["sg-xxx"]')

    from warren.config import WarrenSettings

    s = WarrenSettings()
    assert s.ecs_security_group_ids == ["sg-xxx"]


def test_ecs_subnet_ids_comma_separated_from_env(monkeypatch):
    """WARREN_ECS_SUBNET_IDS as a bare comma-separated string parses to a proper list[str].

    This is the format Terraform's outputs.tf actually emits (join(",", local.subnet_ids)),
    not the JSON-array format the earlier tests in this file assert.
    """
    monkeypatch.setenv("WARREN_SECRET_KEY", "x" * 32)
    monkeypatch.setenv("WARREN_ECS_SUBNET_IDS", "subnet-aaa,subnet-bbb")

    from warren.config import WarrenSettings

    s = WarrenSettings()
    assert s.ecs_subnet_ids == ["subnet-aaa", "subnet-bbb"]


def test_ecs_security_group_ids_comma_separated_from_env(monkeypatch):
    """WARREN_ECS_SECURITY_GROUP_IDS as a bare comma-separated string parses to a proper list[str]."""
    monkeypatch.setenv("WARREN_SECRET_KEY", "x" * 32)
    monkeypatch.setenv("WARREN_ECS_SECURITY_GROUP_IDS", "sg-aaa,sg-bbb")

    from warren.config import WarrenSettings

    s = WarrenSettings()
    assert s.ecs_security_group_ids == ["sg-aaa", "sg-bbb"]


def test_ecs_security_group_ids_single_value_from_env(monkeypatch):
    """WARREN_ECS_SECURITY_GROUP_IDS as a single bare value (no comma) parses to a one-element list.

    This is the exact shape outputs.tf's WARREN_ECS_SECURITY_GROUP_IDS emits, since it is
    local.security_group_id, a bare scalar.
    """
    monkeypatch.setenv("WARREN_SECRET_KEY", "x" * 32)
    monkeypatch.setenv("WARREN_ECS_SECURITY_GROUP_IDS", "sg-aaa")

    from warren.config import WarrenSettings

    s = WarrenSettings()
    assert s.ecs_security_group_ids == ["sg-aaa"]


def test_aws_trusted_assumed_role_patterns_json_array_with_comma_survives_intact(monkeypatch):
    """Issue #31: a single regex pattern containing a comma (e.g. inside a
    character class) must survive intact when supplied as a JSON array --
    the comma-split validator used by ecs_subnet_ids/ecs_security_group_ids
    would have mangled it into broken fragments.
    """
    monkeypatch.setenv("WARREN_SECRET_KEY", "x" * 32)
    pattern = "arn:aws:sts::123456789012:assumed-role/Admin_[a-z,A-Z]+/[^/]+"
    monkeypatch.setenv("WARREN_AWS_TRUSTED_ASSUMED_ROLE_PATTERNS", f'["{pattern}"]')

    from warren.config import WarrenSettings

    s = WarrenSettings()
    assert s.aws_trusted_assumed_role_patterns == [pattern]


def test_aws_trusted_assumed_role_patterns_rejects_comma_separated(monkeypatch):
    """A bare comma-separated string (the format its NoDecode siblings accept)
    must be rejected outright for this field, not silently split into
    corrupted fragments."""
    monkeypatch.setenv("WARREN_SECRET_KEY", "x" * 32)
    monkeypatch.setenv(
        "WARREN_AWS_TRUSTED_ASSUMED_ROLE_PATTERNS",
        "arn:aws:sts::123456789012:assumed-role/Admin_[a-z,A-Z]+/[^/]+",
    )

    from warren.config import WarrenSettings

    with pytest.raises(Exception):
        WarrenSettings()


def test_aws_trusted_assumed_role_patterns_defaults_to_empty(monkeypatch):
    monkeypatch.setenv("WARREN_SECRET_KEY", "x" * 32)

    from warren.config import WarrenSettings

    s = WarrenSettings()
    assert s.aws_trusted_assumed_role_patterns == []


def test_efs_settings_defaults(monkeypatch):
    """WarrenSettings EFS fields default: efs_id='', efs_retention_days=7, efs_reaper_interval_hours=6.

    Empty efs_id is the D-10 opt-out — ephemeral task storage only.
    """
    monkeypatch.setenv("WARREN_SECRET_KEY", "x" * 32)

    from warren.config import WarrenSettings

    s = WarrenSettings()
    assert s.efs_id == ""
    assert s.efs_retention_days == 7
    assert s.efs_reaper_interval_hours == 6


def test_efs_settings_from_env(monkeypatch):
    """WARREN_EFS_* env vars populate efs_id, efs_retention_days, efs_reaper_interval_hours."""
    monkeypatch.setenv("WARREN_SECRET_KEY", "x" * 32)
    monkeypatch.setenv("WARREN_EFS_ID", "fs-0123456789abcdef0")
    monkeypatch.setenv("WARREN_EFS_RETENTION_DAYS", "30")
    monkeypatch.setenv("WARREN_EFS_REAPER_INTERVAL_HOURS", "12")

    from warren.config import WarrenSettings

    s = WarrenSettings()
    assert s.efs_id == "fs-0123456789abcdef0"
    assert s.efs_retention_days == 30
    assert isinstance(s.efs_retention_days, int)
    assert s.efs_reaper_interval_hours == 12
    assert isinstance(s.efs_reaper_interval_hours, int)


def test_efs_access_point_tag_defaults_to_empty(monkeypatch):
    """Issue #7: both halves of the configurable extra EFS tag default to '' --
    purely additive, no extra tag written unless an external deployment opts in."""
    monkeypatch.setenv("WARREN_SECRET_KEY", "x" * 32)

    from warren.config import WarrenSettings

    s = WarrenSettings()
    assert s.efs_access_point_tag_key == ""
    assert s.efs_access_point_tag_value == ""


def test_efs_access_point_tag_from_env(monkeypatch):
    monkeypatch.setenv("WARREN_SECRET_KEY", "x" * 32)
    monkeypatch.setenv("WARREN_EFS_ACCESS_POINT_TAG_KEY", "workspace-provisioner-service")
    monkeypatch.setenv("WARREN_EFS_ACCESS_POINT_TAG_VALUE", "example-dev")

    from warren.config import WarrenSettings

    s = WarrenSettings()
    assert s.efs_access_point_tag_key == "workspace-provisioner-service"
    assert s.efs_access_point_tag_value == "example-dev"


def test_settings_construct_with_only_secret_key(monkeypatch):
    """WarrenSettings constructs successfully with only WARREN_SECRET_KEY set (D-05 cutover)."""
    monkeypatch.setenv("WARREN_SECRET_KEY", "x" * 32)

    from warren.config import WarrenSettings

    s = WarrenSettings()
    assert s.secret_key.get_secret_value() == "x" * 32


def test_auth_token_field_absent():
    """auth_token is no longer a field on WarrenSettings (D-05 clean cutover)."""
    from warren.config import WarrenSettings

    assert "auth_token" not in WarrenSettings.model_fields


def test_bootstrap_token_defaults_to_none(monkeypatch):
    """settings.bootstrap_token is None when WARREN_BOOTSTRAP_TOKEN is unset."""
    monkeypatch.setenv("WARREN_SECRET_KEY", "x" * 32)

    from warren.config import WarrenSettings

    s = WarrenSettings()
    assert s.bootstrap_token is None


def test_bootstrap_token_from_env(monkeypatch):
    """WARREN_BOOTSTRAP_TOKEN=... yields settings.bootstrap_token.get_secret_value() == that value."""
    monkeypatch.setenv("WARREN_SECRET_KEY", "x" * 32)
    monkeypatch.setenv("WARREN_BOOTSTRAP_TOKEN", "abc123" * 6)

    from warren.config import WarrenSettings

    s = WarrenSettings()
    assert s.bootstrap_token is not None
    assert s.bootstrap_token.get_secret_value() == "abc123" * 6


def test_bootstrap_token_masked_in_repr(monkeypatch):
    """repr(settings)/str(settings.bootstrap_token) never contains the raw secret value."""
    monkeypatch.setenv("WARREN_SECRET_KEY", "x" * 32)
    monkeypatch.setenv("WARREN_BOOTSTRAP_TOKEN", "super-secret-value-0123456789abc")

    from warren.config import WarrenSettings

    s = WarrenSettings()
    assert "super-secret-value-0123456789abc" not in repr(s)
    assert "super-secret-value-0123456789abc" not in str(s.bootstrap_token)


def test_secret_key_rejects_short_value(monkeypatch):
    """Audit #44: WARREN_SECRET_KEY shorter than 32 chars fails startup with a clear error."""
    monkeypatch.setenv("WARREN_SECRET_KEY", "too-short")

    from warren.config import WarrenSettings

    with pytest.raises(Exception, match="WARREN_SECRET_KEY must be at least 32 characters"):
        WarrenSettings()


def test_bootstrap_token_rejects_short_value(monkeypatch):
    """Audit #44: WARREN_BOOTSTRAP_TOKEN shorter than 32 chars fails startup with a clear error."""
    monkeypatch.setenv("WARREN_SECRET_KEY", "x" * 32)
    monkeypatch.setenv("WARREN_BOOTSTRAP_TOKEN", "too-short")

    from warren.config import WarrenSettings

    with pytest.raises(Exception, match="WARREN_BOOTSTRAP_TOKEN must be at least 32 characters"):
        WarrenSettings()


def test_ssh_port_range_defaults(monkeypatch):
    """WarrenSettings defaults ssh_port_range_start=30000, ssh_port_range_end=31000."""
    monkeypatch.setenv("WARREN_SECRET_KEY", "x" * 32)

    from warren.config import WarrenSettings

    s = WarrenSettings()
    assert s.ssh_port_range_start == 30000
    assert s.ssh_port_range_end == 31000


def test_ssh_port_range_from_env(monkeypatch):
    """WARREN_SSH_PORT_RANGE_START/END env vars populate the port-range fields."""
    monkeypatch.setenv("WARREN_SECRET_KEY", "x" * 32)
    monkeypatch.setenv("WARREN_SSH_PORT_RANGE_START", "40000")
    monkeypatch.setenv("WARREN_SSH_PORT_RANGE_END", "40100")

    from warren.config import WarrenSettings

    s = WarrenSettings()
    assert s.ssh_port_range_start == 40000
    assert s.ssh_port_range_end == 40100


def test_ssh_advertised_host_default_empty(monkeypatch):
    """WarrenSettings defaults ssh_advertised_host to empty string."""
    monkeypatch.setenv("WARREN_SECRET_KEY", "x" * 32)

    from warren.config import WarrenSettings

    s = WarrenSettings()
    assert s.ssh_advertised_host == ""


def test_ssh_advertised_host_from_env(monkeypatch):
    """WARREN_SSH_ADVERTISED_HOST env var populates ssh_advertised_host."""
    monkeypatch.setenv("WARREN_SECRET_KEY", "x" * 32)
    monkeypatch.setenv("WARREN_SSH_ADVERTISED_HOST", "node2.example.com")

    from warren.config import WarrenSettings

    s = WarrenSettings()
    assert s.ssh_advertised_host == "node2.example.com"


def test_phase4_settings_defaults(monkeypatch):
    """Phase 4 fields (idle reaper, egress bridge, GitHub App, image build) have documented defaults."""
    monkeypatch.setenv("WARREN_SECRET_KEY", "x" * 32)

    from warren.config import WarrenSettings

    s = WarrenSettings()
    assert s.idle_reaper_enabled is True
    assert s.idle_ttl_seconds == 3600.0
    assert s.idle_reaper_poll_interval == 60.0
    assert s.egress_bridge_name == "warren-egress"
    assert s.github_app_id == ""
    assert s.github_app_installation_id == ""
    assert s.github_app_private_key_path is None
    assert s.git_worktree_root == Path("/var/lib/warren/worktrees")
    assert s.image_build_enabled is False
    assert s.image_build_memory == "2g"
    assert s.image_build_cpus == 2.0


def test_phase4_settings_from_env(monkeypatch):
    """WARREN_* overrides reach every new Phase 4 field."""
    monkeypatch.setenv("WARREN_SECRET_KEY", "x" * 32)
    monkeypatch.setenv("WARREN_IDLE_TTL_SECONDS", "120")
    monkeypatch.setenv("WARREN_IDLE_REAPER_ENABLED", "false")
    monkeypatch.setenv("WARREN_IDLE_REAPER_POLL_INTERVAL", "5")
    monkeypatch.setenv("WARREN_EGRESS_BRIDGE_NAME", "custom-bridge")
    monkeypatch.setenv("WARREN_GITHUB_APP_ID", "12345")
    monkeypatch.setenv("WARREN_GITHUB_APP_INSTALLATION_ID", "67890")
    monkeypatch.setenv("WARREN_GITHUB_APP_PRIVATE_KEY_PATH", "/etc/warren/app.pem")
    monkeypatch.setenv("WARREN_GIT_WORKTREE_ROOT", "/tmp/worktrees")
    monkeypatch.setenv("WARREN_IMAGE_BUILD_ENABLED", "1")
    monkeypatch.setenv("WARREN_IMAGE_BUILD_MEMORY", "4g")
    monkeypatch.setenv("WARREN_IMAGE_BUILD_CPUS", "4")

    from warren.config import WarrenSettings

    s = WarrenSettings()
    assert s.idle_ttl_seconds == 120.0
    assert s.idle_reaper_enabled is False
    assert s.idle_reaper_poll_interval == 5.0
    assert s.egress_bridge_name == "custom-bridge"
    assert s.github_app_id == "12345"
    assert s.github_app_installation_id == "67890"
    assert s.github_app_private_key_path == Path("/etc/warren/app.pem")
    assert s.git_worktree_root == Path("/tmp/worktrees")
    assert s.image_build_enabled is True
    assert s.image_build_memory == "4g"
    assert s.image_build_cpus == 4.0


def test_ecs_task_user_defaults_empty_and_reads_env(monkeypatch):
    """AD3: ecs_task_user is opt-in; WARREN_ECS_TASK_USER populates it."""
    monkeypatch.setenv("WARREN_SECRET_KEY", "x" * 32)

    from warren.config import WarrenSettings

    assert WarrenSettings().ecs_task_user == ""
    monkeypatch.setenv("WARREN_ECS_TASK_USER", "1000:1000")
    assert WarrenSettings().ecs_task_user == "1000:1000"


def test_idle_destroy_seconds_off_by_default_and_settable(monkeypatch):
    monkeypatch.setenv("WARREN_SECRET_KEY", "x" * 32)
    monkeypatch.delenv("WARREN_IDLE_DESTROY_SECONDS", raising=False)

    from warren.config import WarrenSettings

    assert WarrenSettings().idle_destroy_seconds is None
    monkeypatch.setenv("WARREN_IDLE_DESTROY_SECONDS", "604800")
    assert WarrenSettings().idle_destroy_seconds == 604800.0
