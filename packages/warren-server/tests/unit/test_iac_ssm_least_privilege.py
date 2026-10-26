"""Guards: workspace secrets touch no SSM/KMS in any IaC (they are delivered through the
EFS root mount); the server image ships a pinned, checksum-verified session-manager-plugin."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

_REPO = Path(__file__).parents[4]
_ECS = _REPO / "resources" / "ecs"
_SRC = _REPO / "packages" / "warren-server" / "src" / "warren"


@pytest.mark.parametrize("path", ["terraform/main.tf", "cdk/warren_stack.py", "setup.sh"])
def test_no_iac_grants_get_parameters_by_path(path):
    assert '"ssm:GetParametersByPath"' not in (_ECS / path).read_text()


def test_secret_paths_never_call_an_ssm_read_api():
    # (The opt-in GitHub App key source in token_issuer.py reads one named parameter.)
    for py in [_SRC / "runtime" / "ecs.py", *(_SRC / "secrets").rglob("*.py"), _SRC / "routes" / "secrets.py"]:
        text = py.read_text()
        for call in ("get_parameters_by_path", "get_parameters(", "get_parameter(", "describe_parameters"):
            assert call not in text, f"{py}: {call}"


def _block(text: str, header: str) -> str:
    start = text.index(header)
    depth = 0
    for i in range(text.index("{", start), len(text)):
        depth += {"{": 1, "}": -1}.get(text[i], 0)
        if depth == 0:
            return text[start : i + 1]
    raise AssertionError(header)


def test_terraform_grants_no_ssm_for_workspace_secrets():
    tf = (_ECS / "terraform" / "main.tf").read_text()
    task_policy = _block(tf, 'data "aws_iam_policy_document" "task_role_policy"')
    assert '"ssm:' not in task_policy
    # The only Decrypt left on the control-plane role is ECS Exec session/log encryption.
    decrypts = [m.start() for m in re.finditer(r'"kms:Decrypt"', task_policy)]
    assert len(decrypts) == 1
    assert 'sid       = "ECSExecLogKMS"' in task_policy[max(0, decrypts[0] - 200) : decrypts[0]]
    exec_policy = _block(tf, 'data "aws_iam_policy_document" "exec_log_policy"')
    assert re.findall(r'"ssm:[A-Za-z]+"', exec_policy) == ['"ssm:GetParameters"']
    assert "resources = [aws_ssm_parameter.warren_secret_key.arn]" in exec_policy
    for gone in ("WARREN_KMS_KEY_ID", "ssm_kms_key_arn", "create_ssm_kms_key", '"ssm:PutParameter"'):
        assert gone not in tf
        assert gone not in (_ECS / "terraform" / "variables.tf").read_text()


def test_terraform_always_mounts_the_efs_root_for_secret_delivery():
    tf = (_ECS / "terraform" / "main.tf").read_text()
    root_ap = _block(tf, 'resource "aws_efs_access_point" "warren_root"')
    assert "count = var.create_efs ? 1 : 0" in root_ap
    assert '{ name = "WARREN_EFS_LOCAL_MOUNT_PATH", value = var.create_efs ? "/mnt/warren-efs-root" : "" }' in tf
    assert "WARREN_EFS_PURGE_WORKSPACE_DATA" in tf
    assert "efs_delete_workspace_data_on_destroy ? [" not in tf


def test_cdk_grants_no_ssm_for_workspace_secrets():
    cdk = (_ECS / "cdk" / "warren_stack.py").read_text()
    for gone in ('"ssm:GetParameters"', '"ssm:PutParameter"', "WARREN_KMS_KEY_ID", "ssm_kms_key_arn"):
        assert gone not in cdk
    assert '"kms:Decrypt",\n' not in cdk[cdk.index('"WarrenTaskPolicy"') :]
    assert "root_ap = efs_fs.add_access_point(" in cdk
    assert 'value="/mnt/warren-efs-root" if root_ap is not None else ""' in cdk


def test_setup_sh_grants_no_ssm_writes():
    sh = (_ECS / "setup.sh").read_text()
    assert '"ssm:PutParameter"' not in sh and '"ssm:DeleteParameter"' not in sh
    assert 'Enable actual EFS data deletion' not in sh  # the root access point is always created


def test_server_image_pins_and_verifies_session_manager_plugin():
    dockerfile = (_REPO / "packages" / "warren-server" / "Dockerfile").read_text()
    assert re.search(r"ARG SESSION_MANAGER_PLUGIN_VERSION=\d+\.\d+\.\d+\.\d+\n", dockerfile)
    for arch in ("AMD64", "ARM64"):
        assert re.search(rf"ARG SESSION_MANAGER_PLUGIN_SHA256_{arch}=[0-9a-f]{{64}}\n", dockerfile)
    assert "https://s3.amazonaws.com/session-manager-downloads/plugin/${SESSION_MANAGER_PLUGIN_VERSION}/${dir}/" in dockerfile
    assert 'sha256sum -c -' in dockerfile
    assert "session-manager-plugin --version" in dockerfile
    publish = (_REPO / ".github" / "workflows" / "warren-server-image.yml").read_text()
    assert "--entrypoint session-manager-plugin" in publish
