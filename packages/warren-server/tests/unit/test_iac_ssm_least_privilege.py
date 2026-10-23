"""Guards: the control plane holds no SSM read action and, for secrets, only
kms:Encrypt; the server image ships a pinned, checksum-verified session-manager-plugin."""

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


def test_terraform_control_plane_kms_is_encrypt_only_for_ssm():
    tf = (_ECS / "terraform" / "main.tf").read_text()
    policy = _block(tf, 'data "aws_iam_policy_document" "task_role_policy"')
    enc = policy[policy.index('sid       = "SSMSecretsKMSEncrypt"') :]
    enc = enc[: enc.index("\n    }\n")]
    assert 'actions   = ["kms:Encrypt"]' in enc
    assert "kms:EncryptionContext:PARAMETER_ARN" in enc and "kms:ViaService" in enc
    # The only Decrypt left on this role is ECS Exec session/log encryption.
    decrypts = [m.start() for m in re.finditer(r'"kms:Decrypt"', policy)]
    assert len(decrypts) == 1
    assert 'sid       = "ECSExecLogKMS"' in policy[max(0, decrypts[0] - 200) : decrypts[0]]
    assert '"ssm:Get' not in policy
    assert 'resources = [local.ssm_secret_parameter_arns]' in _block(policy, "statement {\n    sid    = \"SSMSecretsWrite\"")


def test_terraform_wires_the_ssm_key_into_the_server_and_exec_role():
    tf = (_ECS / "terraform" / "main.tf").read_text()
    assert '{ name = "WARREN_KMS_KEY_ID", value = local.ssm_kms_key_arn }' in tf
    exec_policy = _block(tf, 'data "aws_iam_policy_document" "exec_log_policy"')
    assert "resources = local.exec_decrypt_keys" in exec_policy
    variables = (_ECS / "terraform" / "variables.tf").read_text()
    assert 'variable "create_ssm_kms_key"' in variables and 'variable "ssm_kms_key_arn"' in variables


def test_cdk_control_plane_kms_is_encrypt_only_for_ssm():
    cdk = (_ECS / "cdk" / "warren_stack.py").read_text()
    enc = cdk[cdk.index('sid="SSMSecretsKMSEncrypt"') :]
    enc = enc[: enc.index("),")]
    assert 'actions=["kms:Encrypt"]' in enc
    assert '"kms:Decrypt",\n' not in cdk[cdk.index('"WarrenTaskPolicy"') :]
    assert 'name="WARREN_KMS_KEY_ID", value=ssm_kms_key_arn' in cdk


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
