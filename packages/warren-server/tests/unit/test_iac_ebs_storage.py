"""IaC guards for EBS workspace storage (runtime/ebs.py, runtime/ecs_kms_secrets.py):
Terraform and CDK grant the same, tag-scoped statements, the control plane can only wrap
secrets (GenerateDataKey) and the workspace task role only unwrap them (Decrypt), both
only under warren's encryption context, and the control plane gets the env it needs."""

from __future__ import annotations

import re
from pathlib import Path

_ECS = Path(__file__).parents[4] / "resources" / "ecs"
_TF = (_ECS / "terraform" / "main.tf").read_text()
_TF_VARS = (_ECS / "terraform" / "variables.tf").read_text()
_TF_OUT = (_ECS / "terraform" / "outputs.tf").read_text()
_CDK = (_ECS / "cdk" / "warren_stack.py").read_text()

CONTROL_PLANE_SIDS = {
    "EBSPassInfraRole",
    "EBSDescribe",
    "EBSSnapshotManagedVolume",
    "EBSCreateTaggedSnapshot",
    "EBSTagSnapshotOnCreate",
    "EBSDeleteManaged",
    "SecretsGenerateDataKey",
    "EBSVolumeKMS",
}
ENV = (
    "WARREN_ECS_WORKSPACE_STORAGE",
    "WARREN_ECS_EBS_INFRA_ROLE_ARN",
    "WARREN_ECS_SECRETS_KMS_KEY_ID",
    "WARREN_ECS_EBS_KMS_KEY_ID",
    "WARREN_ECS_EBS_SIZE_GIB",
)


def _block(text: str, header: str) -> str:
    start = text.index(header)
    depth = 0
    for i in range(text.index("{", start), len(text)):
        depth += {"{": 1, "}": -1}.get(text[i], 0)
        if depth == 0:
            return text[start : i + 1]
    raise AssertionError(header)


def _tf_statements(block: str) -> dict[str, str]:
    """sid -> statement text, for every statement in a policy document block."""
    out: dict[str, str] = {}
    for m in re.finditer(r'sid\s*=\s*"([A-Za-z]+)"', block):
        nxt = re.search(r'sid\s*=\s*"', block[m.end() :])
        out[m.group(1)] = block[m.start() : m.end() + (nxt.start() if nxt else len(block))]
    return out


def _cdk_statements(region: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for m in re.finditer(r'sid="([A-Za-z]+)"', region):
        nxt = re.search(r'sid="', region[m.end() :])
        out[m.group(1)] = region[m.start() : m.end() + (nxt.start() if nxt else len(region))]
    return out


def _tf_ebs() -> dict[str, str]:
    return _tf_statements(_block(_TF, 'data "aws_iam_policy_document" "ebs_task_role_policy"'))


def _cdk_ebs() -> dict[str, str]:
    i = _CDK.index('"WarrenEbsStoragePolicy"')
    return _cdk_statements(_CDK[i : _CDK.index("CfnOutputs — WARREN_ECS_*", i)])


def test_terraform_and_cdk_grant_the_same_control_plane_statements():
    assert set(_tf_ebs()) == CONTROL_PLANE_SIDS
    assert set(_cdk_ebs()) == CONTROL_PLANE_SIDS


def test_ec2_mutations_are_scoped_by_the_warren_tag():
    for stmts in (_tf_ebs(), _cdk_ebs()):
        for sid in ("EBSSnapshotManagedVolume", "EBSDeleteManaged"):
            assert "aws:ResourceTag/warren" in stmts[sid], sid
        assert "aws:RequestTag/warren" in stmts["EBSCreateTaggedSnapshot"]
        assert "ec2:CreateAction" in stmts["EBSTagSnapshotOnCreate"]
        assert "CreateSnapshot" in stmts["EBSTagSnapshotOnCreate"]
        assert "iam:PassedToService" in stmts["EBSPassInfraRole"]
        assert "ecs.amazonaws.com" in stmts["EBSPassInfraRole"]
        assert '"ec2:CreateTags"' in stmts["EBSTagSnapshotOnCreate"]
        assert "snapshot/*" in stmts["EBSTagSnapshotOnCreate"]
        assert "volume/*" not in stmts["EBSTagSnapshotOnCreate"]


def test_control_plane_only_wraps_secrets_under_warrens_context():
    for stmts in (_tf_ebs(), _cdk_ebs()):
        gdk = stmts["SecretsGenerateDataKey"]
        assert '"kms:GenerateDataKey"' in gdk and '"kms:Decrypt"' not in gdk
        decrypts = [sid for sid, text in stmts.items() if '"kms:Decrypt"' in text]
        # Only for a customer-managed volume key, and only through EC2.
        assert decrypts == ["EBSVolumeKMS"]
        assert "kms:ViaService" in stmts["EBSVolumeKMS"]
    assert "secrets_context_conditions" in _cdk_ebs()["SecretsGenerateDataKey"]
    assert "kms:EncryptionContext:warren:workspace_id" in _block(
        _TF, 'data "aws_iam_policy_document" "ebs_task_role_policy"'
    )


def test_workspace_task_role_only_unwraps_under_warrens_context():
    tf_ws = _tf_statements(_block(_TF, 'data "aws_iam_policy_document" "workspace_task_role_policy"'))
    stmt = tf_ws["WorkspaceSecretsDecrypt"]
    assert '"kms:Decrypt"' in stmt and "GenerateDataKey" not in stmt
    assert 'variable = "kms:EncryptionContext:warren:workspace_id"' in stmt
    assert '"kms:EncryptionContextKeys"' in stmt and '"warren:container"' in stmt
    i = _CDK.index('"WarrenWorkspaceTaskPolicy",')
    cdk_ws = _cdk_statements(_CDK[i : _CDK.index("task_role = iam.Role(", i)])
    assert "conditions=secrets_context_conditions" in cdk_ws["WorkspaceSecretsDecrypt"]
    ctx = _CDK[_CDK.index("secrets_context_conditions = {") :]
    ctx = ctx[: ctx.index("}\n\n") + 1]
    assert '"Null": {"kms:EncryptionContext:warren:workspace_id": "false"}' in ctx
    assert '"kms:EncryptionContextKeys": ["warren:workspace_id", "warren:container"]' in ctx


def test_infra_role_uses_the_ecs_volumes_managed_policy():
    assert "service-role/AmazonECSInfrastructureRolePolicyForVolumes" in _TF
    assert '"service-role/AmazonECSInfrastructureRolePolicyForVolumes"' in _CDK
    trust = _block(_TF, 'data "aws_iam_policy_document" "ecs_infra_trust"')
    assert '"ecs.amazonaws.com"' in trust
    assert 'iam.ServicePrincipal("ecs.amazonaws.com")' in _CDK
    # A customer-managed volume key's grant is only for AWS resources, via EC2.
    grant = _tf_statements(_block(_TF, 'data "aws_iam_policy_document" "ecs_infra_kms"'))["EBSVolumeKMSGrant"]
    assert "kms:GrantIsForAWSResource" in grant and "kms:ViaService" in grant


def test_ebs_is_opt_in_and_the_secrets_key_rotates():
    assert "ebs_enabled = var.enable_ebs_storage || var.workspace_storage == \"ebs\"" in _TF
    assert "ebs_enabled = enable_ebs_storage or workspace_storage == \"ebs\"" in _CDK
    for header in ('resource "aws_iam_role" "ecs_infra"', 'resource "aws_iam_role_policy" "ebs_task_policy"'):
        assert "count" in _block(_TF, header) and "local.ebs_enabled" in _block(_TF, header)
    key = _block(_TF, 'resource "aws_kms_key" "warren_secrets"')
    assert "enable_key_rotation = true" in key
    assert "enable_key_rotation=True" in _CDK
    storage = _block(_TF_VARS, 'variable "workspace_storage"')
    assert 'default     = "efs"' in storage
    assert 'contains(["efs", "ebs"], var.workspace_storage)' in storage


def test_control_plane_gets_the_ebs_env_and_outputs():
    task_def = _block(_TF, 'resource "aws_ecs_task_definition" "warren_server"')
    for name in ENV:
        assert f'name = "{name}"' in task_def, name
        assert f'name="{name}"' in _CDK, name
    assert "warren_ecs_ebs_infra_role_arn" in _TF_OUT and "warren_ecs_secrets_kms_key_arn" in _TF_OUT
    assert '"WarrenEcsEbsInfraRoleArn"' in _CDK and '"WarrenEcsSecretsKmsKeyArn"' in _CDK
