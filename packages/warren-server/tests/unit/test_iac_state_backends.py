"""IaC guards for the optional AWS state backends (warren/state/): Terraform and CDK
create the same table (pk/sk, gsi1, TTL, PITR, SSE), grant the same opt-in statements,
scope Secrets Manager to the prefix and the warren tag, and wire the same env."""

from __future__ import annotations

import re
from pathlib import Path

from warren.state.dynamodb import GSI1, create_table_kwargs

_ECS = Path(__file__).parents[4] / "resources" / "ecs"
_TF = (_ECS / "terraform" / "main.tf").read_text()
_TF_VARS = (_ECS / "terraform" / "variables.tf").read_text()
_CDK = (_ECS / "cdk" / "warren_stack.py").read_text()
_CDK_APP = (_ECS / "cdk" / "app.py").read_text()
_README = (_ECS / "README.md").read_text()

SIDS = {"StateTable", "StateTableKMS", "SecretsCreateTagged", "SecretsManageTagged", "SecretsList", "SecretsKMS"}
ENV = (
    "WARREN_STATE_BACKEND", "WARREN_DYNAMODB_TABLE", "WARREN_SECRETS_BACKEND",
    "WARREN_SECRETSMANAGER_PREFIX", "WARREN_SECRETSMANAGER_KMS_KEY_ID",
)
FLAGS = (
    "enable_dynamodb_state", "dynamodb_table_name", "dynamodb_kms_key_arn",
    "enable_secretsmanager_secrets", "secretsmanager_prefix", "secretsmanager_kms_key_arn",
)


def _tf_block(header: str) -> str:
    start = _TF.index(header)
    depth = 0
    for i in range(_TF.index("{", start), len(_TF)):
        depth += {"{": 1, "}": -1}.get(_TF[i], 0)
        if depth == 0:
            return _TF[start : i + 1]
    raise AssertionError(header)


def test_both_stacks_grant_the_same_statements():
    tf = set(re.findall(r'sid\s*=\s*"([A-Za-z]+)"', _tf_block('data "aws_iam_policy_document" "state_backend_policy"')))
    start = _CDK.index("Optional AWS state backends (warren-server")
    cdk_region = _CDK[start : _CDK.index("Control-plane task definition — warren-server", start)]
    cdk = set(re.findall(r'sid="([A-Za-z]+)"', cdk_region))
    assert tf == cdk == SIDS


def test_opt_in_flags_default_off():
    for flag in FLAGS:
        assert f'variable "{flag}"' in _TF_VARS
        assert f"{flag}:" in _CDK and flag in _CDK_APP
    for flag in ("enable_dynamodb_state", "enable_secretsmanager_secrets"):
        block = _TF_VARS[_TF_VARS.index(f'variable "{flag}"') :]
        assert re.search(r"default\s*=\s*false", block[: block.index("}")])
        assert f"{flag}: bool = False" in _CDK


def test_table_matches_what_the_server_expects():
    table = _tf_block('resource "aws_dynamodb_table" "warren_state"')
    expected = create_table_kwargs("t")
    assert 'hash_key                    = "pk"' in table and 'range_key                   = "sk"' in table
    assert f'name            = "{GSI1}"' in table and 'projection_type = "ALL"' in table
    assert {a["AttributeName"] for a in expected["AttributeDefinitions"]} == set(
        re.findall(r'name = "(\w+)"\s*\n\s*type = "S"', table)
    )
    assert re.search(r'ttl \{\s*attribute_name = "ttl"\s*enabled\s*= true', table)
    assert re.search(r"point_in_time_recovery \{\s*enabled = true", table)
    assert re.search(r"server_side_encryption \{\s*enabled\s*= true", table)
    for needle in ('time_to_live_attribute="ttl"', "point_in_time_recovery_enabled=True", f'index_name="{GSI1}"',
                   "TableEncryption.AWS_MANAGED", "TableEncryption.CUSTOMER_MANAGED"):
        assert needle in _CDK


def test_secrets_manager_scoped_to_prefix_and_tag():
    policy = _tf_block('data "aws_iam_policy_document" "state_backend_policy"')
    assert "local.secretsmanager_arns" in policy
    assert ":secret:${local.secretsmanager_prefix}/*" in _TF
    assert "aws:RequestTag/warren" in policy and "secretsmanager:ResourceTag/warren" in policy
    assert ":secret:{sm_prefix}/*" in _CDK
    assert '"aws:RequestTag/warren": "true"' in _CDK and '"secretsmanager:ResourceTag/warren": "true"' in _CDK
    # The only unscoped Secrets Manager action is ListSecrets.
    for block in re.split(r"dynamic \"statement\"", policy)[1:]:
        if "secretsmanager:" in block and 'resources = ["*"]' in block:
            assert re.findall(r'"(secretsmanager:\w+)"', block) == ["secretsmanager:ListSecrets"]
    for via in ("dynamodb.", "secretsmanager."):
        assert f'"{via}${{var.aws_region}}.amazonaws.com"' in policy
        assert f'f"{via}{{self.region}}.amazonaws.com"' in _CDK


def test_control_plane_gets_the_env():
    for name in ENV:
        assert f'name = "{name}"' in _TF
        assert f'"{name}"' in _CDK
    assert "WARREN_STATE_BACKEND" in _README and "WARREN_SECRETSMANAGER_PREFIX" in _README
