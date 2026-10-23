"""IaC guards: EFS encrypted at rest (audit #15) and a stop-before-start control-plane
deployment so only one SQLite writer ever runs (audit #10)."""

from __future__ import annotations

import re
from pathlib import Path

_ECS = Path(__file__).parents[4] / "resources" / "ecs"


def _block(text: str, header: str) -> str:
    start = text.index(header)
    depth = 0
    for i in range(text.index("{", start), len(text)):
        depth += {"{": 1, "}": -1}.get(text[i], 0)
        if depth == 0:
            return text[start : i + 1]
    raise AssertionError(header)


def test_terraform_efs_is_encrypted_with_optional_cmk():
    tf = (_ECS / "terraform" / "main.tf").read_text()
    efs = _block(tf, 'resource "aws_efs_file_system" "warren"')
    assert re.search(r"\bencrypted\s+= true", efs)
    assert re.search(r'kms_key_id\s+= var\.efs_kms_key_arn != "" \? var\.efs_kms_key_arn : null', efs)
    assert 'variable "efs_kms_key_arn"' in (_ECS / "terraform" / "variables.tf").read_text()


def test_terraform_control_plane_deploys_stop_before_start():
    tf = (_ECS / "terraform" / "main.tf").read_text()
    svc = _block(tf, 'resource "aws_ecs_service" "warren_server"')
    assert re.search(r"deployment_minimum_healthy_percent\s+= 0\b", svc)
    assert re.search(r"deployment_maximum_percent\s+= 100\b", svc)
    assert re.search(r"desired_count\s+= 1\b", svc)


def test_cdk_efs_is_encrypted_and_service_deploys_stop_before_start():
    cdk = (_ECS / "cdk" / "warren_stack.py").read_text()
    fs = cdk[cdk.index('"WarrenEFSFileSystem"') : cdk.index("control_plane_ap =")]
    assert "encrypted=True" in fs
    assert "kms.Key.from_key_arn(self, \"WarrenEfsKmsKey\", efs_kms_key_arn)" in fs
    svc = cdk[cdk.index('"WarrenServerService"') : cdk.index("network_configuration=", cdk.index('"WarrenServerService"'))]
    assert "minimum_healthy_percent=0," in svc
    assert "maximum_percent=100," in svc
    assert "efs_kms_key_arn=efs_kms_key_arn" in (_ECS / "cdk" / "app.py").read_text()


def test_setup_sh_creates_encrypted_efs():
    sh = (_ECS / "setup.sh").read_text()
    create = sh[sh.index("aws efs create-file-system") : sh.index("--output text)", sh.index("aws efs create-file-system"))]
    assert '"${EFS_ENCRYPTION_ARGS[@]}"' in create
    assert "EFS_ENCRYPTION_ARGS=(--encrypted)" in sh
    assert 'EFS_ENCRYPTION_ARGS+=(--kms-key-id "$WARREN_EFS_KMS_KEY_ID")' in sh
    assert "minimumHealthyPercent=0,maximumPercent=100" in sh
