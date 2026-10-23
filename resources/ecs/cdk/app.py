#!/usr/bin/env python3
"""CDK app entry point for WarrenECSStack.

Usage:
    cdk synth
    cdk deploy

Context variables (pass via --context or cdk.json):
    create_vpc              bool (default: true)  Create a new VPC for warren
    create_efs              bool (default: true)  Create the EFS file system and wire it into
                                                   the control-plane task so ECSRuntime mounts
                                                   it into every workspace task it provisions
    vpc_id                  str  (default: "")    Existing VPC ID (when create_vpc=false)
    subnet_ids              str  (default: "")    Comma-separated subnet IDs (when create_vpc=false)
    sg_id                   str  (default: "")    Existing security group ID (when create_vpc=false)
    image_uri               str  (default: "")    Full container image URI
    control_plane_image_uri str  (default: "")    Image URI for warren-server's own control-plane
                                                   task; falls back to image_uri when empty
    env_suffix              str  (default: prod)  Resource name suffix (e.g. prod, staging, dev)
    ecs_resource_prefix     str  (default: warren) Resource-name prefix the control-plane task
                                                   runs with (WARREN_ECS_RESOURCE_PREFIX)
    kms_key_id              str  (default: "")    KMS key ID/ARN for SSM SecureString encryption
                                                   (WARREN_KMS_KEY_ID); empty uses the AWS-managed key
    efs_kms_key_arn         str  (default: "")    KMS key ARN for EFS encryption at rest (always
                                                   on); empty uses aws/elasticfilesystem
    assign_public_ip        bool (default: false) Assign a public IP to the control-plane service.
                                                   Only meaningful when create_vpc=false; ignored
                                                   (always disabled) when create_vpc=true
    efs_delete_workspace_data_on_destroy
                             bool (default: false) Mount the EFS filesystem root into the
                                                   control-plane task and set
                                                   WARREN_EFS_LOCAL_MOUNT_PATH so the
                                                   access-point-TTL reaper actually deletes a
                                                   workspace's data, not just its access point
                                                   (R13). Only meaningful when create_efs=true.
    exec_owner_principal_tag
                             str  (default: warren-owner) Principal tag carrying a human's
                                                   warren owner_id; ECS Exec is scoped to tasks
                                                   whose <prefix>.owner_id tag matches it (AI1)
    break_glass_principal_arns
                             str  (default: "")    Comma-separated principals allowed to assume
                                                   the break-glass role; empty trusts the account root
    break_glass_require_mfa  bool (default: true)  Require MFA to assume the break-glass role
"""
import aws_cdk as cdk
from warren_stack import WarrenECSStack

app = cdk.App()

# Read configuration from CDK context with sensible defaults.
# Pass overrides via: cdk deploy --context create_vpc=false --context vpc_id=vpc-xxx
create_vpc_raw = app.node.try_get_context("create_vpc")
if create_vpc_raw is None:
    create_vpc = True
elif isinstance(create_vpc_raw, bool):
    create_vpc = create_vpc_raw
else:
    create_vpc = str(create_vpc_raw).lower() not in ("false", "0", "no")

create_efs_raw = app.node.try_get_context("create_efs")
if create_efs_raw is None:
    create_efs = True
elif isinstance(create_efs_raw, bool):
    create_efs = create_efs_raw
else:
    create_efs = str(create_efs_raw).lower() not in ("false", "0", "no", "")

vpc_id = app.node.try_get_context("vpc_id") or ""
subnet_ids_raw = app.node.try_get_context("subnet_ids") or ""
subnet_ids = [s.strip() for s in subnet_ids_raw.split(",") if s.strip()] if subnet_ids_raw else []
security_group_id = app.node.try_get_context("sg_id") or ""
image_uri = app.node.try_get_context("image_uri") or ""
control_plane_image_uri = app.node.try_get_context("control_plane_image_uri") or ""
env_suffix = app.node.try_get_context("env_suffix") or "prod"
ecs_resource_prefix = app.node.try_get_context("ecs_resource_prefix") or "warren"
kms_key_id = app.node.try_get_context("kms_key_id") or ""
efs_kms_key_arn = app.node.try_get_context("efs_kms_key_arn") or ""

assign_public_ip_raw = app.node.try_get_context("assign_public_ip")
if assign_public_ip_raw is None:
    assign_public_ip = False
elif isinstance(assign_public_ip_raw, bool):
    assign_public_ip = assign_public_ip_raw
else:
    assign_public_ip = str(assign_public_ip_raw).lower() in ("true", "1", "yes")

efs_delete_raw = app.node.try_get_context("efs_delete_workspace_data_on_destroy")
if efs_delete_raw is None:
    efs_delete_workspace_data_on_destroy = False
elif isinstance(efs_delete_raw, bool):
    efs_delete_workspace_data_on_destroy = efs_delete_raw
else:
    efs_delete_workspace_data_on_destroy = str(efs_delete_raw).lower() in ("true", "1", "yes")

exec_owner_principal_tag = app.node.try_get_context("exec_owner_principal_tag") or "warren-owner"
break_glass_raw = app.node.try_get_context("break_glass_principal_arns") or ""
break_glass_principal_arns = [a.strip() for a in break_glass_raw.split(",") if a.strip()]
break_glass_mfa_raw = app.node.try_get_context("break_glass_require_mfa")
if break_glass_mfa_raw is None or isinstance(break_glass_mfa_raw, bool):
    break_glass_require_mfa = break_glass_mfa_raw is not False
else:
    break_glass_require_mfa = str(break_glass_mfa_raw).lower() not in ("false", "0", "no")

WarrenECSStack(
    app,
    "WarrenECSStack",
    create_vpc=create_vpc,
    create_efs=create_efs,
    efs_delete_workspace_data_on_destroy=efs_delete_workspace_data_on_destroy,
    vpc_id=vpc_id,
    subnet_ids=subnet_ids,
    security_group_id=security_group_id,
    image_uri=image_uri,
    control_plane_image_uri=control_plane_image_uri,
    env_suffix=env_suffix,
    ecs_resource_prefix=ecs_resource_prefix,
    kms_key_id=kms_key_id,
    efs_kms_key_arn=efs_kms_key_arn,
    assign_public_ip=assign_public_ip,
    exec_owner_principal_tag=exec_owner_principal_tag,
    break_glass_principal_arns=break_glass_principal_arns,
    break_glass_require_mfa=break_glass_require_mfa,
)

app.synth()
