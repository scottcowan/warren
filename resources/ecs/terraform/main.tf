# ---------------------------------------------------------------------------
# Data sources
# ---------------------------------------------------------------------------

data "aws_availability_zones" "available" {
  state = "available"
}

data "aws_caller_identity" "current" {}

# ---------------------------------------------------------------------------
# Locals — conditional ID resolution (Pitfall 5: avoids count=0 index errors)
# ---------------------------------------------------------------------------

locals {
  vpc_id              = var.create_vpc ? aws_vpc.warren[0].id : var.vpc_id
  subnet_ids          = var.create_vpc ? [aws_subnet.a[0].id, aws_subnet.b[0].id] : var.subnet_ids
  security_group_id   = var.create_vpc ? aws_security_group.warren[0].id : var.security_group_id
  efs_arn             = var.create_efs ? aws_efs_file_system.warren[0].arn : ""
  efs_id              = var.create_efs ? aws_efs_file_system.warren[0].id : ""
  control_plane_image = var.control_plane_image_uri != "" ? var.control_plane_image_uri : var.image_uri
}

# ---------------------------------------------------------------------------
# VPC resources — Template A: private subnets + NAT Gateway (default)
# All gated on create_vpc; operators pass existing IDs when create_vpc = false
# ---------------------------------------------------------------------------

resource "aws_vpc" "warren" {
  count = var.create_vpc ? 1 : 0

  cidr_block           = "10.42.0.0/16"
  enable_dns_hostnames = true

  tags = {
    Name   = "warren-vpc-${var.env_suffix}"
    warren = "true"
  }
}

resource "aws_internet_gateway" "warren" {
  count = var.create_vpc ? 1 : 0

  vpc_id = aws_vpc.warren[0].id

  tags = {
    Name = "warren-igw-${var.env_suffix}"
  }
}

resource "aws_eip" "nat" {
  count = var.create_vpc ? 1 : 0

  domain = "vpc"
}

resource "aws_subnet" "public" {
  count = var.create_vpc ? 1 : 0

  vpc_id                  = aws_vpc.warren[0].id
  cidr_block              = "10.42.2.0/24"
  availability_zone       = data.aws_availability_zones.available.names[0]
  map_public_ip_on_launch = true

  tags = {
    Name = "warren-subnet-public-${var.env_suffix}"
  }
}

resource "aws_nat_gateway" "warren" {
  count = var.create_vpc ? 1 : 0

  allocation_id = aws_eip.nat[0].id
  subnet_id     = aws_subnet.public[0].id

  tags = {
    Name = "warren-nat-${var.env_suffix}"
  }

  depends_on = [aws_internet_gateway.warren]
}

resource "aws_subnet" "a" {
  count = var.create_vpc ? 1 : 0

  vpc_id                  = aws_vpc.warren[0].id
  cidr_block              = "10.42.0.0/24"
  availability_zone       = data.aws_availability_zones.available.names[0]
  map_public_ip_on_launch = false

  tags = {
    Name = "warren-subnet-a-${var.env_suffix}"
  }
}

resource "aws_subnet" "b" {
  count = var.create_vpc ? 1 : 0

  vpc_id                  = aws_vpc.warren[0].id
  cidr_block              = "10.42.1.0/24"
  availability_zone       = data.aws_availability_zones.available.names[1]
  map_public_ip_on_launch = false

  tags = {
    Name = "warren-subnet-b-${var.env_suffix}"
  }
}

resource "aws_route_table" "public" {
  count = var.create_vpc ? 1 : 0

  vpc_id = aws_vpc.warren[0].id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.warren[0].id
  }

  tags = {
    Name = "warren-rt-public-${var.env_suffix}"
  }
}

resource "aws_route_table_association" "public" {
  count = var.create_vpc ? 1 : 0

  subnet_id      = aws_subnet.public[0].id
  route_table_id = aws_route_table.public[0].id
}

resource "aws_route_table" "private" {
  count = var.create_vpc ? 1 : 0

  vpc_id = aws_vpc.warren[0].id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.warren[0].id
  }

  tags = {
    Name = "warren-rt-private-${var.env_suffix}"
  }
}

resource "aws_route_table_association" "a" {
  count = var.create_vpc ? 1 : 0

  subnet_id      = aws_subnet.a[0].id
  route_table_id = aws_route_table.private[0].id
}

resource "aws_route_table_association" "b" {
  count = var.create_vpc ? 1 : 0

  subnet_id      = aws_subnet.b[0].id
  route_table_id = aws_route_table.private[0].id
}

resource "aws_security_group" "warren" {
  count = var.create_vpc ? 1 : 0

  name   = "warren-sg-${var.env_suffix}"
  vpc_id = aws_vpc.warren[0].id

  # No ingress — tasks are outbound-only; inbound traffic is not needed for the warren dispatcher
  egress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTPS egress for ECR image pulls, SSM, CloudWatch Logs"
  }

  tags = {
    Name = "warren-sg-${var.env_suffix}"
  }
}

# ---------------------------------------------------------------------------
# EFS — workspace persistence (D-07, D-06)
# ---------------------------------------------------------------------------

# NOTE: flipping create_efs from true to false on an already-applied deployment is blocked by
# prevent_destroy below. To remove an existing EFS deployment, first run
# `terraform state rm 'aws_efs_file_system.warren[0]'` (and manually delete the EFS resource out
# of band if truly no longer needed), then re-apply with create_efs = false.
resource "aws_efs_file_system" "warren" {
  count = var.create_efs ? 1 : 0

  creation_token = "warren-efs-${var.env_suffix}"

  # Audit #15: encryption at rest is explicit. Both attributes force replacement, so
  # an existing unencrypted filesystem is blocked by prevent_destroy below and needs
  # the migration described in resources/ecs/README.md.
  encrypted  = true
  kms_key_id = var.efs_kms_key_arn != "" ? var.efs_kms_key_arn : null

  tags = {
    Name       = "warren-efs-${var.env_suffix}"
    warren     = "true"
    warren-env = var.env_suffix
  }

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_security_group" "warren_efs" {
  count = var.create_vpc && var.create_efs ? 1 : 0

  name   = "warren-efs-sg-${var.env_suffix}"
  vpc_id = aws_vpc.warren[0].id

  ingress {
    from_port       = 2049
    to_port         = 2049
    protocol        = "tcp"
    security_groups = [aws_security_group.warren[0].id]
    description     = "NFS from warren ECS tasks"
  }

  tags = {
    Name = "warren-efs-sg-${var.env_suffix}"
  }
}

resource "aws_security_group_rule" "warren_efs_egress" {
  count = var.create_vpc && var.create_efs ? 1 : 0

  type                     = "egress"
  from_port                = 2049
  to_port                  = 2049
  protocol                 = "tcp"
  security_group_id        = aws_security_group.warren[0].id
  source_security_group_id = aws_security_group.warren_efs[0].id
  description              = "NFS egress to EFS"
}

resource "aws_efs_mount_target" "warren" {
  for_each = var.create_efs ? (var.create_vpc ? toset([aws_subnet.a[0].id, aws_subnet.b[0].id]) : toset(var.subnet_ids)) : toset([])

  file_system_id  = aws_efs_file_system.warren[0].id
  subnet_id       = each.value
  security_groups = var.create_vpc ? [aws_security_group.warren_efs[0].id] : []
}

# Dedicated access point for the control-plane task's own state (SQLite registry + auth
# users/tokens tables), rooted at a DIFFERENT path than per-workspace access points
# (resources/warren-server/src/warren/runtime/efs.py's EFSMount, rooted at
# /workspaces/{workspace_id}) — keeps the control plane's durable state fully separate from
# any workspace's data. Without this, a control-plane task restart loses every minted user
# token, not just workspace tracking state (2026-09-21, explicit operator decision: mirrors
# the Podman path's warren-data named volume).
resource "aws_efs_access_point" "warren_control_plane" {
  count = var.create_efs ? 1 : 0

  file_system_id = aws_efs_file_system.warren[0].id

  root_directory {
    path = "/control-plane"
    creation_info {
      owner_uid   = 1000
      owner_gid   = 1000
      permissions = "0700"
    }
  }

  posix_user {
    uid = 1000
    gid = 1000
  }

  tags = {
    Name   = "warren-control-plane-ap-${var.env_suffix}"
    warren = "true"
  }
}

# R13: only created when the operator explicitly opts into efs_reaper.py actually deleting
# a workspace's data directory on access-point expiry (see efs_delete_workspace_data_on_destroy
# above). Rooted at "/var/lib/warren" (NOT the filesystem's true root "/", and NOT a
# per-workspace subpath like the control-plane access point above) -- the reaper needs to
# reach every workspaces/{id} directory under THIS prefix to delete it, which a
# per-workspace-scoped access point can't provide.
#
# Audit Z10: this was rooted at "/" until this fix. efs.py's per-workspace access points
# (EFSMount) are rooted at "/var/lib/warren/workspaces/{workspace_id}" -- i.e. that's where
# workspace data actually lives on the underlying EFS filesystem. efs_reaper.py's
# _purge_workspace_directory computes its delete target as
# Path(local_mount_path) / "workspaces" / workspace_id. With the OLD "/" root, that mount's
# "workspaces/{id}" resolved to the filesystem's true /workspaces/{id} -- one directory level
# too shallow, which never exists, so every delete silently found nothing (only logged at
# debug level) and no workspace data was ever actually freed despite the feature being
# "on". Rooting here at "/var/lib/warren" makes local_mount_path/workspaces/{id} resolve to
# the real /var/lib/warren/workspaces/{id} data, and is strictly narrower than "/" besides
# (this access point still has no business reaching e.g. "/control-plane").
resource "aws_efs_access_point" "warren_root" {
  count = var.create_efs && var.efs_delete_workspace_data_on_destroy ? 1 : 0

  file_system_id = aws_efs_file_system.warren[0].id

  root_directory {
    path = "/var/lib/warren"
  }

  posix_user {
    uid = 1000
    gid = 1000
  }

  tags = {
    Name   = "warren-root-ap-${var.env_suffix}"
    warren = "true"
  }
}

# Without this, the shared security group + shared workspace task role (below) are not an
# isolation boundary at all: any workspace task can mount the filesystem's root directly over
# plain NFS, bypassing its own access point entirely, and read/write every other workspace's
# directory. These two Deny statements are the standard AWS-documented pattern for requiring TLS
# and requiring every mount go through an access point. This closes the "mount root directly"
# bypass; it does not provide per-workspace isolation — every workspace still shares one task
# role and one security group, neither of which can express "only your own access point."
data "aws_iam_policy_document" "efs_policy" {
  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["elasticfilesystem:ClientMount", "elasticfilesystem:ClientWrite", "elasticfilesystem:ClientRootAccess"]
    resources = [local.efs_arn]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }

  statement {
    sid       = "DenyMountWithoutAccessPoint"
    effect    = "Deny"
    actions   = ["elasticfilesystem:ClientMount", "elasticfilesystem:ClientWrite"]
    resources = [local.efs_arn]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "Null"
      variable = "elasticfilesystem:AccessPointArn"
      values   = ["true"]
    }
  }
}

resource "aws_efs_file_system_policy" "warren" {
  count = var.create_efs ? 1 : 0

  file_system_id = aws_efs_file_system.warren[0].id
  policy         = data.aws_iam_policy_document.efs_policy.json
}

# ---------------------------------------------------------------------------
# ECS cluster (always created)
# ---------------------------------------------------------------------------

# Audit finding #42: "DEFAULT" leaves ECS Exec sessions unlogged — no CloudWatch/S3
# session log and no KMS, so an operator's `warren connect`/`exec` session into a task
# leaves no audit trail. "OVERRIDE" + this log group gives every exec session a
# retained, KMS-encrypted record.
resource "aws_cloudwatch_log_group" "ecs_exec" {
  name              = "/${var.ecs_resource_prefix}/${var.env_suffix}/ecs-exec"
  retention_in_days = 90
  kms_key_id        = var.kms_key_id != "" ? var.kms_key_id : null

  tags = {
    warren = "true"
  }
}

resource "aws_ecs_cluster" "warren" {
  name = "warren-cluster-${var.env_suffix}"

  configuration {
    execute_command_configuration {
      logging    = "OVERRIDE"
      kms_key_id = var.kms_key_id != "" ? var.kms_key_id : null

      log_configuration {
        cloud_watch_log_group_name = aws_cloudwatch_log_group.ecs_exec.name
      }
    }
  }

  tags = {
    warren = "true"
  }

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_ecs_cluster_capacity_providers" "warren" {
  cluster_name = aws_ecs_cluster.warren.name

  capacity_providers = ["FARGATE", "FARGATE_SPOT"]

  default_capacity_provider_strategy {
    base              = 1
    weight            = 1
    capacity_provider = "FARGATE"
  }
}

# ---------------------------------------------------------------------------
# AI1: who may ECS Exec into a workspace task
#
# Deployment model: `warren connect`/`warren exec` run `aws ecs execute-command` with the
# caller's OWN AWS credentials (warren-cli dispatch.py); there is no control-plane exec
# relay yet. So the boundary is IAM on the human principal:
#   - warren-workspace-operator-<env> (managed policy; attach to humans' IAM users, groups
#     or Identity Center permission sets): ecs:ExecuteCommand, and ssm:StartSession with
#     AWS-StartPortForwardingSession (`warren tunnel`), only into a task whose
#     <prefix>.owner_id tag (set by the control plane from the caller's verified identity,
#     never from the request) equals the caller's own `warren-owner` principal tag, plus
#     explicit denies for other owners' and untagged tasks, untagged callers, and every
#     other session document.
#   - warren-break-glass-<env> (role): the only principal this stack gives cluster-wide
#     exec and SSM sessions. Assumed deliberately, MFA-gated by default.
# Principals granted ecs:ExecuteCommand elsewhere (e.g. AdministratorAccess) aren't covered
# by these denies; use the SCP in resources/ecs/README.md for an org-wide guard. Every
# principal's exec sessions stay logged via execute_command_configuration above.
# ---------------------------------------------------------------------------

locals {
  workspace_task_arns   = "arn:aws:ecs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:task/${aws_ecs_cluster.warren.name}/*"
  owner_tag_key         = "${var.ecs_resource_prefix}.owner_id"
  owner_principal_tag   = "$${aws:PrincipalTag/${var.exec_owner_principal_tag}}"
  any_task_arns         = "arn:aws:ecs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:task/*"
  port_forward_document = "arn:aws:ssm:${var.aws_region}::document/AWS-StartPortForwardingSession"
}

data "aws_iam_policy_document" "workspace_operator" {
  statement {
    sid       = "DescribeWorkspaceTasks"
    effect    = "Allow"
    actions   = ["ecs:DescribeTasks", "ecs:ListTasks"]
    resources = ["*"]
    condition {
      test     = "ArnEquals"
      variable = "ecs:cluster"
      values   = [aws_ecs_cluster.warren.arn]
    }
  }

  statement {
    sid       = "ExecOwnWorkspaceTasks"
    effect    = "Allow"
    actions   = ["ecs:ExecuteCommand"]
    resources = [local.workspace_task_arns]
    condition {
      test     = "ArnEquals"
      variable = "ecs:cluster"
      values   = [aws_ecs_cluster.warren.arn]
    }
    condition {
      test     = "StringEquals"
      variable = "ecs:ResourceTag/${local.owner_tag_key}"
      values   = [local.owner_principal_tag]
    }
  }

  # ExecuteCommand authorizes the cluster as well as the task; the cluster grant alone
  # opens nothing (the task statement above still has to match).
  statement {
    sid       = "ExecWorkspaceCluster"
    effect    = "Allow"
    actions   = ["ecs:ExecuteCommand"]
    resources = [aws_ecs_cluster.warren.arn]
  }

  statement {
    sid       = "DenyExecOtherOwners"
    effect    = "Deny"
    actions   = ["ecs:ExecuteCommand"]
    resources = [local.workspace_task_arns]
    condition {
      test     = "StringNotEquals"
      variable = "ecs:ResourceTag/${local.owner_tag_key}"
      values   = [local.owner_principal_tag]
    }
  }

  statement {
    sid       = "DenyExecWithoutOwnerTag"
    effect    = "Deny"
    actions   = ["ecs:ExecuteCommand"]
    resources = [local.workspace_task_arns]
    condition {
      test     = "Null"
      variable = "aws:PrincipalTag/${var.exec_owner_principal_tag}"
      values   = ["true"]
    }
  }

  # `warren tunnel`: `aws ssm start-session --target ecs:<cluster>_<task>_<runtime>
  # --document-name AWS-StartPortForwardingSession`. ssm:StartSession authorizes the ECS
  # task (resource type `task`, condition key aws:ResourceTag/<key>, the task's own tags)
  # and the document separately, so the tag condition sits on the task statement only.
  # The Service Authorization Reference lists the task ARN as task/<id>; both forms are
  # covered. BoolIfExists ssm:SessionDocumentAccessCheck makes Session Manager check the
  # document even when the caller names none (the default shell document is then denied).
  statement {
    sid       = "PortForwardDocument"
    effect    = "Allow"
    actions   = ["ssm:StartSession"]
    resources = [local.port_forward_document]
  }

  statement {
    sid       = "PortForwardOwnWorkspaceTasks"
    effect    = "Allow"
    actions   = ["ssm:StartSession"]
    resources = [local.workspace_task_arns, local.any_task_arns]
    condition {
      test     = "StringEquals"
      variable = "aws:ResourceTag/${local.owner_tag_key}"
      values   = [local.owner_principal_tag]
    }
    condition {
      test     = "BoolIfExists"
      variable = "ssm:SessionDocumentAccessCheck"
      values   = ["true"]
    }
  }

  statement {
    sid       = "DenySsmSessionOtherOwners"
    effect    = "Deny"
    actions   = ["ssm:StartSession"]
    resources = [local.any_task_arns]
    condition {
      test     = "StringNotEquals"
      variable = "aws:ResourceTag/${local.owner_tag_key}"
      values   = [local.owner_principal_tag]
    }
    condition {
      test     = "Null"
      variable = "aws:ResourceTag/${local.owner_tag_key}"
      values   = ["false"]
    }
  }

  statement {
    sid       = "DenySsmSessionUntaggedWorkspaceTasks"
    effect    = "Deny"
    actions   = ["ssm:StartSession"]
    resources = [local.workspace_task_arns]
    condition {
      test     = "Null"
      variable = "aws:ResourceTag/${local.owner_tag_key}"
      values   = ["true"]
    }
  }

  statement {
    sid       = "DenySsmSessionWithoutOwnerTag"
    effect    = "Deny"
    actions   = ["ssm:StartSession"]
    resources = [local.any_task_arns]
    condition {
      test     = "Null"
      variable = "aws:PrincipalTag/${var.exec_owner_principal_tag}"
      values   = ["true"]
    }
  }

  # Any document other than port forwarding (interactive shell, AWS-StartSSHSession,
  # custom documents), on any target, for holders of this policy.
  statement {
    sid     = "DenyNonPortForwardDocuments"
    effect  = "Deny"
    actions = ["ssm:StartSession"]
    not_resources = [
      local.port_forward_document,
      local.any_task_arns,
      "arn:aws:ec2:*:${data.aws_caller_identity.current.account_id}:instance/*",
      "arn:aws:ssm:*:${data.aws_caller_identity.current.account_id}:managed-instance/*",
    ]
  }
}

resource "aws_iam_policy" "workspace_operator" {
  name        = "warren-workspace-operator-${var.env_suffix}"
  description = "ECS Exec into your own warren workspace tasks only (AI1)"
  policy      = data.aws_iam_policy_document.workspace_operator.json
}

data "aws_iam_policy_document" "break_glass_trust" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type = "AWS"
      identifiers = (
        length(var.break_glass_principal_arns) > 0
        ? var.break_glass_principal_arns
        : ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
      )
    }
    dynamic "condition" {
      for_each = var.break_glass_require_mfa ? [1] : []
      content {
        test     = "Bool"
        variable = "aws:MultiFactorAuthPresent"
        values   = ["true"]
      }
    }
  }
}

data "aws_iam_policy_document" "break_glass" {
  statement {
    sid       = "DescribeClusterTasks"
    effect    = "Allow"
    actions   = ["ecs:DescribeTasks", "ecs:ListTasks"]
    resources = ["*"]
    condition {
      test     = "ArnEquals"
      variable = "ecs:cluster"
      values   = [aws_ecs_cluster.warren.arn]
    }
  }

  statement {
    sid       = "ClusterWideExec"
    effect    = "Allow"
    actions   = ["ecs:ExecuteCommand"]
    resources = [local.workspace_task_arns, aws_ecs_cluster.warren.arn]
    condition {
      test     = "ArnEquals"
      variable = "ecs:cluster"
      values   = [aws_ecs_cluster.warren.arn]
    }
  }

  statement {
    sid     = "ClusterWideSsmSessions"
    effect  = "Allow"
    actions = ["ssm:StartSession"]
    resources = [
      local.workspace_task_arns,
      "arn:aws:ssm:${var.aws_region}::document/AWS-StartPortForwardingSession",
      "arn:aws:ssm:${var.aws_region}::document/AWS-StartPortForwardingSessionToRemoteHost",
    ]
  }

  statement {
    sid       = "OwnSessions"
    effect    = "Allow"
    actions   = ["ssm:TerminateSession", "ssm:ResumeSession"]
    resources = ["arn:aws:ssm:*:*:session/$${aws:userid}-*"]
  }
}

resource "aws_iam_role" "break_glass" {
  name                 = "warren-break-glass-${var.env_suffix}"
  description          = "The only warren role with cluster-wide ECS Exec and SSM sessions (AI1)"
  assume_role_policy   = data.aws_iam_policy_document.break_glass_trust.json
  max_session_duration = 3600

  tags = {
    warren = "true"
  }
}

resource "aws_iam_role_policy" "break_glass" {
  name   = "WarrenBreakGlassExec"
  role   = aws_iam_role.break_glass.id
  policy = data.aws_iam_policy_document.break_glass.json
}

# ---------------------------------------------------------------------------
# IAM — trust policy shared by both roles
# ---------------------------------------------------------------------------

data "aws_iam_policy_document" "task_trust" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
  }
}

# ---------------------------------------------------------------------------
# IAM — task role policy (warren-server permissions at runtime)
# Permissions derived from all boto3 calls in packages/warren-server/src/warren/runtime/ecs.py
# ---------------------------------------------------------------------------

data "aws_iam_policy_document" "task_role_policy" {
  # finding #21: ecs:DescribeClusters is the one action here actually authorized against
  # the cluster ARN (its resource type really is "cluster") — kept as its own statement.
  # X1: reference the real cluster resource directly rather than guessing its ARN from
  # ecs_resource_prefix -- the cluster's own name ("warren-cluster-${env_suffix}") is not
  # derived from that prefix, so a prefix-pattern Resource silently stopped matching (and
  # DescribeClusters started failing the control plane's own startup check) for any
  # non-default prefix.
  statement {
    sid       = "ECSCluster"
    effect    = "Allow"
    actions   = ["ecs:DescribeClusters"]
    resources = [aws_ecs_cluster.warren.arn]
  }

  # finding #21: ecs:StopTask and ecs:DescribeTasks actually authorize against the TASK
  # ARN (resource type "task"), not the cluster ARN — a Resource of
  # "arn:aws:ecs:*:*:cluster/warren-*" (the previous shape) never scoped these two
  # actions at all; IAM resource-type mismatches aren't enforced at the ARN level, they're
  # just not satisfiable, so the action falls through to requiring "*" in practice,
  # silently granting StopTask/DescribeTasks against every task in every cluster in the
  # account. The ecs:cluster condition key (not the Resource field) is how AWS's own docs
  # scope these two actions to a specific cluster.
  statement {
    sid       = "ECSTaskScoped"
    effect    = "Allow"
    actions   = ["ecs:StopTask", "ecs:DescribeTasks"]
    resources = ["arn:aws:ecs:*:*:task/*"]

    condition {
      test     = "ArnEquals"
      variable = "ecs:cluster"
      values   = [aws_ecs_cluster.warren.arn]
    }
  }

  # #59: the server-mode exec relay runs ecs:ExecuteCommand as the control plane after its
  # own owner check; scoped to this cluster's tasks.
  statement {
    sid       = "ECSExecWorkspaceTasks"
    effect    = "Allow"
    actions   = ["ecs:ExecuteCommand"]
    resources = ["arn:aws:ecs:*:*:task/${aws_ecs_cluster.warren.name}/*", aws_ecs_cluster.warren.arn]

    condition {
      test     = "ArnEquals"
      variable = "ecs:cluster"
      values   = [aws_ecs_cluster.warren.arn]
    }
  }

  # AI3: the orphan sweep lists this server's tasks (startedBy). Fargate ListTasks has
  # no container instance to authorize against, so Resource is "*"; the ecs:cluster
  # condition keeps it scoped to this cluster.
  statement {
    sid       = "ECSListTasks"
    effect    = "Allow"
    actions   = ["ecs:ListTasks"]
    resources = ["*"]

    condition {
      test     = "ArnEquals"
      variable = "ecs:cluster"
      values   = [aws_ecs_cluster.warren.arn]
    }
  }

  # Audit S13: the comment this statement used to carry ("RegisterTaskDefinition/
  # DeregisterTaskDefinition ignore an inapplicable condition key rather than erroring")
  # was wrong. An absent/inapplicable condition key makes an ArnEquals condition
  # evaluate false -- the statement simply never matches, not "matches without the
  # condition." With DeregisterTaskDefinition in THIS statement, every deregister call
  # was unconditionally denied (no other Allow covers it), so task definition revisions
  # piled up forever -- only RunTask actually supports and is scoped by ecs:cluster here.
  statement {
    sid       = "ECSRunTask"
    effect    = "Allow"
    actions   = ["ecs:RunTask"]
    resources = ["arn:aws:ecs:*:*:task-definition/${var.ecs_resource_prefix}-*"]

    condition {
      test     = "ArnEquals"
      variable = "ecs:cluster"
      values   = [aws_ecs_cluster.warren.arn]
    }
  }

  # R21: the control-plane's own task-definition family
  # ("warren-server-control-plane-${var.env_suffix}" below) starts with
  # "${var.ecs_resource_prefix}-" by default, so ECSRunTask's Allow above (necessarily
  # wildcarded over every workspace family) also matches it — the ecs:cluster condition
  # doesn't help, since the control plane runs on this same cluster. An explicit Deny,
  # which IAM always evaluates ahead of any Allow, closes this without narrowing the
  # workspace-task wildcard (which can't enumerate workspace families in advance; see
  # ecs.py's _slug) or renaming the control-plane's own family (which would be a
  # user-visible, blind change — this task definition's family/service name is read
  # directly off of aws_ecs_task_definition.warren_server below, not duplicated as a
  # separate literal needing its own upkeep here).
  # X2: ECSDeregisterTaskDefinition below is unconditioned (DeregisterTaskDefinition takes
  # no ecs:cluster condition key), so its wildcard also matches the control plane's own
  # family -- same self-match class as RunTask above, so the Deny covers both actions.
  statement {
    sid       = "ECSDenySelfRunTask"
    effect    = "Deny"
    actions   = ["ecs:RunTask", "ecs:DeregisterTaskDefinition"]
    resources = ["arn:aws:ecs:*:*:task-definition/warren-server-control-plane-${var.env_suffix}:*"]
  }

  # DeregisterTaskDefinition supports resource-level scoping by the task-definition ARN
  # itself (unlike RegisterTaskDefinition, which needs Resource = "*" below) -- but not
  # the ecs:cluster condition key, so this is a separate, unconditioned statement rather
  # than folded into ECSRunTask above.
  statement {
    sid       = "ECSDeregisterTaskDefinition"
    effect    = "Allow"
    actions   = ["ecs:DeregisterTaskDefinition"]
    resources = ["arn:aws:ecs:*:*:task-definition/${var.ecs_resource_prefix}-*"]
  }

  # finding #21: ecs:RegisterTaskDefinition does not support resource-level permissions
  # at all — AWS's own "Supported Resource-Level Permissions for Amazon ECS APIs"
  # reference lists it as requiring Resource = "*"; a Resource pattern like
  # "task-definition/warren-*" on this action looks like real scoping but authorizes
  # nothing beyond what "*" already would (and could silently stop granting entirely if
  # AWS ever did add resource-level support with different semantics). Kept in its own
  # statement, with this comment in place of a Resource pattern that would be misleading.
  statement {
    sid       = "ECSRegisterTaskDefinition"
    effect    = "Allow"
    actions   = ["ecs:RegisterTaskDefinition"]
    resources = ["*"]
  }

  # finding #21: ecs:TagResource is required whenever RunTask/RegisterTaskDefinition is
  # called with a `tags:` argument (tag-on-create) — previously granted nowhere, so every
  # RunTask call here (which does pass `tags=[...]`, see ecs.py) was relying on it being
  # silently ignored rather than actually being authorized. Scoped to the two resource
  # types tag-on-create applies to here: the task being run, and the task definition
  # being registered.
  #
  # R21: split into one statement per resource type (rather than one statement covering
  # both arn patterns) so each can carry the condition keys that actually apply to it —
  # ecs:cluster only makes sense for a task/* tag-on-create (RunTask), not a
  # task-definition/* one (RegisterTaskDefinition, which has no cluster at
  # registration time) — plus ecs:CreateAction on both, restricting this permission to
  # tagging performed as part of RunTask/RegisterTaskDefinition specifically, not a
  # standalone TagResource call against an existing task/task-definition (AWS's
  # "Grant permission to tag resources on creation" guide for ECS).
  statement {
    sid       = "ECSTagOnCreateTask"
    effect    = "Allow"
    actions   = ["ecs:TagResource"]
    resources = ["arn:aws:ecs:*:*:task/*"]

    condition {
      test     = "ArnEquals"
      variable = "ecs:cluster"
      values   = [aws_ecs_cluster.warren.arn]
    }

    condition {
      test     = "StringEquals"
      variable = "ecs:CreateAction"
      values   = ["RunTask"]
    }
  }

  statement {
    sid       = "ECSTagOnCreateTaskDef"
    effect    = "Allow"
    actions   = ["ecs:TagResource"]
    resources = ["arn:aws:ecs:*:*:task-definition/${var.ecs_resource_prefix}-*"]

    condition {
      test     = "StringEquals"
      variable = "ecs:CreateAction"
      values   = ["RegisterTaskDefinition"]
    }
  }

  statement {
    sid     = "PassRole"
    effect  = "Allow"
    actions = ["iam:PassRole"]
    # Scoped to the two roles actually passed when registering a workspace task definition
    # (execution + workspace task role) — NOT this role itself (task_role never needs to pass
    # itself to anything at runtime) and not the control-plane's own task_role_arn (that's set
    # directly in aws_ecs_task_definition.warren_server by Terraform's own deploy credentials,
    # not an IAM-authorized runtime call).
    resources = [aws_iam_role.task_exec_role.arn, aws_iam_role.workspace_task_role.arn]
  }

  statement {
    sid    = "SSMSecrets"
    effect = "Allow"
    actions = [
      # GetParametersByPath, matching the actual call (ecs.py's _fetch_ssm_parameter_names uses
      # ssm.get_parameters_by_path with WithDecryption=false) — this role only needs parameter
      # NAMES to build secrets ARNs for the task definition; values are resolved later by the
      # exec role, never by this process (fixes issue #4: secrets exposed through RunTask
      # container overrides). DescribeParameters/GetParameters (the previous grant here) is not
      # the action this call actually requires.
      "ssm:GetParametersByPath",
    ]
    # Path-scoped to var.ecs_resource_prefix (not a hardcoded "warren/" literal) so this
    # stays in sync with whatever WARREN_ECS_RESOURCE_PREFIX the control-plane task is
    # actually running with (finding #15/#17) — a mismatch here would silently deny every
    # SSM lookup even though the path looks right to a casual reader.
    resources = ["arn:aws:ssm:*:*:parameter/${var.ecs_resource_prefix}/*"]
  }

  # finding #17: secrets/ssm_store.py mirrors every `PUT`/`DELETE /secrets` call into SSM
  # Parameter Store at /{resource_prefix}/{server_id}/{owner_id}/{name} (see _param_path) —
  # nothing previously granted this role ssm:PutParameter/DeleteParameter, so since the
  # fix making a failed mirror a 502 (issue #9), every secret write/delete call fails on
  # ECS. Scoped with var.ecs_resource_prefix (not a hardcoded "/warren/*") so this grant
  # tracks whatever WARREN_ECS_RESOURCE_PREFIX the control-plane task is actually running
  # with — a mismatch here would otherwise deny every call even though the app-level path
  # looks identical to a casual reader.
  # R19: narrowed from "/${prefix}/*" to "/${prefix}/${server_id}/*" — ssm_store.py's
  # _param_path shapes every write this grant is actually for as
  # /{resource_prefix}/{server_id}/{owner_id}/{name}, where {server_id} is always THIS
  # control plane's own WARREN_SERVER_ID (self.server_id in ecs.py — every secret this
  # process writes or deletes is necessarily under its own server_id segment, never
  # another's). The previous "/${prefix}/*" grant was broad enough to also cover
  # aws_ssm_parameter.warren_secret_key below, which lives at
  # "/${prefix}/${env_suffix}/control-plane/secret-key" — a DIFFERENT second path
  # segment (var.env_suffix, e.g. "prod") than this role's own server_id
  # ("warren-server-control-plane-${env_suffix}"), so narrowing to the latter excludes
  # the control plane's own secret-key parameter without affecting any legitimate
  # per-workspace secret write/delete.
  statement {
    sid    = "SSMSecretsWrite"
    effect = "Allow"
    actions = [
      "ssm:PutParameter",
      "ssm:DeleteParameter",
    ]
    resources = ["arn:aws:ssm:*:*:parameter/${var.ecs_resource_prefix}/warren-server-control-plane-${var.env_suffix}/*"]
  }

  # finding #17: only needed when the SSM parameters are encrypted with a customer-managed
  # KMS key (WarrenSettings.kms_key_id / var.kms_key_id) rather than the AWS-managed
  # alias/aws/ssm key, which needs no explicit grant. Mirrors this file's existing
  # `dynamic "statement"` pattern for conditional grants (the EFS statements above), gated
  # on var.kms_key_id being non-empty instead of var.create_efs.
  dynamic "statement" {
    for_each = var.kms_key_id != "" ? [1] : []
    content {
      sid    = "SSMSecretsKMS"
      effect = "Allow"
      actions = [
        "kms:Encrypt",
        "kms:Decrypt",
        "kms:GenerateDataKey",
      ]
      resources = [var.kms_key_id]
    }
  }

  statement {
    sid    = "ECSExec"
    effect = "Allow"
    actions = [
      "ssmmessages:CreateControlChannel",
      "ssmmessages:CreateDataChannel",
      "ssmmessages:OpenControlChannel",
      "ssmmessages:OpenDataChannel",
    ]
    resources = ["*"]
  }

  statement {
    sid    = "Logs"
    effect = "Allow"
    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents",
      # Audit #53: the control plane itself (not the workspace task) now creates each
      # workspace log group and sets bounded retention on it directly, rather than
      # relying on the ECS agent's "awslogs-create-group" auto-create (infinite
      # retention, no way to expire).
      "logs:PutRetentionPolicy",
    ]
    resources = ["arn:aws:logs:*:*:log-group:/warren/*"]
  }

  # Audit finding #42 (control-plane half): an operator running `aws ecs execute-command`
  # into the CONTROL-PLANE task itself (not a spawned workspace task) assumes this role,
  # not workspace_task_role — the ECSExecLogging statement on workspace_task_role_policy
  # below never covers this case. Mirrors that statement exactly.
  statement {
    sid    = "ECSExecLogging"
    effect = "Allow"
    actions = [
      "logs:DescribeLogGroups",
      "logs:CreateLogStream",
      "logs:DescribeLogStreams",
      "logs:PutLogEvents",
    ]
    resources = ["${aws_cloudwatch_log_group.ecs_exec.arn}:*", aws_cloudwatch_log_group.ecs_exec.arn]
  }

  # EFS — workspace persistence (D-08). Only meaningful when create_efs = true; HCL has no
  # per-statement `count`, so these statements use `dynamic` instead of the file's usual
  # `count` idiom. Split action-by-action rather than one combined statement: ClientMount/
  # ClientWrite/DescribeMountTargets and CreateAccessPoint are both scoped to the filesystem
  # ARN but need different conditions (RequestTag only makes sense for a *create* call — adding
  # it to a single statement covering ClientMount/ClientWrite too would deny those actions
  # outright, since no RequestTag value exists when IAM evaluates a mount call), and TagResource
  # targets a different resource type (the access-point ARN, not the filesystem ARN) entirely.
  dynamic "statement" {
    for_each = var.create_efs ? [1] : []
    content {
      sid    = "EFSClientAccess"
      effect = "Allow"
      actions = [
        "elasticfilesystem:ClientMount",
        "elasticfilesystem:ClientWrite",
        "elasticfilesystem:DescribeMountTargets",
      ]
      resources = [local.efs_arn]
    }
  }

  # RequestTag enforces that every access point this role creates carries the `warren` tag —
  # without it, EFSDeleteTaggedAccessPoints' ResourceTag condition below can never match an
  # access point created without that tag, making it permanently undeletable via this policy.
  dynamic "statement" {
    for_each = var.create_efs ? [1] : []
    content {
      sid    = "EFSCreateAccessPoint"
      effect = "Allow"
      actions = [
        "elasticfilesystem:CreateAccessPoint",
      ]
      resources = [local.efs_arn]

      condition {
        test     = "StringEquals"
        variable = "aws:RequestTag/warren"
        values   = ["true"]
      }
    }
  }

  # CreateAccessPoint with inline Tags performs its own secondary TagResource authorization
  # check, against the access-point ARN being created — not the filesystem ARN. The previous
  # single EFSMount statement granted TagResource scoped to the filesystem ARN, which is the
  # wrong resource type for this action and likely never actually authorized anything (worth
  # confirming whether tagged access-point creation has been working in practice). The
  # CreateAction condition restricts this to tagging performed as part of a CreateAccessPoint
  # call specifically, not a standalone TagResource call against an existing access point.
  dynamic "statement" {
    for_each = var.create_efs ? [1] : []
    content {
      sid       = "EFSTagAccessPointsOnCreate"
      effect    = "Allow"
      actions   = ["elasticfilesystem:TagResource"]
      resources = ["arn:aws:elasticfilesystem:*:${data.aws_caller_identity.current.account_id}:access-point/*"]

      condition {
        test     = "StringEquals"
        variable = "aws:RequestTag/warren"
        values   = ["true"]
      }

      condition {
        test     = "StringEquals"
        variable = "elasticfilesystem:CreateAction"
        values   = ["CreateAccessPoint"]
      }
    }
  }

  dynamic "statement" {
    for_each = var.create_efs ? [1] : []
    content {
      sid       = "EFSDeleteTaggedAccessPoints"
      effect    = "Allow"
      actions   = ["elasticfilesystem:DeleteAccessPoint"]
      resources = ["arn:aws:elasticfilesystem:*:${data.aws_caller_identity.current.account_id}:access-point/*"]

      condition {
        test     = "StringEquals"
        variable = "elasticfilesystem:AccessPointTag/warren"
        values   = ["true"]
      }
    }
  }

  # finding #16: efs.py's detach() calls a standalone TagResource (setting
  # warren.expires_at so the idle reaper knows when to delete the access point) and
  # the subsequent reattach (ensure_running on a reconnected workspace) calls
  # UntagResource to take that tag back off. Neither was granted anywhere — only
  # EFSTagAccessPointsOnCreate above, which the elasticfilesystem:CreateAction
  # condition restricts to tagging performed as part of a CreateAccessPoint call,
  # so it never authorizes this standalone call. Without this, detach()'s TagResource
  # fails (only logged, per efs.py's module docstring), access points never actually
  # expire, and reattach's UntagResource raises outright.
  #
  # R18: this previously had no ownership scoping at all — it allowed Tag/UntagResource
  # against ANY access point in the account, not just ones this warren deployment
  # created. Two AccessPointTag conditions close that: the bare "warren" tag
  # (TAG_MANAGED, set by efs.py's attach() on every access point this role creates —
  # same tag EFSDeleteTaggedAccessPoints above already checks), and warren.server_instance
  # (TAG_SERVER_INSTANCE, set to this server's own WARREN_SERVER_ID at creation) so one
  # warren-server deployment can't retag another's access points even within the same
  # account. Also narrowed aws:TagKeys/ForAllValues to just warren.expires_at — efs.py's
  # detach()/reattach() path (the only caller of this standalone TagResource/
  # UntagResource, confirmed by reading efs.py) never touches warren.owner_id; the
  # previous grant listing it here was unused surface, and dropping it means ownership,
  # once set by EFSTagAccessPointsOnCreate at creation, can no longer be changed by any
  # standalone call this role is granted.
  dynamic "statement" {
    for_each = var.create_efs ? [1] : []
    content {
      sid       = "EFSLifecycleTagging"
      effect    = "Allow"
      actions   = ["elasticfilesystem:TagResource", "elasticfilesystem:UntagResource"]
      resources = ["arn:aws:elasticfilesystem:*:${data.aws_caller_identity.current.account_id}:access-point/*"]

      condition {
        test     = "ForAllValues:StringEquals"
        variable = "aws:TagKeys"
        values   = ["warren.expires_at"]
      }

      condition {
        test     = "StringEquals"
        variable = "elasticfilesystem:AccessPointTag/warren"
        values   = ["true"]
      }

      condition {
        test     = "StringEquals"
        variable = "elasticfilesystem:AccessPointTag/warren.server_instance"
        values   = ["warren-server-control-plane-${var.env_suffix}"]
      }
    }
  }
}

# ---------------------------------------------------------------------------
# IAM — workspace task role policy. Deliberately NOT the same role as task_role above: the
# control-plane's own task_role carries ecs:RunTask/RegisterTaskDefinition/PassRole and EFS
# access-point management, none of which a spawned workspace task should have. Previously
# WARREN_ECS_TASK_ROLE_ARN pointed workspace tasks at the control-plane's own task_role, so any
# workspace (running untrusted agent-generated code) inherited the full orchestration
# permission set — able to spawn more tasks, read every /warren/* SSM parameter name, or
# create/delete EFS access points for other workspaces. This role is the actual isolation
# boundary between the orchestrator and what it orchestrates.
# ---------------------------------------------------------------------------

# AD1: Fargate allows no sandbox inside a task, so whatever this role grants, the agent holds.
# Keep it to the statements below (packages/warren-server/tests/unit/test_iac_exec_scoping.py).
data "aws_iam_policy_document" "workspace_task_role_policy" {
  statement {
    sid    = "ECSExec"
    effect = "Allow"
    actions = [
      "ssmmessages:CreateControlChannel",
      "ssmmessages:CreateDataChannel",
      "ssmmessages:OpenControlChannel",
      "ssmmessages:OpenDataChannel",
    ]
    resources = ["*"]
  }

  # Deliberately NOT granting ssm:GetParameter/secretsmanager:GetSecretValue here — see
  # the equivalent workspace task-role note in the CDK stack. A single role
  # shared by every workspace can't express "only your own secret", so no secret-read
  # permission is granted at the task-role level at all; values are resolved by the execution
  # role via the task definition's `secrets` block instead (exec_log_policy below).
  #
  # "Only your own secret" is now solved one layer up, before RunTask ever happens: the
  # orchestrator (this repo's warren-server, running as task_role above) resolves which SSM
  # parameters to reference per task by verifying the calling operator's real AWS identity
  # (warren/auth/aws_identity.py — a presigned sts:GetCallerIdentity URL, never raw
  # credentials) and scoping its ListParametersByPath lookup to that identity's own path
  # segment under /warren/*. No new IAM permissions were needed for this — it's additive
  # path structure under the wildcard resources already granted above and on task_exec_role.
  dynamic "statement" {
    for_each = var.create_efs ? [1] : []
    content {
      sid       = "EFSClientAccess"
      effect    = "Allow"
      actions   = ["elasticfilesystem:ClientMount", "elasticfilesystem:ClientWrite"]
      resources = [local.efs_arn]
    }
  }

  # Audit finding #42: the ECS Exec agent (running as this task role, not the execution
  # role) needs explicit CloudWatch Logs access to stream exec session output into
  # aws_cloudwatch_log_group.ecs_exec above, plus KMS access if that log group is
  # encrypted — see https://docs.aws.amazon.com/AmazonECS/latest/developerguide/ecs-exec.html
  statement {
    sid    = "ECSExecLogging"
    effect = "Allow"
    actions = [
      "logs:DescribeLogGroups",
      "logs:CreateLogStream",
      "logs:DescribeLogStreams",
      "logs:PutLogEvents",
    ]
    resources = ["${aws_cloudwatch_log_group.ecs_exec.arn}:*", aws_cloudwatch_log_group.ecs_exec.arn]
  }

  dynamic "statement" {
    for_each = var.kms_key_id != "" ? [1] : []
    content {
      sid       = "ECSExecLogKMS"
      effect    = "Allow"
      actions   = ["kms:Decrypt", "kms:GenerateDataKey"]
      resources = [var.kms_key_id]
    }
  }
}

resource "aws_iam_role" "workspace_task_role" {
  name               = "warren-workspace-task-role-${var.env_suffix}"
  assume_role_policy = data.aws_iam_policy_document.task_trust.json

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_iam_role_policy" "workspace_task_policy" {
  name   = "WarrenWorkspaceTaskPolicy"
  role   = aws_iam_role.workspace_task_role.id
  policy = data.aws_iam_policy_document.workspace_task_role_policy.json
}

# ---------------------------------------------------------------------------
# IAM — execution role log supplement
# AmazonECSTaskExecutionRolePolicy does NOT include logs:CreateLogGroup
# (ecs.py uses "awslogs-create-group": "true" — Pitfall 2)
# ---------------------------------------------------------------------------

data "aws_iam_policy_document" "exec_log_policy" {
  # NOTE: this control-plane task's own log group is hardcoded to
  # "/warren/control-plane-${var.env_suffix}" below, independent of
  # var.ecs_resource_prefix (which only renames per-workspace resources at runtime) — so
  # this stays "/warren/*" rather than "/${var.ecs_resource_prefix}/*". A deployment that
  # also changes its per-workspace WARREN_ECS_RESOURCE_PREFIX away from "warren" would
  # need its own additional logs:CreateLogGroup grant for ecs.py's workspace log groups
  # (f"/{resource_prefix}/{server_id}") — out of scope for this fix (finding #17/#19 were
  # about the control plane's own SSM/secret access, not per-workspace log groups).
  statement {
    sid       = "LogGroupCreate"
    effect    = "Allow"
    actions   = ["logs:CreateLogGroup"]
    resources = ["arn:aws:logs:*:*:log-group:/warren/*"]
  }

  # Required for the ECS agent to resolve `secrets` entries at container start
  # (warren-server repo issue #4 fix: secrets moved from plaintext RunTask
  # overrides to `secrets` ARN references — the execution role, not the task
  # role, is what the ECS agent uses to fetch them).
  statement {
    sid    = "SSMSecretsResolve"
    effect = "Allow"
    actions = [
      "ssm:GetParameters",
    ]
    # var.ecs_resource_prefix-scoped (not hardcoded "warren/") — covers both the
    # workspace-task secrets this role already resolved, and the control-plane's own
    # WARREN_SECRET_KEY parameter (aws_ssm_parameter.warren_secret_key below), which is
    # provisioned under the same prefix (finding #19b).
    resources = ["arn:aws:ssm:*:*:parameter/${var.ecs_resource_prefix}/*"]
  }

  # finding #19b: WARREN_SECRET_KEY is a SecureString (aws_ssm_parameter.warren_secret_key
  # below); when it's encrypted with a customer-managed KMS key the ECS agent (running as
  # this execution role) needs kms:Decrypt to resolve it at container start, same as the
  # SSMSecretsKMS statement on task_role_policy above. The default AWS-managed SSM key
  # (used when var.kms_key_id is empty) needs no explicit grant here.
  dynamic "statement" {
    for_each = var.kms_key_id != "" ? [1] : []
    content {
      sid       = "SSMSecretsResolveKMS"
      effect    = "Allow"
      actions   = ["kms:Decrypt"]
      resources = [var.kms_key_id]
    }
  }
}

# ---------------------------------------------------------------------------
# IAM roles and policy attachments
# ---------------------------------------------------------------------------

resource "aws_iam_role" "task_exec_role" {
  name               = "warren-task-exec-role-${var.env_suffix}"
  assume_role_policy = data.aws_iam_policy_document.task_trust.json

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_iam_role_policy_attachment" "exec_managed" {
  role       = aws_iam_role.task_exec_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonECSTaskExecutionRolePolicy"
}

resource "aws_iam_role_policy" "exec_log_supplement" {
  name   = "WarrenExecLogPolicy"
  role   = aws_iam_role.task_exec_role.id
  policy = data.aws_iam_policy_document.exec_log_policy.json
}

resource "aws_iam_role" "task_role" {
  name               = "warren-task-role-${var.env_suffix}"
  assume_role_policy = data.aws_iam_policy_document.task_trust.json

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_iam_role_policy" "task_policy" {
  name   = "WarrenTaskPolicy"
  role   = aws_iam_role.task_role.id
  policy = data.aws_iam_policy_document.task_role_policy.json
}

# ---------------------------------------------------------------------------
# WARREN_SECRET_KEY — finding #19b / R20. Previously deferred to a runbook requiring a
# plaintext env override on a one-off `run-task` call, which exposes the key in
# plaintext to anyone who can see that invocation (T-07-01). Terraform now generates
# and owns this value directly as a SecureString SSM parameter, wired into the task
# definition's `secrets` block below (resolved by the execution role at container
# start, never appearing in the task definition or RunTask call as plaintext — the
# same mechanism already used for per-workspace secrets, see ecs.py's secret_defs).
#
# R20 (researched, not changed — see below): random_password.result is a plain
# Terraform-managed attribute, so this value is written into Terraform's own state
# file in the clear and is fully recoverable by anyone with state-file read access.
# CDK's equivalent (cdk/warren_stack.py's control_plane_secret) avoids this via
# aws_cdk.aws_secretsmanager.Secret's generate_secret_string, which synthesizes to
# CloudFormation's native AWS::SecretsManager::Secret GenerateSecretString property —
# AWS generates the value server-side during stack deployment, and it never appears
# in the CloudFormation template or in CDK's own state at all.
#
# The hashicorp/aws Terraform provider has no equivalent: aws_secretsmanager_secret
# has no generate_secret_string argument, and aws_secretsmanager_secret_version
# (the resource that actually sets a value) only accepts a `secret_string`/
# `secret_binary` Terraform already has in hand — there is no "ask AWS to generate it
# and never tell Terraform" option for this provider (confirmed by checking the
# provider's resource schema, not assumed). The only way to actually avoid the
# plaintext passing through Terraform at all would be to generate it out-of-band
# (e.g. a null_resource/terraform_data local-exec shelling out to
# `aws secretsmanager create-secret --generate-random-password`, then a `data`
# source to read the ARN back) — a real behavior change (requires the AWS CLI and
# live credentials at `terraform apply` time, changes destroy/recreate semantics,
# and needs a `terraform plan`/`apply` dry run against real AWS to verify) that this
# fix does NOT make blind. Left as random_password + SecureString SSM parameter,
# unchanged; the practical mitigation for this known, documented Terraform
# limitation is an encrypted, access-restricted remote state backend (e.g. S3 with
# SSE-KMS and an IAM policy scoping who can read the state object) rather than
# avoiding random_password altogether.
# ---------------------------------------------------------------------------

resource "random_password" "warren_secret_key" {
  length  = 64
  special = false
}

resource "aws_ssm_parameter" "warren_secret_key" {
  name   = "/${var.ecs_resource_prefix}/${var.env_suffix}/control-plane/secret-key"
  type   = "SecureString"
  value  = random_password.warren_secret_key.result
  key_id = var.kms_key_id != "" ? var.kms_key_id : null

  tags = {
    warren = "true"
  }

  lifecycle {
    # A rotated value here invalidates every stored secret and token at once (no
    # MultiFernet rotation exists yet — see audit finding #44) — changing it must be a
    # deliberate `terraform taint`/apply, never an incidental diff.
    ignore_changes = [value]
  }
}

# ---------------------------------------------------------------------------
# Control-plane service — warren-server running as its own long-lived Fargate
# service (finding #19c), distinct from the per-workspace tasks ECSRuntime
# launches at runtime. Previously a one-off `aws ecs run-task` runbook step that
# never restarted after a crash; aws_ecs_service with desired_count=1 keeps exactly
# one control-plane task running, and WARREN_SERVER_ID (below) is derived from the
# stable service name rather than each restart's ephemeral Fargate task hostname.
# ---------------------------------------------------------------------------

resource "aws_ecs_task_definition" "warren_server" {
  family                   = "warren-server-control-plane-${var.env_suffix}"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]

  # 0.25 vCPU / 0.5 GB is the Fargate minimum and the cheapest entry in
  # VALID_FARGATE_PAIRS (src/warren/runtime/ecs.py), matching WarrenSettings'
  # ecs_cpu/ecs_memory defaults. Cost reasoning: an always-on task at this size
  # is roughly $9/month of Fargate compute, leaving headroom under the
  # $50/month ceiling (D-07.3) whose dominant line item is the Template A NAT
  # Gateway (~$32/month), not compute.
  cpu    = "256"
  memory = "512"

  execution_role_arn = aws_iam_role.task_exec_role.arn
  task_role_arn      = aws_iam_role.task_role.arn

  # Control-plane's own persistent state (SQLite registry + auth users/tokens tables) — a
  # DIFFERENT access point than the per-workspace ones ECSRuntime provisions at runtime
  # (2026-09-21, explicit operator decision). Only declared when create_efs = true; HCL has
  # no per-block `count` on nested `volume` blocks within a resource, so this uses `dynamic`
  # (matching the file's existing pattern for the two EFS IAM statements above).
  dynamic "volume" {
    for_each = var.create_efs ? [1] : []
    content {
      name = "warren-data"
      efs_volume_configuration {
        file_system_id     = aws_efs_file_system.warren[0].id
        transit_encryption = "ENABLED"
        authorization_config {
          access_point_id = aws_efs_access_point.warren_control_plane[0].id
          iam             = "ENABLED"
        }
      }
    }
  }

  # R13: only present when efs_delete_workspace_data_on_destroy = true -- see
  # aws_efs_access_point.warren_root above. Mounted at a path distinct from "warren-data"
  # (the control plane's own /control-plane access point) so the reaper's
  # local_mount_path/workspaces/{id} lookups resolve against the filesystem root, not the
  # control plane's own scoped subtree.
  dynamic "volume" {
    for_each = var.create_efs && var.efs_delete_workspace_data_on_destroy ? [1] : []
    content {
      name = "warren-efs-root"
      efs_volume_configuration {
        file_system_id     = aws_efs_file_system.warren[0].id
        transit_encryption = "ENABLED"
        authorization_config {
          access_point_id = aws_efs_access_point.warren_root[0].id
          iam             = "ENABLED"
        }
      }
    }
  }

  container_definitions = jsonencode([
    {
      name      = "warren-server"
      image     = local.control_plane_image
      essential = true

      portMappings = [
        {
          containerPort = 8420
          protocol      = "tcp"
        }
      ]

      # Mounts the control-plane's own EFS access point (declared above) at
      # WARREN_DATA_DIR's default path — matches the Podman path's warren-data named volume.
      # Empty list when create_efs = false, keeping this task's /var/lib/warren on ephemeral
      # task storage (unaffected by any EFS state).
      mountPoints = concat(
        var.create_efs ? [
          {
            sourceVolume  = "warren-data"
            containerPath = "/var/lib/warren"
            readOnly      = false
          }
        ] : [],
        # R13: filesystem-root mount the reaper walks to actually delete a workspace's
        # data directory (WARREN_EFS_LOCAL_MOUNT_PATH below) -- only present when
        # efs_delete_workspace_data_on_destroy = true.
        var.create_efs && var.efs_delete_workspace_data_on_destroy ? [
          {
            sourceVolume  = "warren-efs-root"
            containerPath = "/mnt/warren-efs-root"
            readOnly      = false
          }
        ] : []
      )

      # Required for `aws ecs execute-command` into this task (POC-02).
      linuxParameters = {
        initProcessEnabled = true
      }

      # The secret key is sourced via `secrets` (below), not a plaintext environment
      # value — resolved by the execution role from SSM at container start, never
      # appearing in the task definition or a RunTask call as plaintext (finding #19b).
      secrets = [
        { name = "WARREN_SECRET_KEY", valueFrom = aws_ssm_parameter.warren_secret_key.arn },
      ]

      # WARREN_SERVER_ID (finding #19a): derived from the stable ECS service name, NOT
      # the task's own ephemeral Fargate hostname (WarrenSettings.server_id's default) —
      # the hostname changes on every restart, which orphans every SSM secret path under
      # it, breaks the aws_audience value clients must match, breaks the EFS reaper's
      # server_instance tag match, and creates a fresh CloudWatch log group per task.
      #
      # WARREN_EFS_ID (2026-09-21 reversal of the original "no EFS" POC scope,
      # per explicit operator decision): when create_efs = true (now the
      # default), this is set so app.py constructs an EFSMount and passes it
      # into ECSRuntime(volume=...) — every workspace task ECSRuntime
      # provisions then actually gets persistent storage via
      # ECSRuntime.provision()'s existing EFS-mount wiring (already coded,
      # previously left dormant here). Empty string when create_efs = false,
      # which keeps ECSRuntime(volume=None) — ephemeral task storage only.
      environment = [
        { name = "WARREN_SERVER_ID", value = "warren-server-control-plane-${var.env_suffix}" },
        { name = "WARREN_RUNTIME_TYPE", value = "ecs" },
        { name = "WARREN_ECS_CLUSTER", value = aws_ecs_cluster.warren.name },
        { name = "WARREN_ECS_SUBNET_IDS", value = join(",", local.subnet_ids) },
        { name = "WARREN_ECS_SECURITY_GROUP_IDS", value = local.security_group_id },
        { name = "WARREN_ECS_TASK_ROLE_ARN", value = aws_iam_role.workspace_task_role.arn },
        { name = "WARREN_ECS_TASK_EXECUTION_ROLE_ARN", value = aws_iam_role.task_exec_role.arn },
        { name = "WARREN_AWS_REGION", value = var.aws_region },
        { name = "WARREN_EFS_ID", value = local.efs_id },
        # R13: only set when efs_delete_workspace_data_on_destroy = true (and create_efs = true),
        # matching the containerPath of the warren-efs-root mount above. Empty string otherwise,
        # which keeps config.py's efs_local_mount_path default ("") -- the reaper still deletes
        # access points but leaves their data directories orphaned, same as before this variable
        # existed.
        {
          name  = "WARREN_EFS_LOCAL_MOUNT_PATH"
          value = (var.create_efs && var.efs_delete_workspace_data_on_destroy) ? "/mnt/warren-efs-root" : ""
        },
        # finding #18: empty by default (trusts no assumed role — every IAM Identity
        # Center caller gets 401 until an operator sets var.aws_trusted_assumed_role_patterns).
        # jsonencode (not a comma-join) because these are regexes matched with
        # re.fullmatch, and IAM role-name characters include literal commas
        # ([\w+=,.@-]) that a comma-split would corrupt (see config.py's
        # _split_comma_separated, which accepts either a JSON array or a bare
        # comma-separated string — JSON array is the only safe choice here).
        { name = "WARREN_AWS_TRUSTED_ASSUMED_ROLE_PATTERNS", value = jsonencode(var.aws_trusted_assumed_role_patterns) },
        # R19: previously never actually set — every IAM resource pattern in this file
        # (task_role_policy's SSMSecrets/SSMSecretsWrite/Logs, workspace_task_role_policy,
        # the ecs_exec log group/execute_command_configuration) is already built from
        # var.ecs_resource_prefix/var.kms_key_id, but without these two env vars the
        # control-plane app itself (WarrenSettings.ecs_resource_prefix/kms_key_id, read by
        # ecs.py/ssm_store.py to build its OWN SSM paths and KMS calls) silently stayed at
        # its defaults ("warren", "") regardless of what these Terraform variables said —
        # a mismatch here would deny every SSM lookup the app makes even though the IAM
        # policy looks correctly scoped to a casual reader.
        { name = "WARREN_ECS_RESOURCE_PREFIX", value = var.ecs_resource_prefix },
        { name = "WARREN_KMS_KEY_ID", value = var.kms_key_id },
      ]

      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = "/warren/control-plane-${var.env_suffix}"
          "awslogs-region"        = var.aws_region
          "awslogs-stream-prefix" = "server"
          "awslogs-create-group"  = "true"
        }
      }
    }
  ])

  tags = {
    warren = "true"
  }
}

# finding #19c: replaces the previous one-off `aws ecs run-task` runbook step, which
# never restarted the control plane after a crash. desired_count = 1 keeps exactly one
# control-plane task running at all times; ECS replaces it automatically on failure,
# and WARREN_SERVER_ID (set above from this resource's own name) stays stable across
# every such replacement.
resource "aws_ecs_service" "warren_server" {
  name            = "warren-server-control-plane-${var.env_suffix}"
  cluster         = aws_ecs_cluster.warren.id
  task_definition = aws_ecs_task_definition.warren_server.arn
  launch_type     = "FARGATE"
  desired_count   = 1

  # Audit #10: stop the old task before starting the new one. The control plane is a
  # single SQLite writer on EFS; the default 100/200 rolling deployment briefly runs two.
  # warren-server also refuses to start while another process holds warren.db.lock.
  deployment_minimum_healthy_percent = 0
  deployment_maximum_percent         = 100

  # Required for `aws ecs execute-command exec` into the running service task
  # (POC-02) — previously passed as `run-task --enable-execute-command`, which has no
  # equivalent on a long-lived service other than this flag.
  enable_execute_command = true

  network_configuration {
    subnets          = local.subnet_ids
    security_groups  = [local.security_group_id]
    assign_public_ip = var.create_vpc ? false : var.assign_public_ip
  }

  tags = {
    warren = "true"
  }
}
