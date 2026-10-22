# Outputs matching WARREN_ECS_* env var names expected by WarrenSettings
# (packages/warren-server/src/warren/config.py)
#
# All VPC-derived values go through locals (Pitfall 5: count=0 index safety).
# WARREN_ECS_IMAGE_URI is documentation only — not a WarrenSettings field;
# warren-server reads image URI from WorkspaceSpec.image at call time.

output "WARREN_ECS_CLUSTER" {
  description = "ECS cluster name — maps to WARREN_ECS_CLUSTER env var"
  value       = aws_ecs_cluster.warren.name
}

output "WARREN_ECS_SUBNET_IDS" {
  description = "Comma-separated subnet IDs for Fargate tasks — maps to WARREN_ECS_SUBNET_IDS env var"
  value       = join(",", local.subnet_ids)
}

output "WARREN_ECS_SECURITY_GROUP_IDS" {
  description = "Security group ID for Fargate tasks — maps to WARREN_ECS_SECURITY_GROUP_IDS env var"
  value       = local.security_group_id
}

output "WARREN_ECS_TASK_ROLE_ARN" {
  description = "Workspace task role ARN (NOT the control-plane's own task_role) — maps to WARREN_ECS_TASK_ROLE_ARN env var"
  value       = aws_iam_role.workspace_task_role.arn
}

output "WARREN_ECS_TASK_EXECUTION_ROLE_ARN" {
  description = "Task execution role ARN — maps to WARREN_ECS_TASK_EXECUTION_ROLE_ARN env var"
  value       = aws_iam_role.task_exec_role.arn
}

output "WARREN_ECS_IMAGE_URI" {
  description = "Image URI provided at apply time (documentation only — not a WarrenSettings field; passed to ECSRuntime.provision() via WorkspaceSpec.image)"
  value       = var.image_uri
}

output "warren_efs_id" {
  description = "EFS file system ID — set as WARREN_EFS_ID. An empty value is expected and correct when create_efs = false (the Phase 5 ECS POC default); in that case leave WARREN_EFS_ID unset on warren-server (setting it to an empty string is also fine — app.py only constructs an EFSMount when settings.efs_id is truthy, so an empty value keeps ECSRuntime(volume=None))."
  value       = var.create_efs ? aws_efs_file_system.warren[0].id : ""
}

# ---------------------------------------------------------------------------
# Control-plane service/task-definition outputs. The control plane now runs as an
# aws_ecs_service (finding #19c), not a one-off `run-task` — these outputs are for
# `aws ecs execute-command`/`describe-services` against it, not a launch command.
# Kept separate from the WARREN_ECS_* block above, whose names are contractually
# bound to WarrenSettings field names.
# ---------------------------------------------------------------------------

output "warren_server_task_definition_arn" {
  description = "Control-plane task definition ARN"
  value       = aws_ecs_task_definition.warren_server.arn
}

output "warren_server_task_definition_family" {
  description = "Control-plane task definition family name"
  value       = aws_ecs_task_definition.warren_server.family
}

output "warren_server_service_name" {
  description = "Control-plane ECS service name — the argument for `aws ecs describe-services`/`execute-command --task` lookups"
  value       = aws_ecs_service.warren_server.name
}

output "warren_workspace_operator_policy_arn" {
  description = "Managed policy for humans who `warren connect` (AI1): ECS Exec only into tasks tagged with their own owner_id"
  value       = aws_iam_policy.workspace_operator.arn
}

output "warren_break_glass_role_arn" {
  description = "The only role with cluster-wide ECS Exec and SSM sessions into workspace tasks (AI1)"
  value       = aws_iam_role.break_glass.arn
}
