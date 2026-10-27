variable "create_vpc" {
  description = "Create a new VPC for warren. If false, provide vpc_id, subnet_ids, security_group_id."
  type        = bool
  default     = true
}

variable "create_efs" {
  description = "Create the EFS file system and its supporting resources for warren, and wire WARREN_EFS_ID into the control-plane task so ECSRuntime actually mounts it into every workspace task it provisions. Defaults to true (2026-09-21 reversal of the original Phase 5 POC's 'no EFS' scope, per explicit operator decision: workspace tasks need persistent storage). Set to false to run without any workspace persistence (ephemeral task storage only, D-10 opt-out)."
  type        = bool
  default     = true
}

# R13: with EFS the control plane always mounts the filesystem's /var/lib/warren (it writes
# workspace secrets onto each workspace's volume through it). This only decides whether
# the reaper also deletes a workspace's data directory when its access point expires
# (WARREN_EFS_PURGE_WORKSPACE_DATA). Default false: data is kept (orphaned) on delete.
variable "efs_delete_workspace_data_on_destroy" {
  description = "Let the access-point-TTL reaper delete a workspace's data directory, not just its access point (WARREN_EFS_PURGE_WORKSPACE_DATA). Default false: the data is orphaned. Only meaningful when create_efs = true."
  type        = bool
  default     = false
}

variable "vpc_id" {
  description = "Existing VPC ID (used when create_vpc = false)"
  type        = string
  default     = ""
}

variable "subnet_ids" {
  description = "List of subnet IDs for Fargate tasks (used when create_vpc = false)"
  type        = list(string)
  default     = []
}

variable "security_group_id" {
  description = "Existing security group ID (used when create_vpc = false)"
  type        = string
  default     = ""
}

# R22: previously driven by `var.create_vpc ? false : true` — meaning any operator
# bringing their OWN VPC (create_vpc = false) got a PUBLIC IP on the control-plane
# service regardless of whether that VPC's subnets are actually private, inverting the
# intent (a BYO-VPC operator is more likely to have deliberately private subnets, not
# less). Driven directly by this variable instead, defaulting to false (the safer
# choice) in both the create_vpc = true case (Template A's subnets are always private,
# behind a NAT Gateway) and the create_vpc = false default (an operator must opt in
# explicitly if their own subnets are actually public).
variable "assign_public_ip" {
  description = "Assign a public IP to the control-plane service's ENI. Only meaningful when create_vpc = false (Template A's own subnets are always private); defaults to false, the safer choice — set true only if your own subnet_ids are public (have an internet gateway route) and you intend the control plane to be reachable without a NAT Gateway."
  type        = bool
  default     = false
}

variable "image_uri" {
  description = "Full image URI for warren-server container (e.g. ghcr.io/scottcowan/warren-server:latest)"
  type        = string
}

variable "control_plane_image_uri" {
  description = "Full image URI for warren-server's own control-plane task (the process that itself runs as a Fargate task and launches workspace tasks). Falls back to var.image_uri when left empty, since the control-plane and workspace images are typically the same warren-server image."
  type        = string
  default     = ""
}

variable "aws_region" {
  description = "AWS region for all resources"
  type        = string
  default     = "us-east-1"
}

variable "env_suffix" {
  description = "Environment suffix appended to resource names (e.g. prod, dev) to allow multiple warren installs in the same account"
  type        = string
  default     = "prod"
}

# finding #17: runtime/ecs.py's ssm_parameter_name shapes every SSM parameter path as
# /{resource_prefix}/{server_id}/{owner_id}/{name} — this variable must match whatever
# WARREN_ECS_RESOURCE_PREFIX (WarrenSettings.ecs_resource_prefix, default "warren") the
# control-plane task is actually running with, so the IAM resource ARN below stays in
# sync with the app's own path prefix instead of a value hardcoded independently of it.
variable "ecs_resource_prefix" {
  description = "Resource-name prefix the control-plane task runs with (WARREN_ECS_RESOURCE_PREFIX / WarrenSettings.ecs_resource_prefix). Must match the deployed task's own setting — it scopes the SSM parameter path this role can read/write."
  type        = string
  default     = "warren"
}

# Customer-managed KMS key for the ECS Exec session/log encryption and the control plane's
# own WARREN_SECRET_KEY SecureString. Empty uses AWS-managed keys. (Workspace secrets are
# not in SSM at all.)
variable "kms_key_id" {
  description = "KMS key ARN for ECS Exec session/log encryption and the control plane's WARREN_SECRET_KEY parameter. Empty (default) uses AWS-managed keys."
  type        = string
  default     = ""
}

# Audit #15: EFS is always encrypted at rest; this only picks the key. Must be a key
# ARN (aws_efs_file_system.kms_key_id requires an ARN). Empty means aws/elasticfilesystem.
variable "efs_kms_key_arn" {
  description = "KMS key ARN for EFS encryption at rest. Empty (default) uses the AWS-managed aws/elasticfilesystem key."
  type        = string
  default     = ""
}

# finding #18: threaded into the control-plane task's WARREN_AWS_TRUSTED_ASSUMED_ROLE_PATTERNS
# env var — see aws_ecs_task_definition.warren_server below. Must be a JSON array of
# *complete* regex patterns (config.py's parsing matches with re.fullmatch, not a prefix
# match), each matched against the full ARN of an assumed-role caller. A correct pattern
# for an IAM Identity Center permission-set role looks like:
#   arn:aws:sts::123456789012:assumed-role/AWSReservedSSO_MyPermissionSet_abc123def456/[^/]+
# (the trailing [^/]+ matches the session name segment, e.g. a user's SSO principal
# name) — note the full-string anchoring: a pattern missing the session-name segment,
# or using a partial match, will never match anything under fullmatch semantics.
variable "aws_trusted_assumed_role_patterns" {
  description = "JSON array of regex patterns (re.fullmatch semantics) matching trusted assumed-role ARNs for AWS-identity secret ownership (WarrenSettings.aws_trusted_assumed_role_patterns). Empty (default) trusts no assumed role — every IAM Identity Center caller gets 401 until this is configured. Example entry for an Identity Center permission set: \"arn:aws:sts::123456789012:assumed-role/AWSReservedSSO_MyPermissionSet_abc123def456/[^/]+\"."
  type        = list(string)
  default     = []
}

# AI1: see main.tf's "who may ECS Exec into a workspace task" section.
variable "exec_owner_principal_tag" {
  description = "Principal tag key whose value is a human's warren owner_id. ecs:ExecuteCommand is allowed only into tasks whose <ecs_resource_prefix>.owner_id tag equals it."
  type        = string
  default     = "warren-owner"
}

variable "break_glass_principal_arns" {
  description = "Principals allowed to assume warren-break-glass-<env_suffix>, the only role with cluster-wide ECS Exec. Empty (default) trusts the account root, i.e. any principal in this account that is separately granted sts:AssumeRole on the role."
  type        = list(string)
  default     = []
}

variable "break_glass_require_mfa" {
  description = "Require aws:MultiFactorAuthPresent to assume the break-glass role. IAM Identity Center role sessions don't carry that key; for them set this to false and restrict break_glass_principal_arns instead."
  type        = bool
  default     = true
}

# ---------------------------------------------------------------------------
# EBS workspace storage (warren-server runtime/ebs.py). Opt-in: each workspace launch gets
# an ECS-managed EBS volume, snapshotted on stop and restored on the next launch, with
# secrets delivered as KMS ciphertext (runtime/ecs_kms_secrets.py) instead of a file on EFS.
# ---------------------------------------------------------------------------

variable "workspace_storage" {
  description = "Deployment default for a new ECS workspace's volume (WARREN_ECS_WORKSPACE_STORAGE): \"efs\" (default, per-workspace EFS access point) or \"ebs\" (ECS-managed EBS volume persisted through snapshots). \"ebs\" implies enable_ebs_storage."
  type        = string
  default     = "efs"

  validation {
    condition     = contains(["efs", "ebs"], var.workspace_storage)
    error_message = "workspace_storage must be \"efs\" or \"ebs\"."
  }
}

variable "enable_ebs_storage" {
  description = "Provision EBS workspace storage (the ECS infrastructure role, secrets KMS key and control-plane grants) so templates can pick `ecs_storage: ebs` while the default stays efs. Implied true when workspace_storage = \"ebs\"."
  type        = bool
  default     = false
}

# Volumes and their snapshots are always encrypted; this only picks the key. Must be an ARN.
variable "ebs_kms_key_arn" {
  description = "KMS key ARN for EBS volume/snapshot encryption (WARREN_ECS_EBS_KMS_KEY_ID). Empty (default) uses the AWS-managed aws/ebs key."
  type        = string
  default     = ""
}

variable "secrets_kms_key_arn" {
  description = "Symmetric KMS key ARN for EBS-mode secrets delivery (WARREN_ECS_SECRETS_KMS_KEY_ID). Empty (default) with EBS enabled creates a dedicated key with rotation."
  type        = string
  default     = ""
}

variable "ebs_size_gib" {
  description = "Size of a new workspace's EBS volume in GiB (WARREN_ECS_EBS_SIZE_GIB)."
  type        = number
  default     = 20

  validation {
    condition     = var.ebs_size_gib >= 1 && var.ebs_size_gib <= 16384
    error_message = "ebs_size_gib must be between 1 and 16384."
  }
}
