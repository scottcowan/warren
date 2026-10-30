"""WarrenECSStack — CDK Python stack that provisions the AWS infrastructure
required by ECSRuntime.

Resources created:
  - ECS Cluster (FARGATE + FARGATE_SPOT capacity providers)
  - IAM task role (warren-task-role-{env_suffix}) — control-plane orchestration
    permissions (RunTask, RegisterTaskDefinition, PassRole, EFS access-point
    management); never handed to a spawned workspace task
  - IAM workspace task role (warren-workspace-task-role-{env_suffix}) — the
    role actually passed to every spawned workspace task: ECS Exec + EFS
    mount only, deliberately excludes RunTask/RegisterTaskDefinition/
    PassRole/access-point management (isolation boundary between the
    orchestrator and what it orchestrates)
  - IAM task execution role (warren-task-exec-role-{env_suffix}) for ECS agent
  - Managed policy warren-workspace-operator-{env_suffix} for humans (ECS Exec
    only into tasks tagged with their own owner_id) and the break-glass role
    warren-break-glass-{env_suffix}, the only cluster-wide exec holder (AI1)
  - VPC, private subnets, NAT Gateway (when create_vpc=True, Template A)
  - Security group with HTTPS-only egress
  - EFS file system + mount targets + resource policy denying insecure
    transport and non-access-point mounts (only when create_efs=True — Phase 5
    ECS POC default is False; see Terraform's resources/ecs/terraform/main.tf
    for the parallel implementation this mirrors)
  - Control-plane ECS task definition (warren-server itself running as a
    Fargate task) — registration only; launching it is a runbook step
    (docs/warren-server-ecs-deploy.md), not something this stack does

CfnOutputs (map to WARREN_ECS_* env vars):
  WARREN_ECS_CLUSTER               — cluster name
  WARREN_ECS_SUBNET_IDS            — comma-separated private subnet IDs
  WARREN_ECS_SECURITY_GROUP_IDS    — security group ID
  WARREN_ECS_TASK_ROLE_ARN         — workspace task role ARN (NOT the control-plane's own task_role)
  WARREN_ECS_TASK_EXECUTION_ROLE_ARN — task execution role ARN
  WARREN_ECS_IMAGE_URI             — image URI (documentation; not a WarrenSettings field)
  WarrenEFSId                      — EFS file system ID (empty when create_efs=False)
  WarrenServerTaskDefinitionArn    — control-plane task definition ARN
  WarrenServerTaskDefinitionFamily — control-plane task definition family
  WarrenRunTaskNetworkConfiguration — awsvpcConfiguration JSON for `aws ecs run-task`
  WarrenWorkspaceOperatorPolicyArn — attach to humans who `warren connect` (AI1)
  WarrenBreakGlassRoleArn          — cluster-wide exec, break-glass only (AI1)

IAM note (T-08-02-01/T-08-03-01): ECS actions are split into two statements —
cluster-scoped (RunTask/StopTask/DescribeTasks/DescribeClusters, scoped to
arn:aws:ecs:*:*:cluster/warren-*) and task-definition-scoped
(RunTask/RegisterTaskDefinition/DeregisterTaskDefinition, scoped to
arn:aws:ecs:*:*:task-definition/warren-*) — rather than a single statement
against the cluster ARN alone, which does not scope the task-definition
actions. Mirrors Terraform's resources/ecs/terraform/main.tf.

Isolation note: workspace tasks run under workspace_task_role, not the
control-plane's own task_role — see warren-server#1 (porting
scottcowan/warren PR #3's Terraform fix to CDK). EFS CreateAccessPoint/
TagResource/DeleteAccessPoint IAM conditions require the bare "warren"
tag that src/warren/runtime/efs.py's attach() now sets (TAG_MANAGED),
alongside the existing warren.* namespaced tags.
"""
from __future__ import annotations

import aws_cdk as cdk
import aws_cdk.aws_ec2 as ec2
import aws_cdk.aws_ecs as ecs
import aws_cdk.aws_efs as efs
import aws_cdk.aws_iam as iam
import aws_cdk.aws_kms as kms
import aws_cdk.aws_logs as logs
import aws_cdk.aws_secretsmanager as secretsmanager
from constructs import Construct


class WarrenECSStack(cdk.Stack):
    """Provision warren ECS infrastructure via CDK.

    Args:
        scope: CDK app scope.
        id: Stack logical ID.
        create_vpc: When True (default), creates a new VPC with private subnets
            and a NAT Gateway (Template A). When False, imports an existing VPC
            by ``vpc_id`` and uses ``subnet_ids`` / ``security_group_id``.
        create_efs: When True (default), creates the EFS file system and its
            supporting security group/mount targets for workspace persistence
            (D-07/D-08), and wires WARREN_EFS_ID into the control-plane task
            so ECSRuntime actually mounts it into every workspace task it
            provisions. Defaults to True (2026-09-21 reversal of the
            original Phase 5 POC's "no EFS" scope, per explicit operator
            decision: workspace tasks need persistent storage). Set False to
            run without any workspace persistence (ephemeral task storage
            only, D-10 opt-out).
        vpc_id: Existing VPC ID (required when create_vpc=False).
        subnet_ids: List of existing subnet IDs (required when create_vpc=False).
        security_group_id: Existing security group ID (optional when
            create_vpc=False; if omitted, tasks run with no custom SG).
        image_uri: Full container image URI. Emitted as an output for
            documentation but is not used by this stack to create resources.
        control_plane_image_uri: Full image URI for warren-server's own
            control-plane task (the process that itself runs as a Fargate
            task and launches workspace tasks). Falls back to ``image_uri``
            when left empty, since the control-plane and workspace images
            are typically the same warren-server image.
        env_suffix: Resource name suffix, e.g. "prod", "staging", "dev".
            Defaults to "prod".
        ecs_resource_prefix: Resource-name prefix the control-plane task runs
            with (WARREN_ECS_RESOURCE_PREFIX / WarrenSettings.ecs_resource_prefix).
            Must match the deployed task's own setting — it scopes the SSM
            parameter path and ECS task-definition/cluster Resource patterns
            this stack's IAM grants it (findings #15/#17/#21).
        kms_key_id: KMS key ARN for ECS Exec session/log encryption and the
            control plane's secret-key secret. Empty (default) uses AWS-managed
            keys. Workspace secrets are not stored in AWS at all.
        aws_trusted_assumed_role_patterns: Regex patterns (re.fullmatch
            semantics) matching trusted assumed-role ARNs for AWS-identity
            secret ownership (WarrenSettings.aws_trusted_assumed_role_patterns).
            None/empty (default) trusts no assumed role — every IAM Identity
            Center caller gets 401 until this is configured (finding #18). A
            correct pattern for an Identity Center permission set looks like
            "arn:aws:sts::123456789012:assumed-role/AWSReservedSSO_MyPermissionSet_abc123def456/[^/]+"
            — note the full-string anchoring: config.py's parsing matches with
            re.fullmatch, not a prefix match.
        workspace_storage: Deployment default for a new ECS workspace's volume
            (WARREN_ECS_WORKSPACE_STORAGE): "efs" (default) or "ebs" (an ECS-managed EBS
            volume persisted through snapshots, warren-server runtime/ebs.py). "ebs"
            implies enable_ebs_storage.
        enable_ebs_storage: Provision EBS workspace storage (ECS infrastructure role,
            secrets KMS key, control-plane and workspace grants) so templates can pick
            `ecs_storage: ebs` while the default stays efs. Default False.
        ebs_kms_key_arn: KMS key ARN for EBS volume/snapshot encryption (always on).
            Empty means aws/ebs. Mirrors terraform's var.ebs_kms_key_arn.
        secrets_kms_key_arn: Symmetric KMS key ARN for EBS-mode secrets delivery
            (runtime/ecs_kms_secrets.py). Empty with EBS enabled creates a dedicated key
            with rotation.
        ebs_size_gib: Size of a new workspace's EBS volume (WARREN_ECS_EBS_SIZE_GIB).
        **kwargs: Passed to cdk.Stack (env, termination_protection, etc.).
    """

    def __init__(
        self,
        scope: Construct,
        id: str,
        *,
        create_vpc: bool = True,
        create_efs: bool = True,
        # R13: mirrors terraform/variables.tf's efs_delete_workspace_data_on_destroy.
        # With EFS the control plane always mounts the filesystem's /var/lib/warren
        # (WARREN_EFS_LOCAL_MOUNT_PATH), because workspace secrets are delivered through
        # it. This only decides whether the reaper also deletes a workspace's data when
        # its access point expires (WARREN_EFS_PURGE_WORKSPACE_DATA). Default False.
        efs_delete_workspace_data_on_destroy: bool = False,
        vpc_id: str = "",
        subnet_ids: list[str] | None = None,
        security_group_id: str = "",
        image_uri: str = "",
        control_plane_image_uri: str = "",
        env_suffix: str = "prod",
        ecs_resource_prefix: str = "warren",
        kms_key_id: str = "",
        # Audit #15: EFS is always encrypted at rest; this only picks the key (an ARN).
        # Empty means aws/elasticfilesystem. Mirrors terraform's var.efs_kms_key_arn.
        efs_kms_key_arn: str = "",
        aws_trusted_assumed_role_patterns: list[str] | None = None,
        # R22: previously driven by `"DISABLED" if create_vpc else "ENABLED"` below —
        # meaning any operator bringing their OWN VPC (create_vpc=False) got a PUBLIC
        # IP on the control-plane service regardless of whether that VPC's subnets are
        # actually private, inverting the intent (a BYO-VPC operator is more likely to
        # have deliberately private subnets, not less). Driven directly by this param
        # instead, defaulting to False (the safer choice) in both the create_vpc=True
        # case (Template A's subnets are always private, behind a NAT Gateway) and the
        # create_vpc=False default (an operator must opt in explicitly if their own
        # subnet_ids are actually public). Mirrors terraform/main.tf's
        # var.assign_public_ip.
        assign_public_ip: bool = False,
        # AI1: mirror terraform/variables.tf's exec_owner_principal_tag /
        # break_glass_principal_arns / break_glass_require_mfa.
        exec_owner_principal_tag: str = "warren-owner",
        break_glass_principal_arns: list[str] | None = None,
        break_glass_require_mfa: bool = True,
        # EBS workspace storage; mirror terraform/variables.tf's workspace_storage /
        # enable_ebs_storage / ebs_kms_key_arn / secrets_kms_key_arn / ebs_size_gib.
        workspace_storage: str = "efs",
        enable_ebs_storage: bool = False,
        ebs_kms_key_arn: str = "",
        secrets_kms_key_arn: str = "",
        ebs_size_gib: int = 20,
        **kwargs,
    ) -> None:
        super().__init__(scope, id, **kwargs)
        if workspace_storage not in ("efs", "ebs"):
            raise ValueError(f"workspace_storage must be 'efs' or 'ebs', not {workspace_storage!r}")
        if not 1 <= int(ebs_size_gib) <= 16384:
            raise ValueError("ebs_size_gib must be between 1 and 16384")
        ebs_enabled = enable_ebs_storage or workspace_storage == "ebs"
        control_plane_image = control_plane_image_uri or image_uri
        server_id = f"warren-server-control-plane-{env_suffix}"

        # ---------------------------------------------------------------
        # VPC — Python if-branch, NOT CfnCondition (per RESEARCH.md anti-patterns)
        # ---------------------------------------------------------------
        if create_vpc:
            # Template A: private subnets + NAT Gateway (default/recommended)
            # NAT Gateway is required because ecs.py uses assignPublicIp=DISABLED;
            # tasks need outbound internet to pull images from ghcr.io.
            vpc = ec2.Vpc(
                self,
                "WarrenVpc",
                ip_addresses=ec2.IpAddresses.cidr("10.42.0.0/16"),
                max_azs=2,
                nat_gateways=1,
                subnet_configuration=[
                    ec2.SubnetConfiguration(
                        name="public",
                        subnet_type=ec2.SubnetType.PUBLIC,
                        cidr_mask=24,
                    ),
                    ec2.SubnetConfiguration(
                        name="private",
                        subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS,
                        cidr_mask=24,
                    ),
                ],
                vpc_name=f"warren-vpc-{env_suffix}",
            )
            # Fargate tasks run in private subnets (assignPublicIp=DISABLED in ecs.py)
            subnet_id_list = [s.subnet_id for s in vpc.private_subnets]
        else:
            # Import an existing VPC by ID
            vpc = ec2.Vpc.from_lookup(self, "ExistingVpc", vpc_id=vpc_id)
            subnet_id_list = list(subnet_ids) if subnet_ids else []

        # ---------------------------------------------------------------
        # Security Group
        # T-08-02-05: no inbound rules; egress restricted to HTTPS only
        # ---------------------------------------------------------------
        if create_vpc:
            sg = ec2.SecurityGroup(
                self,
                "WarrenSG",
                vpc=vpc,
                security_group_name=f"warren-sg-{env_suffix}",
                description="Warren ECS task security group — HTTPS egress only",
                allow_all_outbound=False,  # T-08-02-05: explicit egress only
            )
            # Allow outbound HTTPS so tasks can reach AWS APIs, ECR, ghcr.io
            sg.add_egress_rule(
                peer=ec2.Peer.any_ipv4(),
                connection=ec2.Port.tcp(443),
                description="HTTPS egress for AWS APIs and container registry",
            )
        elif security_group_id:
            sg = ec2.SecurityGroup.from_security_group_id(
                self,
                "ExistingSG",
                security_group_id=security_group_id,
                mutable=False,
            )
        else:
            sg = None  # type: ignore[assignment]

        # ---------------------------------------------------------------
        # EFS Security Group and File System for workspace persistence (D-07)
        # Provisioned only when create_efs=True (Phase 5 ECS POC default is
        # False — no EFS deployed) AND create_vpc=True (same VPC branch as
        # the task SG).
        # ---------------------------------------------------------------
        if create_vpc and create_efs and sg is not None:
            efs_sg = ec2.SecurityGroup(
                self,
                "WarrenEFSSG",
                vpc=vpc,
                security_group_name=f"warren-efs-sg-{env_suffix}",
                description="Warren EFS — NFS inbound from ECS tasks (port 2049)",
                allow_all_outbound=False,
            )
            efs_sg.add_ingress_rule(
                peer=ec2.Peer.security_group_id(sg.security_group_id),
                connection=ec2.Port.tcp(2049),
                description="NFS from warren ECS task security group",
            )
            # NFS egress from task SG to EFS SG
            sg.add_egress_rule(
                peer=ec2.Peer.security_group_id(efs_sg.security_group_id),
                connection=ec2.Port.tcp(2049),
                description="NFS egress to EFS",
            )

            efs_fs = efs.FileSystem(
                self,
                "WarrenEFSFileSystem",
                vpc=vpc,
                security_group=efs_sg,
                file_system_name=f"warren-efs-{env_suffix}",
                removal_policy=cdk.RemovalPolicy.RETAIN,  # operators manage FS lifecycle (D-06)
                lifecycle_policy=efs.LifecyclePolicy.AFTER_90_DAYS,
                encrypted=True,
                kms_key=(
                    kms.Key.from_key_arn(self, "WarrenEfsKmsKey", efs_kms_key_arn)
                    if efs_kms_key_arn
                    else None
                ),
            )
            # Dedicated access point for the control-plane task's own state (SQLite
            # registry + auth users/tokens tables), rooted at a DIFFERENT path than
            # per-workspace access points (src/warren/runtime/efs.py's EFSMount, rooted
            # at /workspaces/{workspace_id}) — 2026-09-21, explicit operator decision;
            # mirrors terraform/main.tf's aws_efs_access_point.warren_control_plane.
            control_plane_ap = efs_fs.add_access_point(
                "WarrenControlPlaneAccessPoint",
                path="/control-plane",
                create_acl=efs.Acl(owner_uid="1000", owner_gid="1000", permissions="0700"),
                posix_user=efs.PosixUser(uid="1000", gid="1000"),
            )
            # Without this, the shared security group + shared workspace task role
            # (below) are not an isolation boundary at all: any workspace task could
            # mount the filesystem's root directly over plain NFS, bypassing its own
            # access point entirely, and read/write every other workspace's directory.
            # These two Deny statements are the standard AWS-documented pattern for
            # requiring TLS and requiring every mount go through an access point.
            # Mirrors terraform/main.tf's aws_efs_file_system_policy.warren.
            efs_fs.add_to_resource_policy(
                iam.PolicyStatement(
                    sid="DenyInsecureTransport",
                    effect=iam.Effect.DENY,
                    principals=[iam.AnyPrincipal()],
                    actions=[
                        "elasticfilesystem:ClientMount",
                        "elasticfilesystem:ClientWrite",
                        "elasticfilesystem:ClientRootAccess",
                    ],
                    resources=[efs_fs.file_system_arn],
                    conditions={"Bool": {"aws:SecureTransport": "false"}},
                )
            )
            efs_fs.add_to_resource_policy(
                iam.PolicyStatement(
                    sid="DenyMountWithoutAccessPoint",
                    effect=iam.Effect.DENY,
                    principals=[iam.AnyPrincipal()],
                    actions=[
                        "elasticfilesystem:ClientMount",
                        "elasticfilesystem:ClientWrite",
                    ],
                    resources=[efs_fs.file_system_arn],
                    conditions={"Null": {"elasticfilesystem:AccessPointArn": "true"}},
                )
            )
            # R13: only created when the operator explicitly opts into efs_reaper.py
            # actually deleting a workspace's data directory on access-point expiry.
            # Rooted at "/var/lib/warren" (NOT the filesystem's true root "/", and NOT a
            # per-workspace subpath like control_plane_ap above) -- the reaper needs to
            # reach every workspaces/{id} directory under THIS prefix to delete it, which
            # a per-workspace-scoped access point can't provide. Mirrors
            # terraform/main.tf's aws_efs_access_point.warren_root.
            #
            # Audit Z10: this was rooted at "/" until this fix. efs.py's per-workspace
            # access points are rooted at "/var/lib/warren/workspaces/{workspace_id}" --
            # that's where workspace data actually lives on the underlying EFS
            # filesystem. efs_reaper.py's _purge_workspace_directory computes its delete
            # target as Path(local_mount_path) / "workspaces" / workspace_id. With the
            # OLD "/" root, that mount's "workspaces/{id}" resolved to the filesystem's
            # true /workspaces/{id} -- one directory level too shallow, which never
            # exists, so every delete silently found nothing (debug-logged only) and no
            # workspace data was ever actually freed despite the feature being "on".
            root_ap = efs_fs.add_access_point(
                "WarrenRootAccessPoint",
                path="/var/lib/warren",
                posix_user=efs.PosixUser(uid="1000", gid="1000"),
            )
        else:
            efs_sg = None  # type: ignore[assignment]
            efs_fs = None  # type: ignore[assignment]
            control_plane_ap = None  # type: ignore[assignment]
            root_ap = None  # type: ignore[assignment]

        # ---------------------------------------------------------------
        # ECS Cluster
        # FARGATE and FARGATE_SPOT capacity providers are available by
        # default on CDK-created clusters.
        # ---------------------------------------------------------------
        # Audit finding #42 / S11: "DEFAULT" leaves ECS Exec sessions unlogged — no
        # CloudWatch/S3 session log and no KMS, so an operator's `warren connect`/`exec`
        # session into a task leaves no audit trail. "OVERRIDE" + this log group gives
        # every exec session a retained, KMS-encrypted record. Mirrors terraform/main.tf's
        # aws_cloudwatch_log_group.ecs_exec / aws_ecs_cluster.warren's
        # execute_command_configuration.
        ecs_exec_log_group = logs.LogGroup(
            self,
            "WarrenEcsExecLogGroup",
            log_group_name=f"/{ecs_resource_prefix}/{env_suffix}/ecs-exec",
            retention=logs.RetentionDays.THREE_MONTHS,
            encryption_key=(
                kms.Key.from_key_arn(self, "WarrenEcsExecLogKmsKey", kms_key_id)
                if kms_key_id
                else None
            ),
            removal_policy=cdk.RemovalPolicy.RETAIN,
        )

        cluster = ecs.Cluster(
            self,
            "WarrenCluster",
            cluster_name=f"warren-cluster-{env_suffix}",
            vpc=vpc,
            execute_command_configuration=ecs.ExecuteCommandConfiguration(
                logging=ecs.ExecuteCommandLogging.OVERRIDE,
                log_configuration=ecs.ExecuteCommandLogConfiguration(
                    cloud_watch_log_group=ecs_exec_log_group,
                ),
                kms_key=(
                    kms.Key.from_key_arn(self, "WarrenEcsExecConfigKmsKey", kms_key_id)
                    if kms_key_id
                    else None
                ),
            ),
        )
        cluster.enable_fargate_capacity_providers()

        # ---------------------------------------------------------------
        # AI1: who may ECS Exec into a workspace task. Mirrors terraform/main.tf's
        # section of the same name (deployment model: `warren connect` runs
        # `aws ecs execute-command` with the caller's own credentials; no
        # control-plane exec relay). Humans get the operator managed policy: exec, and
        # port forwarding (`warren tunnel`), only into tasks whose <prefix>.owner_id tag
        # equals their own `warren-owner` principal tag, plus explicit denies (other
        # owners, untagged tasks and callers, any other session document). The
        # break-glass role is the only principal this stack gives cluster-wide exec.
        # ---------------------------------------------------------------
        workspace_task_arns = f"arn:aws:ecs:{self.region}:{self.account}:task/{cluster.cluster_name}/*"
        any_task_arns = f"arn:aws:ecs:{self.region}:{self.account}:task/*"
        port_forward_document = f"arn:aws:ssm:{self.region}::document/AWS-StartPortForwardingSession"
        owner_tag_key = f"ecs:ResourceTag/{ecs_resource_prefix}.owner_id"
        ssm_owner_tag_key = f"aws:ResourceTag/{ecs_resource_prefix}.owner_id"
        owner_principal_tag = f"${{aws:PrincipalTag/{exec_owner_principal_tag}}}"
        in_cluster = {"ArnEquals": {"ecs:cluster": cluster.cluster_arn}}
        workspace_operator_policy = iam.ManagedPolicy(
            self,
            "WarrenWorkspaceOperatorPolicy",
            managed_policy_name=f"warren-workspace-operator-{env_suffix}",
            description="ECS Exec into your own warren workspace tasks only (AI1)",
            statements=[
                iam.PolicyStatement(
                    sid="DescribeWorkspaceTasks",
                    actions=["ecs:DescribeTasks", "ecs:ListTasks"],
                    resources=["*"],
                    conditions=in_cluster,
                ),
                iam.PolicyStatement(
                    sid="ExecOwnWorkspaceTasks",
                    actions=["ecs:ExecuteCommand"],
                    resources=[workspace_task_arns],
                    conditions={
                        **in_cluster,
                        "StringEquals": {owner_tag_key: owner_principal_tag},
                    },
                ),
                # ExecuteCommand authorizes the cluster too; this alone opens nothing.
                iam.PolicyStatement(
                    sid="ExecWorkspaceCluster",
                    actions=["ecs:ExecuteCommand"],
                    resources=[cluster.cluster_arn],
                ),
                iam.PolicyStatement(
                    sid="DenyExecOtherOwners",
                    effect=iam.Effect.DENY,
                    actions=["ecs:ExecuteCommand"],
                    resources=[workspace_task_arns],
                    conditions={"StringNotEquals": {owner_tag_key: owner_principal_tag}},
                ),
                iam.PolicyStatement(
                    sid="DenyExecWithoutOwnerTag",
                    effect=iam.Effect.DENY,
                    actions=["ecs:ExecuteCommand"],
                    resources=[workspace_task_arns],
                    conditions={"Null": {f"aws:PrincipalTag/{exec_owner_principal_tag}": "true"}},
                ),
                # `warren tunnel` (AWS-StartPortForwardingSession): the task and the
                # document are authorized separately, so the tag condition is on the task
                # statement only. See terraform/main.tf for the reasoning.
                iam.PolicyStatement(
                    sid="PortForwardDocument",
                    actions=["ssm:StartSession"],
                    resources=[port_forward_document],
                ),
                iam.PolicyStatement(
                    sid="PortForwardOwnWorkspaceTasks",
                    actions=["ssm:StartSession"],
                    resources=[workspace_task_arns, any_task_arns],
                    conditions={
                        "StringEquals": {ssm_owner_tag_key: owner_principal_tag},
                        "BoolIfExists": {"ssm:SessionDocumentAccessCheck": "true"},
                    },
                ),
                iam.PolicyStatement(
                    sid="DenySsmSessionOtherOwners",
                    effect=iam.Effect.DENY,
                    actions=["ssm:StartSession"],
                    resources=[any_task_arns],
                    conditions={
                        "StringNotEquals": {ssm_owner_tag_key: owner_principal_tag},
                        "Null": {ssm_owner_tag_key: "false"},
                    },
                ),
                iam.PolicyStatement(
                    sid="DenySsmSessionUntaggedWorkspaceTasks",
                    effect=iam.Effect.DENY,
                    actions=["ssm:StartSession"],
                    resources=[workspace_task_arns],
                    conditions={"Null": {ssm_owner_tag_key: "true"}},
                ),
                iam.PolicyStatement(
                    sid="DenySsmSessionWithoutOwnerTag",
                    effect=iam.Effect.DENY,
                    actions=["ssm:StartSession"],
                    resources=[any_task_arns],
                    conditions={"Null": {f"aws:PrincipalTag/{exec_owner_principal_tag}": "true"}},
                ),
                iam.PolicyStatement(
                    sid="DenyNonPortForwardDocuments",
                    effect=iam.Effect.DENY,
                    actions=["ssm:StartSession"],
                    not_resources=[
                        port_forward_document,
                        any_task_arns,
                        f"arn:aws:ec2:*:{self.account}:instance/*",
                        f"arn:aws:ssm:*:{self.account}:managed-instance/*",
                    ],
                ),
            ],
        )

        break_glass_principal: iam.IPrincipal = (
            iam.CompositePrincipal(*(iam.ArnPrincipal(a) for a in break_glass_principal_arns))
            if break_glass_principal_arns
            else iam.AccountRootPrincipal()
        )
        if break_glass_require_mfa:
            break_glass_principal = iam.PrincipalWithConditions(
                break_glass_principal, {"Bool": {"aws:MultiFactorAuthPresent": "true"}}
            )
        break_glass_role = iam.Role(
            self,
            "WarrenBreakGlassRole",
            role_name=f"warren-break-glass-{env_suffix}",
            assumed_by=break_glass_principal,
            max_session_duration=cdk.Duration.hours(1),
            description="The only warren role with cluster-wide ECS Exec and SSM sessions (AI1)",
        )
        break_glass_role.attach_inline_policy(
            iam.Policy(
                self,
                "WarrenBreakGlassPolicy",
                policy_name="WarrenBreakGlassExec",
                statements=[
                    iam.PolicyStatement(
                        sid="DescribeClusterTasks",
                        actions=["ecs:DescribeTasks", "ecs:ListTasks"],
                        resources=["*"],
                        conditions=in_cluster,
                    ),
                    iam.PolicyStatement(
                        sid="ClusterWideExec",
                        actions=["ecs:ExecuteCommand"],
                        resources=[workspace_task_arns, cluster.cluster_arn],
                        conditions=in_cluster,
                    ),
                    iam.PolicyStatement(
                        sid="ClusterWideSsmSessions",
                        actions=["ssm:StartSession"],
                        resources=[
                            workspace_task_arns,
                            f"arn:aws:ssm:{self.region}::document/AWS-StartPortForwardingSession",
                            f"arn:aws:ssm:{self.region}::document/AWS-StartPortForwardingSessionToRemoteHost",
                        ],
                    ),
                    iam.PolicyStatement(
                        sid="OwnSessions",
                        actions=["ssm:TerminateSession", "ssm:ResumeSession"],
                        resources=["arn:aws:ssm:*:*:session/${aws:userid}-*"],
                    ),
                ],
            )
        )
        cdk.CfnOutput(
            self,
            "WarrenWorkspaceOperatorPolicyArn",
            value=workspace_operator_policy.managed_policy_arn,
            description="Managed policy for humans who `warren connect`: ECS Exec only into their own tasks (AI1)",
            export_name=f"WarrenWorkspaceOperatorPolicyArn-{env_suffix}",
        )
        cdk.CfnOutput(
            self,
            "WarrenBreakGlassRoleArn",
            value=break_glass_role.role_arn,
            description="The only role with cluster-wide ECS Exec and SSM sessions (AI1)",
            export_name=f"WarrenBreakGlassRoleArn-{env_suffix}",
        )

        # ---------------------------------------------------------------
        # WARREN_SECRET_KEY — finding #19b. Previously deferred to a runbook requiring a
        # plaintext env override on a one-off `run-task` call, which exposes the key in
        # plaintext to anyone who can see that invocation (T-07-01). This stack now
        # generates and owns the value directly as a Secrets Manager secret, wired into
        # the task definition's `secrets` block below (resolved by the execution role at
        # container start, never appearing in the task definition or RunTask call as
        # plaintext — the same mechanism already used for per-workspace secrets, see
        # ecs.py's secret_defs). Secrets Manager, not SSM, because CloudFormation's
        # AWS::SSM::Parameter resource cannot create a SecureString parameter at all
        # (unlike Terraform's aws_ssm_parameter, which calls the SSM API directly) —
        # mirrors terraform/main.tf's random_password/aws_ssm_parameter.warren_secret_key
        # in spirit, using the CDK-idiomatic equivalent.
        control_plane_secret = secretsmanager.Secret(
            self,
            "WarrenControlPlaneSecretKey",
            secret_name=f"{ecs_resource_prefix}-{env_suffix}-secret-key",
            description="WARREN_SECRET_KEY for the warren-server control-plane task",
            generate_secret_string=secretsmanager.SecretStringGenerator(
                password_length=64,
                exclude_punctuation=True,
            ),
            encryption_key=(
                kms.Key.from_key_arn(self, "WarrenSecretKeyKmsKey", kms_key_id)
                if kms_key_id
                else None
            ),
        )

        # ---------------------------------------------------------------
        # Task Execution Role (used by ECS agent — image pull, log delivery)
        # D-07: managed policy + logs:CreateLogGroup supplement (Pitfall 2)
        # ---------------------------------------------------------------
        exec_role = iam.Role(
            self,
            "WarrenTaskExecRole",
            role_name=f"warren-task-exec-role-{env_suffix}",
            assumed_by=iam.ServicePrincipal("ecs-tasks.amazonaws.com"),
            description="ECS task execution role for warren — image pull and log delivery",
        )
        exec_role.add_managed_policy(
            iam.ManagedPolicy.from_aws_managed_policy_name("AmazonECSTaskExecutionRolePolicy")
        )
        # Supplement: AmazonECSTaskExecutionRolePolicy does not include logs:CreateLogGroup,
        # but ecs.py uses awslogs-create-group=true — add it to avoid first-launch failure.
        # NOTE: this stays "/warren/*" (not ecs_resource_prefix-scoped) because the
        # control-plane task's own log group is hardcoded to
        # "/warren/control-plane-{env_suffix}" below, independent of ecs_resource_prefix
        # (which only renames per-workspace resources at runtime) — see the matching note
        # in terraform/main.tf's exec_log_policy.
        exec_role.add_to_policy(
            iam.PolicyStatement(
                sid="LogGroupCreate",
                effect=iam.Effect.ALLOW,
                actions=["logs:CreateLogGroup"],
                resources=["arn:aws:logs:*:*:log-group:/warren/*"],
            )
        )
        # finding #19b: WARREN_SECRET_KEY is sourced from Secrets Manager (control_plane_secret
        # above), not SSM — CloudFormation's AWS::SSM::Parameter resource (what CDK's
        # ssm.StringParameter synthesizes to) cannot create a SecureString parameter at all,
        # unlike Terraform's aws_ssm_parameter, which calls the SSM API directly. Secrets
        # Manager is CDK's standard workaround for a stack-generated secret value, and the
        # execution role (not the task role) is what ECS uses to resolve a `secrets` block
        # entry at container start. `grant_read` (rather than a hand-written
        # PolicyStatement) also covers the customer-managed-KMS case automatically — when
        # control_plane_secret.encryption_key is set, it adds the matching kms:Decrypt
        # grant on that specific key for us.
        control_plane_secret.grant_read(exec_role)

        # Workspace tasks get no `secrets` entries (their secrets arrive as a file on their
        # EFS volume, runtime/ecs_secrets.py), so this role needs no SSM access at all.

        # ---------------------------------------------------------------
        # Workspace Task Role — used by spawned per-workspace Fargate tasks.
        # Deliberately NOT the same role as task_role below: the control-plane's
        # own task_role carries ecs:RunTask/RegisterTaskDefinition/PassRole and
        # EFS access-point management, none of which a spawned workspace task
        # should have. Previously WARREN_ECS_TASK_ROLE_ARN pointed workspace
        # tasks at the control-plane's own task_role, so any workspace (running
        # untrusted agent-generated code) inherited the full orchestration
        # permission set — able to spawn more tasks, read every /warren/* SSM
        # parameter name, or create/delete EFS access points for other
        # workspaces. This role is the actual isolation boundary between the
        # orchestrator and what it orchestrates. Mirrors terraform/main.tf's
        # aws_iam_role.workspace_task_role.
        # ---------------------------------------------------------------
        # ---------------------------------------------------------------
        # EBS workspace storage (warren-server runtime/ebs.py, runtime/ecs_kms_secrets.py),
        # only when ebs_enabled. ECS creates and attaches each launch's volume through the
        # infrastructure role (deleteOnTermination=false, so ECS never deletes it); the
        # control plane snapshots a stopped workspace's volume, deletes it, restores from
        # the snapshot on the next launch and deletes everything on destroy, all scoped by
        # the bare `warren=true` tag runtime/ebs.py puts on every volume and snapshot.
        # Fargate allows one EBS volume per task, platform 1.4.0+. Mirrors
        # terraform/main.tf's aws_iam_role.ecs_infra / aws_kms_key.warren_secrets.
        # ---------------------------------------------------------------
        ecs_infra_role = None
        secrets_key_arn = ""
        if ebs_enabled:
            ecs_infra_role = iam.Role(
                self,
                "WarrenEcsInfraRole",
                role_name=f"warren-ecs-infra-role-{env_suffix}",
                assumed_by=iam.ServicePrincipal("ecs.amazonaws.com"),
                description="ECS infrastructure role for warren workspace EBS volumes",
            )
            # Lets ECS create/attach/detach/delete only volumes it manages (AmazonECSCreated/
            # AmazonECSManaged tags); its tag-on-create grant keys on those ECS tags, so
            # warren's own volume tags ride along in the same CreateVolume call.
            ecs_infra_role.add_managed_policy(
                iam.ManagedPolicy.from_aws_managed_policy_name(
                    "service-role/AmazonECSInfrastructureRolePolicyForVolumes"
                )
            )
            if ebs_kms_key_arn:
                # The managed policy carries no KMS grants: a customer-managed volume key
                # needs them here.
                ecs_infra_role.add_to_policy(
                    iam.PolicyStatement(
                        sid="EBSVolumeKMS",
                        effect=iam.Effect.ALLOW,
                        actions=[
                            "kms:GenerateDataKeyWithoutPlaintext",
                            "kms:ReEncrypt*",
                            "kms:Decrypt",
                            "kms:DescribeKey",
                        ],
                        resources=[ebs_kms_key_arn],
                        conditions={"StringEquals": {"kms:ViaService": f"ec2.{self.region}.amazonaws.com"}},
                    )
                )
                ecs_infra_role.add_to_policy(
                    iam.PolicyStatement(
                        sid="EBSVolumeKMSGrant",
                        effect=iam.Effect.ALLOW,
                        actions=["kms:CreateGrant"],
                        resources=[ebs_kms_key_arn],
                        conditions={
                            "StringEquals": {"kms:ViaService": f"ec2.{self.region}.amazonaws.com"},
                            "Bool": {"kms:GrantIsForAWSResource": "true"},
                        },
                    )
                )
            # Secrets delivery key: the control plane may only GenerateDataKey, the
            # workspace task role only Decrypt, both only under warren's encryption context.
            if secrets_kms_key_arn:
                secrets_key_arn = secrets_kms_key_arn
            else:
                secrets_key_arn = kms.Key(
                    self,
                    "WarrenSecretsKey",
                    description=f"warren {env_suffix}: EBS-mode workspace secrets delivery",
                    enable_key_rotation=True,
                ).key_arn
        # Only warren's own encryption context: GenerateDataKey/Decrypt need the workspace
        # id key present and carry no other context keys.
        secrets_context_conditions = {
            "Null": {"kms:EncryptionContext:warren:workspace_id": "false"},
            "ForAllValues:StringEquals": {
                "kms:EncryptionContextKeys": ["warren:workspace_id", "warren:container"]
            },
        }

        # AD1: Fargate allows no sandbox inside a task, so whatever this role grants, the
        # agent holds. Keep it minimal (tests/unit/test_iac_exec_scoping.py in warren-server).
        workspace_task_role = iam.Role(
            self,
            "WarrenWorkspaceTaskRole",
            role_name=f"warren-workspace-task-role-{env_suffix}",
            assumed_by=iam.ServicePrincipal("ecs-tasks.amazonaws.com"),
            description="ECS task role for spawned workspace tasks — ECS Exec + EFS mount only",
        )
        workspace_task_role.attach_inline_policy(
            iam.Policy(
                self,
                "WarrenWorkspaceTaskPolicy",
                policy_name=f"warren-workspace-task-policy-{env_suffix}",
                statements=[
                    iam.PolicyStatement(
                        sid="ECSExec",
                        effect=iam.Effect.ALLOW,
                        actions=[
                            "ssmmessages:CreateControlChannel",
                            "ssmmessages:CreateDataChannel",
                            "ssmmessages:OpenControlChannel",
                            "ssmmessages:OpenDataChannel",
                        ],
                        resources=["*"],
                    ),
                    # Deliberately NOT granting ssm:GetParameter/secretsmanager:GetSecretValue
                    # here — a single role shared by every workspace can't express "only your
                    # own secret", so no secret-read permission is granted at the task-role
                    # level at all; values are resolved by the execution role via the task
                    # definition's `secrets` block instead.
                    #
                    # "Only your own secret" is now solved one layer up, before RunTask ever
                    # happens: the orchestrator (warren-server, running as the task role above)
                    # resolves which SSM parameters to reference per task by verifying the
                    # calling operator's real AWS identity (warren/auth/aws_identity.py — a
                    # presigned sts:GetCallerIdentity URL, never raw credentials) and scoping
                    # its SSM secret paths to that identity's own path segment under
                    # /warren/*. No new IAM permissions were needed for this — it's additive
                    # path structure under the wildcard resources already granted above.
                    *(
                        [
                            iam.PolicyStatement(
                                sid="EFSClientAccess",
                                effect=iam.Effect.ALLOW,
                                actions=[
                                    "elasticfilesystem:ClientMount",
                                    "elasticfilesystem:ClientWrite",
                                ],
                                resources=[efs_fs.file_system_arn],
                            ),
                        ]
                        if efs_fs is not None
                        else []
                    ),
                    # Audit finding #42 / S11: the ECS Exec agent (running as this task
                    # role, not the execution role) needs explicit CloudWatch Logs access
                    # to stream exec session output into ecs_exec_log_group above, plus
                    # KMS access if that log group is encrypted. Mirrors
                    # terraform/main.tf's workspace_task_role_policy ECSExecLogging/
                    # ECSExecLogKMS statements.
                    iam.PolicyStatement(
                        sid="ECSExecLogging",
                        effect=iam.Effect.ALLOW,
                        actions=[
                            "logs:DescribeLogGroups",
                            "logs:CreateLogStream",
                            "logs:DescribeLogStreams",
                            "logs:PutLogEvents",
                        ],
                        resources=[
                            ecs_exec_log_group.log_group_arn,
                            f"{ecs_exec_log_group.log_group_arn}:*",
                        ],
                    ),
                    *(
                        [
                            iam.PolicyStatement(
                                sid="ECSExecLogKMS",
                                effect=iam.Effect.ALLOW,
                                actions=["kms:Decrypt", "kms:GenerateDataKey"],
                                resources=[kms_key_id],
                            ),
                        ]
                        if kms_key_id
                        else []
                    ),
                    # EBS storage: warren-secrets-decrypt in the image (entrypoint and
                    # git-init) unwraps the task's WARREN_SECRETS_BLOB with this role, only
                    # under warren's encryption context; the control plane binds each
                    # envelope to one workspace and one container. Tasks must reach KMS:
                    # the NAT gateway (create_vpc) or a com.amazonaws.<region>.kms VPC
                    # endpoint. Mirrors terraform/main.tf's WorkspaceSecretsDecrypt.
                    *(
                        [
                            iam.PolicyStatement(
                                sid="WorkspaceSecretsDecrypt",
                                effect=iam.Effect.ALLOW,
                                actions=["kms:Decrypt"],
                                resources=[secrets_key_arn],
                                conditions=secrets_context_conditions,
                            ),
                        ]
                        if ebs_enabled
                        else []
                    ),
                ],
            )
        )

        # ---------------------------------------------------------------
        # Task Role (used by warren-server running inside the Fargate task)
        # D-06: five permission statements derived from ecs.py boto3 calls
        # ---------------------------------------------------------------
        task_role = iam.Role(
            self,
            "WarrenTaskRole",
            role_name=f"warren-task-role-{env_suffix}",
            assumed_by=iam.ServicePrincipal("ecs-tasks.amazonaws.com"),
            description="ECS task role for warren-server — ECS, IAM PassRole, SSM, ECS Exec, Logs",
        )
        task_role.attach_inline_policy(
            iam.Policy(
                self,
                "WarrenTaskPolicy",
                policy_name=f"warren-task-policy-{env_suffix}",
                statements=[
                    # ECSCluster — T-08-02-01: ecs:DescribeClusters is the one action here
                    # actually authorized against the cluster ARN (finding #21: its resource
                    # type really is "cluster"); kept as its own statement.
                    # X1: reference the real cluster resource directly rather than guessing
                    # its ARN from ecs_resource_prefix -- the cluster's own name
                    # ("warren-cluster-{env_suffix}") is not derived from that prefix, so a
                    # prefix-pattern Resource silently stopped matching (and
                    # DescribeClusters started failing the control plane's own startup
                    # check) for any non-default prefix.
                    iam.PolicyStatement(
                        sid="ECSCluster",
                        effect=iam.Effect.ALLOW,
                        actions=["ecs:DescribeClusters"],
                        resources=[cluster.cluster_arn],
                    ),
                    # finding #21: ecs:StopTask and ecs:DescribeTasks actually authorize
                    # against the TASK ARN (resource type "task"), not the cluster ARN — a
                    # Resource of "arn:aws:ecs:*:*:cluster/warren-*" (the previous shape)
                    # never scoped these two actions at all. The ecs:cluster condition key
                    # (not the Resource field) is how AWS's own docs scope these two actions
                    # to a specific cluster. Mirrors terraform/main.tf's ECSTaskScoped
                    # statement.
                    iam.PolicyStatement(
                        sid="ECSTaskScoped",
                        effect=iam.Effect.ALLOW,
                        actions=["ecs:StopTask", "ecs:DescribeTasks"],
                        resources=["arn:aws:ecs:*:*:task/*"],
                        conditions={"ArnEquals": {"ecs:cluster": cluster.cluster_arn}},
                    ),
                    # #59: server-mode exec relay (ecs:ExecuteCommand after the control
                    # plane's own owner check). Mirrors terraform/main.tf's ECSExecWorkspaceTasks.
                    iam.PolicyStatement(
                        sid="ECSExecWorkspaceTasks",
                        effect=iam.Effect.ALLOW,
                        actions=["ecs:ExecuteCommand"],
                        resources=[
                            f"arn:aws:ecs:*:*:task/{cluster.cluster_name}/*",
                            cluster.cluster_arn,
                        ],
                        conditions={"ArnEquals": {"ecs:cluster": cluster.cluster_arn}},
                    ),
                    # AI3: orphan sweep. Fargate ListTasks authorizes against "*"; the
                    # ecs:cluster condition scopes it. Mirrors terraform/main.tf's ECSListTasks.
                    iam.PolicyStatement(
                        sid="ECSListTasks",
                        effect=iam.Effect.ALLOW,
                        actions=["ecs:ListTasks"],
                        resources=["*"],
                        conditions={"ArnEquals": {"ecs:cluster": cluster.cluster_arn}},
                    ),
                    # ECSRunTask — T-08-03-01: task-definition-scoped, restricted to
                    # {ecs_resource_prefix}-* families and (finding #21) additionally to this
                    # cluster via the ecs:cluster condition key -- only RunTask actually
                    # supports and is scoped by ecs:cluster here.
                    iam.PolicyStatement(
                        sid="ECSRunTask",
                        effect=iam.Effect.ALLOW,
                        actions=["ecs:RunTask"],
                        resources=[f"arn:aws:ecs:*:*:task-definition/{ecs_resource_prefix}-*"],
                        conditions={"ArnEquals": {"ecs:cluster": cluster.cluster_arn}},
                    ),
                    # S13/R17: an ArnEquals condition on a key an action doesn't support
                    # evaluates to FALSE, not "ignored" -- DeregisterTaskDefinition has no
                    # ecs:cluster condition key, so folding it into ECSRunTask's
                    # ecs:cluster-conditioned statement above unconditionally denied it
                    # (no other Allow covers it), piling up task definition revisions
                    # forever. DeregisterTaskDefinition does support resource-level scoping
                    # by the task-definition ARN itself, so it gets its own, unconditioned
                    # statement instead. Mirrors terraform/main.tf's
                    # ECSDeregisterTaskDefinition.
                    iam.PolicyStatement(
                        sid="ECSDeregisterTaskDefinition",
                        effect=iam.Effect.ALLOW,
                        actions=["ecs:DeregisterTaskDefinition"],
                        resources=[f"arn:aws:ecs:*:*:task-definition/{ecs_resource_prefix}-*"],
                    ),
                    # R21: ECSRunTask's Allow above, necessarily wildcarded over every
                    # workspace family (ecs.py's _slug can't be enumerated in advance),
                    # also matches the control-plane's own family
                    # ("warren-server-control-plane-{env_suffix}" below, which starts with
                    # "{ecs_resource_prefix}-" by default) — the ecs:cluster condition
                    # doesn't help, since the control plane runs on this same cluster. An
                    # explicit Deny (which IAM always evaluates ahead of any Allow) closes
                    # this without narrowing the workspace wildcard or renaming the
                    # control-plane's own family (a user-visible, blind change). Mirrors
                    # terraform/main.tf's ECSDenySelfRunTask.
                    # X2: ECSDeregisterTaskDefinition above is unconditioned
                    # (DeregisterTaskDefinition takes no ecs:cluster condition key), so its
                    # wildcard also matches the control plane's own family -- same
                    # self-match class as RunTask, so the Deny covers both actions.
                    iam.PolicyStatement(
                        sid="ECSDenySelfRunTask",
                        effect=iam.Effect.DENY,
                        actions=["ecs:RunTask", "ecs:DeregisterTaskDefinition"],
                        resources=[
                            f"arn:aws:ecs:*:*:task-definition/warren-server-control-plane-{env_suffix}:*"
                        ],
                    ),
                    # finding #21: ecs:RegisterTaskDefinition does not support resource-level
                    # permissions at all — AWS's own "Supported Resource-Level Permissions
                    # for Amazon ECS APIs" reference lists it as requiring Resource = "*"; a
                    # Resource pattern like "task-definition/warren-*" on this action looks
                    # like real scoping but authorizes nothing beyond what "*" already would.
                    # Kept in its own statement, with this comment in place of a Resource
                    # pattern that would be misleading.
                    iam.PolicyStatement(
                        sid="ECSRegisterTaskDefinition",
                        effect=iam.Effect.ALLOW,
                        actions=["ecs:RegisterTaskDefinition"],
                        resources=["*"],
                    ),
                    # finding #21: ecs:TagResource is required whenever RunTask/
                    # RegisterTaskDefinition is called with a `tags=` argument
                    # (tag-on-create) — previously granted nowhere. Split into one
                    # statement per resource type (R21) so each carries the condition keys
                    # that actually apply to it: ecs:cluster only makes sense for a task/*
                    # tag-on-create (RunTask), not a task-definition/* one
                    # (RegisterTaskDefinition, no cluster at registration time); both get
                    # ecs:CreateAction, restricting this permission to tagging performed as
                    # part of RunTask/RegisterTaskDefinition specifically, not a standalone
                    # TagResource call against an existing resource (AWS's "Grant
                    # permission to tag resources on creation" guide for ECS). Mirrors
                    # terraform/main.tf's ECSTagOnCreateTask/ECSTagOnCreateTaskDef.
                    iam.PolicyStatement(
                        sid="ECSTagOnCreateTask",
                        effect=iam.Effect.ALLOW,
                        actions=["ecs:TagResource"],
                        resources=["arn:aws:ecs:*:*:task/*"],
                        conditions={
                            "ArnEquals": {"ecs:cluster": cluster.cluster_arn},
                            "StringEquals": {"ecs:CreateAction": "RunTask"},
                        },
                    ),
                    iam.PolicyStatement(
                        sid="ECSTagOnCreateTaskDef",
                        effect=iam.Effect.ALLOW,
                        actions=["ecs:TagResource"],
                        resources=[f"arn:aws:ecs:*:*:task-definition/{ecs_resource_prefix}-*"],
                        conditions={
                            "StringEquals": {"ecs:CreateAction": "RegisterTaskDefinition"}
                        },
                    ),
                    # PassRole — T-08-02-02: scoped to the two roles actually passed when
                    # registering a workspace task definition (execution + workspace task
                    # role) — NOT this role itself and not the control-plane's own
                    # task_role_arn (that's set directly in the CfnTaskDefinition below by
                    # CDK's own deploy credentials, not an IAM-authorized runtime call).
                    iam.PolicyStatement(
                        sid="PassRole",
                        effect=iam.Effect.ALLOW,
                        actions=["iam:PassRole"],
                        resources=[exec_role.role_arn, workspace_task_role.role_arn],
                    ),
                    # No SSM action at all: workspace secrets live only in warren's own
                    # SQLite store and reach a task as a file on its EFS volume, written
                    # through the warren-efs-root mount. Mirrors terraform/main.tf.
                    # ECS Exec into this task with an encrypted session/log key. Not an SSM
                    # read: this role can never obtain a SecureString's ciphertext.
                    *(
                        [
                            iam.PolicyStatement(
                                sid="ECSExecLogKMS",
                                effect=iam.Effect.ALLOW,
                                actions=["kms:Decrypt", "kms:GenerateDataKey"],
                                resources=[kms_key_id],
                            ),
                        ]
                        if kms_key_id
                        else []
                    ),
                    # ECSExec — ssmmessages for ECS Exec (warren shell access)
                    iam.PolicyStatement(
                        sid="ECSExec",
                        effect=iam.Effect.ALLOW,
                        actions=[
                            "ssmmessages:CreateControlChannel",
                            "ssmmessages:CreateDataChannel",
                            "ssmmessages:OpenControlChannel",
                            "ssmmessages:OpenDataChannel",
                        ],
                        resources=["*"],
                    ),
                    # Logs — CloudWatch Logs for warren tasks
                    # Audit S4/#53: logs:PutRetentionPolicy was missing here (Terraform
                    # already had it) -- the control plane itself creates each workspace
                    # log group and sets bounded retention on it directly, rather than
                    # relying on the ECS agent's "awslogs-create-group" auto-create
                    # (infinite retention, no way to expire). Without it, every ECS
                    # provision under this CDK path hit AccessDenied.
                    iam.PolicyStatement(
                        sid="Logs",
                        effect=iam.Effect.ALLOW,
                        actions=[
                            "logs:CreateLogGroup",
                            "logs:CreateLogStream",
                            "logs:PutLogEvents",
                            "logs:PutRetentionPolicy",
                        ],
                        resources=["arn:aws:logs:*:*:log-group:/warren/*"],
                    ),
                    # Audit finding #42 (control-plane half) / S11: an operator running
                    # `aws ecs execute-command` into the CONTROL-PLANE task itself (not a
                    # spawned workspace task) assumes this role, not
                    # workspace_task_role — the ECSExecLogging statement on that role
                    # never covers this case. Mirrors it exactly, and
                    # terraform/main.tf's task_role_policy ECSExecLogging statement.
                    iam.PolicyStatement(
                        sid="ECSExecLogging",
                        effect=iam.Effect.ALLOW,
                        actions=[
                            "logs:DescribeLogGroups",
                            "logs:CreateLogStream",
                            "logs:DescribeLogStreams",
                            "logs:PutLogEvents",
                        ],
                        resources=[
                            ecs_exec_log_group.log_group_arn,
                            f"{ecs_exec_log_group.log_group_arn}:*",
                        ],
                    ),
                    # EFS — workspace persistence (D-08); only added when EFS is provisioned.
                    # Split action-by-action rather than one combined statement:
                    # ClientMount/ClientWrite/DescribeMountTargets and CreateAccessPoint are
                    # both scoped to the filesystem ARN but need different conditions
                    # (RequestTag only makes sense for a *create* call), and TagResource
                    # targets a different resource type (the access-point ARN, not the
                    # filesystem ARN) entirely. Mirrors terraform/main.tf's EFSClientAccess/
                    # EFSCreateAccessPoint/EFSTagAccessPointsOnCreate split.
                    *(
                        [
                            iam.PolicyStatement(
                                sid="EFSClientAccess",
                                effect=iam.Effect.ALLOW,
                                actions=[
                                    "elasticfilesystem:ClientMount",
                                    "elasticfilesystem:ClientWrite",
                                    "elasticfilesystem:DescribeMountTargets",
                                    # efs.py's reattach and the reaper list access points.
                                    "elasticfilesystem:DescribeAccessPoints",
                                ],
                                resources=[efs_fs.file_system_arn],
                            ),
                            # RequestTag enforces that every access point this role creates
                            # carries the `warren` tag (src/warren/runtime/efs.py's
                            # TAG_MANAGED) — without it, EFSDeleteTaggedAccessPoints' tag
                            # condition below can never match an access point created
                            # without that tag, making it permanently undeletable via this
                            # policy.
                            iam.PolicyStatement(
                                sid="EFSCreateAccessPoint",
                                effect=iam.Effect.ALLOW,
                                actions=["elasticfilesystem:CreateAccessPoint"],
                                resources=[efs_fs.file_system_arn],
                                conditions={
                                    "StringEquals": {"aws:RequestTag/warren": "true"}
                                },
                            ),
                            # CreateAccessPoint with inline Tags performs its own secondary
                            # TagResource authorization check, against the access-point ARN
                            # being created — not the filesystem ARN. The CreateAction
                            # condition restricts this to tagging performed as part of a
                            # CreateAccessPoint call specifically, not a standalone
                            # TagResource call against an existing access point.
                            iam.PolicyStatement(
                                sid="EFSTagAccessPointsOnCreate",
                                effect=iam.Effect.ALLOW,
                                actions=["elasticfilesystem:TagResource"],
                                resources=[
                                    f"arn:aws:elasticfilesystem:{self.region}:{self.account}:access-point/*"
                                ],
                                conditions={
                                    "StringEquals": {
                                        "aws:RequestTag/warren": "true",
                                        "elasticfilesystem:CreateAction": "CreateAccessPoint",
                                    }
                                },
                            ),
                            iam.PolicyStatement(
                                sid="EFSDeleteTaggedAccessPoints",
                                effect=iam.Effect.ALLOW,
                                actions=["elasticfilesystem:DeleteAccessPoint"],
                                resources=[
                                    f"arn:aws:elasticfilesystem:{self.region}:{self.account}:access-point/*"
                                ],
                                conditions={
                                    "StringEquals": {
                                        "aws:ResourceTag/warren": "true"
                                    }
                                },
                            ),
                            # finding #16: efs.py's detach() calls a standalone TagResource
                            # (setting warren.expires_at so the idle reaper knows when to
                            # delete the access point) and the subsequent reattach calls
                            # UntagResource to take that tag back off. Neither was granted
                            # anywhere — EFSTagAccessPointsOnCreate above is restricted by its
                            # CreateAction condition to tagging performed as part of
                            # CreateAccessPoint itself, so it never authorizes this standalone
                            # call. Without this, detach()'s TagResource fails (only logged),
                            # access points never actually expire, and reattach's
                            # UntagResource raises outright. Scoped by aws:TagKeys/
                            # ForAllValues to just the two tag keys this lifecycle path
                            # actually sets/removes, narrower than the filesystem-wide access
                            # already granted for creation. Mirrors terraform/main.tf's
                            # EFSLifecycleTagging statement.
                            # R18: scoped with aws:ResourceTag conditions — the bare
                            # "warren" tag (set by efs.py's attach() on every access
                            # point this role creates, same tag EFSDeleteTaggedAccessPoints
                            # above already checks) and warren.server_instance (set to
                            # this server's own WARREN_SERVER_ID at creation) — so one
                            # warren-server deployment can't retag another's access
                            # points even within the same account. aws:TagKeys/
                            # ForAllValues is also narrowed to just warren.expires_at:
                            # efs.py's detach()/reattach() path (the only caller of this
                            # standalone TagResource/UntagResource) never touches
                            # warren.owner_id, so dropping it means ownership, once set
                            # by EFSTagAccessPointsOnCreate at creation, can no longer be
                            # changed by any standalone call this role is granted.
                            # Mirrors terraform/main.tf's EFSLifecycleTagging statement.
                            iam.PolicyStatement(
                                sid="EFSLifecycleTagging",
                                effect=iam.Effect.ALLOW,
                                actions=[
                                    "elasticfilesystem:TagResource",
                                    "elasticfilesystem:UntagResource",
                                ],
                                resources=[
                                    f"arn:aws:elasticfilesystem:{self.region}:{self.account}:access-point/*"
                                ],
                                conditions={
                                    "ForAllValues:StringEquals": {
                                        "aws:TagKeys": ["warren.expires_at"]
                                    },
                                    "StringEquals": {
                                        "aws:ResourceTag/warren": "true",
                                        "aws:ResourceTag/warren.server_instance": (
                                            f"warren-server-control-plane-{env_suffix}"
                                        ),
                                    },
                                },
                            ),
                        ]
                        if efs_fs is not None
                        else []
                    ),
                ],
            )
        )

        # EBS workspace storage: its own policy (mirrors terraform/main.tf's
        # ebs_task_role_policy), so WarrenTaskPolicy's only kms:Decrypt stays ECS Exec's.
        if ebs_enabled and ecs_infra_role is not None:
            task_role.attach_inline_policy(
                iam.Policy(
                    self,
                    "WarrenEbsStoragePolicy",
                    policy_name=f"warren-ebs-storage-policy-{env_suffix}",
                    statements=[
                        iam.PolicyStatement(
                            sid="EBSPassInfraRole",
                            effect=iam.Effect.ALLOW,
                            actions=["iam:PassRole"],
                            resources=[ecs_infra_role.role_arn],
                            conditions={"StringEquals": {"iam:PassedToService": "ecs.amazonaws.com"}},
                        ),
                        # Describe* has no resource-level permissions; runtime/ebs.py
                        # filters on its own tags.
                        iam.PolicyStatement(
                            sid="EBSDescribe",
                            effect=iam.Effect.ALLOW,
                            actions=["ec2:DescribeVolumes", "ec2:DescribeSnapshots"],
                            resources=["*"],
                        ),
                        # CreateSnapshot authorizes against both the source volume and the
                        # new snapshot.
                        iam.PolicyStatement(
                            sid="EBSSnapshotManagedVolume",
                            effect=iam.Effect.ALLOW,
                            actions=["ec2:CreateSnapshot"],
                            resources=["arn:aws:ec2:*:*:volume/*"],
                            conditions={"StringEquals": {"aws:ResourceTag/warren": "true"}},
                        ),
                        iam.PolicyStatement(
                            sid="EBSCreateTaggedSnapshot",
                            effect=iam.Effect.ALLOW,
                            actions=["ec2:CreateSnapshot"],
                            resources=["arn:aws:ec2:*::snapshot/*"],
                            conditions={"StringEquals": {"aws:RequestTag/warren": "true"}},
                        ),
                        iam.PolicyStatement(
                            sid="EBSTagSnapshotOnCreate",
                            effect=iam.Effect.ALLOW,
                            actions=["ec2:CreateTags"],
                            resources=["arn:aws:ec2:*::snapshot/*"],
                            conditions={"StringEquals": {"ec2:CreateAction": "CreateSnapshot"}},
                        ),
                        iam.PolicyStatement(
                            sid="EBSDeleteManaged",
                            effect=iam.Effect.ALLOW,
                            actions=["ec2:DeleteVolume", "ec2:DeleteSnapshot"],
                            resources=["arn:aws:ec2:*:*:volume/*", "arn:aws:ec2:*::snapshot/*"],
                            conditions={"StringEquals": {"aws:ResourceTag/warren": "true"}},
                        ),
                        # No kms:Decrypt: the control plane only wraps, the task role unwraps.
                        iam.PolicyStatement(
                            sid="SecretsGenerateDataKey",
                            effect=iam.Effect.ALLOW,
                            actions=["kms:GenerateDataKey"],
                            resources=[secrets_key_arn],
                            conditions=secrets_context_conditions,
                        ),
                        # Snapshotting a volume encrypted with a customer-managed key goes
                        # through that key.
                        *(
                            [
                                iam.PolicyStatement(
                                    sid="EBSVolumeKMS",
                                    effect=iam.Effect.ALLOW,
                                    actions=[
                                        "kms:CreateGrant",
                                        "kms:GenerateDataKeyWithoutPlaintext",
                                        "kms:ReEncrypt*",
                                        "kms:Decrypt",
                                        "kms:DescribeKey",
                                    ],
                                    resources=[ebs_kms_key_arn],
                                    conditions={
                                        "StringEquals": {"kms:ViaService": f"ec2.{self.region}.amazonaws.com"}
                                    },
                                ),
                            ]
                            if ebs_kms_key_arn
                            else []
                        ),
                    ],
                )
            )

        # ---------------------------------------------------------------
        # CfnOutputs — WARREN_ECS_* env vars (D-03)
        # ---------------------------------------------------------------
        cdk.CfnOutput(
            self,
            "WARREN_ECS_CLUSTER",
            value=cluster.cluster_name,
            description="ECS cluster name — set as WARREN_ECS_CLUSTER",
            export_name=f"WarrenECSCluster-{env_suffix}",
        )
        cdk.CfnOutput(
            self,
            "WARREN_ECS_SUBNET_IDS",
            value=",".join(subnet_id_list),
            description="Comma-separated subnet IDs — set as WARREN_ECS_SUBNET_IDS",
            export_name=f"WarrenECSSubnetIds-{env_suffix}",
        )
        cdk.CfnOutput(
            self,
            "WARREN_ECS_SECURITY_GROUP_IDS",
            value=sg.security_group_id if sg is not None else "",
            description="Security group ID — set as WARREN_ECS_SECURITY_GROUP_IDS",
            export_name=f"WarrenECSSecurityGroupIds-{env_suffix}",
        )
        cdk.CfnOutput(
            self,
            "WARREN_ECS_TASK_ROLE_ARN",
            value=workspace_task_role.role_arn,
            description=(
                "Workspace task role ARN (NOT the control-plane's own task_role) — "
                "set as WARREN_ECS_TASK_ROLE_ARN"
            ),
            export_name=f"WarrenECSTaskRoleArn-{env_suffix}",
        )
        cdk.CfnOutput(
            self,
            "WARREN_ECS_TASK_EXECUTION_ROLE_ARN",
            value=exec_role.role_arn,
            description="Task execution role ARN — set as WARREN_ECS_TASK_EXECUTION_ROLE_ARN",
            export_name=f"WarrenECSTaskExecutionRoleArn-{env_suffix}",
        )
        # IMAGE_URI is a documentation output only — not a WarrenSettings field.
        # warren-server's ECSRuntime.provision() takes the image URI from
        # WorkspaceSpec.image at call time, not from settings.
        cdk.CfnOutput(
            self,
            "WARREN_ECS_IMAGE_URI",
            value=image_uri or "(not provided — pass via --context image_uri=...)",
            description="Container image URI (documentation only) — not a WarrenSettings field",
            export_name=f"WarrenECSImageUri-{env_suffix}",
        )
        # Always emitted (even when create_efs=False) so downstream tooling never has to
        # special-case a missing output — an empty value is expected and correct in that
        # case (app.py only constructs an EFSMount when settings.efs_id is truthy, so an
        # empty WARREN_EFS_ID keeps ECSRuntime(volume=None)). Mirrors terraform/outputs.tf.
        cdk.CfnOutput(
            self,
            "WarrenEFSId",
            value=efs_fs.file_system_id if efs_fs is not None else "",
            description=(
                "EFS file system ID — set as WARREN_EFS_ID. Empty is expected and "
                "correct when create_efs=False (the Phase 5 ECS POC default)."
            ),
            export_name=f"WarrenEFSId-{env_suffix}",
        )
        # EBS workspace storage; empty when not enabled. Mirrors terraform/outputs.tf.
        cdk.CfnOutput(
            self,
            "WarrenEcsEbsInfraRoleArn",
            value=ecs_infra_role.role_arn if ecs_infra_role is not None else "",
            description="ECS infrastructure role for workspace EBS volumes — set as WARREN_ECS_EBS_INFRA_ROLE_ARN",
            export_name=f"WarrenEcsEbsInfraRoleArn-{env_suffix}",
        )
        cdk.CfnOutput(
            self,
            "WarrenEcsSecretsKmsKeyArn",
            value=secrets_key_arn,
            description="KMS key for EBS-mode secrets delivery — set as WARREN_ECS_SECRETS_KMS_KEY_ID",
            export_name=f"WarrenEcsSecretsKmsKeyArn-{env_suffix}",
        )

        # ---------------------------------------------------------------
        # Control-plane task definition — warren-server running as its own
        # Fargate task, distinct from the per-workspace tasks ECSRuntime
        # launches at runtime. Launched as a long-lived ecs.CfnService below
        # (finding #19c), not a one-off `run-task` — mirrors terraform/main.tf's
        # aws_ecs_task_definition + aws_ecs_service.
        # ---------------------------------------------------------------
        control_plane_task_def = ecs.CfnTaskDefinition(
            self,
            "WarrenServerTaskDefinition",
            family=f"warren-server-control-plane-{env_suffix}",
            network_mode="awsvpc",
            requires_compatibilities=["FARGATE"],
            # 0.25 vCPU / 0.5 GB is the Fargate minimum and the cheapest entry in
            # VALID_FARGATE_PAIRS (src/warren/runtime/ecs.py), matching WarrenSettings'
            # ecs_cpu/ecs_memory defaults. Cost reasoning: an always-on task at this
            # size is roughly $9/month of Fargate compute, leaving headroom under the
            # $50/month ceiling (D-07.3) whose dominant line item is the Template A
            # NAT Gateway (~$32/month), not compute.
            cpu="256",
            memory="512",
            execution_role_arn=exec_role.role_arn,
            task_role_arn=task_role.role_arn,
            # Control-plane's own persistent state (SQLite registry + auth users/tokens
            # tables) — the WarrenControlPlaneAccessPoint created above, distinct from the
            # per-workspace access points ECSRuntime provisions at runtime (2026-09-21,
            # explicit operator decision). Empty when create_efs=False.
            volumes=(
                [
                    ecs.CfnTaskDefinition.VolumeProperty(
                        name="warren-data",
                        efs_volume_configuration=ecs.CfnTaskDefinition.EFSVolumeConfigurationProperty(
                            filesystem_id=efs_fs.file_system_id,
                            transit_encryption="ENABLED",
                            authorization_config=ecs.CfnTaskDefinition.AuthorizationConfigProperty(
                                access_point_id=control_plane_ap.access_point_id,
                                iam="ENABLED",
                            ),
                        ),
                    )
                ]
                if efs_fs is not None
                else []
            )
            + (
                # /var/lib/warren of the filesystem: secret delivery onto each workspace's
                # volume, and, with efs_delete_workspace_data_on_destroy, R13 purges.
                [
                    ecs.CfnTaskDefinition.VolumeProperty(
                        name="warren-efs-root",
                        efs_volume_configuration=ecs.CfnTaskDefinition.EFSVolumeConfigurationProperty(
                            filesystem_id=efs_fs.file_system_id,
                            transit_encryption="ENABLED",
                            authorization_config=ecs.CfnTaskDefinition.AuthorizationConfigProperty(
                                access_point_id=root_ap.access_point_id,
                                iam="ENABLED",
                            ),
                        ),
                    )
                ]
                if root_ap is not None
                else []
            ),
            container_definitions=[
                ecs.CfnTaskDefinition.ContainerDefinitionProperty(
                    name="warren-server",
                    image=control_plane_image,
                    essential=True,
                    port_mappings=[
                        ecs.CfnTaskDefinition.PortMappingProperty(
                            container_port=8420,
                            protocol="tcp",
                        )
                    ],
                    # Mounts the control-plane's own EFS access point (volumes= above) at
                    # WARREN_DATA_DIR's default path — matches the Podman path's warren-data
                    # named volume. Empty when create_efs=False, keeping /var/lib/warren on
                    # ephemeral task storage.
                    mount_points=(
                        [
                            ecs.CfnTaskDefinition.MountPointProperty(
                                source_volume="warren-data",
                                container_path="/var/lib/warren",
                                read_only=False,
                            )
                        ]
                        if efs_fs is not None
                        else []
                    )
                    + (
                        # Matches WARREN_EFS_LOCAL_MOUNT_PATH below.
                        [
                            ecs.CfnTaskDefinition.MountPointProperty(
                                source_volume="warren-efs-root",
                                container_path="/mnt/warren-efs-root",
                                read_only=False,
                            )
                        ]
                        if root_ap is not None
                        else []
                    ),
                    # Required for `aws ecs execute-command` into this task (POC-02).
                    linux_parameters=ecs.CfnTaskDefinition.LinuxParametersProperty(
                        init_process_enabled=True
                    ),
                    # finding #19b: the secret key is sourced via `secrets` (below), not a
                    # plaintext environment value — resolved by the execution role from
                    # Secrets Manager at container start, never appearing in the task
                    # definition or a RunTask call as plaintext.
                    secrets=[
                        ecs.CfnTaskDefinition.SecretProperty(
                            name="WARREN_SECRET_KEY",
                            value_from=control_plane_secret.secret_arn,
                        ),
                    ],
                    #
                    # WARREN_SERVER_ID (finding #19a): derived from the stable ECS service
                    # name, NOT the task's own ephemeral Fargate hostname (WarrenSettings.
                    # server_id's default) — the hostname changes on every restart, which
                    # orphans every SSM secret path under it, breaks the aws_audience value
                    # clients must match, breaks the EFS reaper's server_instance tag match,
                    # and creates a fresh CloudWatch log group per task.
                    #
                    # WARREN_EFS_ID (2026-09-21 reversal of the original "no EFS" POC
                    # scope, per explicit operator decision): when create_efs=True
                    # (now the default), this is set so app.py constructs an
                    # EFSMount and passes it into ECSRuntime(volume=...) — every
                    # workspace task ECSRuntime provisions then actually gets
                    # persistent storage via ECSRuntime.provision()'s existing
                    # EFS-mount wiring (already coded, previously left dormant
                    # here). Empty string when create_efs=False, which keeps
                    # ECSRuntime(volume=None) — ephemeral task storage only.
                    environment=[
                        ecs.CfnTaskDefinition.KeyValuePairProperty(
                            name="WARREN_SERVER_ID",
                            value=server_id,
                        ),
                        ecs.CfnTaskDefinition.KeyValuePairProperty(
                            name="WARREN_RUNTIME_TYPE", value="ecs"
                        ),
                        ecs.CfnTaskDefinition.KeyValuePairProperty(
                            name="WARREN_ECS_CLUSTER", value=cluster.cluster_name
                        ),
                        ecs.CfnTaskDefinition.KeyValuePairProperty(
                            name="WARREN_ECS_SUBNET_IDS", value=",".join(subnet_id_list)
                        ),
                        ecs.CfnTaskDefinition.KeyValuePairProperty(
                            name="WARREN_ECS_SECURITY_GROUP_IDS",
                            value=sg.security_group_id if sg is not None else "",
                        ),
                        ecs.CfnTaskDefinition.KeyValuePairProperty(
                            name="WARREN_ECS_TASK_ROLE_ARN", value=workspace_task_role.role_arn
                        ),
                        ecs.CfnTaskDefinition.KeyValuePairProperty(
                            name="WARREN_ECS_TASK_EXECUTION_ROLE_ARN",
                            value=exec_role.role_arn,
                        ),
                        ecs.CfnTaskDefinition.KeyValuePairProperty(
                            name="WARREN_AWS_REGION", value=self.region
                        ),
                        ecs.CfnTaskDefinition.KeyValuePairProperty(
                            name="WARREN_EFS_ID",
                            value=efs_fs.file_system_id if efs_fs is not None else "",
                        ),
                        # The warren-efs-root mount: secret delivery (runtime/ecs_secrets.py)
                        # and, only with efs_delete_workspace_data_on_destroy, R13 purges.
                        ecs.CfnTaskDefinition.KeyValuePairProperty(
                            name="WARREN_EFS_LOCAL_MOUNT_PATH",
                            value="/mnt/warren-efs-root" if root_ap is not None else "",
                        ),
                        ecs.CfnTaskDefinition.KeyValuePairProperty(
                            name="WARREN_EFS_PURGE_WORKSPACE_DATA",
                            value="true" if efs_delete_workspace_data_on_destroy else "false",
                        ),
                        # finding #18: empty by default (trusts no assumed role — every IAM
                        # Identity Center caller gets 401 until an operator sets
                        # aws_trusted_assumed_role_patterns). JSON-encoded (not a comma-join)
                        # because these are regexes matched with re.fullmatch, and IAM
                        # role-name characters include literal commas ([\w+=,.@-]) that a
                        # comma-split would corrupt (see config.py's _split_comma_separated,
                        # which accepts either a JSON array or a bare comma-separated string
                        # — JSON array is the only safe choice here).
                        ecs.CfnTaskDefinition.KeyValuePairProperty(
                            name="WARREN_AWS_TRUSTED_ASSUMED_ROLE_PATTERNS",
                            value=cdk.Fn.to_json_string(
                                aws_trusted_assumed_role_patterns or []
                            ),
                        ),
                        # R19: the IAM resource patterns in this stack are built from
                        # ecs_resource_prefix, so the app must run with the same prefix.
                        ecs.CfnTaskDefinition.KeyValuePairProperty(
                            name="WARREN_ECS_RESOURCE_PREFIX", value=ecs_resource_prefix
                        ),
                        # EBS workspace storage (runtime/ebs.py): the default mode, and what
                        # an EBS launch needs. Empty role/key when EBS isn't enabled, so a
                        # template asking for `ecs_storage: ebs` is refused (422).
                        ecs.CfnTaskDefinition.KeyValuePairProperty(
                            name="WARREN_ECS_WORKSPACE_STORAGE", value=workspace_storage
                        ),
                        ecs.CfnTaskDefinition.KeyValuePairProperty(
                            name="WARREN_ECS_EBS_INFRA_ROLE_ARN",
                            value=ecs_infra_role.role_arn if ecs_infra_role is not None else "",
                        ),
                        ecs.CfnTaskDefinition.KeyValuePairProperty(
                            name="WARREN_ECS_SECRETS_KMS_KEY_ID", value=secrets_key_arn
                        ),
                        ecs.CfnTaskDefinition.KeyValuePairProperty(
                            name="WARREN_ECS_EBS_SIZE_GIB", value=str(int(ebs_size_gib))
                        ),
                        *(
                            [
                                ecs.CfnTaskDefinition.KeyValuePairProperty(
                                    name="WARREN_ECS_EBS_KMS_KEY_ID", value=ebs_kms_key_arn
                                )
                            ]
                            if ebs_kms_key_arn
                            else []
                        ),
                    ],
                    log_configuration=ecs.CfnTaskDefinition.LogConfigurationProperty(
                        log_driver="awslogs",
                        options={
                            "awslogs-group": f"/warren/control-plane-{env_suffix}",
                            "awslogs-region": self.region,
                            "awslogs-stream-prefix": "server",
                            "awslogs-create-group": "true",
                        },
                    ),
                )
            ],
            tags=[cdk.CfnTag(key="warren", value="true")],
        )

        # ---------------------------------------------------------------
        # Control-plane service (finding #19c) — replaces the previous one-off
        # `aws ecs run-task` runbook step, which never restarted the control plane
        # after a crash. desired_count=1 keeps exactly one control-plane task running
        # at all times; ECS replaces it automatically on failure, and WARREN_SERVER_ID
        # (set above from this resource's own name) stays stable across every such
        # replacement. Mirrors terraform/main.tf's aws_ecs_service.warren_server.
        # ---------------------------------------------------------------
        control_plane_service = ecs.CfnService(
            self,
            "WarrenServerService",
            service_name=f"warren-server-control-plane-{env_suffix}",
            cluster=cluster.cluster_name,
            task_definition=control_plane_task_def.attr_task_definition_arn,
            launch_type="FARGATE",
            desired_count=1,
            # Audit #10: stop-before-start -- the control plane is a single SQLite
            # writer on EFS, and the default 100/200 rolling deployment briefly runs
            # two. Mirrors terraform/main.tf.
            deployment_configuration=ecs.CfnService.DeploymentConfigurationProperty(
                minimum_healthy_percent=0,
                maximum_percent=100,
            ),
            # Required for `aws ecs execute-command` into the running service task
            # (POC-02) — previously passed as `run-task --enable-execute-command`, which
            # has no equivalent on a long-lived service other than this flag.
            enable_execute_command=True,
            network_configuration=ecs.CfnService.NetworkConfigurationProperty(
                awsvpc_configuration=ecs.CfnService.AwsVpcConfigurationProperty(
                    subnets=subnet_id_list,
                    security_groups=[sg.security_group_id if sg is not None else ""],
                    assign_public_ip=(
                        "DISABLED" if create_vpc or not assign_public_ip else "ENABLED"
                    ),
                )
            ),
            tags=[cdk.CfnTag(key="warren", value="true")],
        )

        # ---------------------------------------------------------------
        # Control-plane service/task-definition outputs — for `aws ecs
        # execute-command`/`describe-services` against the running service, not a
        # launch command. Kept separate from the WARREN_ECS_* block above, whose
        # names are contractually bound to WarrenSettings field names. Mirrors
        # terraform/outputs.tf.
        # ---------------------------------------------------------------
        cdk.CfnOutput(
            self,
            "WarrenServerTaskDefinitionArn",
            value=control_plane_task_def.attr_task_definition_arn,
            description="Control-plane task definition ARN",
            export_name=f"WarrenServerTaskDefinitionArn-{env_suffix}",
        )
        cdk.CfnOutput(
            self,
            "WarrenServerTaskDefinitionFamily",
            value=f"warren-server-control-plane-{env_suffix}",
            description="Control-plane task definition family name",
            export_name=f"WarrenServerTaskDefinitionFamily-{env_suffix}",
        )
        cdk.CfnOutput(
            self,
            "WarrenServerServiceName",
            value=control_plane_service.service_name or f"warren-server-control-plane-{env_suffix}",
            description="Control-plane ECS service name — the argument for `aws ecs describe-services`/`execute-command --task` lookups",
            export_name=f"WarrenServerServiceName-{env_suffix}",
        )
