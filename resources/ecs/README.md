# ECS Infrastructure for Warren

## Overview

`resources/ecs/` provides three interchangeable ways to provision the AWS infrastructure that
`ECSRuntime` needs to run workspaces on AWS Fargate. All three tools — `setup.sh`, CDK (`cdk/`),
and Terraform (`terraform/`) — accept the same inputs (image URI, optional existing VPC) and
produce the same six outputs: cluster name, subnet IDs, security group ID, task role ARN,
execution role ARN, and image URI. Pick the tool that fits your existing AWS tooling; the
resulting warren-server environment is identical.

## Which Tool to Use

| Tool | When to use |
|------|-------------|
| `setup.sh` | Quick start — only needs the `aws` CLI. No extra runtimes. |
| CDK (`cdk/`) | You already use AWS CDK for infrastructure. |
| Terraform (`terraform/`) | You already use Terraform for infrastructure. |

All three are idempotent: running them again against the same AWS account and environment suffix
will skip resources that already exist (or are already in state) and re-print the same env vars.

## Resources Created

All three tools provision the same set of AWS resources:

- **ECS cluster** — `warren-cluster-$ENV` with FARGATE and FARGATE_SPOT capacity providers
- **IAM task role** — `warren-task-role-$ENV` with scoped ECS, SSM, ECS Exec, and CloudWatch
  Logs permissions (the role that warren-server itself assumes at runtime inside Fargate)
- **IAM task execution role** — `warren-task-exec-role-$ENV` with
  `AmazonECSTaskExecutionRolePolicy` plus an inline `logs:CreateLogGroup` supplement
  (the role the ECS agent uses to pull the container image and ship logs)
- **VPC** (optional, created unless you supply an existing VPC) — `warren-vpc-$ENV` with two
  private subnets across two AZs and a security group `warren-sg-$ENV`
- **SSM path prefix** — `/warren/` (used by ECSRuntime for parameter retrieval at task launch)
- **ECS Exec access** — managed policy `warren-workspace-operator-$ENV` for humans and the
  break-glass role `warren-break-glass-$ENV` (see [ECS Exec access](#ecs-exec-access))

Resource names all carry an `$ENV` (environment) suffix — default `prod` — so you can run
multiple warren environments in the same AWS account.

## VPC Templates

When creating a new VPC, choose one of three network templates. The default is Template A.

### Template A — Private Subnets + NAT Gateway (default, recommended)

Tasks run in private subnets. Outbound internet traffic (image pulls from ghcr.io, AWS API
calls) routes through a NAT Gateway. Inbound: none. Tasks have no public IP.

- `assignPublicIp: DISABLED` — this is the warren-server default. No config change needed.
- **Cost:** ~$32/month for the NAT Gateway (plus data transfer).
- **Use when:** you want the most secure setup and don't mind the NAT Gateway cost.

### Template B — Public Subnets + Public IP

Tasks run in public subnets and receive a public Elastic Network Interface IP. No NAT Gateway
needed. Inbound: none (security group allows no ingress).

- **Required config change:** set `WARREN_ECS_ASSIGN_PUBLIC_IP=true` in warren-server's
  environment. Without this, tasks will fail to reach the internet because Fargate needs
  `assignPublicIp: ENABLED` to route traffic on public subnets.
- **Cost:** ~$0/month extra networking overhead (public IPs are free for running tasks in
  Fargate; data transfer charges apply normally).
- **Use when:** you want the simplest and cheapest setup and are comfortable with public IPs.

### Template C — Private Subnets + VPC Endpoints (no internet)

Tasks run in private subnets with no internet egress. Interface VPC endpoints provide
connectivity to ECR, SSM, and CloudWatch Logs entirely within the AWS network.

- `assignPublicIp: DISABLED` — correct for this template. No config change needed.
- **Cost:** ~$7/month per VPC endpoint (typically three endpoints = ~$21/month).
- **Important:** `ghcr.io` (GitHub Container Registry) is **not reachable** via VPC endpoints.
  This template requires Amazon ECR images. If you use `ghcr.io/scottcowan/warren-server`,
  you must push the image to ECR first and update `WARREN_ECS_IMAGE_URI` accordingly.
- **Use when:** your security policy prohibits internet egress from task subnets.

## Fargate isolation: the task role is the control

There is no sandbox inside a Fargate task. Tested 2026-10-18 on platform 1.4.0 (kernel 6.1,
x86_64): `unshare -U`, `bwrap`, and `bwrap --unshare-user/--unshare-net/--unshare-pid` all fail
with `Operation not permitted`, as root and as uid 1000. The kernel allows user namespaces,
but the container runs under a seccomp filter with Docker's default capabilities, and
Fargate rejects `SYS_ADMIN` ("SYS_ADMIN is not allowed on Fargate") and `NET_ADMIN`. So the
agent can't be hidden from the task metadata/credentials endpoint `169.254.170.2`, which is
reachable from inside the task.

What that means for anything you run on the ECS runtime:

- Everything in a workspace task is agent-controlled, including any warren helper or
  sidecar process in the same task. Don't put anything in the task that the agent mustn't
  have. (The `git-init` container is the one exception by design: its clone credentials are
  wiped before it touches the volume, and it exits before the workspace container starts.)
- The workspace task role (`warren-workspace-task-role-$ENV`, `WARREN_ECS_TASK_ROLE_ARN`)
  is the agent's AWS identity. Keep it minimal: today it is EFS `ClientMount`/`ClientWrite`,
  the ECS Exec channel (`ssmmessages:*Channel`) and writes to the exec log group. Don't add
  per-workspace secrets, `ecs:*`, `iam:PassRole`, SSM/Secrets Manager reads or any other
  orchestration permission to it. A unit test (`test_iac_exec_scoping.py`) fails if any of
  the three IaC paths grants more.
- Secrets reach a task only through the task definition's `secrets` block, resolved by the
  execution role at container start. They still end up in the task's environment, so the
  agent can read every secret its template declares, and nothing else.
- Don't plan an in-task bwrap/namespace layer for ECS. Isolation between workspaces comes
  from separate tasks, separate EFS access points and the IAM above.

## EFS (Workspace + Control-Plane Persistence) — `create_efs`

The Terraform stack's `create_efs` variable controls whether the EFS file system, its
security group, its egress rule, its mount targets, and the task role's two EFS IAM
statements (`EFSMount`, `EFSDeleteTaggedAccessPoints`) are created. It gates **two
independent** persistence paths, each with its own access point on the same file system:

1. **Workspace persistence** — populates the control-plane task definition's
   `WARREN_EFS_ID` env var. `app.py` constructs an `EFSMount` from it and passes it into
   `ECSRuntime(volume=...)`, so `ECSRuntime.provision()`'s EFS-mount wiring attaches
   persistent storage (rooted at `/workspaces/{workspace_id}` on the file system) to every
   workspace task it provisions.
2. **Control-plane persistence** (added 2026-09-21) — a *separate* access point
   (`aws_efs_access_point.warren_control_plane`, rooted at `/control-plane`) mounted
   directly into the control-plane task definition itself at `/var/lib/warren`
   (`WARREN_DATA_DIR`'s default). This is what makes warren-server's own SQLite database —
   the workspace registry *and* the Phase 2 auth users/tokens tables — survive a
   control-plane task restart, mirroring the Podman path's `warren-data` named volume.
   Without this, every control-plane restart (deploy, crash, scaling event) silently loses
   every minted user token, not just workspace tracking state.

- **Default: `true`** (reversed 2026-09-21, per explicit operator decision — the original
  Phase 5 POC framing left this `false` and is now superseded; the deploy runbook that
  covered this history was internal-rollout-specific and has been removed). A
  default `terraform apply` now creates the EFS file system, mount targets, and IAM
  statements, and every workspace `ECSRuntime` provisions gets durable storage.
- **`create_efs = false`** runs without any workspace persistence (ephemeral task storage
  only, D-10 opt-out):
  ```bash
  terraform apply -var="image_uri=..." -var="create_efs=false"
  ```
- **Caveat — flipping `true` to `false` on an already-applied deployment:** the EFS file
  system carries `lifecycle { prevent_destroy = true }`, so a plain re-apply with
  `create_efs = false` will fail rather than silently destroy data. To remove EFS from an
  existing deployment, first run
  `terraform state rm 'aws_efs_file_system.warren[0]'` (and manually delete the EFS
  resource out of band if it's truly no longer needed), then re-apply with
  `create_efs = false`.

### EFS encryption at rest

All three tools create the file system with encryption at rest explicitly enabled
(audit #15). The key is optional: Terraform `efs_kms_key_arn`, CDK context
`efs_kms_key_arn`, setup.sh env `WARREN_EFS_KMS_KEY_ID`; empty uses the AWS-managed
`aws/elasticfilesystem` key. A customer-managed key's policy must let EFS use it.

Encryption can't be turned on for an existing file system. If yours predates this
(`aws efs describe-file-systems --query 'FileSystems[].[FileSystemId,Encrypted]'`),
Terraform's `prevent_destroy` blocks the replacement plan and CDK would orphan the old
file system (`RETAIN`) and create a new, empty one. To migrate: stop the control-plane
service, create the new encrypted file system (or let the stack create it after
`terraform state rm 'aws_efs_file_system.warren[0]'`), copy `/control-plane` and
`/workspaces` across (AWS DataSync, or `rsync` from a task mounting both), then start the
service and delete the old file system once verified.

### Single control-plane writer

warren-server keeps its registry, auth and secrets in SQLite under `/var/lib/warren` on
EFS, so exactly one control-plane process may have it open (audit #10):

- The control-plane service deploys stop-before-start
  (`deployment_minimum_healthy_percent = 0`, `deployment_maximum_percent = 100`).
  The default 100/200 rolling update briefly runs the old and new task together.
  Expect a short outage on every deploy.
- warren-server takes an exclusive lock on `warren.db.lock` next to the database at
  startup. If another process holds it, the new task retries for up to
  `WARREN_WRITER_LOCK_WAIT_S` (default 120s; `0` fails fast) and only then exits. The
  wait covers a just-stopped task whose NFSv4 lock lingers until its lease expires.
  Without it, the new task would exit at startup, and those exits count toward the
  deployment circuit breaker.
- `WARREN_SQLITE_JOURNAL_MODE=auto` (the default) uses `DELETE` journaling when the data
  dir is on NFS/EFS, because WAL's shared-memory index isn't safe on network
  filesystems. Use `wal`/`delete` to override.

**CDK parity:** `resources/ecs/cdk/warren_stack.py` accepts the same `create_efs` (default
`True`) and `control_plane_image_uri` parameters as Terraform, producing the identical
resource set and the same `WARREN_EFS_ID` wiring into the control-plane task. Verified
with `cdk.App().synth()` against `aws-cdk-lib==2.255.0` in both the default (EFS-on) and
`create_efs=False` states (no live AWS account needed — `cdk synth`/`.synth()` only needs
`env={account, region}` when the stack does a live VPC lookup via
`ec2.Vpc.from_lookup`, which only happens on the `create_vpc=False` path).

```bash
cdk deploy --context create_efs=false --context image_uri=ghcr.io/scottcowan/warren-server:latest
```

**`resources/ecs/setup.sh` remains Phase-2-shaped** (always creates EFS, no control-plane
task definition) — it was not updated to match, since it is documented as the "quick
start" path for a full production deployment, not the Phase 5 POC's narrower footprint.
Use Terraform or CDK for the POC.

## Control-Plane Task Definition (Terraform and CDK)

Both the Terraform and CDK stacks register a Fargate task definition that runs
warren-server **itself**, distinct from the per-workspace tasks `ECSRuntime` launches at
runtime. This is the missing half of the ECS POC: without it there is no warren-server
process running in AWS at all.

- `control_plane_image_uri` — full image URI for the control-plane task. Falls back to
  `image_uri` when left empty, since the control-plane and workspace images are typically
  the same warren-server image.
  ```bash
  # Terraform
  terraform apply \
    -var="image_uri=ghcr.io/scottcowan/warren-server:latest" \
    -var="control_plane_image_uri=ghcr.io/scottcowan/warren-server:latest"

  # CDK
  cdk deploy \
    --context image_uri=ghcr.io/scottcowan/warren-server:latest \
    --context control_plane_image_uri=ghcr.io/scottcowan/warren-server:latest
  ```
- `warren_server_task_definition_arn` / `WarrenServerTaskDefinitionArn` — the task
  definition ARN, the argument for `aws ecs run-task --task-definition`.
- `warren_server_task_definition_family` / `WarrenServerTaskDefinitionFamily` — the task
  definition family name.
- `warren_run_task_network_configuration` / `WarrenRunTaskNetworkConfiguration` — the
  `awsvpcConfiguration` JSON to paste into `aws ecs run-task --network-configuration` when
  launching the control-plane task.

**Neither stack runs this task definition — only registers it.** Launching it is a one-off
`aws ecs run-task --enable-execute-command` step — not an `aws_ecs_service`, ALB, NLB, or
API Gateway.

warren-server listens on `127.0.0.1:8420` inside the task by default, so the API is not
reachable from the VPC at all. The CLI reaches it with an SSM `AWS-StartPortForwardingSession`
to the task, which connects to the task's own loopback. Don't set `WARREN_HOST` here unless you
put something in front of the task (a load balancer, a VPC peer), and then pair it with
`WARREN_TLS_CERTFILE`/`WARREN_TLS_KEYFILE`
([Listening address](../../packages/warren-server/README.md#listening-address)).

## Setup Instructions

### Option 1: setup.sh

**Prerequisites:**

- `aws` CLI installed and configured (`aws sts get-caller-identity` succeeds)
- IAM permissions to create roles, ECS clusters, and VPC resources (see
  [IAM Permissions Required](#iam-permissions-required-to-run-the-scripts))

**Steps:**

```bash
chmod +x resources/ecs/setup.sh
./resources/ecs/setup.sh
```

The wizard will ask for:
1. Environment suffix (default: `prod`)
2. AWS region (default: `us-east-1` or `$AWS_DEFAULT_REGION`)
3. Container image URI (e.g. `ghcr.io/scottcowan/warren-server:latest`)
4. VPC template choice (A / B / C)
5. Whether to create a new VPC or use an existing one (if existing: VPC ID, subnet IDs,
   security group ID)

At the end the wizard prints six `export WARREN_ECS_*` lines. Paste them into your
warren-server environment (ECS task definition env vars or shell profile).

### Option 2: CDK

**Prerequisites:**

- Node.js 20+ and `npm install -g aws-cdk` (`cdk --version` should print 2.x)
- Python 3.11+

**Steps:**

```bash
cd resources/ecs/cdk

# Create and activate a Python virtual environment
uv venv .venv && source .venv/bin/activate
# or: python3 -m venv .venv && source .venv/bin/activate

pip install -r requirements.txt

# One-time CDK bootstrap (creates the CDKToolkit CloudFormation stack in your account)
cdk bootstrap

# Deploy — accept IAM changes when prompted
cdk deploy
```

Capture outputs from the CloudFormation console or from `cdk deploy` stdout. They appear as
`WarrenECSStack.WARREN_ECS_CLUSTER`, `WarrenECSStack.WARREN_ECS_SUBNET_IDS`, etc.

**Customisation via CDK context:**

```bash
# Use an existing VPC instead of creating one
cdk deploy \
  --context create_vpc=false \
  --context vpc_id=vpc-0123456789abcdef0 \
  --context subnet_ids=subnet-aaa,subnet-bbb \
  --context security_group_id=sg-xxx

# Change environment suffix (default: prod)
cdk deploy --context env_suffix=staging

# Run without workspace EFS persistence — ephemeral task storage only (default: true)
cdk deploy --context image_uri=ghcr.io/scottcowan/warren-server:latest --context create_efs=false

# Control-plane task using a different image than workspace tasks
cdk deploy \
  --context image_uri=ghcr.io/scottcowan/warren-server:latest \
  --context control_plane_image_uri=ghcr.io/scottcowan/warren-server:control-plane
```

### Option 3: Terraform

**Prerequisites:**

- Terraform >= 1.3. Install via tfenv if needed:
  ```bash
  tfenv install 1.9.0 && tfenv use 1.9.0
  ```

**Steps:**

```bash
cd resources/ecs/terraform

terraform init

# Review the plan, then type "yes" to apply
terraform apply -var="image_uri=ghcr.io/scottcowan/warren-server:latest"
```

After apply, capture outputs:

```bash
terraform output
```

Outputs are formatted as `WARREN_ECS_CLUSTER = "warren-cluster-prod"`, etc.

**Using an existing VPC:**

```bash
terraform apply \
  -var="image_uri=ghcr.io/scottcowan/warren-server:latest" \
  -var="create_vpc=false" \
  -var="vpc_id=vpc-0123456789abcdef0" \
  -var='subnet_ids=["subnet-aaa","subnet-bbb"]' \
  -var="security_group_id=sg-xxx"
```

**Changing environment suffix:**

```bash
terraform apply -var="image_uri=..." -var="env_suffix=staging"
```

## Wiring Outputs into warren-server

After running any of the three tools, set these environment variables in warren-server's runtime
environment (ECS task definition, `.env` file, or shell):

```bash
export WARREN_ECS_CLUSTER=warren-cluster-prod
export WARREN_ECS_SUBNET_IDS=subnet-aaa,subnet-bbb
export WARREN_ECS_SECURITY_GROUP_IDS=sg-xxx
export WARREN_ECS_TASK_ROLE_ARN=arn:aws:iam::123456789012:role/warren-task-role-prod
export WARREN_ECS_TASK_EXECUTION_ROLE_ARN=arn:aws:iam::123456789012:role/warren-task-exec-role-prod
export WARREN_ECS_IMAGE_URI=ghcr.io/scottcowan/warren-server:latest
```

**Mapping to WarrenSettings fields:**

| Environment variable | WarrenSettings field | Notes |
|----------------------|---------------------|-------|
| `WARREN_ECS_CLUSTER` | `ecs_cluster` | Cluster name (not ARN) |
| `WARREN_ECS_SUBNET_IDS` | `ecs_subnet_ids` | Comma-separated list |
| `WARREN_ECS_SECURITY_GROUP_IDS` | `ecs_security_group_ids` | Comma-separated list |
| `WARREN_ECS_TASK_ROLE_ARN` | `ecs_task_role_arn` | Full ARN |
| `WARREN_ECS_TASK_EXECUTION_ROLE_ARN` | `ecs_task_execution_role_arn` | Full ARN |
| `WARREN_ECS_RESOURCE_PREFIX` | `ecs_resource_prefix` | Defaults to `warren`; override if your deployment's infra naming doesn't use "warren" anywhere (see issue #2) |
| `WARREN_ECS_IMAGE_URI` | *(not a WarrenSettings field)* | See note below |

> **Note on `WARREN_ECS_IMAGE_URI`:** This variable is printed for documentation and operator
> reference. It is **not** read from the environment by `WarrenSettings`. Warren-server reads
> the container image URI from the `WorkspaceSpec` submitted at workspace-provision time. The
> export line is useful for tracking which image URI you provisioned against, and as a default
> to copy into workspace specs.

**Template B users only:** also add:

```bash
export WARREN_ECS_ASSIGN_PUBLIC_IP=true
```

This enables `assignPublicIp: ENABLED` in the Fargate task network configuration. Without it
tasks on public subnets have no route to the internet.

**Activating ECS runtime:** set `WARREN_RUNTIME_TYPE=ecs` to switch warren-server from the
default Podman runtime to ECSRuntime.

## ECS Exec access

Every workspace task carries a `warren.owner_id` tag (`<WARREN_ECS_RESOURCE_PREFIX>.owner_id`).
The control plane sets it from the caller's verified AWS identity when it creates the
workspace; a value in the request body is ignored. On ECS the owner_id is the first 32 hex
characters of the SHA-256 of the caller's ARN (`warren/auth/aws_identity.py`):

```bash
ARN=$(aws sts get-caller-identity --query Arn --output text)
printf %s "$ARN" | shasum -a 256 | cut -c1-32
```

**Deployment model these IaC paths support: direct exec with the caller's own credentials.**
`warren connect` / `warren exec` run `aws ecs execute-command` as the human (warren-cli
`dispatch.py`), so access is enforced in IAM on the human principal. All three tools
(`setup.sh`, CDK, Terraform) create the same two things:

- **`warren-workspace-operator-$ENV`** (managed policy). Attach it to every human who connects:
  their IAM user, group, or IAM Identity Center permission set (as a customer-managed policy).
  It allows two things, both only into tasks whose `warren.owner_id` tag equals
  `${aws:PrincipalTag/warren-owner}`:
  - `ecs:ExecuteCommand` (`warren connect` / `warren exec`), conditioned on
    `ecs:ResourceTag/warren.owner_id`. ExecuteCommand also authorizes the cluster, so the
    cluster ARN is allowed on its own; that grant opens nothing without the task match.
  - `ssm:StartSession` with the `AWS-StartPortForwardingSession` document only
    (`warren tunnel`, target `ecs:<cluster>_<task>_<runtime>`), conditioned on
    `aws:ResourceTag/warren.owner_id`. SSM authorizes the target task and the document as
    separate resources, so the tag condition is on the task statement and the document is
    allowed by ARN. `BoolIfExists ssm:SessionDocumentAccessCheck = true` makes Session
    Manager check the document even when the caller doesn't name one, so the default shell
    document is refused. `AWS-StartPortForwardingSessionToRemoteHost` isn't granted, since
    warren doesn't use it.

  It explicitly denies exec and SSM sessions into a task with another owner's tag or, inside
  the warren cluster, no tag (the control-plane task included), and both for a caller with
  no `warren-owner` tag. It also denies `ssm:StartSession` with any other document (the
  interactive shell, `AWS-StartSSHSession`, custom documents) on any target. Holders of the
  policy can therefore only port-forward with Session Manager, including on EC2. Give a
  human who also needs shell sessions elsewhere a separate principal.

  References: the Service Authorization Reference (`ssm:StartSession` resource types
  `task` with `aws:ResourceTag/${TagKey}`, and `document`, plus condition key
  `ssm:SessionDocumentAccessCheck`; `ecs:ExecuteCommand` resources `cluster` and `task`),
  and the ECS Exec guide's "Limiting access to the Start Session action", which conditions
  `ssm:StartSession` on `arn:aws:ecs:*:*:task/*` with `aws:ResourceTag`. The reference
  lists the SSM task ARN as `task/<id>` and the ECS guide uses `task/<cluster>/<id>`, so the
  policy covers both forms.
- **`warren-break-glass-$ENV`** (role). The only principal these stacks give cluster-wide
  `ecs:ExecuteCommand` and `ssm:StartSession`. Its trust policy requires MFA by default.
  Terraform `break_glass_principal_arns` / CDK context `break_glass_principal_arns` restrict
  who may assume it. Without them it trusts the account root, so only principals you also
  grant `sts:AssumeRole` on the role can use it.

Matching the caller to the tag: each human needs a `warren-owner` principal tag whose value is
their own owner_id (computed as above).

- IAM users: `aws iam tag-user --user-name alice --tags Key=warren-owner,Value=<owner_id>`.
- IAM Identity Center: map a per-user attribute to the session tag `warren-owner` (attributes
  for access control). The value is the hash of that user's assumed-role session ARN, so
  store it as a user attribute. The role must also match
  `WARREN_AWS_TRUSTED_ASSUMED_ROLE_PATTERNS`, or the control plane rejects the caller anyway.

Consequences:

- `warren tunnel` works for owners into their own tasks. Port-forward sessions aren't
  captured by the ECS Exec session log (only `execute-command` sessions are), but
  CloudTrail records each `StartSession`.
- The denies only apply to principals that have the operator policy attached. A principal
  given `ecs:ExecuteCommand` or `ssm:StartSession` some other way (for example
  `AdministratorAccess`) is not limited by it. For an organization-wide guard, add an SCP
  (`aws:ResourceTag` is evaluated by both actions):

  ```json
  {
    "Effect": "Deny",
    "Action": ["ecs:ExecuteCommand", "ssm:StartSession"],
    "Resource": "arn:aws:ecs:*:<account>:task/*",
    "Condition": {
      "StringNotEquals": {"aws:ResourceTag/warren.owner_id": "${aws:PrincipalTag/warren-owner}"},
      "Null": {"aws:ResourceTag/warren.owner_id": "false"},
      "ArnNotLike": {"aws:PrincipalArn": "arn:aws:iam::<account>:role/warren-break-glass-<env>"}
    }
  }
  ```

- Exec logging is unchanged. The cluster's `executeCommandConfiguration` (`logging=OVERRIDE`
  into `/warren/<env>/ecs-exec`) records every session, owner and break-glass alike.

**Not yet supported: a control-plane exec relay.** In that model humans hold no ECS or SSM
permissions at all, the control plane checks workspace ownership itself and brokers the
session. No IaC here grants for it, and the CLI doesn't use it yet.

## Per-user cost attribution

The same `warren.owner_id` task tag splits Fargate cost per user. It's an opaque hash, not an
email, so it can appear in billing data without exposing identities.

1. Launch at least one workspace so the tag key exists in the account.
2. Activate it as a cost-allocation tag in the payer (management) account: Billing and Cost
   Management, Cost allocation tags, select `warren.owner_id`, Activate. Or:

   ```bash
   aws ce update-cost-allocation-tags-status \
     --cost-allocation-tags-status TagKey=warren.owner_id,Status=Active
   ```

3. Cost Explorer and the Cost and Usage Report then group Fargate vCPU/memory charges by
   `warren.owner_id`. Activation isn't retroactive and can take up to 24 hours to show up.
   `warren.project` and `warren.intent` can be activated the same way.

Fargate task tags propagate to billing only for tasks launched with them, so tasks started
before this tag existed show as untagged.

EFS storage can't be split per user. Every workspace's data sits on one shared file system,
and cost allocation tags on access points (which carry `warren.owner_id` too) don't attribute
storage. EFS shows up as a single line item. If you need it per user, estimate it from
directory sizes on the file system. EC2 and EKS runtimes don't exist yet, so this covers
Fargate only.

## IAM Permissions Required to Run the Scripts

Your AWS credentials need the following permissions to provision the infrastructure:

**ECS:**
- `ecs:CreateCluster`, `ecs:DescribeClusters`, `ecs:PutClusterCapacityProviders`

**IAM:**
- `iam:CreateRole`, `iam:GetRole`, `iam:PutRolePolicy`, `iam:AttachRolePolicy`,
  `iam:PassRole`, `iam:CreatePolicy`, `iam:GetPolicy`

**EC2 / VPC (only if creating a new VPC):**
- `ec2:CreateVpc`, `ec2:DescribeVpcs`, `ec2:CreateSubnet`, `ec2:DescribeSubnets`,
  `ec2:CreateInternetGateway`, `ec2:AttachInternetGateway`,
  `ec2:CreateNatGateway`, `ec2:DescribeNatGateways`, `ec2:AllocateAddress`,
  `ec2:CreateRouteTable`, `ec2:CreateRoute`, `ec2:AssociateRouteTable`,
  `ec2:CreateSecurityGroup`, `ec2:DescribeSecurityGroups`,
  `ec2:AuthorizeSecurityGroupEgress`, `ec2:CreateTags`

**VPC endpoints (Template C only):**
- `ec2:CreateVpcEndpoint`, `ec2:DescribeVpcEndpoints`

**SSM (none — the `/warren/` path prefix is used by the running task, not the provisioner).**

All provisioned IAM roles follow least-privilege principles:
- Task role ECS actions are scoped to `arn:aws:ecs:*:*:cluster/warren-*`
- Task role `iam:PassRole` is scoped to the exact execution role ARN
- Task role SSM access is scoped to `arn:aws:ssm:*:*:parameter/warren/*`
- Avoid attaching `AdministratorAccess` to your provisioner credentials;
  the list above is the complete set of permissions needed.

## Post-Setup Verification

After setting the `WARREN_ECS_*` environment variables:

1. Restart warren-server with `WARREN_RUNTIME_TYPE=ecs`.
2. Run `warren doctor` to verify ECS availability — it checks AWS credential validity, cluster
   reachability, and resolved task definition.

A passing `warren doctor` output confirms that `ECSRuntime` can reach the cluster, that the
IAM roles are correctly configured, and that warren-server is ready to provision workspaces on
Fargate.
