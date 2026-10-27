#!/usr/bin/env bash
# Warren ECS Infrastructure Setup Wizard
# Provisions: ECS cluster, IAM task role, IAM task execution role, VPC (optional).
# Prints WARREN_ECS_* export lines to stdout when complete.
# Usage: bash resources/ecs/setup.sh
set -euo pipefail

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
prompt() {
  local prompt_text="$1"
  local default_value="${2:-}"
  local result
  if [[ -n "$default_value" ]]; then
    read -r -p "$prompt_text (default: $default_value): " result
    echo "${result:-$default_value}"
  else
    local val=""
    while [[ -z "$val" ]]; do
      read -r -p "$prompt_text: " val
      if [[ -z "$val" ]]; then
        echo "  This value is required." >&2
      fi
    done
    echo "$val"
  fi
}

yesno() {
  local prompt_text="$1"
  local default_value="${2:-y}"
  local result
  while true; do
    read -r -p "$prompt_text [y/n] (default: $default_value): " result
    result="${result:-$default_value}"
    case "$result" in
      y|Y|yes|YES) echo "y"; return ;;
      n|N|no|NO)   echo "n"; return ;;
      *) echo "  Please enter y or n." >&2 ;;
    esac
  done
}

# ---------------------------------------------------------------------------
# Preflight: verify AWS credentials
# ---------------------------------------------------------------------------
echo ""
echo "=== Warren ECS Infrastructure Setup ==="
echo ""
echo "Checking AWS credentials..."
if ! aws sts get-caller-identity > /dev/null 2>&1; then
  echo ""
  echo "ERROR: AWS credentials not configured or expired." >&2
  echo "" >&2
  echo "To fix this, run one of:" >&2
  echo "  aws configure                   # static credentials" >&2
  echo "  aws sso login                   # SSO profile" >&2
  echo "  export AWS_PROFILE=<profile>    # switch profile" >&2
  echo "" >&2
  exit 1
fi

ACCOUNT_ID=$(aws sts get-caller-identity --query "Account" --output text)
echo "Authenticated as account: $ACCOUNT_ID"
echo ""

# ---------------------------------------------------------------------------
# Wizard: environment suffix and region
# ---------------------------------------------------------------------------
REGION="${AWS_DEFAULT_REGION:-us-east-1}"
echo "AWS region: $REGION  (override with AWS_DEFAULT_REGION)"
echo ""

ENV=$(prompt "Environment suffix (used to name resources like warren-cluster-<ENV>)" "prod")
# IAM role names have a 64-char limit; "warren-task-exec-role-" is 22 chars, leaving 42 for ENV.
# We cap at 40 to leave a small safety margin and enforce safe resource-name characters.
if [[ ! "$ENV" =~ ^[a-zA-Z0-9_-]{1,40}$ ]]; then
  echo "ERROR: ENV suffix must be 1-40 alphanumeric/hyphen/underscore characters." >&2
  exit 1
fi
echo ""
echo "Resources will be named: warren-cluster-$ENV, warren-task-role-$ENV, etc."
echo ""

# ---------------------------------------------------------------------------
# Wizard: IMAGE_URI (required, no ECR creation)
# ---------------------------------------------------------------------------
IMAGE_URI=$(prompt "IMAGE_URI for warren-server container (e.g. ghcr.io/scottcowan/warren-server:latest)")
echo ""

# ---------------------------------------------------------------------------
# Step 0b: ECS Exec CloudWatch log group (idempotent — Pattern 4 / Pitfall 6)
# Audit finding #42 / S11: "DEFAULT" leaves ECS Exec sessions unlogged — no
# CloudWatch/S3 session log, so an operator's `warren connect`/`exec` session into a
# task leaves no audit trail. "OVERRIDE" + this log group gives every exec session a
# retained record. Mirrors terraform/main.tf's aws_cloudwatch_log_group.ecs_exec /
# cdk/warren_stack.py's WarrenEcsExecLogGroup. No KMS option here — unlike Terraform/
# CDK, this script has no var.kms_key_id equivalent.
# ---------------------------------------------------------------------------
ECS_EXEC_LOG_GROUP="/warren/$ENV/ecs-exec"
echo "--- ECS Exec Log Group ---"
if aws logs describe-log-groups \
    --log-group-name-prefix "$ECS_EXEC_LOG_GROUP" \
    --query "logGroups[?logGroupName=='$ECS_EXEC_LOG_GROUP'] | length(@)" \
    --output text | grep -q "^0$"; then
  echo "Creating CloudWatch log group '$ECS_EXEC_LOG_GROUP'..."
  aws logs create-log-group \
    --log-group-name "$ECS_EXEC_LOG_GROUP" \
    --tags warren=true
  aws logs put-retention-policy \
    --log-group-name "$ECS_EXEC_LOG_GROUP" \
    --retention-in-days 90
  echo "CloudWatch log group '$ECS_EXEC_LOG_GROUP' created."
else
  echo "CloudWatch log group '$ECS_EXEC_LOG_GROUP' already exists. Skipping."
fi
echo ""

# ---------------------------------------------------------------------------
# Step 1: ECS Cluster (idempotent — Pattern 4 / Pitfall 6)
# ---------------------------------------------------------------------------
CLUSTER_NAME="warren-cluster-$ENV"
echo "--- ECS Cluster ---"
CLUSTER_STATUS=$(aws ecs describe-clusters \
  --clusters "$CLUSTER_NAME" \
  --query "clusters[0].status" \
  --output text 2>/dev/null || echo "NONE")

if [[ "$CLUSTER_STATUS" == "ACTIVE" ]]; then
  echo "ECS cluster '$CLUSTER_NAME' already exists. Skipping."
else
  echo "Creating ECS cluster '$CLUSTER_NAME'..."
  aws ecs create-cluster \
    --cluster-name "$CLUSTER_NAME" \
    --capacity-providers FARGATE FARGATE_SPOT \
    --default-capacity-provider-strategy \
      capacityProvider=FARGATE,weight=1,base=1 \
    --configuration "executeCommandConfiguration={logging=OVERRIDE,cloudWatchLogConfiguration={cloudWatchLogGroupName=$ECS_EXEC_LOG_GROUP}}" \
    --tags key=warren,value=true key=warren-env,value="$ENV" \
    --output text > /dev/null
  echo "ECS cluster '$CLUSTER_NAME' created."
fi
echo ""

# ---------------------------------------------------------------------------
# Step 2: VPC branch
# ---------------------------------------------------------------------------
CREATE_VPC=$(yesno "Create a new VPC for warren?" "y")
echo ""

if [[ "$CREATE_VPC" == "n" ]]; then
  # Use existing VPC resources
  VPC_ID=$(prompt "Existing VPC ID (e.g. vpc-0abc1234)")
  SUBNET_IDS=$(prompt "Existing subnet IDs (comma-separated, e.g. subnet-aaa,subnet-bbb)")
  SG_ID=$(prompt "Existing security group ID (e.g. sg-0abc1234)")
  echo ""
  echo "Using existing VPC: $VPC_ID"

else
  # New VPC — prompt for template
  echo "Select VPC network template:"
  echo "  A — Private subnets + NAT Gateway (recommended, ~\$32/month, assignPublicIp=DISABLED)"
  echo "  B — Public subnets + public IP (no NAT cost, WARREN_ECS_ASSIGN_PUBLIC_IP=true required)"
  echo "  C — Private subnets + VPC endpoints, no internet (ghcr.io unreachable; Amazon ECR only)"
  echo ""
  VPC_TEMPLATE=""
  while [[ "$VPC_TEMPLATE" != "A" && "$VPC_TEMPLATE" != "B" && "$VPC_TEMPLATE" != "C" ]]; do
    read -r -p "Template [A/B/C] (default: A): " VPC_TEMPLATE
    VPC_TEMPLATE="${VPC_TEMPLATE:-A}"
    VPC_TEMPLATE="${VPC_TEMPLATE^^}"
    if [[ "$VPC_TEMPLATE" != "A" && "$VPC_TEMPLATE" != "B" && "$VPC_TEMPLATE" != "C" ]]; then
      echo "  Please enter A, B, or C." >&2
    fi
  done
  echo ""

  VPC_NAME="warren-vpc-$ENV"

  # VPC idempotency: check by tag Name (Pattern 5)
  VPC_ID=$(aws ec2 describe-vpcs \
    --filters "Name=tag:Name,Values=$VPC_NAME" \
    --query "Vpcs[0].VpcId" \
    --output text 2>/dev/null || echo "None")

  if [[ "$VPC_ID" == "None" || -z "$VPC_ID" ]]; then
    echo "Creating VPC '$VPC_NAME' (CIDR 10.42.0.0/16)..."
    VPC_ID=$(aws ec2 create-vpc \
      --cidr-block 10.42.0.0/16 \
      --query "Vpc.VpcId" \
      --output text)
    aws ec2 create-tags --resources "$VPC_ID" \
      --tags "Key=Name,Value=$VPC_NAME" "Key=warren,Value=true" "Key=warren-env,Value=$ENV"
    aws ec2 modify-vpc-attribute --vpc-id "$VPC_ID" --enable-dns-support
    aws ec2 modify-vpc-attribute --vpc-id "$VPC_ID" --enable-dns-hostnames
    echo "VPC $VPC_ID created."
  else
    echo "VPC '$VPC_NAME' already exists ($VPC_ID). Skipping VPC creation."
  fi

  # Get AZs for this region
  AZ_A=$(aws ec2 describe-availability-zones \
    --query "AvailabilityZones[0].ZoneName" \
    --output text)
  AZ_B=$(aws ec2 describe-availability-zones \
    --query "AvailabilityZones[1].ZoneName" \
    --output text)

  if [[ "$VPC_TEMPLATE" == "A" ]]; then
    # Template A: Private subnets + NAT Gateway
    # Private subnets
    SUBNET_A_NAME="warren-subnet-a-$ENV"
    SUBNET_B_NAME="warren-subnet-b-$ENV"
    # Public subnet for NAT GW
    SUBNET_PUB_NAME="warren-subnet-pub-$ENV"

    SUBNET_A_ID=$(aws ec2 describe-subnets \
      --filters "Name=tag:Name,Values=$SUBNET_A_NAME" \
      --query "Subnets[0].SubnetId" \
      --output text 2>/dev/null || echo "None")

    if [[ "$SUBNET_A_ID" == "None" || -z "$SUBNET_A_ID" ]]; then
      echo "Creating private subnets..."
      SUBNET_A_ID=$(aws ec2 create-subnet \
        --vpc-id "$VPC_ID" \
        --cidr-block 10.42.0.0/24 \
        --availability-zone "$AZ_A" \
        --query "Subnet.SubnetId" \
        --output text)
      aws ec2 create-tags --resources "$SUBNET_A_ID" \
        --tags "Key=Name,Value=$SUBNET_A_NAME" "Key=warren,Value=true"

      SUBNET_B_ID=$(aws ec2 create-subnet \
        --vpc-id "$VPC_ID" \
        --cidr-block 10.42.1.0/24 \
        --availability-zone "$AZ_B" \
        --query "Subnet.SubnetId" \
        --output text)
      aws ec2 create-tags --resources "$SUBNET_B_ID" \
        --tags "Key=Name,Value=$SUBNET_B_NAME" "Key=warren,Value=true"

      SUBNET_PUB_ID=$(aws ec2 create-subnet \
        --vpc-id "$VPC_ID" \
        --cidr-block 10.42.2.0/24 \
        --availability-zone "$AZ_A" \
        --query "Subnet.SubnetId" \
        --output text)
      aws ec2 create-tags --resources "$SUBNET_PUB_ID" \
        --tags "Key=Name,Value=$SUBNET_PUB_NAME" "Key=warren,Value=true"
      echo "Subnets created: $SUBNET_A_ID, $SUBNET_B_ID (private), $SUBNET_PUB_ID (public)"
    else
      SUBNET_B_ID=$(aws ec2 describe-subnets \
        --filters "Name=tag:Name,Values=$SUBNET_B_NAME" \
        --query "Subnets[0].SubnetId" \
        --output text)
      SUBNET_PUB_ID=$(aws ec2 describe-subnets \
        --filters "Name=tag:Name,Values=$SUBNET_PUB_NAME" \
        --query "Subnets[0].SubnetId" \
        --output text)
      echo "Private subnets already exist. Skipping."
    fi

    # Internet Gateway
    IGW_ID=$(aws ec2 describe-internet-gateways \
      --filters "Name=attachment.vpc-id,Values=$VPC_ID" \
      --query "InternetGateways[0].InternetGatewayId" \
      --output text 2>/dev/null || echo "None")

    if [[ "$IGW_ID" == "None" || -z "$IGW_ID" ]]; then
      echo "Creating Internet Gateway..."
      IGW_ID=$(aws ec2 create-internet-gateway \
        --query "InternetGateway.InternetGatewayId" \
        --output text)
      aws ec2 attach-internet-gateway --internet-gateway-id "$IGW_ID" --vpc-id "$VPC_ID"
      aws ec2 create-tags --resources "$IGW_ID" \
        --tags "Key=Name,Value=warren-igw-$ENV" "Key=warren,Value=true"
      echo "Internet Gateway $IGW_ID created and attached."
    else
      echo "Internet Gateway already attached ($IGW_ID). Skipping."
    fi

    # Public route table for public subnet
    PUB_RTB_ID=$(aws ec2 describe-route-tables \
      --filters "Name=tag:Name,Values=warren-rtb-pub-$ENV" \
      --query "RouteTables[0].RouteTableId" \
      --output text 2>/dev/null || echo "None")

    if [[ "$PUB_RTB_ID" == "None" || -z "$PUB_RTB_ID" ]]; then
      PUB_RTB_ID=$(aws ec2 create-route-table \
        --vpc-id "$VPC_ID" \
        --query "RouteTable.RouteTableId" \
        --output text)
      aws ec2 create-tags --resources "$PUB_RTB_ID" \
        --tags "Key=Name,Value=warren-rtb-pub-$ENV" "Key=warren,Value=true"
      aws ec2 create-route \
        --route-table-id "$PUB_RTB_ID" \
        --destination-cidr-block 0.0.0.0/0 \
        --gateway-id "$IGW_ID" > /dev/null
      aws ec2 associate-route-table \
        --route-table-id "$PUB_RTB_ID" \
        --subnet-id "$SUBNET_PUB_ID" > /dev/null
    fi

    # NAT Gateway
    NAT_GW_ID=$(aws ec2 describe-nat-gateways \
      --filter "Name=subnet-id,Values=$SUBNET_PUB_ID" "Name=state,Values=available,pending" \
      --query "NatGateways[0].NatGatewayId" \
      --output text 2>/dev/null || echo "None")

    if [[ "$NAT_GW_ID" == "None" || -z "$NAT_GW_ID" ]]; then
      echo "Allocating Elastic IP and creating NAT Gateway (this takes ~1-2 minutes)..."
      # Check for an existing EIP tagged warren-nat-eip-$ENV to avoid leaking allocations
      # if a previous run failed after allocate-address but before create-nat-gateway.
      EIP_ALLOC=$(aws ec2 describe-addresses \
        --filters "Name=tag:Name,Values=warren-nat-eip-$ENV" \
        --query "Addresses[0].AllocationId" \
        --output text 2>/dev/null || echo "None")
      if [[ "$EIP_ALLOC" == "None" || -z "$EIP_ALLOC" ]]; then
        EIP_ALLOC=$(aws ec2 allocate-address \
          --domain vpc \
          --query "AllocationId" \
          --output text)
        aws ec2 create-tags --resources "$EIP_ALLOC" \
          --tags "Key=Name,Value=warren-nat-eip-$ENV" "Key=warren,Value=true" 2>/dev/null || true
      else
        echo "Reusing existing EIP $EIP_ALLOC (warren-nat-eip-$ENV)."
      fi
      NAT_GW_ID=$(aws ec2 create-nat-gateway \
        --subnet-id "$SUBNET_PUB_ID" \
        --allocation-id "$EIP_ALLOC" \
        --query "NatGateway.NatGatewayId" \
        --output text)
      aws ec2 create-tags --resources "$NAT_GW_ID" \
        --tags "Key=Name,Value=warren-nat-$ENV" "Key=warren,Value=true"
      echo "Waiting for NAT Gateway $NAT_GW_ID to become available..."
      aws ec2 wait nat-gateway-available --nat-gateway-ids "$NAT_GW_ID"
      echo "NAT Gateway ready."
    else
      echo "NAT Gateway already exists ($NAT_GW_ID). Skipping."
    fi

    # Private route table with 0.0.0.0/0 → NAT GW
    PRIV_RTB_ID=$(aws ec2 describe-route-tables \
      --filters "Name=tag:Name,Values=warren-rtb-priv-$ENV" \
      --query "RouteTables[0].RouteTableId" \
      --output text 2>/dev/null || echo "None")

    if [[ "$PRIV_RTB_ID" == "None" || -z "$PRIV_RTB_ID" ]]; then
      PRIV_RTB_ID=$(aws ec2 create-route-table \
        --vpc-id "$VPC_ID" \
        --query "RouteTable.RouteTableId" \
        --output text)
      aws ec2 create-tags --resources "$PRIV_RTB_ID" \
        --tags "Key=Name,Value=warren-rtb-priv-$ENV" "Key=warren,Value=true"
      aws ec2 create-route \
        --route-table-id "$PRIV_RTB_ID" \
        --destination-cidr-block 0.0.0.0/0 \
        --nat-gateway-id "$NAT_GW_ID" > /dev/null
      aws ec2 associate-route-table \
        --route-table-id "$PRIV_RTB_ID" \
        --subnet-id "$SUBNET_A_ID" > /dev/null
      aws ec2 associate-route-table \
        --route-table-id "$PRIV_RTB_ID" \
        --subnet-id "$SUBNET_B_ID" > /dev/null
    fi

    # Security group — egress 443 only, no inbound (T-08-01-05)
    SG_NAME="warren-sg-$ENV"
    SG_ID=$(aws ec2 describe-security-groups \
      --filters "Name=group-name,Values=$SG_NAME" "Name=vpc-id,Values=$VPC_ID" \
      --query "SecurityGroups[0].GroupId" \
      --output text 2>/dev/null || echo "None")

    if [[ "$SG_ID" == "None" || -z "$SG_ID" ]]; then
      echo "Creating security group '$SG_NAME' (egress 443 only, no inbound)..."
      SG_ID=$(aws ec2 create-security-group \
        --group-name "$SG_NAME" \
        --description "Warren ECS tasks — egress 443 only" \
        --vpc-id "$VPC_ID" \
        --query "GroupId" \
        --output text)
      aws ec2 create-tags --resources "$SG_ID" \
        --tags "Key=Name,Value=$SG_NAME" "Key=warren,Value=true"
      # Remove default egress rule then add egress 443 only
      aws ec2 revoke-security-group-egress \
        --group-id "$SG_ID" \
        --protocol -1 \
        --cidr 0.0.0.0/0 2>/dev/null || true
      aws ec2 authorize-security-group-egress \
        --group-id "$SG_ID" \
        --protocol tcp \
        --port 443 \
        --cidr 0.0.0.0/0 > /dev/null
      echo "Security group $SG_ID created."
    else
      echo "Security group '$SG_NAME' already exists ($SG_ID). Skipping."
    fi

    SUBNET_IDS="$SUBNET_A_ID,$SUBNET_B_ID"
    echo ""
    echo "Template A provisioned: private subnets with NAT Gateway."
    echo "assignPublicIp=DISABLED is correct for this template."

  elif [[ "$VPC_TEMPLATE" == "B" ]]; then
    # Template B: Public subnets + public IP
    SUBNET_A_NAME="warren-subnet-a-$ENV"
    SUBNET_B_NAME="warren-subnet-b-$ENV"

    SUBNET_A_ID=$(aws ec2 describe-subnets \
      --filters "Name=tag:Name,Values=$SUBNET_A_NAME" \
      --query "Subnets[0].SubnetId" \
      --output text 2>/dev/null || echo "None")

    if [[ "$SUBNET_A_ID" == "None" || -z "$SUBNET_A_ID" ]]; then
      echo "Creating public subnets..."
      SUBNET_A_ID=$(aws ec2 create-subnet \
        --vpc-id "$VPC_ID" \
        --cidr-block 10.42.0.0/24 \
        --availability-zone "$AZ_A" \
        --query "Subnet.SubnetId" \
        --output text)
      aws ec2 create-tags --resources "$SUBNET_A_ID" \
        --tags "Key=Name,Value=$SUBNET_A_NAME" "Key=warren,Value=true"

      SUBNET_B_ID=$(aws ec2 create-subnet \
        --vpc-id "$VPC_ID" \
        --cidr-block 10.42.1.0/24 \
        --availability-zone "$AZ_B" \
        --query "Subnet.SubnetId" \
        --output text)
      aws ec2 create-tags --resources "$SUBNET_B_ID" \
        --tags "Key=Name,Value=$SUBNET_B_NAME" "Key=warren,Value=true"
      echo "Public subnets created: $SUBNET_A_ID, $SUBNET_B_ID"
    else
      SUBNET_B_ID=$(aws ec2 describe-subnets \
        --filters "Name=tag:Name,Values=$SUBNET_B_NAME" \
        --query "Subnets[0].SubnetId" \
        --output text)
      echo "Public subnets already exist. Skipping."
    fi

    # Internet Gateway
    IGW_ID=$(aws ec2 describe-internet-gateways \
      --filters "Name=attachment.vpc-id,Values=$VPC_ID" \
      --query "InternetGateways[0].InternetGatewayId" \
      --output text 2>/dev/null || echo "None")

    if [[ "$IGW_ID" == "None" || -z "$IGW_ID" ]]; then
      echo "Creating Internet Gateway..."
      IGW_ID=$(aws ec2 create-internet-gateway \
        --query "InternetGateway.InternetGatewayId" \
        --output text)
      aws ec2 attach-internet-gateway --internet-gateway-id "$IGW_ID" --vpc-id "$VPC_ID"
      aws ec2 create-tags --resources "$IGW_ID" \
        --tags "Key=Name,Value=warren-igw-$ENV" "Key=warren,Value=true"
    fi

    # Public route table
    PUB_RTB_ID=$(aws ec2 describe-route-tables \
      --filters "Name=tag:Name,Values=warren-rtb-$ENV" \
      --query "RouteTables[0].RouteTableId" \
      --output text 2>/dev/null || echo "None")

    if [[ "$PUB_RTB_ID" == "None" || -z "$PUB_RTB_ID" ]]; then
      PUB_RTB_ID=$(aws ec2 create-route-table \
        --vpc-id "$VPC_ID" \
        --query "RouteTable.RouteTableId" \
        --output text)
      aws ec2 create-tags --resources "$PUB_RTB_ID" \
        --tags "Key=Name,Value=warren-rtb-$ENV" "Key=warren,Value=true"
      aws ec2 create-route \
        --route-table-id "$PUB_RTB_ID" \
        --destination-cidr-block 0.0.0.0/0 \
        --gateway-id "$IGW_ID" > /dev/null
      aws ec2 associate-route-table \
        --route-table-id "$PUB_RTB_ID" \
        --subnet-id "$SUBNET_A_ID" > /dev/null
      aws ec2 associate-route-table \
        --route-table-id "$PUB_RTB_ID" \
        --subnet-id "$SUBNET_B_ID" > /dev/null
    fi

    # Security group — egress all, no inbound (T-08-01-05)
    SG_NAME="warren-sg-$ENV"
    SG_ID=$(aws ec2 describe-security-groups \
      --filters "Name=group-name,Values=$SG_NAME" "Name=vpc-id,Values=$VPC_ID" \
      --query "SecurityGroups[0].GroupId" \
      --output text 2>/dev/null || echo "None")

    if [[ "$SG_ID" == "None" || -z "$SG_ID" ]]; then
      echo "Creating security group '$SG_NAME' (egress all, no inbound)..."
      SG_ID=$(aws ec2 create-security-group \
        --group-name "$SG_NAME" \
        --description "Warren ECS tasks — egress all (Template B)" \
        --vpc-id "$VPC_ID" \
        --query "GroupId" \
        --output text)
      aws ec2 create-tags --resources "$SG_ID" \
        --tags "Key=Name,Value=$SG_NAME" "Key=warren,Value=true"
      echo "Security group $SG_ID created."
    else
      echo "Security group '$SG_NAME' already exists ($SG_ID). Skipping."
    fi

    SUBNET_IDS="$SUBNET_A_ID,$SUBNET_B_ID"
    echo ""
    echo "WARNING: Template B uses public subnets. You MUST set"
    echo "  WARREN_ECS_ASSIGN_PUBLIC_IP=true"
    echo "in warren-server's environment to enable public IP assignment on tasks."
    echo "Without this, Fargate tasks cannot reach ghcr.io for image pulls."

  else
    # Template C: Private subnets + VPC endpoints (no internet)
    SUBNET_A_NAME="warren-subnet-a-$ENV"
    SUBNET_B_NAME="warren-subnet-b-$ENV"

    SUBNET_A_ID=$(aws ec2 describe-subnets \
      --filters "Name=tag:Name,Values=$SUBNET_A_NAME" \
      --query "Subnets[0].SubnetId" \
      --output text 2>/dev/null || echo "None")

    if [[ "$SUBNET_A_ID" == "None" || -z "$SUBNET_A_ID" ]]; then
      echo "Creating private subnets..."
      SUBNET_A_ID=$(aws ec2 create-subnet \
        --vpc-id "$VPC_ID" \
        --cidr-block 10.42.0.0/24 \
        --availability-zone "$AZ_A" \
        --query "Subnet.SubnetId" \
        --output text)
      aws ec2 create-tags --resources "$SUBNET_A_ID" \
        --tags "Key=Name,Value=$SUBNET_A_NAME" "Key=warren,Value=true"

      SUBNET_B_ID=$(aws ec2 create-subnet \
        --vpc-id "$VPC_ID" \
        --cidr-block 10.42.1.0/24 \
        --availability-zone "$AZ_B" \
        --query "Subnet.SubnetId" \
        --output text)
      aws ec2 create-tags --resources "$SUBNET_B_ID" \
        --tags "Key=Name,Value=$SUBNET_B_NAME" "Key=warren,Value=true"
      echo "Private subnets created: $SUBNET_A_ID, $SUBNET_B_ID"
    else
      SUBNET_B_ID=$(aws ec2 describe-subnets \
        --filters "Name=tag:Name,Values=$SUBNET_B_NAME" \
        --query "Subnets[0].SubnetId" \
        --output text)
      echo "Private subnets already exist. Skipping."
    fi

    # Security group for VPC endpoints — egress 443 only, no inbound (T-08-01-05)
    SG_NAME="warren-sg-$ENV"
    SG_ID=$(aws ec2 describe-security-groups \
      --filters "Name=group-name,Values=$SG_NAME" "Name=vpc-id,Values=$VPC_ID" \
      --query "SecurityGroups[0].GroupId" \
      --output text 2>/dev/null || echo "None")

    if [[ "$SG_ID" == "None" || -z "$SG_ID" ]]; then
      echo "Creating security group '$SG_NAME' (egress 443 only, no inbound)..."
      SG_ID=$(aws ec2 create-security-group \
        --group-name "$SG_NAME" \
        --description "Warren ECS tasks — egress 443 only (Template C)" \
        --vpc-id "$VPC_ID" \
        --query "GroupId" \
        --output text)
      aws ec2 create-tags --resources "$SG_ID" \
        --tags "Key=Name,Value=$SG_NAME" "Key=warren,Value=true"
      aws ec2 revoke-security-group-egress \
        --group-id "$SG_ID" \
        --protocol -1 \
        --cidr 0.0.0.0/0 2>/dev/null || true
      aws ec2 authorize-security-group-egress \
        --group-id "$SG_ID" \
        --protocol tcp \
        --port 443 \
        --cidr 0.0.0.0/0 > /dev/null
      echo "Security group $SG_ID created."
    else
      echo "Security group '$SG_NAME' already exists ($SG_ID). Skipping."
    fi

    # VPC endpoints for ECS, ECR, SSM, Logs (Template C — no internet)
    PRIVATE_DNS_ENABLED="true"
    for SVC_NAME in \
        "com.amazonaws.$REGION.ecs" \
        "com.amazonaws.$REGION.ecr.api" \
        "com.amazonaws.$REGION.ecr.dkr" \
        "com.amazonaws.$REGION.ssm" \
        "com.amazonaws.$REGION.ssmmessages" \
        "com.amazonaws.$REGION.logs"; do

      EP_ID=$(aws ec2 describe-vpc-endpoints \
        --filters "Name=vpc-id,Values=$VPC_ID" \
          "Name=service-name,Values=$SVC_NAME" \
          "Name=vpc-endpoint-state,Values=available,pending" \
        --query "VpcEndpoints[0].VpcEndpointId" \
        --output text 2>/dev/null || echo "None")

      if [[ "$EP_ID" == "None" || -z "$EP_ID" ]]; then
        echo "Creating VPC endpoint: $SVC_NAME ..."
        aws ec2 create-vpc-endpoint \
          --vpc-id "$VPC_ID" \
          --vpc-endpoint-type Interface \
          --service-name "$SVC_NAME" \
          --subnet-ids "$SUBNET_A_ID" "$SUBNET_B_ID" \
          --security-group-ids "$SG_ID" \
          --private-dns-enabled "$PRIVATE_DNS_ENABLED" \
          --tag-specifications "ResourceType=vpc-endpoint,Tags=[{Key=warren,Value=true},{Key=warren-env,Value=$ENV}]" \
          --output text > /dev/null
      else
        echo "VPC endpoint $SVC_NAME already exists ($EP_ID). Skipping."
      fi
    done

    SUBNET_IDS="$SUBNET_A_ID,$SUBNET_B_ID"
    echo ""
    echo "WARNING: Template C uses private subnets with VPC endpoints only."
    echo "There is NO outbound internet. You MUST use Amazon ECR images — ghcr.io is unreachable."
  fi

fi  # end VPC branch

echo ""

# ---------------------------------------------------------------------------
# Step 3: IAM task role (idempotent — Pattern 6)
# ---------------------------------------------------------------------------
TASK_ROLE_NAME="warren-task-role-$ENV"
EXEC_ROLE_NAME="warren-task-exec-role-$ENV"
# finding #20: declared here (not just in Step 3b below) so the TASK_POLICY heredoc's
# PassRole statement can reference it before that role is actually created.
WORKSPACE_ROLE_NAME="warren-workspace-task-role-$ENV"

echo "--- IAM Task Role ---"
if ! aws iam get-role --role-name "$TASK_ROLE_NAME" > /dev/null 2>&1; then
  echo "Creating IAM task role '$TASK_ROLE_NAME'..."

  TRUST_POLICY='{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"Service": "ecs-tasks.amazonaws.com"},
    "Action": "sts:AssumeRole"
  }]
}'

  aws iam create-role \
    --role-name "$TASK_ROLE_NAME" \
    --assume-role-policy-document "$TRUST_POLICY" \
    --tags "Key=warren,Value=true" "Key=warren-env,Value=$ENV" \
    --output text > /dev/null

  # Inline policy: WarrenTaskPolicy (D-06 + threat model T-08-01-01/02/03). Mirrors
  # terraform/main.tf's data.aws_iam_policy_document.task_role_policy / cdk/
  # warren_stack.py's WarrenTaskPolicy (findings #17/#20/#21 — this script had drifted
  # from both since PR #3).
  #
  # No SSM action at all: workspace secrets live only in warren-server's own SQLite store
  # and reach a task as a file on its EFS volume, written through the control plane's
  # mount of the filesystem (WARREN_EFS_LOCAL_MOUNT_PATH, resources/ecs/README.md).
  #
  # R17/S13/X2: DeregisterTaskDefinition takes no ecs:cluster condition key -- an
  # ArnEquals condition on a key an action doesn't support evaluates to FALSE, not
  # "ignored", so folding it into the old combined ECSTaskDef statement (with RunTask,
  # under the ecs:cluster condition) unconditionally denied it, piling up task
  # definition revisions forever. Split into ECSRunTask (conditioned) and
  # ECSDeregisterTaskDefinition (unconditioned, scoped only by the task-definition ARN
  # itself) below, and ECSDenySelfRunTask now also denies DeregisterTaskDefinition
  # against the control plane's own family, since that unconditioned wildcard matches
  # it too. Mirrors terraform/main.tf and cdk/warren_stack.py.
  #
  # Z11/X1: ECSCluster's Resource below used to guess the cluster ARN from a
  # "warren-*" wildcard, which only happened to match because the cluster name
  # ("warren-cluster-$ENV") starts with "warren-" too -- Terraform and CDK-Python
  # already fixed this (X1) by referencing the real cluster resource/construct
  # directly instead of guessing. setup.sh has no such construct reference, but it
  # does already know the exact cluster name via $CLUSTER_NAME (set above), so this
  # now builds the real ARN directly instead of a prefix guess.
  #
  # S4/#53: the "Logs" statement below gained logs:PutRetentionPolicy (Terraform
  # already had it) -- the control plane itself creates each workspace log group and
  # sets bounded retention on it directly, rather than relying on the ECS agent's
  # "awslogs-create-group" auto-create (infinite retention, no way to expire).
  # Without it, every ECS provision under this script hit AccessDenied.
  TASK_POLICY=$(cat <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ECSCluster",
      "Effect": "Allow",
      "Action": ["ecs:DescribeClusters"],
      "Resource": "arn:aws:ecs:${REGION}:${ACCOUNT_ID}:cluster/${CLUSTER_NAME}"
    },
    {
      "Sid": "ECSTaskScoped",
      "Effect": "Allow",
      "Action": ["ecs:StopTask", "ecs:DescribeTasks"],
      "Resource": "arn:aws:ecs:*:*:task/*",
      "Condition": {
        "ArnEquals": {"ecs:cluster": "arn:aws:ecs:${REGION}:${ACCOUNT_ID}:cluster/${CLUSTER_NAME}"}
      }
    },
    {
      "Sid": "ECSExecWorkspaceTasks",
      "Effect": "Allow",
      "Action": "ecs:ExecuteCommand",
      "Resource": ["arn:aws:ecs:${REGION}:${ACCOUNT_ID}:task/${CLUSTER_NAME}/*", "arn:aws:ecs:${REGION}:${ACCOUNT_ID}:cluster/${CLUSTER_NAME}"],
      "Condition": {
        "ArnEquals": {"ecs:cluster": "arn:aws:ecs:${REGION}:${ACCOUNT_ID}:cluster/${CLUSTER_NAME}"}
      }
    },
    {
      "Sid": "ECSListTasks",
      "Effect": "Allow",
      "Action": ["ecs:ListTasks"],
      "Resource": "*",
      "Condition": {
        "ArnEquals": {"ecs:cluster": "arn:aws:ecs:${REGION}:${ACCOUNT_ID}:cluster/${CLUSTER_NAME}"}
      }
    },
    {
      "Sid": "ECSRunTask",
      "Effect": "Allow",
      "Action": ["ecs:RunTask"],
      "Resource": "arn:aws:ecs:*:${ACCOUNT_ID}:task-definition/warren-*",
      "Condition": {
        "ArnEquals": {"ecs:cluster": "arn:aws:ecs:${REGION}:${ACCOUNT_ID}:cluster/${CLUSTER_NAME}"}
      }
    },
    {
      "Sid": "ECSDeregisterTaskDefinition",
      "Effect": "Allow",
      "Action": ["ecs:DeregisterTaskDefinition"],
      "Resource": "arn:aws:ecs:*:${ACCOUNT_ID}:task-definition/warren-*"
    },
    {
      "Sid": "ECSDenySelfRunTask",
      "Effect": "Deny",
      "Action": ["ecs:RunTask", "ecs:DeregisterTaskDefinition"],
      "Resource": "arn:aws:ecs:*:${ACCOUNT_ID}:task-definition/warren-server-control-plane-${ENV}:*"
    },
    {
      "Sid": "ECSRegisterTaskDefinition",
      "Effect": "Allow",
      "Action": ["ecs:RegisterTaskDefinition"],
      "Resource": "*"
    },
    {
      "Sid": "ECSTagOnCreateTask",
      "Effect": "Allow",
      "Action": ["ecs:TagResource"],
      "Resource": "arn:aws:ecs:*:*:task/*",
      "Condition": {
        "ArnEquals": {"ecs:cluster": "arn:aws:ecs:${REGION}:${ACCOUNT_ID}:cluster/${CLUSTER_NAME}"},
        "StringEquals": {"ecs:CreateAction": "RunTask"}
      }
    },
    {
      "Sid": "ECSTagOnCreateTaskDef",
      "Effect": "Allow",
      "Action": ["ecs:TagResource"],
      "Resource": "arn:aws:ecs:*:${ACCOUNT_ID}:task-definition/warren-*",
      "Condition": {
        "StringEquals": {"ecs:CreateAction": "RegisterTaskDefinition"}
      }
    },
    {
      "Sid": "PassRole",
      "Effect": "Allow",
      "Action": "iam:PassRole",
      "Resource": [
        "arn:aws:iam::${ACCOUNT_ID}:role/${EXEC_ROLE_NAME}",
        "arn:aws:iam::${ACCOUNT_ID}:role/${WORKSPACE_ROLE_NAME}"
      ]
    },
    {
      "Sid": "ECSExec",
      "Effect": "Allow",
      "Action": [
        "ssmmessages:CreateControlChannel",
        "ssmmessages:CreateDataChannel",
        "ssmmessages:OpenControlChannel",
        "ssmmessages:OpenDataChannel"
      ],
      "Resource": "*"
    },
    {
      "Sid": "Logs",
      "Effect": "Allow",
      "Action": [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents",
        "logs:PutRetentionPolicy"
      ],
      "Resource": "arn:aws:logs:*:*:log-group:/warren/*"
    },
    {
      "Sid": "ECSExecLogging",
      "Effect": "Allow",
      "Action": [
        "logs:DescribeLogGroups",
        "logs:CreateLogStream",
        "logs:DescribeLogStreams",
        "logs:PutLogEvents"
      ],
      "Resource": [
        "arn:aws:logs:${REGION}:${ACCOUNT_ID}:log-group:${ECS_EXEC_LOG_GROUP}",
        "arn:aws:logs:${REGION}:${ACCOUNT_ID}:log-group:${ECS_EXEC_LOG_GROUP}:*"
      ]
    }
  ]
}
POLICY
)

  aws iam put-role-policy \
    --role-name "$TASK_ROLE_NAME" \
    --policy-name "WarrenTaskPolicy" \
    --policy-document "$TASK_POLICY"

  echo "IAM task role '$TASK_ROLE_NAME' created with inline policy."
else
  echo "IAM task role '$TASK_ROLE_NAME' already exists. Skipping."
fi

TASK_ROLE_ARN=$(aws iam get-role \
  --role-name "$TASK_ROLE_NAME" \
  --query "Role.Arn" \
  --output text)
echo ""

# ---------------------------------------------------------------------------
# Step 3b: IAM workspace task role (idempotent — Pattern 6)
# finding #20: this role did not exist in setup.sh at all — it exported the
# control-plane's OWN role ($TASK_ROLE_NAME, with ecs:RunTask/RegisterTaskDefinition/
# PassRole/EFS access-point management) as WARREN_ECS_TASK_ROLE_ARN, so every workspace
# task (running untrusted agent-generated code) inherited the full orchestration
# permission set. Mirrors terraform/main.tf's aws_iam_role.workspace_task_role / cdk/
# warren_stack.py's WarrenWorkspaceTaskRole: ECS Exec + EFS mount only.
# AD1: Fargate allows no sandbox inside a task, so whatever this role grants, the agent
# holds. Keep it minimal (warren-server tests/unit/test_iac_exec_scoping.py).
# ---------------------------------------------------------------------------
echo "--- IAM Workspace Task Role ---"
if ! aws iam get-role --role-name "$WORKSPACE_ROLE_NAME" > /dev/null 2>&1; then
  echo "Creating IAM workspace task role '$WORKSPACE_ROLE_NAME'..."

  # Defined here (not reused from Step 3's $TRUST_POLICY) because that variable is only
  # ever set inside Step 3's own `if` branch — it would be unset here whenever the
  # control-plane role already existed and that branch was skipped.
  WORKSPACE_TRUST_POLICY='{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"Service": "ecs-tasks.amazonaws.com"},
    "Action": "sts:AssumeRole"
  }]
}'

  aws iam create-role \
    --role-name "$WORKSPACE_ROLE_NAME" \
    --assume-role-policy-document "$WORKSPACE_TRUST_POLICY" \
    --tags "Key=warren,Value=true" "Key=warren-env,Value=$ENV" \
    --output text > /dev/null

  WORKSPACE_POLICY=$(cat <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ECSExec",
      "Effect": "Allow",
      "Action": [
        "ssmmessages:CreateControlChannel",
        "ssmmessages:CreateDataChannel",
        "ssmmessages:OpenControlChannel",
        "ssmmessages:OpenDataChannel"
      ],
      "Resource": "*"
    },
    {
      "Sid": "EFSClientAccess",
      "Effect": "Allow",
      "Action": [
        "elasticfilesystem:ClientMount",
        "elasticfilesystem:ClientWrite"
      ],
      "Resource": "arn:aws:elasticfilesystem:*:${ACCOUNT_ID}:file-system/*"
    },
    {
      "Sid": "ECSExecLogging",
      "Effect": "Allow",
      "Action": [
        "logs:DescribeLogGroups",
        "logs:CreateLogStream",
        "logs:DescribeLogStreams",
        "logs:PutLogEvents"
      ],
      "Resource": [
        "arn:aws:logs:${REGION}:${ACCOUNT_ID}:log-group:${ECS_EXEC_LOG_GROUP}",
        "arn:aws:logs:${REGION}:${ACCOUNT_ID}:log-group:${ECS_EXEC_LOG_GROUP}:*"
      ]
    }
  ]
}
POLICY
)

  aws iam put-role-policy \
    --role-name "$WORKSPACE_ROLE_NAME" \
    --policy-name "WarrenWorkspaceTaskPolicy" \
    --policy-document "$WORKSPACE_POLICY"

  echo "IAM workspace task role '$WORKSPACE_ROLE_NAME' created with inline policy."
else
  echo "IAM workspace task role '$WORKSPACE_ROLE_NAME' already exists. Skipping."
fi

WORKSPACE_ROLE_ARN=$(aws iam get-role \
  --role-name "$WORKSPACE_ROLE_NAME" \
  --query "Role.Arn" \
  --output text)
echo ""

# ---------------------------------------------------------------------------
# Step 4: IAM task execution role (idempotent — Pattern 6)
# ---------------------------------------------------------------------------
echo "--- IAM Task Execution Role ---"
if ! aws iam get-role --role-name "$EXEC_ROLE_NAME" > /dev/null 2>&1; then
  echo "Creating IAM task execution role '$EXEC_ROLE_NAME'..."

  TRUST_POLICY='{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"Service": "ecs-tasks.amazonaws.com"},
    "Action": "sts:AssumeRole"
  }]
}'

  aws iam create-role \
    --role-name "$EXEC_ROLE_NAME" \
    --assume-role-policy-document "$TRUST_POLICY" \
    --tags "Key=warren,Value=true" "Key=warren-env,Value=$ENV" \
    --output text > /dev/null

  # Managed policy: AmazonECSTaskExecutionRolePolicy (D-07)
  aws iam attach-role-policy \
    --role-name "$EXEC_ROLE_NAME" \
    --policy-arn "arn:aws:iam::aws:policy/AmazonECSTaskExecutionRolePolicy"

  # Inline supplement: logs:CreateLogGroup (Pitfall 2 fix), plus ssm:GetParameters so
  # the ECS agent can resolve the control plane's own WARREN_SECRET_KEY if you keep it
  # as an SSM SecureString under /warren/ (finding #19b; narrow the Resource to that one
  # parameter, or drop the statement if it's in Secrets Manager). Workspace tasks have
  # no `secrets` entries and need no SSM access.
  EXEC_LOG_POLICY='{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "LogGroupCreate",
      "Effect": "Allow",
      "Action": "logs:CreateLogGroup",
      "Resource": "arn:aws:logs:*:*:log-group:/warren/*"
    },
    {
      "Sid": "ControlPlaneSecretKey",
      "Effect": "Allow",
      "Action": "ssm:GetParameters",
      "Resource": "arn:aws:ssm:*:*:parameter/warren/*"
    }
  ]
}'

  aws iam put-role-policy \
    --role-name "$EXEC_ROLE_NAME" \
    --policy-name "WarrenExecLogPolicy" \
    --policy-document "$EXEC_LOG_POLICY"

  echo "IAM task execution role '$EXEC_ROLE_NAME' created."
else
  echo "IAM task execution role '$EXEC_ROLE_NAME' already exists. Skipping."
fi

EXEC_ROLE_ARN=$(aws iam get-role \
  --role-name "$EXEC_ROLE_NAME" \
  --query "Role.Arn" \
  --output text)
echo ""

# ---------------------------------------------------------------------------
# Step 4b: who may ECS Exec into a workspace task (AI1, idempotent — Pattern 6)
# Mirrors terraform/main.tf's section of the same name. Deployment model: `warren
# connect` runs `aws ecs execute-command` with the caller's own credentials (no
# control-plane exec relay), so humans get the operator managed policy (exec and
# AWS-StartPortForwardingSession tunnels only into tasks whose warren.owner_id tag equals
# their own warren-owner principal tag; explicit denies for other owners, untagged tasks
# and callers, and any other session document) and the
# break-glass role is the only cluster-wide exec holder. Exec logging (Step 0b) applies
# to both.
# ---------------------------------------------------------------------------
echo "--- ECS Exec access (operator policy + break-glass role) ---"
OWNER_PRINCIPAL_TAG="warren-owner"
OPERATOR_POLICY_NAME="warren-workspace-operator-$ENV"
OPERATOR_POLICY_ARN="arn:aws:iam::${ACCOUNT_ID}:policy/${OPERATOR_POLICY_NAME}"
BREAK_GLASS_ROLE_NAME="warren-break-glass-$ENV"
CLUSTER_ARN="arn:aws:ecs:${REGION}:${ACCOUNT_ID}:cluster/${CLUSTER_NAME}"
WORKSPACE_TASK_ARNS="arn:aws:ecs:${REGION}:${ACCOUNT_ID}:task/${CLUSTER_NAME}/*"
ANY_TASK_ARNS="arn:aws:ecs:${REGION}:${ACCOUNT_ID}:task/*"
PORT_FORWARD_DOCUMENT="arn:aws:ssm:${REGION}::document/AWS-StartPortForwardingSession"

if ! aws iam get-policy --policy-arn "$OPERATOR_POLICY_ARN" > /dev/null 2>&1; then
  OPERATOR_POLICY=$(cat <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DescribeWorkspaceTasks",
      "Effect": "Allow",
      "Action": ["ecs:DescribeTasks", "ecs:ListTasks"],
      "Resource": "*",
      "Condition": {"ArnEquals": {"ecs:cluster": "${CLUSTER_ARN}"}}
    },
    {
      "Sid": "ExecOwnWorkspaceTasks",
      "Effect": "Allow",
      "Action": "ecs:ExecuteCommand",
      "Resource": "${WORKSPACE_TASK_ARNS}",
      "Condition": {
        "ArnEquals": {"ecs:cluster": "${CLUSTER_ARN}"},
        "StringEquals": {"ecs:ResourceTag/warren.owner_id": "\${aws:PrincipalTag/${OWNER_PRINCIPAL_TAG}}"}
      }
    },
    {
      "Sid": "ExecWorkspaceCluster",
      "Effect": "Allow",
      "Action": "ecs:ExecuteCommand",
      "Resource": "${CLUSTER_ARN}"
    },
    {
      "Sid": "DenyExecOtherOwners",
      "Effect": "Deny",
      "Action": "ecs:ExecuteCommand",
      "Resource": "${WORKSPACE_TASK_ARNS}",
      "Condition": {
        "StringNotEquals": {"ecs:ResourceTag/warren.owner_id": "\${aws:PrincipalTag/${OWNER_PRINCIPAL_TAG}}"}
      }
    },
    {
      "Sid": "DenyExecWithoutOwnerTag",
      "Effect": "Deny",
      "Action": "ecs:ExecuteCommand",
      "Resource": "${WORKSPACE_TASK_ARNS}",
      "Condition": {"Null": {"aws:PrincipalTag/${OWNER_PRINCIPAL_TAG}": "true"}}
    },
    {
      "Sid": "PortForwardDocument",
      "Effect": "Allow",
      "Action": "ssm:StartSession",
      "Resource": "${PORT_FORWARD_DOCUMENT}"
    },
    {
      "Sid": "PortForwardOwnWorkspaceTasks",
      "Effect": "Allow",
      "Action": "ssm:StartSession",
      "Resource": ["${WORKSPACE_TASK_ARNS}", "${ANY_TASK_ARNS}"],
      "Condition": {
        "StringEquals": {"aws:ResourceTag/warren.owner_id": "\${aws:PrincipalTag/${OWNER_PRINCIPAL_TAG}}"},
        "BoolIfExists": {"ssm:SessionDocumentAccessCheck": "true"}
      }
    },
    {
      "Sid": "DenySsmSessionOtherOwners",
      "Effect": "Deny",
      "Action": "ssm:StartSession",
      "Resource": "${ANY_TASK_ARNS}",
      "Condition": {
        "StringNotEquals": {"aws:ResourceTag/warren.owner_id": "\${aws:PrincipalTag/${OWNER_PRINCIPAL_TAG}}"},
        "Null": {"aws:ResourceTag/warren.owner_id": "false"}
      }
    },
    {
      "Sid": "DenySsmSessionUntaggedWorkspaceTasks",
      "Effect": "Deny",
      "Action": "ssm:StartSession",
      "Resource": "${WORKSPACE_TASK_ARNS}",
      "Condition": {"Null": {"aws:ResourceTag/warren.owner_id": "true"}}
    },
    {
      "Sid": "DenySsmSessionWithoutOwnerTag",
      "Effect": "Deny",
      "Action": "ssm:StartSession",
      "Resource": "${ANY_TASK_ARNS}",
      "Condition": {"Null": {"aws:PrincipalTag/${OWNER_PRINCIPAL_TAG}": "true"}}
    },
    {
      "Sid": "DenyNonPortForwardDocuments",
      "Effect": "Deny",
      "Action": "ssm:StartSession",
      "NotResource": [
        "${PORT_FORWARD_DOCUMENT}",
        "${ANY_TASK_ARNS}",
        "arn:aws:ec2:*:${ACCOUNT_ID}:instance/*",
        "arn:aws:ssm:*:${ACCOUNT_ID}:managed-instance/*"
      ]
    }
  ]
}
POLICY
)
  aws iam create-policy \
    --policy-name "$OPERATOR_POLICY_NAME" \
    --description "ECS Exec into your own warren workspace tasks only (AI1)" \
    --policy-document "$OPERATOR_POLICY" \
    --tags "Key=warren,Value=true" "Key=warren-env,Value=$ENV" \
    --output text > /dev/null
  echo "Managed policy '$OPERATOR_POLICY_NAME' created."
else
  echo "Managed policy '$OPERATOR_POLICY_NAME' already exists. Skipping."
fi

if ! aws iam get-role --role-name "$BREAK_GLASS_ROLE_NAME" > /dev/null 2>&1; then
  BREAK_GLASS_TRUST=$(cat <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"AWS": "arn:aws:iam::${ACCOUNT_ID}:root"},
    "Action": "sts:AssumeRole",
    "Condition": {"Bool": {"aws:MultiFactorAuthPresent": "true"}}
  }]
}
POLICY
)
  BREAK_GLASS_POLICY=$(cat <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DescribeClusterTasks",
      "Effect": "Allow",
      "Action": ["ecs:DescribeTasks", "ecs:ListTasks"],
      "Resource": "*",
      "Condition": {"ArnEquals": {"ecs:cluster": "${CLUSTER_ARN}"}}
    },
    {
      "Sid": "ClusterWideExec",
      "Effect": "Allow",
      "Action": "ecs:ExecuteCommand",
      "Resource": ["${WORKSPACE_TASK_ARNS}", "${CLUSTER_ARN}"],
      "Condition": {"ArnEquals": {"ecs:cluster": "${CLUSTER_ARN}"}}
    },
    {
      "Sid": "ClusterWideSsmSessions",
      "Effect": "Allow",
      "Action": "ssm:StartSession",
      "Resource": [
        "${WORKSPACE_TASK_ARNS}",
        "arn:aws:ssm:${REGION}::document/AWS-StartPortForwardingSession",
        "arn:aws:ssm:${REGION}::document/AWS-StartPortForwardingSessionToRemoteHost"
      ]
    },
    {
      "Sid": "OwnSessions",
      "Effect": "Allow",
      "Action": ["ssm:TerminateSession", "ssm:ResumeSession"],
      "Resource": "arn:aws:ssm:*:*:session/\${aws:userid}-*"
    }
  ]
}
POLICY
)
  aws iam create-role \
    --role-name "$BREAK_GLASS_ROLE_NAME" \
    --assume-role-policy-document "$BREAK_GLASS_TRUST" \
    --max-session-duration 3600 \
    --description "The only warren role with cluster-wide ECS Exec and SSM sessions (AI1)" \
    --tags "Key=warren,Value=true" "Key=warren-env,Value=$ENV" \
    --output text > /dev/null
  aws iam put-role-policy \
    --role-name "$BREAK_GLASS_ROLE_NAME" \
    --policy-name "WarrenBreakGlassExec" \
    --policy-document "$BREAK_GLASS_POLICY"
  echo "Break-glass role '$BREAK_GLASS_ROLE_NAME' created (MFA required to assume)."
else
  echo "Break-glass role '$BREAK_GLASS_ROLE_NAME' already exists. Skipping."
fi
BREAK_GLASS_ROLE_ARN="arn:aws:iam::${ACCOUNT_ID}:role/${BREAK_GLASS_ROLE_NAME}"
echo ""

# ---------------------------------------------------------------------------
# Step 5: EFS File System for workspace persistence (D-07)
# ---------------------------------------------------------------------------
echo "--- EFS Workspace Persistence ---"
EFS_NAME="warren-efs-$ENV"
WARREN_EFS_ID=$(aws efs describe-file-systems \
  --query "FileSystems[?Tags[?Key=='Name' && Value=='$EFS_NAME']].FileSystemId | [0]" \
  --output text 2>/dev/null || echo "None")

# Audit #15: always encrypted at rest. WARREN_EFS_KMS_KEY_ID (optional) picks a
# customer-managed key; unset uses aws/elasticfilesystem. Mirrors terraform's
# var.efs_kms_key_arn / CDK's efs_kms_key_arn.
EFS_ENCRYPTION_ARGS=(--encrypted)
if [[ -n "${WARREN_EFS_KMS_KEY_ID:-}" ]]; then
  EFS_ENCRYPTION_ARGS+=(--kms-key-id "$WARREN_EFS_KMS_KEY_ID")
fi

if [[ "$WARREN_EFS_ID" == "None" || -z "$WARREN_EFS_ID" ]]; then
  echo "Creating encrypted EFS file system '$EFS_NAME'..."
  WARREN_EFS_ID=$(aws efs create-file-system \
    --performance-mode generalPurpose \
    --throughput-mode bursting \
    "${EFS_ENCRYPTION_ARGS[@]}" \
    --tags Key=Name,Value="$EFS_NAME" Key=warren,Value=true Key=warren-env,Value="$ENV" \
    --query "FileSystemId" \
    --output text)
  echo "EFS file system $WARREN_EFS_ID created."
else
  echo "EFS file system '$EFS_NAME' already exists ($WARREN_EFS_ID). Skipping."
  EFS_ENCRYPTED=$(aws efs describe-file-systems --file-system-id "$WARREN_EFS_ID" \
    --query "FileSystems[0].Encrypted" --output text)
  if [[ "$EFS_ENCRYPTED" != "True" ]]; then
    echo "WARNING: $WARREN_EFS_ID is NOT encrypted at rest. Encryption cannot be enabled" >&2
    echo "  on an existing filesystem; migrate per resources/ecs/README.md (EFS encryption)." >&2
  fi
fi

# finding #20: no filesystem resource policy existed here at all. Without it, any
# workspace task can mount the filesystem's root directly over plain NFS, bypassing its
# own access point entirely, and read/write every other workspace's directory — these
# two Deny statements are the standard AWS-documented pattern for requiring TLS and
# requiring every mount go through an access point. Mirrors terraform/main.tf's
# aws_efs_file_system_policy.warren / cdk/warren_stack.py's add_to_resource_policy calls.
echo "Applying EFS file system policy (deny insecure transport, deny non-access-point mounts)..."
EFS_FS_POLICY=$(cat <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyInsecureTransport",
      "Effect": "Deny",
      "Principal": "*",
      "Action": [
        "elasticfilesystem:ClientMount",
        "elasticfilesystem:ClientWrite",
        "elasticfilesystem:ClientRootAccess"
      ],
      "Resource": "arn:aws:elasticfilesystem:*:${ACCOUNT_ID}:file-system/${WARREN_EFS_ID}",
      "Condition": {
        "Bool": {"aws:SecureTransport": "false"}
      }
    },
    {
      "Sid": "DenyMountWithoutAccessPoint",
      "Effect": "Deny",
      "Principal": "*",
      "Action": [
        "elasticfilesystem:ClientMount",
        "elasticfilesystem:ClientWrite"
      ],
      "Resource": "arn:aws:elasticfilesystem:*:${ACCOUNT_ID}:file-system/${WARREN_EFS_ID}",
      "Condition": {
        "Null": {"elasticfilesystem:AccessPointArn": "true"}
      }
    }
  ]
}
POLICY
)
aws efs put-file-system-policy \
  --file-system-id "$WARREN_EFS_ID" \
  --policy "$EFS_FS_POLICY" > /dev/null
echo "EFS file system policy applied."

EFS_SG_NAME="warren-efs-sg-$ENV"
# warren-efs-sg-* security group isolates NFS traffic to EFS from task SG
EFS_SG_ID=$(aws ec2 describe-security-groups \
  --filters "Name=group-name,Values=$EFS_SG_NAME" "Name=vpc-id,Values=$VPC_ID" \
  --query "SecurityGroups[0].GroupId" \
  --output text 2>/dev/null || echo "None")

if [[ "$EFS_SG_ID" == "None" || -z "$EFS_SG_ID" ]]; then
  echo "Creating EFS security group '$EFS_SG_NAME'..."
  EFS_SG_ID=$(aws ec2 create-security-group \
    --group-name "$EFS_SG_NAME" \
    --description "Warren EFS — NFS inbound from ECS tasks" \
    --vpc-id "$VPC_ID" \
    --query "GroupId" \
    --output text)
  aws ec2 create-tags --resources "$EFS_SG_ID" \
    --tags "Key=Name,Value=$EFS_SG_NAME" "Key=warren,Value=true"
  # NFS inbound to EFS from task SG
  aws ec2 authorize-security-group-ingress \
    --group-id "$EFS_SG_ID" \
    --protocol tcp \
    --port 2049 \
    --source-group "$SG_ID" > /dev/null
  echo "EFS security group $EFS_SG_ID created with NFS inbound rule."
else
  echo "EFS security group '$EFS_SG_NAME' already exists ($EFS_SG_ID). Skipping."
fi

# NFS egress from task SG to EFS SG (idempotent — ignore DuplicatePermission error)
echo "Ensuring NFS egress on task security group $SG_ID → EFS SG $EFS_SG_ID (port 2049)..."
aws ec2 authorize-security-group-egress \
  --group-id "$SG_ID" \
  --ip-permissions "[{\"IpProtocol\":\"tcp\",\"FromPort\":2049,\"ToPort\":2049,\"UserIdGroupPairs\":[{\"GroupId\":\"$EFS_SG_ID\"}]}]" \
  > /dev/null 2>&1 || true

echo "Ensuring EFS mount targets in subnets..."
IFS=',' read -ra _SUBNET_ARRAY <<< "$SUBNET_IDS"
for SUBNET in "${_SUBNET_ARRAY[@]}"; do
  MT_CHECK=$(aws efs describe-mount-targets \
    --file-system-id "$WARREN_EFS_ID" \
    --query "MountTargets[?SubnetId=='$SUBNET'].MountTargetId | [0]" \
    --output text 2>/dev/null || echo "None")
  if [[ "$MT_CHECK" == "None" || -z "$MT_CHECK" ]]; then
    aws efs create-mount-target \
      --file-system-id "$WARREN_EFS_ID" \
      --subnet-id "$SUBNET" \
      --security-groups "$EFS_SG_ID" > /dev/null
    echo "  Mount target created in subnet $SUBNET."
  else
    echo "  Mount target already exists in subnet $SUBNET ($MT_CHECK). Skipping."
  fi
done

# The control plane mounts this access point (WARREN_EFS_LOCAL_MOUNT_PATH) to write each
# ECS workspace's secrets onto its volume just before RunTask (runtime/ecs_secrets.py),
# so it is always created. With WARREN_EFS_PURGE_WORKSPACE_DATA=true (R13) the
# access-point-TTL reaper also deletes a workspace's data directory through it. Rooted at
# "/var/lib/warren" (NOT the filesystem's true root "/", and NOT a per-workspace subpath
# like WarrenControlPlaneAccessPoint in terraform/main.tf or cdk/warren_stack.py) -- the
# reaper needs to reach every workspaces/{id} directory under THIS prefix to delete it.
# Mirrors terraform/main.tf's
# aws_efs_access_point.warren_root / cdk/warren_stack.py's WarrenRootAccessPoint.
#
# Audit Z10: this was rooted at "/" until this fix. efs.py's per-workspace access points
# are rooted at "/var/lib/warren/workspaces/{workspace_id}" -- that's where workspace
# data actually lives on the underlying EFS filesystem. efs_reaper.py's
# _purge_workspace_directory computes its delete target as
# Path(local_mount_path) / "workspaces" / workspace_id. With the OLD "/" root, that
# mount's "workspaces/{id}" resolved to the filesystem's true /workspaces/{id} -- one
# directory level too shallow, which never exists, so every delete silently found
# nothing (debug-logged only) and no workspace data was ever actually freed despite the
# feature being "on".
WARREN_EFS_ROOT_AP_ID=""
WARREN_EFS_PURGE_WORKSPACE_DATA=false
if [[ "$(yesno "Delete a workspace's EFS data when its access point is reaped (R13)" "n")" == "y" ]]; then
  WARREN_EFS_PURGE_WORKSPACE_DATA=true
fi
EFS_ROOT_AP_NAME="warren-root-ap-$ENV"
WARREN_EFS_ROOT_AP_ID=$(aws efs describe-access-points \
  --file-system-id "$WARREN_EFS_ID" \
  --query "AccessPoints[?Tags[?Key=='Name' && Value=='$EFS_ROOT_AP_NAME']].AccessPointId | [0]" \
  --output text 2>/dev/null || echo "None")
if [[ "$WARREN_EFS_ROOT_AP_ID" == "None" || -z "$WARREN_EFS_ROOT_AP_ID" ]]; then
  echo "Creating EFS root access point '$EFS_ROOT_AP_NAME'..."
  WARREN_EFS_ROOT_AP_ID=$(aws efs create-access-point \
    --file-system-id "$WARREN_EFS_ID" \
    --posix-user Uid=1000,Gid=1000 \
    --root-directory "Path=/var/lib/warren" \
    --tags Key=Name,Value="$EFS_ROOT_AP_NAME" Key=warren,Value=true \
    --query "AccessPointId" \
    --output text)
  echo "EFS root access point $WARREN_EFS_ROOT_AP_ID created."
else
  echo "EFS root access point '$EFS_ROOT_AP_NAME' already exists ($WARREN_EFS_ROOT_AP_ID). Skipping."
fi

# WarrenTaskEFSPolicy — EFS IAM inline policy for task role (D-08). finding #20/#16:
# the previous EFSAccessPoints statement granted TagResource scoped to the FILESYSTEM
# ARN — the wrong resource type (CreateAccessPoint's own tag-on-create authorization
# check is against the ACCESS-POINT ARN being created, not the filesystem), so it likely
# never actually authorized tagged access-point creation at all. Split to match
# terraform/main.tf's EFSCreateAccessPoint/EFSTagAccessPointsOnCreate/
# EFSLifecycleTagging statements, and add the TagResource/UntagResource grant efs.py's
# detach()/reattach path needs (finding #16) that this script never had.
EFS_TASK_POLICY=$(cat <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "EFSMount",
      "Effect": "Allow",
      "Action": [
        "elasticfilesystem:ClientMount",
        "elasticfilesystem:ClientWrite",
        "elasticfilesystem:DescribeMountTargets",
        "elasticfilesystem:DescribeAccessPoints"
      ],
      "Resource": "arn:aws:elasticfilesystem:*:$ACCOUNT_ID:file-system/$WARREN_EFS_ID"
    },
    {
      "Sid": "EFSCreateAccessPoint",
      "Effect": "Allow",
      "Action": "elasticfilesystem:CreateAccessPoint",
      "Resource": "arn:aws:elasticfilesystem:*:$ACCOUNT_ID:file-system/$WARREN_EFS_ID",
      "Condition": {
        "StringEquals": {"aws:RequestTag/warren": "true"}
      }
    },
    {
      "Sid": "EFSTagAccessPointsOnCreate",
      "Effect": "Allow",
      "Action": "elasticfilesystem:TagResource",
      "Resource": "arn:aws:elasticfilesystem:*:$ACCOUNT_ID:access-point/*",
      "Condition": {
        "StringEquals": {
          "aws:RequestTag/warren": "true",
          "elasticfilesystem:CreateAction": "CreateAccessPoint"
        }
      }
    },
    {
      "Sid": "EFSLifecycleTagging",
      "Effect": "Allow",
      "Action": [
        "elasticfilesystem:TagResource",
        "elasticfilesystem:UntagResource"
      ],
      "Resource": "arn:aws:elasticfilesystem:*:$ACCOUNT_ID:access-point/*",
      "Condition": {
        "ForAllValues:StringEquals": {
          "aws:TagKeys": ["warren.expires_at"]
        },
        "StringEquals": {
          "aws:ResourceTag/warren": "true"
        }
      }
    },
    {
      "Sid": "EFSDeleteTaggedAccessPoints",
      "Effect": "Allow",
      "Action": "elasticfilesystem:DeleteAccessPoint",
      "Resource": "arn:aws:elasticfilesystem:*:$ACCOUNT_ID:access-point/*",
      "Condition": {
        "StringEquals": {
          "aws:ResourceTag/warren": "true"
        }
      }
    }
  ]
}
POLICY
)
aws iam put-role-policy \
  --role-name "$TASK_ROLE_NAME" \
  --policy-name "WarrenTaskEFSPolicy" \
  --policy-document "$EFS_TASK_POLICY"
echo "EFS IAM policy attached to task role."
echo ""

# ---------------------------------------------------------------------------
# Step 6: Print WARREN_ECS_* export lines to stdout (D-03)
# ---------------------------------------------------------------------------
echo "========================================================================"
echo "Setup complete. Add the following exports to your warren-server environment:"
echo "========================================================================"
echo ""
# Subnet IDs and SG IDs are output as JSON arrays — pydantic-settings v2 requires
# JSON-encoded values for list[str] fields (plain comma-separated values are not split).
# Parse SUBNET_IDS (comma-separated) into a JSON array for the export line.
IFS=',' read -ra _SUBNET_ARR <<< "$SUBNET_IDS"
SUBNET_JSON="["
for i in "${!_SUBNET_ARR[@]}"; do
  SUBNET_JSON+="\"${_SUBNET_ARR[$i]}\""
  [[ $i -lt $(( ${#_SUBNET_ARR[@]} - 1 )) ]] && SUBNET_JSON+=","
done
SUBNET_JSON+="]"

echo "export WARREN_ECS_CLUSTER=\"$CLUSTER_NAME\""
echo "export WARREN_ECS_SUBNET_IDS='${SUBNET_JSON}'"
echo "export WARREN_ECS_SECURITY_GROUP_IDS='[\"${SG_ID}\"]'"
# finding #20: this used to export $TASK_ROLE_ARN (the control-plane's OWN role) here —
# every workspace task then inherited ecs:RunTask/RegisterTaskDefinition/PassRole/EFS
# access-point management. $WORKSPACE_ROLE_ARN (Step 3b above) is the narrowly-scoped
# role actually meant for spawned workspace tasks.
echo "export WARREN_ECS_TASK_ROLE_ARN=\"$WORKSPACE_ROLE_ARN\""
echo "export WARREN_ECS_TASK_EXECUTION_ROLE_ARN=\"$EXEC_ROLE_ARN\""
echo "export WARREN_ECS_IMAGE_URI=\"$IMAGE_URI\""
echo "export WARREN_EFS_ID=\"$WARREN_EFS_ID\""
if [[ -n "$WARREN_EFS_ROOT_AP_ID" ]]; then
  echo ""
  echo "Workspace secrets are delivered through the filesystem: mount access point"
  echo "  $WARREN_EFS_ROOT_AP_ID into the control-plane task at /mnt/warren-efs-root"
  echo "  (iam=ENABLED, transit encryption enabled), then:"
  echo "  export WARREN_EFS_LOCAL_MOUNT_PATH=\"/mnt/warren-efs-root\""
  echo "  export WARREN_EFS_PURGE_WORKSPACE_DATA=\"$WARREN_EFS_PURGE_WORKSPACE_DATA\""
fi
echo ""
echo "The control-plane task itself still needs (not generated by this script):"
echo "  - WARREN_SERVER_ID set to a STABLE value (e.g. your ECS service name) — the"
echo "    default (hostname) changes on every Fargate restart, breaking the AWS"
echo "    audience clients sign for and the EFS reaper's server-instance match (finding #19a)."
echo "  - WARREN_SECRET_KEY sourced from a real secret store (SSM SecureString /"
echo "    Secrets Manager) via the task definition's 'secrets' block — never a"
echo "    plaintext env override on a run-task call (finding #19b)."
echo "  - Running as a long-lived ECS service (desired_count=1), not a one-off"
echo "    'run-task', so it restarts automatically after a crash (finding #19c)."
echo "  - That service deploying stop-before-start (audit #10): it is a single SQLite"
echo "    writer on EFS, so create it with"
echo "    --deployment-configuration minimumHealthyPercent=0,maximumPercent=100"
echo "  - WARREN_AWS_TRUSTED_ASSUMED_ROLE_PATTERNS if operators authenticate via IAM"
echo "    Identity Center assumed roles — empty by default, which rejects every such"
echo "    caller with 401 (finding #18). Must be a JSON array of complete regexes"
echo "    (matched with re.fullmatch), e.g.:"
echo "    export WARREN_AWS_TRUSTED_ASSUMED_ROLE_PATTERNS='[\"arn:aws:sts::${ACCOUNT_ID}:assumed-role/AWSReservedSSO_MyPermissionSet_abc123def456/[^/]+\"]'"
echo "  See resources/ecs/terraform/main.tf or resources/ecs/cdk/warren_stack.py for a"
echo "  fully automated reference of all three."
echo ""
echo "ECS Exec access (AI1, see resources/ecs/README.md \"ECS Exec access\"):"
echo "  - Attach $OPERATOR_POLICY_ARN to every human who runs 'warren connect',"
echo "    and tag each one with ${OWNER_PRINCIPAL_TAG}=<their warren owner_id>."
echo "  - Break-glass (cluster-wide exec) only via $BREAK_GLASS_ROLE_ARN."
echo ""
echo "========================================================================"
echo "Next step: run 'warren doctor' to verify the infrastructure is correctly"
echo "wired to warren-server."
echo "========================================================================"
