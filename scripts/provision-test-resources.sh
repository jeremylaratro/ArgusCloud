#!/bin/bash
#
# CloudHound Test Resource Provisioner
# Automatically creates AWS resources for security assessment testing
#
# Usage: ./provision-test-resources.sh [--profile PROFILE] [--region REGION] [--cleanup]
#
# Cost estimate: < $1 if cleaned up within 1 hour, < $10 if left for 24 hours
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Defaults
PROFILE=""
REGION="us-east-1"
CLEANUP=false
PREFIX="ch-test"
TIMESTAMP=$(date +%s)

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --profile)
            PROFILE="$2"
            shift 2
            ;;
        --region)
            REGION="$2"
            shift 2
            ;;
        --cleanup)
            CLEANUP=true
            shift
            ;;
        --help|-h)
            echo "Usage: $0 [--profile PROFILE] [--region REGION] [--cleanup]"
            echo ""
            echo "Options:"
            echo "  --profile   AWS CLI profile to use"
            echo "  --region    AWS region (default: us-east-1)"
            echo "  --cleanup   Remove all test resources instead of creating them"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Build AWS CLI command prefix
AWS_CMD="aws"
if [[ -n "$PROFILE" ]]; then
    AWS_CMD="aws --profile $PROFILE"
fi
AWS_CMD="$AWS_CMD --region $REGION"

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[OK]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_section() { echo -e "\n${GREEN}=== $1 ===${NC}"; }

# Verify AWS credentials
verify_credentials() {
    log_section "Verifying AWS Credentials"

    ACCOUNT_ID=$($AWS_CMD sts get-caller-identity --query 'Account' --output text 2>/dev/null) || {
        log_error "Failed to verify AWS credentials. Check your profile/credentials."
        exit 1
    }

    CALLER_ARN=$($AWS_CMD sts get-caller-identity --query 'Arn' --output text)
    log_success "Authenticated as: $CALLER_ARN"
    log_info "Account ID: $ACCOUNT_ID"
    log_info "Region: $REGION"
}

# Track created resources for cleanup
CREATED_RESOURCES=""
save_resource() {
    echo "$1:$2" >> /tmp/cloudhound-test-resources.txt
    CREATED_RESOURCES="$CREATED_RESOURCES\n$1: $2"
}

# Cleanup function
cleanup_resources() {
    log_section "Cleaning Up Test Resources"

    # IAM User
    log_info "Removing IAM user..."
    $AWS_CMD iam delete-login-profile --user-name ${PREFIX}-user 2>/dev/null || true
    for key in $($AWS_CMD iam list-access-keys --user-name ${PREFIX}-user --query 'AccessKeyMetadata[].AccessKeyId' --output text 2>/dev/null); do
        $AWS_CMD iam delete-access-key --user-name ${PREFIX}-user --access-key-id $key 2>/dev/null || true
    done
    $AWS_CMD iam detach-user-policy --user-name ${PREFIX}-user --policy-arn arn:aws:iam::aws:policy/ReadOnlyAccess 2>/dev/null || true
    $AWS_CMD iam delete-user --user-name ${PREFIX}-user 2>/dev/null && log_success "Deleted IAM user" || true

    # IAM Roles
    log_info "Removing IAM roles..."
    $AWS_CMD iam delete-role --role-name ${PREFIX}-open-trust-role 2>/dev/null && log_success "Deleted open trust role" || true

    # Lambda role
    $AWS_CMD iam detach-role-policy --role-name ${PREFIX}-lambda-role --policy-arn arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole 2>/dev/null || true
    $AWS_CMD iam delete-role --role-name ${PREFIX}-lambda-role 2>/dev/null && log_success "Deleted Lambda role" || true

    # EC2 role and instance profile
    $AWS_CMD iam remove-role-from-instance-profile --instance-profile-name ${PREFIX}-ec2-profile --role-name ${PREFIX}-ec2-role 2>/dev/null || true
    $AWS_CMD iam delete-instance-profile --instance-profile-name ${PREFIX}-ec2-profile 2>/dev/null || true
    $AWS_CMD iam detach-role-policy --role-name ${PREFIX}-ec2-role --policy-arn arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess 2>/dev/null || true
    $AWS_CMD iam delete-role --role-name ${PREFIX}-ec2-role 2>/dev/null && log_success "Deleted EC2 role" || true

    # Lambda function
    log_info "Removing Lambda function..."
    $AWS_CMD lambda delete-function-url-config --function-name ${PREFIX}-function 2>/dev/null || true
    $AWS_CMD lambda delete-function --function-name ${PREFIX}-function 2>/dev/null && log_success "Deleted Lambda function" || true

    # S3 buckets
    log_info "Removing S3 buckets..."
    for bucket in $($AWS_CMD s3api list-buckets --query "Buckets[?starts_with(Name, '${PREFIX}')].Name" --output text 2>/dev/null); do
        $AWS_CMD s3 rb "s3://$bucket" --force 2>/dev/null && log_success "Deleted bucket: $bucket" || true
    done

    # EC2 instances
    log_info "Terminating EC2 instances..."
    INSTANCE_IDS=$($AWS_CMD ec2 describe-instances \
        --filters "Name=tag:Name,Values=${PREFIX}-instance" "Name=instance-state-name,Values=running,stopped,pending" \
        --query 'Reservations[].Instances[].InstanceId' --output text 2>/dev/null)
    if [[ -n "$INSTANCE_IDS" ]]; then
        $AWS_CMD ec2 terminate-instances --instance-ids $INSTANCE_IDS 2>/dev/null && log_success "Terminated EC2 instances" || true
        log_info "Waiting for instances to terminate..."
        $AWS_CMD ec2 wait instance-terminated --instance-ids $INSTANCE_IDS 2>/dev/null || true
    fi

    # Security groups (wait for instances to terminate first)
    log_info "Removing security groups..."
    sleep 5
    SG_ID=$($AWS_CMD ec2 describe-security-groups --filters "Name=group-name,Values=${PREFIX}-open-sg" --query 'SecurityGroups[0].GroupId' --output text 2>/dev/null)
    if [[ -n "$SG_ID" && "$SG_ID" != "None" ]]; then
        $AWS_CMD ec2 delete-security-group --group-id $SG_ID 2>/dev/null && log_success "Deleted security group" || true
    fi

    # EC2 snapshots
    log_info "Removing EC2 snapshots..."
    for snap in $($AWS_CMD ec2 describe-snapshots --owner-ids $ACCOUNT_ID --filters "Name=description,Values=${PREFIX}*" --query 'Snapshots[].SnapshotId' --output text 2>/dev/null); do
        $AWS_CMD ec2 delete-snapshot --snapshot-id $snap 2>/dev/null && log_success "Deleted snapshot: $snap" || true
    done

    # EC2 volumes
    log_info "Removing EC2 volumes..."
    for vol in $($AWS_CMD ec2 describe-volumes --filters "Name=tag:Name,Values=${PREFIX}*" --query 'Volumes[].VolumeId' --output text 2>/dev/null); do
        $AWS_CMD ec2 delete-volume --volume-id $vol 2>/dev/null && log_success "Deleted volume: $vol" || true
    done

    # CloudWatch Log Groups
    log_info "Removing CloudWatch log groups..."
    $AWS_CMD logs delete-log-group --log-group-name /${PREFIX}/test-logs 2>/dev/null && log_success "Deleted log group" || true

    # KMS keys (schedule deletion)
    log_info "Scheduling KMS key deletion..."
    KEY_ID=$($AWS_CMD kms list-aliases --query "Aliases[?AliasName=='alias/${PREFIX}-key'].TargetKeyId" --output text 2>/dev/null)
    if [[ -n "$KEY_ID" && "$KEY_ID" != "None" ]]; then
        $AWS_CMD kms delete-alias --alias-name alias/${PREFIX}-key 2>/dev/null || true
        $AWS_CMD kms schedule-key-deletion --key-id $KEY_ID --pending-window-in-days 7 2>/dev/null && log_success "Scheduled KMS key deletion (7 days)" || true
    fi

    rm -f /tmp/cloudhound-test-resources.txt
    log_section "Cleanup Complete"
}

# Run cleanup if requested
if $CLEANUP; then
    verify_credentials
    cleanup_resources
    exit 0
fi

# ============================================================================
# RESOURCE CREATION
# ============================================================================

verify_credentials

echo ""
echo -e "${YELLOW}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${YELLOW}║  CloudHound Test Resource Provisioner                        ║${NC}"
echo -e "${YELLOW}║                                                              ║${NC}"
echo -e "${YELLOW}║  This will create intentionally misconfigured resources      ║${NC}"
echo -e "${YELLOW}║  for security testing. Estimated cost: <\$1/hour             ║${NC}"
echo -e "${YELLOW}║                                                              ║${NC}"
echo -e "${YELLOW}║  Run with --cleanup when done to remove all resources        ║${NC}"
echo -e "${YELLOW}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""
read -p "Continue? (y/N) " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    exit 1
fi

# ============================================================================
# 1. IAM Resources (Free)
# ============================================================================
log_section "Creating IAM Resources"

# Open trust role
log_info "Creating role with open trust policy..."
$AWS_CMD iam create-role --role-name ${PREFIX}-open-trust-role \
    --assume-role-policy-document '{
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": "*",
            "Action": "sts:AssumeRole"
        }]
    }' --no-cli-pager >/dev/null 2>&1 && log_success "Created open trust role" || log_warn "Role may already exist"
save_resource "iam-role" "${PREFIX}-open-trust-role"

# IAM user without MFA
log_info "Creating IAM user without MFA..."
$AWS_CMD iam create-user --user-name ${PREFIX}-user --no-cli-pager >/dev/null 2>&1 || true
$AWS_CMD iam create-login-profile --user-name ${PREFIX}-user --password 'CloudHound-Test-123!' --no-password-reset-required --no-cli-pager >/dev/null 2>&1 || true
$AWS_CMD iam attach-user-policy --user-name ${PREFIX}-user --policy-arn arn:aws:iam::aws:policy/ReadOnlyAccess 2>/dev/null || true
log_success "Created IAM user with console access (no MFA)"
save_resource "iam-user" "${PREFIX}-user"

# Multiple access keys
log_info "Creating multiple access keys..."
$AWS_CMD iam create-access-key --user-name ${PREFIX}-user --no-cli-pager >/dev/null 2>&1 || true
$AWS_CMD iam create-access-key --user-name ${PREFIX}-user --no-cli-pager >/dev/null 2>&1 || true
log_success "Created multiple access keys for user"

# ============================================================================
# 2. S3 Buckets (Free when empty)
# ============================================================================
log_section "Creating S3 Buckets"

BUCKET_NAME="${PREFIX}-public-${ACCOUNT_ID}"
log_info "Creating public S3 bucket..."

# Create bucket (handle us-east-1 special case)
if [[ "$REGION" == "us-east-1" ]]; then
    $AWS_CMD s3api create-bucket --bucket $BUCKET_NAME --no-cli-pager >/dev/null 2>&1 || true
else
    $AWS_CMD s3api create-bucket --bucket $BUCKET_NAME \
        --create-bucket-configuration LocationConstraint=$REGION --no-cli-pager >/dev/null 2>&1 || true
fi

# Disable block public access
$AWS_CMD s3api put-public-access-block --bucket $BUCKET_NAME \
    --public-access-block-configuration '{
        "BlockPublicAcls": false,
        "IgnorePublicAcls": false,
        "BlockPublicPolicy": false,
        "RestrictPublicBuckets": false
    }' 2>/dev/null || true

# Add public policy
$AWS_CMD s3api put-bucket-policy --bucket $BUCKET_NAME --policy '{
    "Version": "2012-10-17",
    "Statement": [{
        "Sid": "PublicRead",
        "Effect": "Allow",
        "Principal": "*",
        "Action": "s3:GetObject",
        "Resource": "arn:aws:s3:::'$BUCKET_NAME'/*"
    }]
}' 2>/dev/null && log_success "Created public S3 bucket: $BUCKET_NAME" || log_warn "Could not set public policy"
save_resource "s3-bucket" "$BUCKET_NAME"

# Unversioned bucket (versioning disabled by default)
BUCKET2="${PREFIX}-noversion-${ACCOUNT_ID}"
log_info "Creating unversioned S3 bucket..."
if [[ "$REGION" == "us-east-1" ]]; then
    $AWS_CMD s3api create-bucket --bucket $BUCKET2 --no-cli-pager >/dev/null 2>&1 || true
else
    $AWS_CMD s3api create-bucket --bucket $BUCKET2 \
        --create-bucket-configuration LocationConstraint=$REGION --no-cli-pager >/dev/null 2>&1 || true
fi
log_success "Created unversioned S3 bucket: $BUCKET2"
save_resource "s3-bucket" "$BUCKET2"

# ============================================================================
# 3. EC2 Security Group (Free)
# ============================================================================
log_section "Creating EC2 Security Group"

log_info "Getting default VPC..."
VPC_ID=$($AWS_CMD ec2 describe-vpcs --filters "Name=isDefault,Values=true" --query 'Vpcs[0].VpcId' --output text 2>/dev/null)

if [[ -z "$VPC_ID" || "$VPC_ID" == "None" ]]; then
    log_warn "No default VPC found. Skipping EC2 resources."
else
    log_info "Creating open security group..."
    SG_ID=$($AWS_CMD ec2 create-security-group \
        --group-name ${PREFIX}-open-sg \
        --description "CloudHound test - open to world" \
        --vpc-id $VPC_ID \
        --query 'GroupId' --output text 2>/dev/null) || true

    if [[ -n "$SG_ID" && "$SG_ID" != "None" ]]; then
        $AWS_CMD ec2 authorize-security-group-ingress \
            --group-id $SG_ID \
            --protocol tcp \
            --port 22 \
            --cidr 0.0.0.0/0 2>/dev/null || true
        $AWS_CMD ec2 authorize-security-group-ingress \
            --group-id $SG_ID \
            --protocol tcp \
            --port 3389 \
            --cidr 0.0.0.0/0 2>/dev/null || true
        log_success "Created open security group: $SG_ID (SSH+RDP from 0.0.0.0/0)"
        save_resource "security-group" "$SG_ID"
    fi
fi

# ============================================================================
# 4. EC2 Instance with IAM Role (~$0.01/hour for t2.micro, free tier eligible)
# ============================================================================
log_section "Creating EC2 Instance"

if [[ -n "$VPC_ID" && "$VPC_ID" != "None" ]]; then
    # Create EC2 role
    log_info "Creating EC2 IAM role..."
    $AWS_CMD iam create-role --role-name ${PREFIX}-ec2-role \
        --assume-role-policy-document '{
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"Service": "ec2.amazonaws.com"},
                "Action": "sts:AssumeRole"
            }]
        }' --no-cli-pager >/dev/null 2>&1 || true

    $AWS_CMD iam attach-role-policy --role-name ${PREFIX}-ec2-role \
        --policy-arn arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess 2>/dev/null || true

    $AWS_CMD iam create-instance-profile --instance-profile-name ${PREFIX}-ec2-profile --no-cli-pager >/dev/null 2>&1 || true
    $AWS_CMD iam add-role-to-instance-profile \
        --instance-profile-name ${PREFIX}-ec2-profile \
        --role-name ${PREFIX}-ec2-role 2>/dev/null || true
    log_success "Created EC2 IAM role and instance profile"
    save_resource "iam-role" "${PREFIX}-ec2-role"

    # Wait for instance profile to propagate
    log_info "Waiting for IAM propagation..."
    sleep 10

    # Get latest Amazon Linux 2 AMI
    log_info "Finding latest Amazon Linux 2 AMI..."
    AMI_ID=$($AWS_CMD ec2 describe-images \
        --owners amazon \
        --filters "Name=name,Values=amzn2-ami-hvm-*-x86_64-gp2" "Name=state,Values=available" \
        --query 'sort_by(Images, &CreationDate)[-1].ImageId' \
        --output text 2>/dev/null)

    if [[ -n "$AMI_ID" && "$AMI_ID" != "None" ]]; then
        # Get a subnet
        SUBNET_ID=$($AWS_CMD ec2 describe-subnets \
            --filters "Name=vpc-id,Values=$VPC_ID" \
            --query 'Subnets[0].SubnetId' --output text 2>/dev/null)

        log_info "Launching t2.micro instance..."
        INSTANCE_ID=$($AWS_CMD ec2 run-instances \
            --image-id $AMI_ID \
            --instance-type t2.micro \
            --subnet-id $SUBNET_ID \
            --security-group-ids $SG_ID \
            --iam-instance-profile Name=${PREFIX}-ec2-profile \
            --associate-public-ip-address \
            --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=${PREFIX}-instance}]" \
            --query 'Instances[0].InstanceId' --output text 2>/dev/null) || true

        if [[ -n "$INSTANCE_ID" && "$INSTANCE_ID" != "None" ]]; then
            log_success "Launched EC2 instance: $INSTANCE_ID (t2.micro with public IP and IAM role)"
            save_resource "ec2-instance" "$INSTANCE_ID"
        else
            log_warn "Failed to launch EC2 instance"
        fi
    else
        log_warn "Could not find AMI"
    fi
fi

# ============================================================================
# 5. Lambda Function with Public URL (Free for idle functions)
# ============================================================================
log_section "Creating Lambda Function"

log_info "Creating Lambda execution role..."
$AWS_CMD iam create-role --role-name ${PREFIX}-lambda-role \
    --assume-role-policy-document '{
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "lambda.amazonaws.com"},
            "Action": "sts:AssumeRole"
        }]
    }' --no-cli-pager >/dev/null 2>&1 || true

$AWS_CMD iam attach-role-policy --role-name ${PREFIX}-lambda-role \
    --policy-arn arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole 2>/dev/null || true
save_resource "iam-role" "${PREFIX}-lambda-role"

log_info "Waiting for role propagation..."
sleep 10

# Create function code
LAMBDA_CODE='exports.handler = async (event) => { return { statusCode: 200, body: JSON.stringify({ message: "CloudHound Test" }) }; };'
TMPDIR=$(mktemp -d)
echo "$LAMBDA_CODE" > $TMPDIR/index.js
(cd $TMPDIR && zip -q function.zip index.js)

log_info "Creating Lambda function..."
$AWS_CMD lambda create-function \
    --function-name ${PREFIX}-function \
    --runtime nodejs18.x \
    --role "arn:aws:iam::${ACCOUNT_ID}:role/${PREFIX}-lambda-role" \
    --handler index.handler \
    --zip-file fileb://$TMPDIR/function.zip \
    --no-cli-pager >/dev/null 2>&1 || true

rm -rf $TMPDIR

# Create public function URL
log_info "Creating public function URL..."
$AWS_CMD lambda create-function-url-config \
    --function-name ${PREFIX}-function \
    --auth-type NONE \
    --no-cli-pager >/dev/null 2>&1 || true

$AWS_CMD lambda add-permission \
    --function-name ${PREFIX}-function \
    --statement-id FunctionURLAllowPublicAccess \
    --action lambda:InvokeFunctionUrl \
    --principal "*" \
    --function-url-auth-type NONE \
    --no-cli-pager >/dev/null 2>&1 || true

FUNC_URL=$($AWS_CMD lambda get-function-url-config --function-name ${PREFIX}-function --query 'FunctionUrl' --output text 2>/dev/null) || true
if [[ -n "$FUNC_URL" && "$FUNC_URL" != "None" ]]; then
    log_success "Created Lambda with public URL: $FUNC_URL"
else
    log_success "Created Lambda function (public URL may need manual verification)"
fi
save_resource "lambda" "${PREFIX}-function"

# ============================================================================
# 6. CloudWatch Log Group (Free for minimal data)
# ============================================================================
log_section "Creating CloudWatch Log Group"

log_info "Creating log group without retention..."
$AWS_CMD logs create-log-group --log-group-name /${PREFIX}/test-logs 2>/dev/null || true
log_success "Created log group without retention policy: /${PREFIX}/test-logs"
save_resource "log-group" "/${PREFIX}/test-logs"

# ============================================================================
# 7. KMS Key (~$1/month, prorated)
# ============================================================================
log_section "Creating KMS Key"

log_info "Creating KMS key without rotation..."
KEY_ID=$($AWS_CMD kms create-key \
    --description "CloudHound test key - no rotation" \
    --query 'KeyMetadata.KeyId' --output text 2>/dev/null) || true

if [[ -n "$KEY_ID" && "$KEY_ID" != "None" ]]; then
    $AWS_CMD kms create-alias --alias-name alias/${PREFIX}-key --target-key-id $KEY_ID 2>/dev/null || true
    log_success "Created KMS key without rotation: $KEY_ID"
    save_resource "kms-key" "$KEY_ID"
else
    log_warn "Failed to create KMS key"
fi

# ============================================================================
# Summary
# ============================================================================
log_section "Provisioning Complete"

echo ""
echo -e "${GREEN}Created Resources:${NC}"
cat /tmp/cloudhound-test-resources.txt 2>/dev/null | while read line; do
    echo "  - $line"
done

echo ""
echo -e "${YELLOW}Security Findings to Expect:${NC}"
echo "  - aws-iam-open-trust        (open trust role)"
echo "  - aws-iam-user-no-mfa       (user without MFA)"
echo "  - aws-iam-user-multiple-keys (user with 2 access keys)"
echo "  - aws-s3-public-bucket      (public S3 bucket)"
echo "  - aws-s3-policy-allows-all  (S3 policy with Principal: *)"
echo "  - aws-s3-no-versioning      (unversioned bucket)"
echo "  - aws-ec2-open-security-group (0.0.0.0/0 ingress)"
echo "  - aws-ec2-imds-exposure     (public EC2 with IAM role)"
echo "  - aws-lambda-public-url     (public Lambda URL, no auth)"
echo "  - aws-logging-cloudwatch-no-retention (no log retention)"
echo "  - aws-kms-key-no-rotation   (KMS key without rotation)"

echo ""
echo -e "${BLUE}Next Steps:${NC}"
echo "  1. Run CloudHound collection:"
if [[ -n "$PROFILE" ]]; then
    echo "     cloudhound collect --profile $PROFILE --region $REGION --output ./data"
else
    echo "     cloudhound collect --region $REGION --output ./data"
fi
echo "  2. Normalize and analyze:"
echo "     cloudhound normalize --input ./data --output ./normalized"
echo "     cloudhound analyze --input ./normalized"
echo ""
echo -e "${RED}IMPORTANT:${NC} Run cleanup when done to avoid charges:"
echo "  $0 --cleanup$([ -n "$PROFILE" ] && echo " --profile $PROFILE")"
echo ""
echo -e "${YELLOW}Estimated cost: ~\$0.02/hour (mostly EC2 t2.micro)${NC}"
echo -e "${YELLOW}KMS key: \$1/month prorated - cleanup schedules deletion${NC}"
