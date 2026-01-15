# AWS Resource Setup Guide for ArgusCloud Testing

This guide walks you through creating AWS resources to test ArgusCloud's security assessment capabilities.

## Prerequisites

- AWS CLI configured with credentials (`aws configure`)
- Sufficient IAM permissions to create resources
- A dedicated test account or isolated region recommended

## Quick Start

Run ArgusCloud collection after setup:
```bash
arguscloud collect --profile your-profile --output ./data
arguscloud normalize --input ./data --output ./normalized
arguscloud analyze --input ./normalized
```

---

## 1. IAM Resources

### Create a Role with Open Trust Policy (Triggers: `aws-iam-open-trust`)

```bash
# Create role with overly permissive trust policy
aws iam create-role --role-name arguscloud-test-open-trust \
  --assume-role-policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Principal": "*",
      "Action": "sts:AssumeRole"
    }]
  }'
```

### Create IAM User Without MFA (Triggers: `aws-iam-user-no-mfa`)

```bash
# Create user with console access but no MFA
aws iam create-user --user-name arguscloud-test-user
aws iam create-login-profile --user-name arguscloud-test-user --password 'TempPassword123!'
aws iam attach-user-policy --user-name arguscloud-test-user \
  --policy-arn arn:aws:iam::aws:policy/ReadOnlyAccess
```

### Create User with Multiple Access Keys (Triggers: `aws-iam-user-multiple-keys`)

```bash
aws iam create-access-key --user-name arguscloud-test-user
aws iam create-access-key --user-name arguscloud-test-user
```

---

## 2. S3 Buckets

### Create Public Bucket (Triggers: `aws-s3-public-bucket`, `aws-s3-policy-allows-all`)

```bash
BUCKET_NAME="arguscloud-test-public-$(date +%s)"

# Create bucket
aws s3api create-bucket --bucket $BUCKET_NAME --region us-east-1

# Disable block public access
aws s3api put-public-access-block --bucket $BUCKET_NAME \
  --public-access-block-configuration '{
    "BlockPublicAcls": false,
    "IgnorePublicAcls": false,
    "BlockPublicPolicy": false,
    "RestrictPublicBuckets": false
  }'

# Add public policy
aws s3api put-bucket-policy --bucket $BUCKET_NAME --policy '{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": "*",
    "Action": "s3:GetObject",
    "Resource": "arn:aws:s3:::'$BUCKET_NAME'/*"
  }]
}'
```

### Create Bucket Without Encryption (Triggers: `aws-s3-no-encryption`)

```bash
BUCKET_NAME="arguscloud-test-unencrypted-$(date +%s)"
aws s3api create-bucket --bucket $BUCKET_NAME --region us-east-1
# Note: New buckets have encryption by default in 2024+,
# but ArgusCloud will still check the configuration
```

### Create Bucket Without Versioning (Triggers: `aws-s3-no-versioning`)

```bash
# Versioning is disabled by default on new buckets
BUCKET_NAME="arguscloud-test-noversion-$(date +%s)"
aws s3api create-bucket --bucket $BUCKET_NAME --region us-east-1
```

---

## 3. EC2 Resources

### Create Open Security Group (Triggers: `aws-ec2-open-security-group`)

```bash
# Get default VPC
VPC_ID=$(aws ec2 describe-vpcs --filters "Name=isDefault,Values=true" --query 'Vpcs[0].VpcId' --output text)

# Create security group with open ingress
SG_ID=$(aws ec2 create-security-group \
  --group-name arguscloud-test-open-sg \
  --description "ArgusCloud test - open security group" \
  --vpc-id $VPC_ID \
  --query 'GroupId' --output text)

aws ec2 authorize-security-group-ingress \
  --group-id $SG_ID \
  --protocol tcp \
  --port 22 \
  --cidr 0.0.0.0/0
```

### Create Public EC2 Instance with IAM Role (Triggers: `aws-ec2-imds-exposure`)

```bash
# Create IAM role for EC2
aws iam create-role --role-name arguscloud-test-ec2-role \
  --assume-role-policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Principal": {"Service": "ec2.amazonaws.com"},
      "Action": "sts:AssumeRole"
    }]
  }'

aws iam attach-role-policy --role-name arguscloud-test-ec2-role \
  --policy-arn arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess

aws iam create-instance-profile --instance-profile-name arguscloud-test-profile
aws iam add-role-to-instance-profile \
  --instance-profile-name arguscloud-test-profile \
  --role-name arguscloud-test-ec2-role

# Launch instance (uses Amazon Linux 2 AMI - update AMI ID for your region)
aws ec2 run-instances \
  --image-id ami-0c02fb55956c7d316 \
  --instance-type t2.micro \
  --security-group-ids $SG_ID \
  --iam-instance-profile Name=arguscloud-test-profile \
  --associate-public-ip-address \
  --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=arguscloud-test-instance}]'
```

### Create Public Snapshot (Triggers: `aws-ec2-public-snapshot`)

```bash
# Create a small volume
VOLUME_ID=$(aws ec2 create-volume \
  --availability-zone us-east-1a \
  --size 1 \
  --volume-type gp3 \
  --query 'VolumeId' --output text)

sleep 10  # Wait for volume creation

# Create snapshot
SNAPSHOT_ID=$(aws ec2 create-snapshot \
  --volume-id $VOLUME_ID \
  --description "ArgusCloud test snapshot" \
  --query 'SnapshotId' --output text)

sleep 30  # Wait for snapshot

# Make snapshot public
aws ec2 modify-snapshot-attribute \
  --snapshot-id $SNAPSHOT_ID \
  --attribute createVolumePermission \
  --operation-type add \
  --group-names all
```

---

## 4. RDS Databases

### Create Public RDS Snapshot (Triggers: `aws-rds-public-snapshot`)

```bash
# Create a small RDS instance first
aws rds create-db-instance \
  --db-instance-identifier arguscloud-test-db \
  --db-instance-class db.t3.micro \
  --engine mysql \
  --master-username admin \
  --master-user-password 'TempPassword123!' \
  --allocated-storage 20

# Wait for instance (takes ~5-10 minutes)
aws rds wait db-instance-available --db-instance-identifier arguscloud-test-db

# Create snapshot
aws rds create-db-snapshot \
  --db-instance-identifier arguscloud-test-db \
  --db-snapshot-identifier arguscloud-test-snapshot

# Wait for snapshot
aws rds wait db-snapshot-completed --db-snapshot-identifier arguscloud-test-snapshot

# Make snapshot public
aws rds modify-db-snapshot-attribute \
  --db-snapshot-identifier arguscloud-test-snapshot \
  --attribute-name restore \
  --values-to-add all
```

---

## 5. Lambda Functions

### Create Lambda with Public URL (Triggers: `aws-lambda-public-url`)

```bash
# Create execution role
aws iam create-role --role-name arguscloud-test-lambda-role \
  --assume-role-policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Principal": {"Service": "lambda.amazonaws.com"},
      "Action": "sts:AssumeRole"
    }]
  }'

aws iam attach-role-policy --role-name arguscloud-test-lambda-role \
  --policy-arn arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole

sleep 10  # Wait for role propagation

# Create function code
echo 'exports.handler = async (event) => { return { statusCode: 200, body: "Hello" }; };' > index.js
zip function.zip index.js

# Create Lambda function
aws lambda create-function \
  --function-name arguscloud-test-function \
  --runtime nodejs18.x \
  --role arn:aws:iam::$(aws sts get-caller-identity --query Account --output text):role/arguscloud-test-lambda-role \
  --handler index.handler \
  --zip-file fileb://function.zip

# Create public function URL with no auth
aws lambda create-function-url-config \
  --function-name arguscloud-test-function \
  --auth-type NONE

aws lambda add-permission \
  --function-name arguscloud-test-function \
  --statement-id FunctionURLAllowPublicAccess \
  --action lambda:InvokeFunctionUrl \
  --principal "*" \
  --function-url-auth-type NONE

rm index.js function.zip
```

---

## 6. KMS Keys

### Create KMS Key Without Rotation (Triggers: `aws-kms-key-no-rotation`)

```bash
KEY_ID=$(aws kms create-key \
  --description "ArgusCloud test key" \
  --query 'KeyMetadata.KeyId' --output text)

# Rotation is disabled by default
aws kms create-alias --alias-name alias/arguscloud-test-key --target-key-id $KEY_ID
```

---

## 7. CloudWatch Logs

### Create Log Group Without Retention (Triggers: `aws-logging-cloudwatch-no-retention`)

```bash
# Log groups have no retention by default (never expire)
aws logs create-log-group --log-group-name /arguscloud/test-logs
```

---

## 8. EKS Cluster (Optional - costs apply)

### Create EKS with Public Endpoint (Triggers: `aws-eks-public-endpoint`)

```bash
# Create EKS cluster (requires VPC with subnets)
aws eks create-cluster \
  --name arguscloud-test-cluster \
  --role-arn arn:aws:iam::$(aws sts get-caller-identity --query Account --output text):role/arguscloud-test-eks-role \
  --resources-vpc-config subnetIds=subnet-xxx,subnet-yyy,endpointPublicAccess=true,endpointPrivateAccess=false
```

---

## 9. CodeBuild

### Create CodeBuild with Privileged Mode (Triggers: `aws-codebuild-privileged-mode`)

```bash
# Create CodeBuild service role first
aws iam create-role --role-name arguscloud-test-codebuild-role \
  --assume-role-policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Principal": {"Service": "codebuild.amazonaws.com"},
      "Action": "sts:AssumeRole"
    }]
  }'

# Create CodeBuild project with privileged mode
aws codebuild create-project \
  --name arguscloud-test-build \
  --source type=NO_SOURCE,buildspec="version: 0.2\nphases:\n  build:\n    commands:\n      - echo test" \
  --artifacts type=NO_ARTIFACTS \
  --environment type=LINUX_CONTAINER,image=aws/codebuild/standard:5.0,computeType=BUILD_GENERAL1_SMALL,privilegedMode=true \
  --service-role arn:aws:iam::$(aws sts get-caller-identity --query Account --output text):role/arguscloud-test-codebuild-role
```

---

## Cleanup

Run these commands to delete all test resources:

```bash
# IAM
aws iam delete-login-profile --user-name arguscloud-test-user 2>/dev/null
aws iam list-access-keys --user-name arguscloud-test-user --query 'AccessKeyMetadata[].AccessKeyId' --output text | xargs -n1 aws iam delete-access-key --user-name arguscloud-test-user --access-key-id
aws iam detach-user-policy --user-name arguscloud-test-user --policy-arn arn:aws:iam::aws:policy/ReadOnlyAccess 2>/dev/null
aws iam delete-user --user-name arguscloud-test-user
aws iam delete-role --role-name arguscloud-test-open-trust

# EC2 roles
aws iam remove-role-from-instance-profile --instance-profile-name arguscloud-test-profile --role-name arguscloud-test-ec2-role 2>/dev/null
aws iam delete-instance-profile --instance-profile-name arguscloud-test-profile 2>/dev/null
aws iam detach-role-policy --role-name arguscloud-test-ec2-role --policy-arn arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess 2>/dev/null
aws iam delete-role --role-name arguscloud-test-ec2-role 2>/dev/null

# Lambda
aws lambda delete-function-url-config --function-name arguscloud-test-function 2>/dev/null
aws lambda delete-function --function-name arguscloud-test-function 2>/dev/null
aws iam detach-role-policy --role-name arguscloud-test-lambda-role --policy-arn arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole 2>/dev/null
aws iam delete-role --role-name arguscloud-test-lambda-role 2>/dev/null

# S3 (list and delete buckets with 'arguscloud-test' prefix)
aws s3api list-buckets --query 'Buckets[?starts_with(Name, `arguscloud-test`)].Name' --output text | xargs -n1 aws s3 rb --force s3://

# EC2
aws ec2 describe-instances --filters "Name=tag:Name,Values=arguscloud-test-instance" --query 'Reservations[].Instances[].InstanceId' --output text | xargs -n1 aws ec2 terminate-instances --instance-ids
aws ec2 describe-security-groups --filters "Name=group-name,Values=arguscloud-test-open-sg" --query 'SecurityGroups[].GroupId' --output text | xargs -n1 aws ec2 delete-security-group --group-id

# RDS
aws rds delete-db-snapshot --db-snapshot-identifier arguscloud-test-snapshot 2>/dev/null
aws rds delete-db-instance --db-instance-identifier arguscloud-test-db --skip-final-snapshot 2>/dev/null

# KMS (schedule deletion)
aws kms list-aliases --query 'Aliases[?AliasName==`alias/arguscloud-test-key`].TargetKeyId' --output text | xargs -n1 aws kms schedule-key-deletion --pending-window-in-days 7 --key-id

# CloudWatch Logs
aws logs delete-log-group --log-group-name /arguscloud/test-logs 2>/dev/null

# CodeBuild
aws codebuild delete-project --name arguscloud-test-build 2>/dev/null
aws iam delete-role --role-name arguscloud-test-codebuild-role 2>/dev/null

echo "Cleanup complete!"
```

---

## Cost Considerations

| Resource | Estimated Cost |
|----------|---------------|
| IAM resources | Free |
| S3 buckets (empty) | Free |
| Security groups | Free |
| EC2 t2.micro | ~$0.01/hr (free tier eligible) |
| RDS db.t3.micro | ~$0.02/hr |
| Lambda (idle) | Free |
| KMS key | $1/month |
| EKS cluster | ~$0.10/hr |
| CloudWatch Logs | Free (minimal) |

**Recommendation**: Create resources, run ArgusCloud assessment, then immediately clean up to minimize costs.
