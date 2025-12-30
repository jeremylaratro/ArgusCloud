# CloudHound IAM Policies

AWS inline policies have a 2048 character limit, so permissions are split into 4 policies.

## Policies

| Policy | Purpose |
|--------|---------|
| `cloudhound-collect-iam.json` | IAM, Organizations, SSO collection |
| `cloudhound-collect-compute.json` | EC2, S3, Lambda, EKS, ECR, RDS collection |
| `cloudhound-collect-security.json` | Security services, KMS, logging collection |
| `cloudhound-provision.json` | Create test resources (optional) |

## Quick Setup

### Option 1: AWS CLI (Recommended)

```bash
# Create user
aws iam create-user --user-name cloudhound

# Attach all 4 policies
for policy in cloudhound-collect-iam cloudhound-collect-compute cloudhound-collect-security cloudhound-provision; do
  aws iam put-user-policy \
    --user-name cloudhound \
    --policy-name $policy \
    --policy-document file://policies/${policy}.json
done

# Create access key
aws iam create-access-key --user-name cloudhound

# Configure CLI
aws configure --profile cloudhound
```

### Option 2: Collection Only (Read-Only)

Skip `cloudhound-provision.json` if you don't need to create test resources:

```bash
aws iam create-user --user-name cloudhound-readonly

for policy in cloudhound-collect-iam cloudhound-collect-compute cloudhound-collect-security; do
  aws iam put-user-policy \
    --user-name cloudhound-readonly \
    --policy-name $policy \
    --policy-document file://policies/${policy}.json
done

aws iam create-access-key --user-name cloudhound-readonly
```

### Option 3: Use AWS Managed Policy

For collection only, you can use the AWS managed `ReadOnlyAccess` policy instead:

```bash
aws iam create-user --user-name cloudhound
aws iam attach-user-policy \
  --user-name cloudhound \
  --policy-arn arn:aws:iam::aws:policy/ReadOnlyAccess
aws iam create-access-key --user-name cloudhound
```

Note: `ReadOnlyAccess` grants broader permissions than needed but is simpler to manage.

## Cleanup

```bash
# Delete inline policies
for policy in cloudhound-collect-iam cloudhound-collect-compute cloudhound-collect-security cloudhound-provision; do
  aws iam delete-user-policy --user-name cloudhound --policy-name $policy 2>/dev/null
done

# Delete access keys
aws iam list-access-keys --user-name cloudhound --query 'AccessKeyMetadata[].AccessKeyId' --output text | \
  xargs -n1 aws iam delete-access-key --user-name cloudhound --access-key-id

# Delete user
aws iam delete-user --user-name cloudhound
```
