# ArgusCloud IAM Policies

AWS inline policies have a 2048 character limit, so permissions are split into 4 policies.

## Policies

| Policy | Purpose |
|--------|---------|
| `arguscloud-collect-iam.json` | IAM, Organizations, SSO collection |
| `arguscloud-collect-compute.json` | EC2, S3, Lambda, EKS, ECR, RDS collection |
| `arguscloud-collect-security.json` | Security services, KMS, logging collection |
| `arguscloud-provision.json` | Create test resources (optional) |

## Quick Setup

### Option 1: AWS CLI (Recommended)

```bash
# Create user
aws iam create-user --user-name arguscloud

# Attach all 4 policies
for policy in arguscloud-collect-iam arguscloud-collect-compute arguscloud-collect-security arguscloud-provision; do
  aws iam put-user-policy \
    --user-name arguscloud \
    --policy-name $policy \
    --policy-document file://policies/${policy}.json
done

# Create access key
aws iam create-access-key --user-name arguscloud

# Configure CLI
aws configure --profile arguscloud
```

### Option 2: Collection Only (Read-Only)

Skip `arguscloud-provision.json` if you don't need to create test resources:

```bash
aws iam create-user --user-name arguscloud-readonly

for policy in arguscloud-collect-iam arguscloud-collect-compute arguscloud-collect-security; do
  aws iam put-user-policy \
    --user-name arguscloud-readonly \
    --policy-name $policy \
    --policy-document file://policies/${policy}.json
done

aws iam create-access-key --user-name arguscloud-readonly
```

### Option 3: Use AWS Managed Policy

For collection only, you can use the AWS managed `ReadOnlyAccess` policy instead:

```bash
aws iam create-user --user-name arguscloud
aws iam attach-user-policy \
  --user-name arguscloud \
  --policy-arn arn:aws:iam::aws:policy/ReadOnlyAccess
aws iam create-access-key --user-name arguscloud
```

Note: `ReadOnlyAccess` grants broader permissions than needed but is simpler to manage.

## Cleanup

```bash
# Delete inline policies
for policy in arguscloud-collect-iam arguscloud-collect-compute arguscloud-collect-security arguscloud-provision; do
  aws iam delete-user-policy --user-name arguscloud --policy-name $policy 2>/dev/null
done

# Delete access keys
aws iam list-access-keys --user-name arguscloud --query 'AccessKeyMetadata[].AccessKeyId' --output text | \
  xargs -n1 aws iam delete-access-key --user-name arguscloud --access-key-id

# Delete user
aws iam delete-user --user-name arguscloud
```
