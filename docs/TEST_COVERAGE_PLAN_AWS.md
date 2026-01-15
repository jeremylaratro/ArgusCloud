# ArgusCloud Test Coverage Plan - AWS Dependent Tests

**IMPORTANT:** These tests require AWS credentials or extensive mocking with `moto` library.
Wait to implement these until the non-AWS tests are complete.

---

## Prerequisites

```bash
pip install moto[all]>=4.0.0
```

---

## Phase A: IAM Collectors (AWS Required)

### A.1 IAM Collector Tests
**File:** `tests/test_collectors_iam.py`
**Source:** `arguscloud/collectors/aws/iam.py`

Tests needed (using moto):
- [ ] iam-summary collector
  - [ ] Empty account
  - [ ] Account with users/roles/policies
  - [ ] Pagination handling
- [ ] iam-roles collector
  - [ ] Empty roles list
  - [ ] Role with attached policies
  - [ ] Role with inline policies
  - [ ] Role trust relationships
  - [ ] Paginated role listing
  - [ ] Permission denied handling
- [ ] iam-users collector
  - [ ] Empty users list
  - [ ] User with access keys
  - [ ] User with MFA devices
  - [ ] User group memberships
  - [ ] Password policy extraction
- [ ] iam-policies collector
  - [ ] Customer managed policies
  - [ ] Policy versions
  - [ ] Policy document parsing
- [ ] sso collector
  - [ ] SSO configuration
  - [ ] Permission sets
  - [ ] Account assignments

**Example moto pattern:**
```python
import boto3
from moto import mock_iam

@mock_iam
def test_iam_roles_collector():
    # Setup mock IAM
    client = boto3.client("iam", region_name="us-east-1")
    client.create_role(
        RoleName="TestRole",
        AssumeRolePolicyDocument='{"Version":"2012-10-17","Statement":[]}',
    )

    # Run collector
    from arguscloud.collectors.aws.iam import collect_iam_roles
    result = collect_iam_roles(session=boto3.Session())

    # Assert
    assert len(result.records) == 1
    assert result.records[0]["RoleName"] == "TestRole"
```

---

## Phase B: Storage Collectors (AWS Required)

### B.1 S3 Collector Tests
**File:** `tests/test_collectors_s3.py`
**Source:** `arguscloud/collectors/aws/storage.py`

Tests needed (using moto):
- [ ] s3 collector
  - [ ] Empty bucket list
  - [ ] Bucket with policy
  - [ ] Bucket with ACL
  - [ ] Public bucket detection
  - [ ] Encryption settings
  - [ ] Versioning status
  - [ ] Logging configuration
  - [ ] Cross-region replication

### B.2 KMS Collector Tests
**File:** `tests/test_collectors_kms.py`
**Source:** `arguscloud/collectors/aws/storage.py`

Tests needed (using moto):
- [ ] kms collector
  - [ ] Empty key list
  - [ ] Key with policy
  - [ ] Key rotation status
  - [ ] Key aliases
  - [ ] Cross-account access

---

## Phase C: EC2/VPC Collectors (AWS Required)

### C.1 EC2 Collector Tests
**File:** `tests/test_collectors_ec2.py`
**Source:** `arguscloud/collectors/aws/ec2.py`

Tests needed (using moto):
- [ ] ec2 collector
  - [ ] Empty instance list
  - [ ] Instance with IMDS v1
  - [ ] Instance with IMDS v2
  - [ ] Instance with IAM role
  - [ ] Instance with security groups
  - [ ] Instance in VPC
  - [ ] Terminated instances handling
- [ ] ec2-images collector
  - [ ] Private AMIs
  - [ ] Public AMIs
  - [ ] Shared AMIs
  - [ ] AMI permissions

### C.2 VPC Collector Tests
**File:** `tests/test_collectors_vpc.py`
**Source:** `arguscloud/collectors/aws/ec2.py`

Tests needed (using moto):
- [ ] vpc collector
  - [ ] Default VPC
  - [ ] Custom VPC
  - [ ] VPC with subnets
  - [ ] Public vs private subnets
  - [ ] Internet gateway
  - [ ] NAT gateway
  - [ ] Route tables
  - [ ] Security groups
  - [ ] Network ACLs
  - [ ] VPC peering

---

## Phase D: Compute Collectors (AWS Required)

### D.1 Lambda Collector Tests
**File:** `tests/test_collectors_lambda.py`
**Source:** `arguscloud/collectors/aws/compute.py`

Tests needed (using moto):
- [ ] lambda collector
  - [ ] Empty function list
  - [ ] Function with VPC
  - [ ] Function with layers
  - [ ] Function with environment variables
  - [ ] Function with resource policy
  - [ ] Public function URL
  - [ ] Paginated listing

### D.2 EKS Collector Tests
**File:** `tests/test_collectors_eks.py`
**Source:** `arguscloud/collectors/aws/compute.py`

Tests needed (using moto):
- [ ] eks collector
  - [ ] Empty cluster list
  - [ ] Cluster with public endpoint
  - [ ] Cluster with private endpoint
  - [ ] Cluster node groups
  - [ ] Cluster logging

### D.3 ECR Collector Tests
**File:** `tests/test_collectors_ecr.py`
**Source:** `arguscloud/collectors/aws/compute.py`

Tests needed (using moto):
- [ ] ecr collector
  - [ ] Empty repository list
  - [ ] Repository with policy
  - [ ] Cross-account access
  - [ ] Image scanning settings

### D.4 CodeBuild Collector Tests
**File:** `tests/test_collectors_codebuild.py`
**Source:** `arguscloud/collectors/aws/compute.py`

Tests needed (using moto):
- [ ] codebuild collector
  - [ ] Empty project list
  - [ ] Project with privileged mode
  - [ ] Project with environment secrets
  - [ ] Project with VPC

---

## Phase E: Security/Logging Collectors (AWS Required)

### E.1 CloudTrail Collector Tests
**File:** `tests/test_collectors_cloudtrail.py`
**Source:** `arguscloud/collectors/aws/security.py`

Tests needed (using moto):
- [ ] cloudtrail collector
  - [ ] No trails
  - [ ] Single region trail
  - [ ] Multi-region trail
  - [ ] Organization trail
  - [ ] Trail logging status
  - [ ] S3 delivery errors

### E.2 GuardDuty Collector Tests
**File:** `tests/test_collectors_guardduty.py`
**Source:** `arguscloud/collectors/aws/security.py`

Tests needed (using moto):
- [ ] guardduty collector
  - [ ] No detector
  - [ ] Enabled detector
  - [ ] Findings listing
  - [ ] Finding severity

### E.3 Config Collector Tests
**File:** `tests/test_collectors_config.py`
**Source:** `arguscloud/collectors/aws/security.py`

Tests needed (using moto):
- [ ] config collector
  - [ ] No recorders
  - [ ] Active recorder
  - [ ] Config rules
  - [ ] Compliance status

### E.4 Security Hub Collector Tests
**File:** `tests/test_collectors_securityhub.py`
**Source:** `arguscloud/collectors/aws/security.py`

Tests needed:
- [ ] securityhub collector
  - [ ] Hub not enabled
  - [ ] Hub enabled
  - [ ] Findings listing
  - [ ] Standards compliance

---

## Phase F: Data/Messaging Collectors (AWS Required)

### F.1 RDS Collector Tests
**File:** `tests/test_collectors_rds.py`
**Source:** `arguscloud/collectors/aws/storage.py`

Tests needed (using moto):
- [ ] rds collector
  - [ ] Empty instance list
  - [ ] Encrypted instance
  - [ ] Unencrypted instance
  - [ ] Public instance
  - [ ] Snapshots
  - [ ] Public snapshots
  - [ ] Automated backups

### F.2 Secrets Manager Collector Tests
**File:** `tests/test_collectors_secrets.py`
**Source:** `arguscloud/collectors/aws/identity.py`

Tests needed (using moto):
- [ ] secretsmanager collector
  - [ ] Empty secrets list
  - [ ] Secret with rotation
  - [ ] Secret without rotation
  - [ ] Secret access policy

### F.3 SNS/SQS Collector Tests
**File:** `tests/test_collectors_messaging.py`
**Source:** `arguscloud/collectors/aws/messaging.py`

Tests needed (using moto):
- [ ] sns collector
  - [ ] Empty topic list
  - [ ] Topic with policy
  - [ ] Cross-account access
- [ ] sqs collector
  - [ ] Empty queue list
  - [ ] Queue with policy
  - [ ] Cross-account access

---

## Phase G: Organization/STS Collectors (AWS Required)

### G.1 Organizations Collector Tests
**File:** `tests/test_collectors_org.py`
**Source:** `arguscloud/collectors/aws/org.py`

Tests needed (using moto):
- [ ] org collector
  - [ ] Not in organization
  - [ ] Organization root
  - [ ] Organizational units
  - [ ] Service control policies
  - [ ] Account listing

### G.2 STS Collector Tests
**File:** `tests/test_collectors_sts.py`
**Source:** `arguscloud/collectors/aws/sts.py`

Tests needed (using moto):
- [ ] sts collector
  - [ ] Caller identity
  - [ ] Account ID extraction
  - [ ] ARN parsing

---

## Implementation Notes

### Moto Coverage

Not all AWS services are fully supported by moto. Check status at:
https://github.com/getmoto/moto/blob/master/IMPLEMENTATION_COVERAGE.md

**Well supported (use moto):**
- IAM ✓
- S3 ✓
- EC2 ✓
- Lambda ✓
- STS ✓
- CloudTrail ✓
- GuardDuty ✓
- KMS ✓
- RDS ✓
- SNS/SQS ✓

**Limited support (may need manual mocking):**
- EKS (partial)
- Security Hub (partial)
- Organizations (partial)
- SSO (limited)

### Alternative: Integration Tests with Real AWS

For services not well supported by moto, consider:
1. Using a dedicated test AWS account
2. Running as integration tests (not unit tests)
3. Using LocalStack for more comprehensive mocking

```bash
# Run integration tests separately
pytest tests/integration/ -v --aws-profile test-account
```

---

## Estimated Test Counts

| Phase | Collectors | Estimated Tests |
|-------|------------|-----------------|
| A | IAM (5) | 80-100 |
| B | Storage (2) | 40-50 |
| C | EC2/VPC (2) | 60-80 |
| D | Compute (4) | 60-80 |
| E | Security (4) | 50-60 |
| F | Data/Messaging (3) | 40-50 |
| G | Org/STS (2) | 20-30 |
| **Total** | **22** | **350-450** |

---

## Priority Order

1. **Phase A** - IAM collectors (most critical for security analysis)
2. **Phase C** - EC2/VPC collectors (core infrastructure)
3. **Phase B** - Storage collectors (S3 is heavily used)
4. **Phase E** - Security collectors (logging/monitoring)
5. **Phase D** - Compute collectors
6. **Phase F** - Data collectors
7. **Phase G** - Org collectors
