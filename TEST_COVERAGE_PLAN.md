# CloudHound Test Coverage Plan

## Current State
- **Total Tests:** 266 (all passing)
- **Coverage:** 34%
- **Target:** 800+ tests, 70%+ coverage

---

## Phase 1: Normalizers (No AWS Required)

### 1.1 Lambda Normalizer Tests
**File:** `tests/test_normalizers_lambda.py`
**Source:** `cloudhound/normalizers/aws/compute.py`

Tests needed:
- [ ] Empty records handling
- [ ] Basic Lambda function normalization
- [ ] Function with public URL
- [ ] Function with VPC configuration
- [ ] Function with environment variables
- [ ] Function with layers
- [ ] Resource policy parsing
- [ ] Edge creation (FunctionHasRole, etc.)

### 1.2 VPC Normalizer Tests
**File:** `tests/test_normalizers_vpc.py`
**Source:** `cloudhound/normalizers/aws/ec2.py`

Tests needed:
- [ ] Empty records handling
- [ ] VPC normalization with subnets
- [ ] Security group normalization
- [ ] Ingress/egress rule parsing
- [ ] Route table normalization
- [ ] Internet gateway detection
- [ ] NAT gateway handling
- [ ] Edge creation (VPCContains, SGProtects, etc.)

### 1.3 CloudTrail Normalizer Tests
**File:** `tests/test_normalizers_cloudtrail.py`
**Source:** `cloudhound/normalizers/aws/security.py`

Tests needed:
- [ ] Empty records handling
- [ ] Basic trail normalization
- [ ] Multi-region trail
- [ ] Organization trail
- [ ] S3 destination parsing
- [ ] CloudWatch logs integration
- [ ] Trail status (logging/not logging)

### 1.4 GuardDuty Normalizer Tests
**File:** `tests/test_normalizers_guardduty.py`
**Source:** `cloudhound/normalizers/aws/security.py`

Tests needed:
- [ ] Empty records handling
- [ ] Detector normalization
- [ ] Finding normalization
- [ ] Severity mapping
- [ ] Resource extraction from findings

### 1.5 Organizations Normalizer Tests
**File:** `tests/test_normalizers_org.py`
**Source:** `cloudhound/normalizers/aws/org.py`

Tests needed:
- [ ] Empty records handling
- [ ] Account normalization
- [ ] OU hierarchy
- [ ] SCP extraction
- [ ] Edge creation (AccountInOU, etc.)

---

## Phase 2: Additional Rules (No AWS Required)

### 2.1 Compute Rules (Expand existing)
**File:** `tests/test_rules_compute.py` (expand)

Additional tests needed:
- [ ] aws-lambda-public-url rule
- [ ] aws-eks-public-endpoint rule
- [ ] aws-ecr-cross-account-access rule
- [ ] aws-codebuild-privileged-mode rule
- [ ] aws-codebuild-env-secrets rule

### 2.2 Data Protection Rules (Expand existing)
**File:** `tests/test_rules_data.py` (expand)

Additional tests needed:
- [ ] aws-rds-public-snapshot rule
- [ ] aws-rds-unencrypted-snapshot rule
- [ ] aws-kms-key-public-access rule

### 2.3 Snapshot/Encryption Rules
**File:** `tests/test_rules_snapshots.py`

Tests needed:
- [ ] aws-ec2-public-snapshot rule
- [ ] aws-ec2-unencrypted-snapshot rule
- [ ] aws-s3-no-encryption rule
- [ ] aws-s3-no-versioning rule

### 2.4 Additional Logging Rules
**File:** `tests/test_rules_logging.py` (expand)

Additional tests needed:
- [ ] aws-logging-no-config rule
- [ ] aws-logging-no-guardduty rule
- [ ] aws-logging-cloudwatch-no-retention rule
- [ ] aws-secrets-no-rotation rule
- [ ] aws-kms-key-no-rotation rule

---

## Phase 3: API Tests (No AWS Required)

### 3.1 API Server Tests
**File:** `tests/test_api_server.py`

Tests needed:
- [ ] Health endpoint (GET /health)
- [ ] Graph endpoint (GET /graph) with filters
- [ ] Attack paths endpoint (GET /attackpaths)
- [ ] Findings endpoint (GET /findings)
- [ ] Resources endpoint (GET /resources)
- [ ] Query endpoint (POST /query) - Cypher injection prevention
- [ ] Export endpoints (GET /export/<format>)
- [ ] Error handling (invalid params, missing auth)
- [ ] CORS headers

### 3.2 API Authentication Tests
**File:** `tests/test_api_auth.py`

Tests needed:
- [ ] Token creation (POST /auth/token)
- [ ] Token verification (GET /auth/verify)
- [ ] X-API-Key header validation
- [ ] Bearer token validation
- [ ] Expired token handling
- [ ] Invalid token handling
- [ ] Auth disabled mode

---

## Phase 4: CLI Tests (No AWS Required)

### 4.1 CLI Command Tests
**File:** `tests/test_cli_main.py`

Tests needed:
- [ ] Help output
- [ ] Version output
- [ ] normalize command - argument parsing
- [ ] normalize command - missing input error
- [ ] analyze command - argument parsing
- [ ] analyze command - severity filtering
- [ ] export command - format validation
- [ ] export command - output file creation
- [ ] serve command - port argument
- [ ] serve command - auth flag
- [ ] import command - Neo4j URI parsing
- [ ] keygen command - prefix handling

---

## Phase 5: Utilities & Edge Cases

### 5.1 Policy Utilities (Expand existing)
**File:** `tests/test_core_base.py` (expand)

Additional tests needed:
- [ ] Complex policy conditions
- [ ] Wildcard principal handling
- [ ] Cross-account access patterns
- [ ] Service-linked role detection

### 5.2 Graph Operations
**File:** `tests/test_core_graph.py` (expand)

Additional tests needed:
- [ ] Large graph handling
- [ ] Duplicate node detection
- [ ] Edge deduplication
- [ ] Graph merging

---

## Implementation Order

1. **Phase 1** - Normalizers (estimated: 150 tests)
2. **Phase 2** - Rules (estimated: 100 tests)
3. **Phase 3** - API (estimated: 80 tests)
4. **Phase 4** - CLI (estimated: 50 tests)
5. **Phase 5** - Utilities (estimated: 30 tests)

**Total new tests:** ~410
**Final total:** ~676 tests
**Expected coverage:** 60-70%

---

## Dependencies to Add

```
# requirements-dev.txt additions
pytest-mock>=3.10.0
pytest-cov>=4.0.0
```

---

## Running Tests

```bash
# Run all tests
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=cloudhound --cov-report=html

# Run specific phase
pytest tests/test_normalizers_*.py -v
pytest tests/test_rules_*.py -v
pytest tests/test_api_*.py -v
pytest tests/test_cli_*.py -v
```
