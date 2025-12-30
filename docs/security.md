# CloudHound Security Guide

This guide covers security best practices for deploying and operating CloudHound.

## Table of Contents

- [Credential Handling](#credential-handling)
- [IAM Policy Requirements](#iam-policy-requirements)
- [Network Security](#network-security)
- [Neo4j Security](#neo4j-security)
- [Authentication & Authorization](#authentication--authorization)
- [Data Protection](#data-protection)
- [Audit Logging](#audit-logging)
- [Incident Response](#incident-response)

## Credential Handling

### AWS Credentials

CloudHound requires AWS credentials to collect cloud resource data. Follow these best practices:

#### Never Store Credentials in Code

```python
# BAD - Never do this
access_key = "AKIAIOSFODNN7EXAMPLE"
secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# GOOD - Use environment variables or IAM roles
# Credentials are passed via API request and cleared after use
```

#### Use Temporary Credentials

Prefer temporary credentials (STS) over long-term access keys:

```bash
# Get temporary credentials
aws sts assume-role \
  --role-arn arn:aws:iam::123456789012:role/CloudHoundCollector \
  --role-session-name cloudhound-collection
```

#### Credential Lifecycle

1. Credentials are received via API request
2. Used immediately to create boto3 session
3. **Cleared from memory** after session creation
4. Never persisted to disk or database

### API Keys

CloudHound API keys should be:
- Generated using `cloudhound auth generate-key`
- Stored securely (secrets manager, vault)
- Rotated regularly
- Scoped to minimum required permissions

## IAM Policy Requirements

### Minimum Read-Only Policy

Use this policy for CloudHound collection:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "CloudHoundReadOnly",
            "Effect": "Allow",
            "Action": [
                "iam:Get*",
                "iam:List*",
                "sts:GetCallerIdentity",
                "ec2:Describe*",
                "s3:GetBucket*",
                "s3:ListBucket",
                "s3:ListAllMyBuckets",
                "lambda:List*",
                "lambda:GetFunction",
                "lambda:GetPolicy",
                "kms:List*",
                "kms:Describe*",
                "kms:GetKeyPolicy",
                "secretsmanager:List*",
                "secretsmanager:Describe*",
                "rds:Describe*",
                "sns:List*",
                "sns:GetTopicAttributes",
                "sqs:List*",
                "sqs:GetQueueAttributes",
                "cloudtrail:Describe*",
                "cloudtrail:GetTrailStatus",
                "guardduty:List*",
                "guardduty:Get*",
                "securityhub:Get*",
                "securityhub:List*",
                "organizations:Describe*",
                "organizations:List*",
                "eks:Describe*",
                "eks:List*",
                "ecr:Describe*",
                "ecr:GetRepositoryPolicy",
                "logs:Describe*",
                "ssm:Describe*",
                "ssm:List*",
                "codebuild:List*",
                "codebuild:BatchGet*",
                "codepipeline:List*",
                "codepipeline:Get*",
                "cloudformation:Describe*",
                "cloudformation:List*",
                "sso:List*",
                "sso:Describe*",
                "identitystore:List*",
                "identitystore:Describe*"
            ],
            "Resource": "*"
        }
    ]
}
```

### Cross-Account Collection

For multi-account environments, create a role in each target account:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "AWS": "arn:aws:iam::MANAGEMENT_ACCOUNT:role/CloudHoundCollector"
            },
            "Action": "sts:AssumeRole",
            "Condition": {
                "StringEquals": {
                    "sts:ExternalId": "your-external-id"
                }
            }
        }
    ]
}
```

## Network Security

### API Server

1. **Run behind reverse proxy** - Never expose directly to internet
2. **Use TLS** - Always encrypt traffic
3. **Restrict access** - Use firewall rules

```bash
# Example: Only allow access from internal network
iptables -A INPUT -p tcp --dport 9847 -s 10.0.0.0/8 -j ACCEPT
iptables -A INPUT -p tcp --dport 9847 -j DROP
```

### Neo4j Database

1. **Disable remote HTTP** - Only use Bolt protocol
2. **Network isolation** - Run in private subnet
3. **Firewall rules** - Allow only API server access

```yaml
# Neo4j config
dbms.default_listen_address=127.0.0.1  # Local only
dbms.connector.http.enabled=false       # Disable HTTP
```

### Recommended Architecture

```
                Internet
                    │
                    ▼
            ┌───────────────┐
            │   Firewall    │
            └───────┬───────┘
                    │
            ┌───────▼───────┐
            │   WAF/CDN     │  (Optional)
            └───────┬───────┘
                    │
            ┌───────▼───────┐
            │ Load Balancer │
            │   (TLS Term)  │
            └───────┬───────┘
                    │
        Private Network (VPC)
    ┌───────────────┼───────────────┐
    │               │               │
    ▼               ▼               ▼
┌───────┐     ┌───────┐     ┌───────┐
│  UI   │     │  API  │     │ Neo4j │
│(nginx)│     │Server │     │  DB   │
└───────┘     └───┬───┘     └───────┘
                  │
                  └─────────────────▶
```

## Neo4j Security

### Authentication

Always enable authentication:

```bash
# Environment variable
NEO4J_AUTH=neo4j/your_secure_password
```

### Encryption

Enable encryption at rest:

```properties
# neo4j.conf
dbms.directories.data=/encrypted-volume/data
```

### Access Control

Create dedicated users with minimal permissions:

```cypher
// Create read-only user for CloudHound
CREATE USER cloudhound SET PASSWORD 'secure_password' SET PASSWORD CHANGE NOT REQUIRED;
GRANT ROLE reader TO cloudhound;

// Create admin user for management
CREATE USER admin SET PASSWORD 'admin_password' SET PASSWORD CHANGE NOT REQUIRED;
GRANT ROLE admin TO admin;
```

## Authentication & Authorization

### JWT Tokens

CloudHound uses JWT tokens for API authentication:

- **Algorithm:** HS256
- **Expiry:** Configurable (default 1 hour)
- **Required claims:** `exp`, `iat`

```bash
# Set a strong JWT secret (min 32 characters)
export CLOUDHOUND_JWT_SECRET="your-very-long-and-secure-secret-key-here"
```

### API Key Authentication

API keys are:
- SHA256 hashed before storage
- Compared using constant-time algorithm
- Prefixed with `ch_` for identification

### CORS Configuration

Configure specific origins (never use `*` in production):

```bash
# Single origin
CLOUDHOUND_CORS_ORIGINS=https://cloudhound.example.com

# Multiple origins
CLOUDHOUND_CORS_ORIGINS=https://cloudhound.example.com,https://admin.example.com
```

## Data Protection

### Query Validation

CloudHound implements whitelist-based Cypher query validation:

**Allowed:**
- `MATCH ... RETURN ...` (read queries)
- `CALL db.*` (database procedures)
- `CALL apoc.*` (APOC procedures)

**Blocked:**
- `CREATE`, `MERGE`, `DELETE` (write operations)
- `SET`, `REMOVE` (property modifications)
- `DROP` (schema changes)

### Upload Protection

- **Zip bomb protection:** Max 500MB uncompressed, 1000 files
- **Content-type validation:** Strict JSON/JSONL parsing
- **Size limits:** Configurable upload limits

### Data Retention

Consider implementing:
- Profile auto-expiration
- Scheduled data cleanup
- Audit log rotation

```python
# Example: Delete profiles older than 90 days
MATCH (n:Profile)
WHERE n.created_at < datetime() - duration('P90D')
DETACH DELETE n
```

## Audit Logging

### Enable Logging

```bash
CLOUDHOUND_LOG_LEVEL=INFO
```

### Security Events Logged

- Authentication attempts (success/failure)
- API key creation/deletion
- Profile creation/deletion
- AWS collection starts
- Query execution
- Export operations

### Log Format

```json
{
  "timestamp": "2024-01-15T10:30:00Z",
  "level": "INFO",
  "event": "auth_success",
  "user": "api_key:ci-pipeline",
  "ip": "10.0.1.50",
  "method": "GET",
  "path": "/graph"
}
```

### Log Retention

- Retain logs for at least 90 days
- Use centralized logging (ELK, Splunk)
- Set up alerts for security events

## Incident Response

### Security Contacts

Establish security contact procedures:
- Primary security contact
- Escalation path
- Emergency procedures

### Response Checklist

1. **Detect:** Monitor logs for suspicious activity
2. **Contain:** Disable compromised API keys
3. **Investigate:** Review audit logs
4. **Remediate:** Rotate credentials, patch vulnerabilities
5. **Report:** Document incident and lessons learned

### Emergency Actions

```bash
# Revoke all API keys (emergency)
cloudhound auth revoke-all

# Disable API authentication temporarily
CLOUDHOUND_AUTH_ENABLED=false cloudhound serve

# Force JWT secret rotation (invalidates all tokens)
export CLOUDHOUND_JWT_SECRET="new-secret-key"
```

### Vulnerability Reporting

See [SECURITY.md](../SECURITY.md) for vulnerability reporting procedures.

---

## Security Checklist

Use this checklist for production deployments:

### Infrastructure
- [ ] API server behind TLS-terminating proxy
- [ ] Neo4j in private network
- [ ] Firewall rules configured
- [ ] Network segmentation in place

### Authentication
- [ ] `CLOUDHOUND_AUTH_ENABLED=true`
- [ ] Strong JWT secret (32+ chars)
- [ ] API keys rotated regularly
- [ ] CORS origins configured

### Database
- [ ] Neo4j authentication enabled
- [ ] Strong Neo4j password
- [ ] Remote HTTP disabled
- [ ] Encryption at rest enabled

### Monitoring
- [ ] Audit logging enabled
- [ ] Log aggregation configured
- [ ] Security alerts set up
- [ ] Regular log review process

### Operations
- [ ] Incident response plan documented
- [ ] Security contacts established
- [ ] Backup procedures tested
- [ ] Recovery procedures tested

---

For additional security information, see:
- [SECURITY.md](../SECURITY.md) - Vulnerability reporting
- [Deployment Guide](deployment.md) - Secure deployment
