# ArgusCloud Current Status

**Version:** 0.3.0
**Last Updated:** 2025-12-31

## Project Overview

ArgusCloud is a multi-cloud security graph analytics tool that collects cloud resource data, normalizes it into a graph structure, and analyzes attack paths and security findings.

## Architecture Summary

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────┐
│  CLI/Collectors │────▶│  Neo4j Graph DB  │◀────│   API       │
└─────────────────┘     └──────────────────┘     └─────────────┘
                                                       │
                                                       ▼
                                                 ┌─────────────┐
                                                 │   Web UI    │
                                                 └─────────────┘
```

## Completed Features

### Core Infrastructure
- [x] Graph schema and architecture (`docs/domain-model.md`)
- [x] Neo4j loader with batch MERGE operations
- [x] JSONL bundle I/O format
- [x] CLI interface with collect/serve/export commands

### AWS Collectors (20+ services)
- [x] IAM (roles, users, policies, groups)
- [x] Organizations
- [x] CloudTrail, GuardDuty, SecurityHub, Detective, Config
- [x] S3, KMS, Secrets Manager, SSM Parameter Store
- [x] VPC, EC2, Security Groups
- [x] EKS, ECR, Lambda
- [x] CloudFormation, CodeBuild
- [x] SNS, SQS

### Normalizer & Rules Engine
- [x] Node/edge deduplication for scale
- [x] Admin role detection
- [x] Rule severity and explanations
- [x] Attack path analysis (BFS to admin)

### Security Rules
- [x] Open trust policies
- [x] Missing GuardDuty/CloudTrail/Config
- [x] Public resource policies
- [x] Open security groups
- [x] KMS external access
- [x] Assume-role chain analysis
- [x] CodeBuild env/privileged risks

### API Server (v0.3.0)
- [x] Flask-based REST API with 22 endpoints
- [x] JWT/API key authentication
- [x] Cypher query validation (injection prevention)
- [x] CORS security with specific origins
- [x] Pydantic request validation
- [x] Profile management (save/load graph views)
- [x] Export formats: JSON, SARIF, HTML
- [x] **NEW:** Prometheus metrics endpoint (`/metrics`)
- [x] **NEW:** Rate limiting middleware
- [x] **NEW:** Graceful shutdown handling
- [x] **NEW:** Health/readiness probes

### Web UI
- [x] Graph visualization with D3.js
- [x] Attack path table and filtering
- [x] Resource statistics dashboard
- [x] Bundle upload interface
- [x] **NEW:** Modular CSS/JS architecture

### Testing & Quality
- [x] pytest suite (495 tests passing)
- [x] **NEW:** Integration tests with testcontainers
- [x] **NEW:** Security tests (injection, auth, validation)
- [x] **NEW:** AWS collector tests with moto

### Documentation
- [x] API reference (`docs/api-reference.md`)
- [x] Security guide (`docs/security.md`)
- [x] Deployment guide (`docs/deployment.md`)
- [x] Contributing guide (`CONTRIBUTING.md`)
- [x] AWS setup guide (`AWS_SETUP_GUIDE.md`)

## Test Coverage

```
495 tests passing
32 skipped (require external dependencies)
Test categories:
- Unit tests: API, auth, exporters, collectors
- Integration tests: Full API workflow
- Security tests: Injection, auth bypass, validation
```

## Dependencies

### Production
- boto3 >= 1.28.0
- flask >= 2.3.0
- flask-cors >= 4.0.0
- flask-openapi3 >= 3.0.0
- neo4j >= 5.0.0
- PyJWT >= 2.0.0
- pydantic >= 2.0.0

### Optional (Production)
- prometheus-client >= 0.17.0 (metrics)
- flask-limiter >= 3.0.0 (rate limiting)

### Development
- pytest, pytest-cov, pytest-mock
- black, mypy, ruff
- testcontainers >= 3.0.0 (integration tests)
- moto >= 4.0.0 (AWS mocking)

## Known Issues

1. **Dependabot Alerts:** 3 moderate vulnerabilities flagged - review at GitHub security tab
2. **Deprecation Warnings:** `datetime.utcnow()` deprecated in Python 3.12+ (58 warnings)
3. **pytest mark:** Unknown `integration` mark warning (cosmetic)

## File Structure

```
arguscloud/
├── api/
│   ├── server.py      # Main API server
│   ├── auth.py        # Authentication
│   ├── collect.py     # Collection jobs
│   ├── uploads.py     # File uploads
│   ├── metrics.py     # Prometheus metrics (NEW)
│   ├── ratelimit.py   # Rate limiting (NEW)
│   └── shutdown.py    # Graceful shutdown (NEW)
├── cli/
│   └── main.py        # CLI commands
├── collectors/
│   └── aws/           # AWS service collectors
├── core/
│   ├── graph.py       # Graph operations
│   └── normalize.py   # Data normalization
├── exporters/         # JSON, SARIF, HTML export
├── plugins/           # Plugin system
└── rules/             # Security rules engine

ui/
├── index.html         # Main HTML (refactored)
├── css/
│   └── main.css       # Extracted styles (NEW)
└── js/
    └── app.js         # Extracted JavaScript (NEW)

tests/
├── integration/       # API integration tests (NEW)
├── security/          # Security tests (NEW)
├── collectors/        # Collector tests (NEW)
└── test_*.py          # Unit tests
```
