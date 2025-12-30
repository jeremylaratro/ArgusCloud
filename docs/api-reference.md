# CloudHound API Reference

This document provides a complete reference for the CloudHound REST API.

## Base URL

```
http://localhost:9847
```

## Authentication

Most endpoints require authentication via JWT token or API key.

### JWT Token Authentication

1. Obtain a token:
```bash
curl -X POST http://localhost:9847/auth/token \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "secret"}'
```

2. Include in requests:
```bash
curl http://localhost:9847/graph \
  -H "Authorization: Bearer <token>"
```

### API Key Authentication

```bash
curl http://localhost:9847/graph \
  -H "X-API-Key: <your-api-key>"
```

---

## System Endpoints

### Health Check

Check API and dependency status.

```
GET /health
```

**Authentication:** None required

**Response:**
```json
{
  "status": "ok",
  "checks": {
    "neo4j": "ok",
    "plugins": "ok (3 loaded)"
  },
  "version": "0.2.0"
}
```

**Status Codes:**
- `200` - System healthy
- `503` - System degraded

---

### List Plugins

List installed plugins.

```
GET /plugins
```

**Authentication:** None required

**Response:**
```json
{
  "plugins": [
    {
      "name": "aws-collector",
      "version": "1.0.0",
      "description": "AWS resource collector"
    }
  ],
  "count": 1,
  "errors": []
}
```

---

## Graph Endpoints

### Get Graph Data

Retrieve nodes and edges from the graph.

```
GET /graph
```

**Authentication:** Required (read access)

**Query Parameters:**
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `limit` | integer | 500 | Max results (1-10000) |
| `provider` | string | - | Filter by provider (aws, gcp, azure) |
| `type` | string | - | Filter by node type |

**Example:**
```bash
curl "http://localhost:9847/graph?provider=aws&limit=100" \
  -H "Authorization: Bearer <token>"
```

**Response:**
```json
{
  "nodes": [
    {
      "id": "arn:aws:iam::123456789012:role/AdminRole",
      "type": "Role",
      "provider": "aws",
      "properties": {
        "RoleName": "AdminRole",
        "CreateDate": "2023-01-15T10:30:00Z"
      }
    }
  ],
  "edges": [
    {
      "src": "arn:aws:iam::123456789012:user/alice",
      "dst": "arn:aws:iam::123456789012:role/AdminRole",
      "type": "CanAssume",
      "properties": {}
    }
  ],
  "meta": {
    "total_nodes": 1,
    "total_edges": 1,
    "limit": 100
  }
}
```

---

### Get Attack Paths

Retrieve identified attack path edges.

```
GET /attackpaths
```

**Authentication:** Required (read access)

**Query Parameters:**
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `limit` | integer | 500 | Max results |
| `severity` | string | - | Filter: critical, high, medium, low |
| `provider` | string | - | Filter by provider |

**Example:**
```bash
curl "http://localhost:9847/attackpaths?severity=critical" \
  -H "Authorization: Bearer <token>"
```

**Response:**
```json
{
  "edges": [
    {
      "src": "arn:aws:iam::123456789012:user/alice",
      "dst": "arn:aws:iam::123456789012:role/AdminRole",
      "type": "AttackPath",
      "properties": {
        "severity": "critical",
        "rule": "PrivilegeEscalation",
        "description": "User can escalate to admin role"
      }
    }
  ],
  "meta": {
    "total": 1,
    "limit": 500
  }
}
```

---

### Get Findings Summary

Get aggregated security findings.

```
GET /findings
```

**Authentication:** Required (read access)

**Response:**
```json
{
  "total": 42,
  "by_severity": {
    "critical": 5,
    "high": 12,
    "medium": 20,
    "low": 5
  },
  "by_rule": {
    "PrivilegeEscalation": 8,
    "PublicAccess": 15,
    "WeakPolicy": 19
  },
  "critical_findings": [...],
  "high_findings": [...]
}
```

---

### Get Resource Inventory

Get resource counts by type.

```
GET /resources
```

**Authentication:** Required (read access)

**Query Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| `provider` | string | Filter by provider |

**Response:**
```json
{
  "total": 150,
  "by_type": {
    "Role": 25,
    "User": 10,
    "S3Bucket": 45,
    "EC2Instance": 70
  }
}
```

---

### Execute Custom Query

Execute a read-only Cypher query.

```
POST /query
```

**Authentication:** Required (full access)

**Request Body:**
```json
{
  "cypher": "MATCH (n:Resource) WHERE n.type = 'Role' RETURN n.id, n.name LIMIT 10",
  "limit": 100
}
```

**Allowed Query Patterns:**
- `MATCH ... RETURN ...`
- `CALL db.*`
- `CALL apoc.*`

**Response:**
```json
{
  "results": [
    {"n.id": "role/Admin", "n.name": "AdminRole"}
  ],
  "count": 1
}
```

**Error Responses:**
- `400` - Missing or invalid query
- `403` - Query not allowed (write queries, etc.)
- `500` - Query execution failed

---

## Profile Endpoints

### List Profiles

List all saved profiles.

```
GET /profiles
```

**Authentication:** Required (read access)

**Response:**
```json
{
  "profiles": [
    {
      "name": "aws-prod",
      "created_at": "2024-01-15T10:30:00Z",
      "updated_at": "2024-01-15T10:30:00Z",
      "node_count": 150,
      "edge_count": 300
    }
  ]
}
```

---

### Get Profile

Get a specific profile's data.

```
GET /profiles/{name}
```

**Authentication:** Required (read access)

**Response:**
```json
{
  "name": "aws-prod",
  "nodes": [...],
  "edges": [...],
  "meta": {
    "node_count": 150,
    "edge_count": 300
  }
}
```

---

### Create/Update Profile

Save nodes and edges to a profile.

```
POST /profiles
```

**Authentication:** Required (full access)

**Request Body:**
```json
{
  "name": "aws-prod-account",
  "nodes": [
    {
      "id": "arn:aws:iam::123456789012:role/AdminRole",
      "type": "Role",
      "provider": "aws",
      "properties": {"RoleName": "AdminRole"}
    }
  ],
  "edges": [
    {
      "src": "arn:aws:iam::123456789012:user/alice",
      "dst": "arn:aws:iam::123456789012:role/AdminRole",
      "type": "CanAssume",
      "properties": {}
    }
  ],
  "mode": "create"
}
```

**Modes:**
| Mode | Description |
|------|-------------|
| `create` | Fail if profile exists |
| `overwrite` | Replace existing profile |
| `merge` | Add to existing profile |

**Response:**
```json
{
  "success": true,
  "name": "aws-prod-account",
  "node_count": 1,
  "edge_count": 1,
  "mode": "create"
}
```

**Error Responses:**
- `400` - Invalid name or empty data
- `409` - Profile exists (create mode)

---

### Delete Profile

Delete a profile and all its data.

```
DELETE /profiles/{name}
```

**Authentication:** Required (full access)

**Response:**
```json
{
  "success": true,
  "deleted": "aws-prod"
}
```

---

### Rename Profile

Rename an existing profile.

```
POST /profiles/{name}/rename
```

**Authentication:** Required (full access)

**Request Body:**
```json
{
  "new_name": "aws-prod-v2"
}
```

**Response:**
```json
{
  "success": true,
  "old_name": "aws-prod",
  "new_name": "aws-prod-v2"
}
```

---

## Collection Endpoints

### Start AWS Collection

Start collecting data from an AWS account.

```
POST /collect/aws
```

**Authentication:** Required (full access)

**Request Body:**
```json
{
  "access_key": "AKIAIOSFODNN7EXAMPLE",
  "secret_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
  "session_token": null,
  "region": "us-east-1",
  "services": ["iam", "s3", "ec2"],
  "profile_name": "my-aws-account"
}
```

**Parameters:**
| Field | Required | Description |
|-------|----------|-------------|
| `access_key` | Yes | AWS access key ID |
| `secret_key` | Yes | AWS secret access key |
| `session_token` | No | Session token for temp credentials |
| `region` | No | Primary region (default: us-east-1) |
| `services` | No | Services to collect (default: all) |
| `profile_name` | No | Profile name (auto-generated if omitted) |

**Available Services:**
- `iam`, `iam-roles`, `iam-users`, `iam-policies`
- `s3`
- `ec2`
- `lambda`
- `kms`
- `vpc`

**Response (202 Accepted):**
```json
{
  "job_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "running",
  "message": "Collection started"
}
```

---

### Get Collection Status

Get status of a collection job.

```
GET /collect/{job_id}
```

**Authentication:** Required (read access)

**Response:**
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "running",
  "created_at": "2024-01-15T10:30:00Z",
  "updated_at": "2024-01-15T10:31:00Z",
  "progress": {
    "services_completed": 3,
    "services_total": 10
  },
  "result": null,
  "error": null
}
```

**Status Values:**
| Status | Description |
|--------|-------------|
| `pending` | Job queued |
| `running` | Collection in progress |
| `completed` | Successfully finished |
| `failed` | Error occurred |
| `cancelled` | User cancelled |

---

### Cancel Collection

Cancel a running collection job.

```
POST /collect/{job_id}/cancel
```

**Authentication:** Required (full access)

**Response:**
```json
{
  "success": true,
  "message": "Job cancelled"
}
```

---

### List Collection Jobs

List recent collection jobs.

```
GET /collect/jobs
```

**Authentication:** Required (read access)

**Response:**
```json
{
  "jobs": [...],
  "count": 5
}
```

---

## Upload Endpoints

### Upload Files

Upload JSONL files or ZIP archives.

```
POST /upload
```

**Authentication:** Required (full access)

**Content-Type:** `multipart/form-data`

**Example:**
```bash
curl -X POST http://localhost:9847/upload \
  -H "Authorization: Bearer <token>" \
  -F "file=@data.zip"
```

**Supported Formats:**
- `.jsonl` - Individual JSONL files
- `.zip` - ZIP archive containing JSONL files

**Protection Limits:**
- Max uncompressed size: 500MB
- Max files per archive: 1000

**Response (202 Accepted):**
```json
{
  "job_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "running",
  "total_files": 15,
  "total_profiles": 3,
  "message": "Upload processing started"
}
```

---

### Get Upload Status

Get status of an upload job.

```
GET /upload/{job_id}
```

**Authentication:** Required (read access)

---

### List Upload Jobs

List recent upload jobs.

```
GET /upload/jobs
```

**Authentication:** Required (read access)

---

## Export Endpoints

### Export Data

Export graph data and findings.

```
GET /export/{format}
```

**Authentication:** Required (read access)

**Formats:**
| Format | Content-Type | Description |
|--------|--------------|-------------|
| `json` | application/json | Full JSON export |
| `sarif` | application/json | SARIF format for security tools |
| `html` | text/html | HTML report |

**Example:**
```bash
curl "http://localhost:9847/export/sarif" \
  -H "Authorization: Bearer <token>" \
  -o findings.sarif
```

---

## Error Responses

All errors return JSON with this structure:

```json
{
  "error": "Short error message",
  "message": "Detailed description (optional)",
  "details": {"field": "value"}
}
```

### Common Error Codes

| Code | Description |
|------|-------------|
| `400` | Bad request (invalid input) |
| `401` | Unauthorized (missing/invalid auth) |
| `403` | Forbidden (insufficient permissions) |
| `404` | Resource not found |
| `409` | Conflict (resource exists) |
| `500` | Internal server error |
| `503` | Service unavailable |

---

## Rate Limits

| Endpoint | Limit |
|----------|-------|
| `/query` | 100/minute |
| `/collect/aws` | 10/hour |
| Other endpoints | 1000/minute |

Rate limit headers:
```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1642680000
```

---

## OpenAPI Specification

The full OpenAPI 3.0 specification is available programmatically:

```python
from cloudhound.api.openapi import get_openapi_spec
spec = get_openapi_spec()
```

This can be used to generate client SDKs or integrate with API documentation tools.
