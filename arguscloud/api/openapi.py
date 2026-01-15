"""OpenAPI/Swagger schema definitions for ArgusCloud API.

This module provides OpenAPI 3.0 documentation for all API endpoints,
enabling automatic API documentation generation via Swagger UI.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


# ============ Info and Tags ============

API_INFO = {
    "title": "ArgusCloud API",
    "version": "0.2.0",
    "description": """
ArgusCloud is a multi-cloud security graph analytics tool that helps
identify security misconfigurations and attack paths across AWS, GCP,
and Azure environments.

## Authentication

Most endpoints require authentication via JWT token or API key.
Include the token in the `Authorization` header:

```
Authorization: Bearer <token>
```

Or use an API key:

```
X-API-Key: <key>
```

Obtain a token via `POST /auth/token`.

## Rate Limits

- Query endpoint: 100 requests/minute
- Collection endpoints: 10 requests/hour
- Other endpoints: 1000 requests/minute

## Error Handling

All errors return a JSON response with:
- `error`: Short error message
- `message`: (optional) Detailed description
- `details`: (optional) Additional context
""",
    "contact": {
        "name": "ArgusCloud Support",
        "url": "https://github.com/jeremylaratro/cloudhound/issues",
    },
    "license": {
        "name": "Non-Commercial License",
        "url": "https://github.com/jeremylaratro/cloudhound/blob/main/LICENSE",
    },
}

API_TAGS = [
    {
        "name": "System",
        "description": "Health checks and system information",
    },
    {
        "name": "Authentication",
        "description": "Token generation and verification",
    },
    {
        "name": "Graph",
        "description": "Graph data queries and visualization",
    },
    {
        "name": "Findings",
        "description": "Security findings and attack paths",
    },
    {
        "name": "Profiles",
        "description": "Profile management for saved graph data",
    },
    {
        "name": "Collection",
        "description": "AWS data collection operations",
    },
    {
        "name": "Upload",
        "description": "Bulk data upload operations",
    },
    {
        "name": "Export",
        "description": "Data export in various formats",
    },
]


# ============ Request Schemas ============


class AuthTokenRequest(BaseModel):
    """Request body for token generation."""

    username: str = Field(..., description="Username for authentication")
    password: str = Field(..., description="Password for authentication")

    model_config = {"json_schema_extra": {"example": {"username": "admin", "password": "secret"}}}


class QueryRequest(BaseModel):
    """Request body for custom Cypher queries."""

    cypher: str = Field(
        ...,
        description="Cypher query to execute (MATCH...RETURN or CALL queries only)",
        min_length=1,
    )
    limit: int = Field(
        default=500,
        description="Maximum number of results to return",
        ge=1,
        le=10000,
    )

    model_config = {
        "json_schema_extra": {
            "example": {
                "cypher": "MATCH (n:Resource) WHERE n.type = 'Role' RETURN n.id, n.name LIMIT 10",
                "limit": 100,
            }
        }
    }


class ProfileCreateRequest(BaseModel):
    """Request body for creating/updating profiles."""

    name: str = Field(
        ...,
        description="Profile name (alphanumeric, _, -, . allowed)",
        min_length=1,
        max_length=100,
    )
    nodes: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="List of node objects with id, type, provider, properties",
    )
    edges: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="List of edge objects with src, dst, type, properties",
    )
    mode: str = Field(
        default="create",
        description="Save mode: create (fail if exists), overwrite (replace), merge (add)",
        pattern="^(create|overwrite|merge)$",
    )

    model_config = {
        "json_schema_extra": {
            "example": {
                "name": "aws-prod-account",
                "nodes": [
                    {
                        "id": "arn:aws:iam::123456789012:role/AdminRole",
                        "type": "Role",
                        "provider": "aws",
                        "properties": {"RoleName": "AdminRole"},
                    }
                ],
                "edges": [
                    {
                        "src": "arn:aws:iam::123456789012:user/alice",
                        "dst": "arn:aws:iam::123456789012:role/AdminRole",
                        "type": "CanAssume",
                        "properties": {},
                    }
                ],
                "mode": "create",
            }
        }
    }


class ProfileRenameRequest(BaseModel):
    """Request body for renaming a profile."""

    new_name: str = Field(
        ...,
        description="New profile name",
        min_length=1,
        max_length=100,
    )

    model_config = {"json_schema_extra": {"example": {"new_name": "aws-prod-account-v2"}}}


class AWSCollectionRequest(BaseModel):
    """Request body for starting AWS data collection."""

    access_key: str = Field(
        ...,
        description="AWS access key ID (AKIA... or ASIA...)",
        min_length=20,
        max_length=128,
    )
    secret_key: str = Field(
        ...,
        description="AWS secret access key (40 characters)",
        min_length=40,
        max_length=128,
    )
    session_token: Optional[str] = Field(
        default=None,
        description="AWS session token (required for temporary credentials)",
        max_length=2048,
    )
    region: str = Field(
        default="us-east-1",
        description="Primary AWS region for API calls",
        max_length=30,
    )
    services: List[str] = Field(
        default_factory=list,
        description="Services to collect (empty = all supported)",
    )
    profile_name: Optional[str] = Field(
        default=None,
        description="Profile name to save results (auto-generated if not provided)",
        max_length=100,
    )

    model_config = {
        "json_schema_extra": {
            "example": {
                "access_key": "AKIAIOSFODNN7EXAMPLE",
                "secret_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                "region": "us-east-1",
                "services": ["iam", "s3", "ec2"],
                "profile_name": "my-aws-account",
            }
        }
    }


# ============ Response Schemas ============


class HealthResponse(BaseModel):
    """Health check response."""

    status: str = Field(description="Overall status: ok, degraded, or error")
    checks: Dict[str, str] = Field(description="Individual component check results")
    version: str = Field(description="API version")

    model_config = {
        "json_schema_extra": {
            "example": {
                "status": "ok",
                "checks": {"neo4j": "ok", "plugins": "ok (3 loaded)"},
                "version": "0.2.0",
            }
        }
    }


class PluginsResponse(BaseModel):
    """List of installed plugins."""

    plugins: List[Dict[str, Any]] = Field(description="Plugin information")
    count: int = Field(description="Number of loaded plugins")
    errors: List[str] = Field(description="Plugin load errors if any")

    model_config = {
        "json_schema_extra": {
            "example": {
                "plugins": [
                    {
                        "name": "aws-collector",
                        "version": "1.0.0",
                        "description": "AWS resource collector",
                    }
                ],
                "count": 1,
                "errors": [],
            }
        }
    }


class AuthTokenResponse(BaseModel):
    """JWT token response."""

    token: str = Field(description="JWT access token")
    expires_in: int = Field(description="Token expiration time in seconds")

    model_config = {
        "json_schema_extra": {
            "example": {"token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...", "expires_in": 3600}
        }
    }


class NodeSchema(BaseModel):
    """Graph node schema."""

    id: str = Field(description="Unique node identifier (usually ARN)")
    type: str = Field(description="Node type (Role, User, S3Bucket, etc.)")
    provider: str = Field(description="Cloud provider (aws, gcp, azure)")
    properties: Dict[str, Any] = Field(description="Node properties")

    model_config = {
        "json_schema_extra": {
            "example": {
                "id": "arn:aws:iam::123456789012:role/AdminRole",
                "type": "Role",
                "provider": "aws",
                "properties": {"RoleName": "AdminRole", "CreateDate": "2023-01-15T10:30:00Z"},
            }
        }
    }


class EdgeSchema(BaseModel):
    """Graph edge schema."""

    src: str = Field(description="Source node ID")
    dst: str = Field(description="Destination node ID")
    type: str = Field(description="Edge type (CanAssume, HasAccess, AttackPath, etc.)")
    properties: Dict[str, Any] = Field(description="Edge properties")

    model_config = {
        "json_schema_extra": {
            "example": {
                "src": "arn:aws:iam::123456789012:user/alice",
                "dst": "arn:aws:iam::123456789012:role/AdminRole",
                "type": "CanAssume",
                "properties": {"condition": None},
            }
        }
    }


class GraphResponse(BaseModel):
    """Graph data response."""

    nodes: List[NodeSchema] = Field(description="List of graph nodes")
    edges: List[EdgeSchema] = Field(description="List of graph edges")
    meta: Dict[str, Any] = Field(description="Metadata about the response")

    model_config = {
        "json_schema_extra": {
            "example": {
                "nodes": [
                    {
                        "id": "arn:aws:iam::123456789012:role/AdminRole",
                        "type": "Role",
                        "provider": "aws",
                        "properties": {},
                    }
                ],
                "edges": [
                    {
                        "src": "arn:aws:iam::123456789012:user/alice",
                        "dst": "arn:aws:iam::123456789012:role/AdminRole",
                        "type": "CanAssume",
                        "properties": {},
                    }
                ],
                "meta": {"total_nodes": 1, "total_edges": 1, "limit": 500},
            }
        }
    }


class AttackPathsResponse(BaseModel):
    """Attack paths response."""

    edges: List[EdgeSchema] = Field(description="List of attack path edges")
    meta: Dict[str, Any] = Field(description="Response metadata")

    model_config = {
        "json_schema_extra": {
            "example": {
                "edges": [
                    {
                        "src": "arn:aws:iam::123456789012:user/alice",
                        "dst": "arn:aws:iam::123456789012:role/AdminRole",
                        "type": "AttackPath",
                        "properties": {
                            "severity": "high",
                            "rule": "PrivilegeEscalation",
                            "description": "User can escalate to admin role",
                        },
                    }
                ],
                "meta": {"total": 1, "limit": 500},
            }
        }
    }


class FindingsResponse(BaseModel):
    """Security findings summary response."""

    total: int = Field(description="Total number of findings")
    by_severity: Dict[str, int] = Field(description="Count by severity level")
    by_rule: Dict[str, int] = Field(description="Count by rule type")
    critical_findings: List[EdgeSchema] = Field(description="Top critical findings")
    high_findings: List[EdgeSchema] = Field(description="Top high findings")

    model_config = {
        "json_schema_extra": {
            "example": {
                "total": 42,
                "by_severity": {"critical": 5, "high": 12, "medium": 20, "low": 5},
                "by_rule": {"PrivilegeEscalation": 8, "PublicAccess": 15, "WeakPolicy": 19},
                "critical_findings": [],
                "high_findings": [],
            }
        }
    }


class ResourcesResponse(BaseModel):
    """Resource inventory response."""

    total: int = Field(description="Total number of resources")
    by_type: Dict[str, int] = Field(description="Count by resource type")

    model_config = {
        "json_schema_extra": {
            "example": {
                "total": 150,
                "by_type": {"Role": 25, "User": 10, "S3Bucket": 45, "EC2Instance": 70},
            }
        }
    }


class QueryResponse(BaseModel):
    """Custom query response."""

    results: List[Dict[str, Any]] = Field(description="Query results")
    count: int = Field(description="Number of results returned")

    model_config = {
        "json_schema_extra": {
            "example": {
                "results": [{"n.id": "role/Admin", "n.name": "AdminRole"}],
                "count": 1,
            }
        }
    }


class ProfileListResponse(BaseModel):
    """List of profiles response."""

    profiles: List[Dict[str, Any]] = Field(description="Profile summaries")

    model_config = {
        "json_schema_extra": {
            "example": {
                "profiles": [
                    {
                        "name": "aws-prod",
                        "created_at": "2024-01-15T10:30:00Z",
                        "updated_at": "2024-01-15T10:30:00Z",
                        "node_count": 150,
                        "edge_count": 300,
                    }
                ]
            }
        }
    }


class ProfileDetailResponse(BaseModel):
    """Profile detail response."""

    name: str = Field(description="Profile name")
    nodes: List[NodeSchema] = Field(description="Profile nodes")
    edges: List[EdgeSchema] = Field(description="Profile edges")
    meta: Dict[str, Any] = Field(description="Profile metadata")

    model_config = {
        "json_schema_extra": {
            "example": {
                "name": "aws-prod",
                "nodes": [],
                "edges": [],
                "meta": {"node_count": 150, "edge_count": 300},
            }
        }
    }


class ProfileSaveResponse(BaseModel):
    """Profile save response."""

    success: bool = Field(description="Whether the operation succeeded")
    name: str = Field(description="Profile name")
    node_count: int = Field(description="Number of nodes saved")
    edge_count: int = Field(description="Number of edges saved")
    mode: str = Field(description="Save mode used")

    model_config = {
        "json_schema_extra": {
            "example": {
                "success": True,
                "name": "aws-prod",
                "node_count": 150,
                "edge_count": 300,
                "mode": "create",
            }
        }
    }


class ProfileDeleteResponse(BaseModel):
    """Profile delete response."""

    success: bool = Field(description="Whether deletion succeeded")
    deleted: str = Field(description="Name of deleted profile")

    model_config = {"json_schema_extra": {"example": {"success": True, "deleted": "aws-prod"}}}


class ProfileRenameResponse(BaseModel):
    """Profile rename response."""

    success: bool = Field(description="Whether rename succeeded")
    old_name: str = Field(description="Previous profile name")
    new_name: str = Field(description="New profile name")

    model_config = {
        "json_schema_extra": {
            "example": {"success": True, "old_name": "aws-prod", "new_name": "aws-prod-v2"}
        }
    }


class JobStartResponse(BaseModel):
    """Job start response for async operations."""

    job_id: str = Field(description="Unique job identifier")
    status: str = Field(description="Current job status")
    message: str = Field(description="Status message")

    model_config = {
        "json_schema_extra": {
            "example": {
                "job_id": "550e8400-e29b-41d4-a716-446655440000",
                "status": "running",
                "message": "Collection started",
            }
        }
    }


class JobStatusResponse(BaseModel):
    """Job status response."""

    id: str = Field(description="Job identifier")
    status: str = Field(description="Current status: pending, running, completed, failed, cancelled")
    created_at: str = Field(description="Job creation timestamp")
    updated_at: str = Field(description="Last update timestamp")
    progress: Optional[Dict[str, Any]] = Field(description="Progress details")
    result: Optional[Dict[str, Any]] = Field(description="Job result (when completed)")
    error: Optional[str] = Field(description="Error message (when failed)")

    model_config = {
        "json_schema_extra": {
            "example": {
                "id": "550e8400-e29b-41d4-a716-446655440000",
                "status": "running",
                "created_at": "2024-01-15T10:30:00Z",
                "updated_at": "2024-01-15T10:31:00Z",
                "progress": {"services_completed": 3, "services_total": 10},
                "result": None,
                "error": None,
            }
        }
    }


class JobListResponse(BaseModel):
    """List of jobs response."""

    jobs: List[JobStatusResponse] = Field(description="List of job statuses")
    count: int = Field(description="Number of jobs")

    model_config = {
        "json_schema_extra": {
            "example": {
                "jobs": [
                    {
                        "id": "550e8400-e29b-41d4-a716-446655440000",
                        "status": "completed",
                        "created_at": "2024-01-15T10:30:00Z",
                        "updated_at": "2024-01-15T10:35:00Z",
                    }
                ],
                "count": 1,
            }
        }
    }


class UploadStartResponse(BaseModel):
    """Upload job start response."""

    job_id: str = Field(description="Unique job identifier")
    status: str = Field(description="Current job status")
    total_files: int = Field(description="Number of files being processed")
    total_profiles: int = Field(description="Number of profiles detected")
    message: str = Field(description="Status message")

    model_config = {
        "json_schema_extra": {
            "example": {
                "job_id": "550e8400-e29b-41d4-a716-446655440000",
                "status": "running",
                "total_files": 15,
                "total_profiles": 3,
                "message": "Upload processing started",
            }
        }
    }


class ErrorResponse(BaseModel):
    """Standard error response."""

    error: str = Field(description="Short error message")
    message: Optional[str] = Field(description="Detailed error description")
    details: Optional[Dict[str, Any]] = Field(description="Additional error context")

    model_config = {
        "json_schema_extra": {
            "example": {
                "error": "Validation failed",
                "message": "Profile name contains invalid characters",
                "details": {"field": "name", "pattern": "^[a-zA-Z0-9_\\-\\.]{1,100}$"},
            }
        }
    }


# ============ OpenAPI Path Definitions ============

OPENAPI_PATHS = {
    "/health": {
        "get": {
            "tags": ["System"],
            "summary": "Health check",
            "description": "Check the health status of the API and its dependencies.",
            "operationId": "health",
            "responses": {
                "200": {
                    "description": "System is healthy",
                    "content": {"application/json": {"schema": HealthResponse.model_json_schema()}},
                },
                "503": {
                    "description": "System is degraded",
                    "content": {"application/json": {"schema": HealthResponse.model_json_schema()}},
                },
            },
        }
    },
    "/plugins": {
        "get": {
            "tags": ["System"],
            "summary": "List plugins",
            "description": "List all installed and loaded plugins.",
            "operationId": "listPlugins",
            "responses": {
                "200": {
                    "description": "Plugin list",
                    "content": {"application/json": {"schema": PluginsResponse.model_json_schema()}},
                }
            },
        }
    },
    "/auth/token": {
        "post": {
            "tags": ["Authentication"],
            "summary": "Generate auth token",
            "description": "Generate a JWT access token for API authentication.",
            "operationId": "createToken",
            "requestBody": {
                "required": True,
                "content": {
                    "application/json": {"schema": AuthTokenRequest.model_json_schema()}
                },
            },
            "responses": {
                "200": {
                    "description": "Token generated successfully",
                    "content": {
                        "application/json": {"schema": AuthTokenResponse.model_json_schema()}
                    },
                },
                "401": {
                    "description": "Invalid credentials",
                    "content": {"application/json": {"schema": ErrorResponse.model_json_schema()}},
                },
            },
        }
    },
    "/graph": {
        "get": {
            "tags": ["Graph"],
            "summary": "Get graph data",
            "description": "Retrieve nodes and edges from the graph database.",
            "operationId": "getGraph",
            "security": [{"bearerAuth": []}, {"apiKey": []}],
            "parameters": [
                {
                    "name": "limit",
                    "in": "query",
                    "schema": {"type": "integer", "default": 500, "maximum": 10000},
                    "description": "Maximum number of results",
                },
                {
                    "name": "provider",
                    "in": "query",
                    "schema": {"type": "string", "enum": ["aws", "gcp", "azure"]},
                    "description": "Filter by cloud provider",
                },
                {
                    "name": "type",
                    "in": "query",
                    "schema": {"type": "string"},
                    "description": "Filter by node type",
                },
            ],
            "responses": {
                "200": {
                    "description": "Graph data",
                    "content": {"application/json": {"schema": GraphResponse.model_json_schema()}},
                },
                "401": {
                    "description": "Unauthorized",
                    "content": {"application/json": {"schema": ErrorResponse.model_json_schema()}},
                },
            },
        }
    },
    "/attackpaths": {
        "get": {
            "tags": ["Findings"],
            "summary": "Get attack paths",
            "description": "Retrieve identified attack path edges.",
            "operationId": "getAttackPaths",
            "security": [{"bearerAuth": []}, {"apiKey": []}],
            "parameters": [
                {
                    "name": "limit",
                    "in": "query",
                    "schema": {"type": "integer", "default": 500},
                    "description": "Maximum number of results",
                },
                {
                    "name": "severity",
                    "in": "query",
                    "schema": {"type": "string", "enum": ["critical", "high", "medium", "low"]},
                    "description": "Filter by severity level",
                },
                {
                    "name": "provider",
                    "in": "query",
                    "schema": {"type": "string"},
                    "description": "Filter by cloud provider",
                },
            ],
            "responses": {
                "200": {
                    "description": "Attack paths",
                    "content": {
                        "application/json": {"schema": AttackPathsResponse.model_json_schema()}
                    },
                },
            },
        }
    },
    "/findings": {
        "get": {
            "tags": ["Findings"],
            "summary": "Get findings summary",
            "description": "Get aggregated security findings summary.",
            "operationId": "getFindings",
            "security": [{"bearerAuth": []}, {"apiKey": []}],
            "responses": {
                "200": {
                    "description": "Findings summary",
                    "content": {
                        "application/json": {"schema": FindingsResponse.model_json_schema()}
                    },
                },
            },
        }
    },
    "/resources": {
        "get": {
            "tags": ["Graph"],
            "summary": "Get resource inventory",
            "description": "Get aggregated resource counts by type.",
            "operationId": "getResources",
            "security": [{"bearerAuth": []}, {"apiKey": []}],
            "parameters": [
                {
                    "name": "provider",
                    "in": "query",
                    "schema": {"type": "string"},
                    "description": "Filter by cloud provider",
                }
            ],
            "responses": {
                "200": {
                    "description": "Resource inventory",
                    "content": {
                        "application/json": {"schema": ResourcesResponse.model_json_schema()}
                    },
                },
            },
        }
    },
    "/query": {
        "post": {
            "tags": ["Graph"],
            "summary": "Execute Cypher query",
            "description": "Execute a custom read-only Cypher query. Only MATCH...RETURN and CALL queries are allowed.",
            "operationId": "executeQuery",
            "security": [{"bearerAuth": []}, {"apiKey": []}],
            "requestBody": {
                "required": True,
                "content": {"application/json": {"schema": QueryRequest.model_json_schema()}},
            },
            "responses": {
                "200": {
                    "description": "Query results",
                    "content": {"application/json": {"schema": QueryResponse.model_json_schema()}},
                },
                "400": {
                    "description": "Invalid query",
                    "content": {"application/json": {"schema": ErrorResponse.model_json_schema()}},
                },
                "403": {
                    "description": "Query not allowed",
                    "content": {"application/json": {"schema": ErrorResponse.model_json_schema()}},
                },
            },
        }
    },
    "/export/{format}": {
        "get": {
            "tags": ["Export"],
            "summary": "Export data",
            "description": "Export graph data and findings in various formats.",
            "operationId": "exportData",
            "security": [{"bearerAuth": []}, {"apiKey": []}],
            "parameters": [
                {
                    "name": "format",
                    "in": "path",
                    "required": True,
                    "schema": {"type": "string", "enum": ["json", "sarif", "html"]},
                    "description": "Export format",
                }
            ],
            "responses": {
                "200": {
                    "description": "Exported data",
                    "content": {
                        "application/json": {"schema": {"type": "object"}},
                        "text/html": {"schema": {"type": "string"}},
                    },
                },
                "400": {
                    "description": "Unknown format",
                    "content": {"application/json": {"schema": ErrorResponse.model_json_schema()}},
                },
            },
        }
    },
    "/profiles": {
        "get": {
            "tags": ["Profiles"],
            "summary": "List profiles",
            "description": "List all saved profiles with metadata.",
            "operationId": "listProfiles",
            "security": [{"bearerAuth": []}, {"apiKey": []}],
            "responses": {
                "200": {
                    "description": "Profile list",
                    "content": {
                        "application/json": {"schema": ProfileListResponse.model_json_schema()}
                    },
                },
            },
        },
        "post": {
            "tags": ["Profiles"],
            "summary": "Create/update profile",
            "description": "Save nodes and edges to a named profile.",
            "operationId": "saveProfile",
            "security": [{"bearerAuth": []}, {"apiKey": []}],
            "requestBody": {
                "required": True,
                "content": {
                    "application/json": {"schema": ProfileCreateRequest.model_json_schema()}
                },
            },
            "responses": {
                "200": {
                    "description": "Profile saved",
                    "content": {
                        "application/json": {"schema": ProfileSaveResponse.model_json_schema()}
                    },
                },
                "400": {
                    "description": "Invalid request",
                    "content": {"application/json": {"schema": ErrorResponse.model_json_schema()}},
                },
                "409": {
                    "description": "Profile already exists",
                    "content": {"application/json": {"schema": ErrorResponse.model_json_schema()}},
                },
            },
        },
    },
    "/profiles/{name}": {
        "get": {
            "tags": ["Profiles"],
            "summary": "Get profile",
            "description": "Get a specific profile's nodes and edges.",
            "operationId": "getProfile",
            "security": [{"bearerAuth": []}, {"apiKey": []}],
            "parameters": [
                {
                    "name": "name",
                    "in": "path",
                    "required": True,
                    "schema": {"type": "string"},
                    "description": "Profile name",
                }
            ],
            "responses": {
                "200": {
                    "description": "Profile data",
                    "content": {
                        "application/json": {"schema": ProfileDetailResponse.model_json_schema()}
                    },
                },
                "404": {
                    "description": "Profile not found",
                    "content": {"application/json": {"schema": ErrorResponse.model_json_schema()}},
                },
            },
        },
        "delete": {
            "tags": ["Profiles"],
            "summary": "Delete profile",
            "description": "Delete a profile and all its data.",
            "operationId": "deleteProfile",
            "security": [{"bearerAuth": []}, {"apiKey": []}],
            "parameters": [
                {
                    "name": "name",
                    "in": "path",
                    "required": True,
                    "schema": {"type": "string"},
                    "description": "Profile name",
                }
            ],
            "responses": {
                "200": {
                    "description": "Profile deleted",
                    "content": {
                        "application/json": {"schema": ProfileDeleteResponse.model_json_schema()}
                    },
                },
                "404": {
                    "description": "Profile not found",
                    "content": {"application/json": {"schema": ErrorResponse.model_json_schema()}},
                },
            },
        },
    },
    "/profiles/{name}/rename": {
        "post": {
            "tags": ["Profiles"],
            "summary": "Rename profile",
            "description": "Rename an existing profile.",
            "operationId": "renameProfile",
            "security": [{"bearerAuth": []}, {"apiKey": []}],
            "parameters": [
                {
                    "name": "name",
                    "in": "path",
                    "required": True,
                    "schema": {"type": "string"},
                    "description": "Current profile name",
                }
            ],
            "requestBody": {
                "required": True,
                "content": {
                    "application/json": {"schema": ProfileRenameRequest.model_json_schema()}
                },
            },
            "responses": {
                "200": {
                    "description": "Profile renamed",
                    "content": {
                        "application/json": {"schema": ProfileRenameResponse.model_json_schema()}
                    },
                },
                "404": {
                    "description": "Profile not found",
                    "content": {"application/json": {"schema": ErrorResponse.model_json_schema()}},
                },
                "409": {
                    "description": "Target name already exists",
                    "content": {"application/json": {"schema": ErrorResponse.model_json_schema()}},
                },
            },
        }
    },
    "/collect/aws": {
        "post": {
            "tags": ["Collection"],
            "summary": "Start AWS collection",
            "description": "Start an AWS data collection job with provided credentials.",
            "operationId": "startAWSCollection",
            "security": [{"bearerAuth": []}, {"apiKey": []}],
            "requestBody": {
                "required": True,
                "content": {
                    "application/json": {"schema": AWSCollectionRequest.model_json_schema()}
                },
            },
            "responses": {
                "202": {
                    "description": "Collection started",
                    "content": {
                        "application/json": {"schema": JobStartResponse.model_json_schema()}
                    },
                },
                "400": {
                    "description": "Invalid credentials format",
                    "content": {"application/json": {"schema": ErrorResponse.model_json_schema()}},
                },
            },
        }
    },
    "/collect/{job_id}": {
        "get": {
            "tags": ["Collection"],
            "summary": "Get collection status",
            "description": "Get the status of a collection job.",
            "operationId": "getCollectionStatus",
            "security": [{"bearerAuth": []}, {"apiKey": []}],
            "parameters": [
                {
                    "name": "job_id",
                    "in": "path",
                    "required": True,
                    "schema": {"type": "string", "format": "uuid"},
                    "description": "Job ID",
                }
            ],
            "responses": {
                "200": {
                    "description": "Job status",
                    "content": {
                        "application/json": {"schema": JobStatusResponse.model_json_schema()}
                    },
                },
                "404": {
                    "description": "Job not found",
                    "content": {"application/json": {"schema": ErrorResponse.model_json_schema()}},
                },
            },
        }
    },
    "/collect/{job_id}/cancel": {
        "post": {
            "tags": ["Collection"],
            "summary": "Cancel collection",
            "description": "Cancel a running collection job.",
            "operationId": "cancelCollection",
            "security": [{"bearerAuth": []}, {"apiKey": []}],
            "parameters": [
                {
                    "name": "job_id",
                    "in": "path",
                    "required": True,
                    "schema": {"type": "string", "format": "uuid"},
                    "description": "Job ID",
                }
            ],
            "responses": {
                "200": {
                    "description": "Job cancelled",
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "properties": {
                                    "success": {"type": "boolean"},
                                    "message": {"type": "string"},
                                },
                            }
                        }
                    },
                },
                "404": {
                    "description": "Job not found or already completed",
                    "content": {"application/json": {"schema": ErrorResponse.model_json_schema()}},
                },
            },
        }
    },
    "/collect/jobs": {
        "get": {
            "tags": ["Collection"],
            "summary": "List collection jobs",
            "description": "List recent collection jobs.",
            "operationId": "listCollectionJobs",
            "security": [{"bearerAuth": []}, {"apiKey": []}],
            "responses": {
                "200": {
                    "description": "Job list",
                    "content": {
                        "application/json": {"schema": JobListResponse.model_json_schema()}
                    },
                },
            },
        }
    },
    "/upload": {
        "post": {
            "tags": ["Upload"],
            "summary": "Upload data files",
            "description": "Upload JSONL files or ZIP archives containing JSONL files.",
            "operationId": "uploadFiles",
            "security": [{"bearerAuth": []}, {"apiKey": []}],
            "requestBody": {
                "required": True,
                "content": {
                    "multipart/form-data": {
                        "schema": {
                            "type": "object",
                            "properties": {
                                "file": {
                                    "type": "string",
                                    "format": "binary",
                                    "description": "JSONL or ZIP file to upload",
                                }
                            },
                        }
                    }
                },
            },
            "responses": {
                "202": {
                    "description": "Upload started",
                    "content": {
                        "application/json": {"schema": UploadStartResponse.model_json_schema()}
                    },
                },
                "400": {
                    "description": "Invalid file",
                    "content": {"application/json": {"schema": ErrorResponse.model_json_schema()}},
                },
            },
        }
    },
    "/upload/{job_id}": {
        "get": {
            "tags": ["Upload"],
            "summary": "Get upload status",
            "description": "Get the status of an upload job.",
            "operationId": "getUploadStatus",
            "security": [{"bearerAuth": []}, {"apiKey": []}],
            "parameters": [
                {
                    "name": "job_id",
                    "in": "path",
                    "required": True,
                    "schema": {"type": "string", "format": "uuid"},
                    "description": "Job ID",
                }
            ],
            "responses": {
                "200": {
                    "description": "Job status",
                    "content": {
                        "application/json": {"schema": JobStatusResponse.model_json_schema()}
                    },
                },
                "404": {
                    "description": "Job not found",
                    "content": {"application/json": {"schema": ErrorResponse.model_json_schema()}},
                },
            },
        }
    },
    "/upload/jobs": {
        "get": {
            "tags": ["Upload"],
            "summary": "List upload jobs",
            "description": "List recent upload jobs.",
            "operationId": "listUploadJobs",
            "security": [{"bearerAuth": []}, {"apiKey": []}],
            "responses": {
                "200": {
                    "description": "Job list",
                    "content": {
                        "application/json": {"schema": JobListResponse.model_json_schema()}
                    },
                },
            },
        }
    },
}


def get_openapi_spec() -> Dict[str, Any]:
    """Generate complete OpenAPI specification.

    Returns:
        OpenAPI 3.0 specification as a dictionary
    """
    return {
        "openapi": "3.0.3",
        "info": API_INFO,
        "servers": [
            {"url": "http://localhost:5000", "description": "Development server"},
            {"url": "http://localhost:9847", "description": "Default API server"},
        ],
        "tags": API_TAGS,
        "paths": OPENAPI_PATHS,
        "components": {
            "securitySchemes": {
                "bearerAuth": {
                    "type": "http",
                    "scheme": "bearer",
                    "bearerFormat": "JWT",
                    "description": "JWT token obtained from /auth/token",
                },
                "apiKey": {
                    "type": "apiKey",
                    "in": "header",
                    "name": "X-API-Key",
                    "description": "API key for service-to-service communication",
                },
            },
            "schemas": {
                "HealthResponse": HealthResponse.model_json_schema(),
                "ErrorResponse": ErrorResponse.model_json_schema(),
                "GraphResponse": GraphResponse.model_json_schema(),
                "NodeSchema": NodeSchema.model_json_schema(),
                "EdgeSchema": EdgeSchema.model_json_schema(),
                "ProfileCreateRequest": ProfileCreateRequest.model_json_schema(),
                "AWSCollectionRequest": AWSCollectionRequest.model_json_schema(),
                "JobStatusResponse": JobStatusResponse.model_json_schema(),
            },
        },
    }
