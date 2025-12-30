"""Pydantic request/response models for CloudHound API.

Provides input validation and serialization for API endpoints.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, field_validator


# Validation patterns
PROFILE_NAME_PATTERN = re.compile(r'^[a-zA-Z0-9_\-\.]{1,100}$')
AWS_ACCESS_KEY_PATTERN = re.compile(r'^A[KS]IA[0-9A-Z]{16}$')


class ProfileRequest(BaseModel):
    """Request model for creating/updating profiles."""

    name: str = Field(..., min_length=1, max_length=100)
    nodes: List[Dict[str, Any]] = Field(default_factory=list)
    edges: List[Dict[str, Any]] = Field(default_factory=list)
    mode: str = Field(default="create", pattern="^(create|overwrite|merge)$")

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str) -> str:
        if not PROFILE_NAME_PATTERN.match(v):
            raise ValueError(
                "Profile name must be 1-100 characters, "
                "alphanumeric with _ - . allowed"
            )
        return v


class RenameProfileRequest(BaseModel):
    """Request model for renaming a profile."""

    new_name: str = Field(..., min_length=1, max_length=100)

    @field_validator("new_name")
    @classmethod
    def validate_name(cls, v: str) -> str:
        if not PROFILE_NAME_PATTERN.match(v):
            raise ValueError(
                "Profile name must be 1-100 characters, "
                "alphanumeric with _ - . allowed"
            )
        return v


class QueryRequest(BaseModel):
    """Request model for Cypher queries."""

    cypher: str = Field(..., min_length=1)
    limit: int = Field(default=500, ge=1, le=10000)


class CollectAWSRequest(BaseModel):
    """Request model for AWS collection."""

    access_key: str = Field(..., min_length=20, max_length=128)
    secret_key: str = Field(..., min_length=40, max_length=128)
    session_token: Optional[str] = Field(default=None, max_length=2048)
    region: str = Field(default="us-east-1", max_length=30)
    services: List[str] = Field(default_factory=list)
    profile_name: Optional[str] = Field(default=None, max_length=100)

    @field_validator("access_key")
    @classmethod
    def validate_access_key(cls, v: str) -> str:
        if not AWS_ACCESS_KEY_PATTERN.match(v):
            raise ValueError(
                "Invalid AWS access key format. "
                "Expected AKIA/ASIA followed by 16 alphanumeric characters."
            )
        return v

    @field_validator("secret_key")
    @classmethod
    def validate_secret_key(cls, v: str) -> str:
        if len(v) != 40:
            raise ValueError("AWS secret key must be exactly 40 characters")
        return v

    @field_validator("profile_name")
    @classmethod
    def validate_profile_name(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and not PROFILE_NAME_PATTERN.match(v):
            raise ValueError(
                "Profile name must be 1-100 characters, "
                "alphanumeric with _ - . allowed"
            )
        return v


class NodeModel(BaseModel):
    """Model for a graph node."""

    id: str
    type: str
    provider: str = "unknown"
    properties: Dict[str, Any] = Field(default_factory=dict)


class EdgeModel(BaseModel):
    """Model for a graph edge."""

    src: str
    dst: str
    type: str
    properties: Dict[str, Any] = Field(default_factory=dict)


class GraphResponse(BaseModel):
    """Response model for graph data."""

    nodes: List[NodeModel]
    edges: List[EdgeModel]
    meta: Dict[str, Any] = Field(default_factory=dict)


class ProfileResponse(BaseModel):
    """Response model for profile data."""

    name: str
    nodes: List[NodeModel]
    edges: List[EdgeModel]
    meta: Dict[str, Any] = Field(default_factory=dict)


class ErrorResponse(BaseModel):
    """Standard error response model."""

    error: str
    message: Optional[str] = None
    details: Optional[Dict[str, Any]] = None


class HealthResponse(BaseModel):
    """Health check response model."""

    status: str
    database: Optional[str] = None
    checks: Dict[str, str] = Field(default_factory=dict)


class JobResponse(BaseModel):
    """Response model for async job status."""

    job_id: str
    status: str
    message: Optional[str] = None
    progress: Optional[Dict[str, Any]] = None
