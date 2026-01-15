"""ArgusCloud centralized configuration management.

Uses pydantic-settings to load configuration from environment variables
and .env files with validation.
"""

from __future__ import annotations

import os
from functools import lru_cache
from typing import List, Optional

try:
    from pydantic_settings import BaseSettings
    from pydantic import Field
except ImportError:
    # Fallback for when pydantic-settings is not installed
    from pydantic import BaseSettings, Field


class Settings(BaseSettings):
    """ArgusCloud application settings.

    All settings can be overridden via environment variables
    prefixed with ARGUSCLOUD_.

    Example:
        ARGUSCLOUD_API_PORT=8080
        ARGUSCLOUD_NEO4J_URI=bolt://neo4j:7687
    """

    # API Server
    api_host: str = Field(default="0.0.0.0", description="API server bind address")
    api_port: int = Field(default=9847, description="API server port")

    # Neo4j Database
    neo4j_uri: str = Field(
        default="bolt://localhost:7687",
        description="Neo4j connection URI"
    )
    neo4j_user: str = Field(default="neo4j", description="Neo4j username")
    neo4j_password: str = Field(default="", description="Neo4j password")

    # Authentication
    jwt_secret: str = Field(default="", description="JWT signing secret (auto-generated if empty)")
    jwt_expiry: int = Field(default=3600, description="JWT token expiry in seconds")
    auth_enabled: bool = Field(default=True, description="Enable authentication")

    # CORS
    cors_origins: List[str] = Field(
        default=["http://localhost:8080", "http://127.0.0.1:8080"],
        description="Allowed CORS origins"
    )

    # Query limits
    max_query_limit: int = Field(default=10000, description="Maximum query result limit")
    default_query_limit: int = Field(default=500, description="Default query result limit")

    # Security
    max_zip_size: int = Field(
        default=500 * 1024 * 1024,
        description="Maximum uncompressed ZIP size in bytes"
    )
    max_zip_files: int = Field(default=1000, description="Maximum files in ZIP archive")

    # Logging
    log_level: str = Field(default="INFO", description="Logging level")

    class Config:
        env_prefix = "ARGUSCLOUD_"
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = False

    def get_cors_origins(self) -> List[str]:
        """Get CORS origins, handling comma-separated env var."""
        # Check if there's a comma-separated string from env
        cors_env = os.environ.get("ARGUSCLOUD_CORS_ORIGINS", "")
        if cors_env:
            return [o.strip() for o in cors_env.split(",") if o.strip()]
        return self.cors_origins


@lru_cache()
def get_settings() -> Settings:
    """Get cached settings instance.

    Returns:
        Settings instance loaded from environment
    """
    return Settings()


# Convenience alias
settings = get_settings()
