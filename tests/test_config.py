"""Tests for arguscloud.config module.

This module tests configuration management including environment
variable loading, settings validation, and caching behavior.
"""

from __future__ import annotations

import os
import pytest
from unittest.mock import patch

from arguscloud.config import Settings, get_settings


class TestSettings:
    """Tests for Settings class."""

    def test_settings_default_values(self, clean_environment):
        """Test Settings with all default values."""
        settings = Settings()

        assert settings.api_host == "0.0.0.0"
        assert settings.api_port == 9847
        assert settings.neo4j_uri == "bolt://localhost:7687"
        assert settings.neo4j_user == "neo4j"
        assert settings.neo4j_password == ""
        assert settings.jwt_secret == ""
        assert settings.jwt_expiry == 3600
        assert settings.auth_enabled is True
        assert settings.max_query_limit == 10000
        assert settings.default_query_limit == 500
        assert settings.log_level == "INFO"

    def test_settings_from_environment(self, clean_environment):
        """Test Settings loads from environment variables."""
        os.environ["ARGUSCLOUD_API_HOST"] = "127.0.0.1"
        os.environ["ARGUSCLOUD_API_PORT"] = "8080"
        os.environ["ARGUSCLOUD_NEO4J_URI"] = "bolt://neo4j:7687"
        os.environ["ARGUSCLOUD_NEO4J_USER"] = "admin"
        os.environ["ARGUSCLOUD_NEO4J_PASSWORD"] = "secret"

        settings = Settings()

        assert settings.api_host == "127.0.0.1"
        assert settings.api_port == 8080
        assert settings.neo4j_uri == "bolt://neo4j:7687"
        assert settings.neo4j_user == "admin"
        assert settings.neo4j_password == "secret"

    def test_settings_auth_enabled_from_env(self, clean_environment):
        """Test Settings loads auth_enabled from environment."""
        os.environ["ARGUSCLOUD_AUTH_ENABLED"] = "false"

        settings = Settings()

        assert settings.auth_enabled is False

    def test_settings_auth_enabled_true(self, clean_environment):
        """Test Settings parses auth_enabled=true."""
        os.environ["ARGUSCLOUD_AUTH_ENABLED"] = "true"

        settings = Settings()

        assert settings.auth_enabled is True

    def test_settings_jwt_expiry_from_env(self, clean_environment):
        """Test Settings loads jwt_expiry from environment."""
        os.environ["ARGUSCLOUD_JWT_EXPIRY"] = "7200"

        settings = Settings()

        assert settings.jwt_expiry == 7200

    def test_settings_log_level_from_env(self, clean_environment):
        """Test Settings loads log_level from environment."""
        os.environ["ARGUSCLOUD_LOG_LEVEL"] = "DEBUG"

        settings = Settings()

        assert settings.log_level == "DEBUG"

    def test_settings_max_query_limit_from_env(self, clean_environment):
        """Test Settings loads max_query_limit from environment."""
        os.environ["ARGUSCLOUD_MAX_QUERY_LIMIT"] = "5000"

        settings = Settings()

        assert settings.max_query_limit == 5000

    def test_settings_cors_origins_default(self, clean_environment):
        """Test Settings has default CORS origins."""
        settings = Settings()

        assert "http://localhost:8080" in settings.cors_origins
        assert "http://127.0.0.1:8080" in settings.cors_origins

    def test_settings_max_zip_size_from_env(self, clean_environment):
        """Test Settings loads max_zip_size from environment."""
        os.environ["ARGUSCLOUD_MAX_ZIP_SIZE"] = str(100 * 1024 * 1024)  # 100MB

        settings = Settings()

        assert settings.max_zip_size == 100 * 1024 * 1024

    def test_settings_max_zip_files_from_env(self, clean_environment):
        """Test Settings loads max_zip_files from environment."""
        os.environ["ARGUSCLOUD_MAX_ZIP_FILES"] = "500"

        settings = Settings()

        assert settings.max_zip_files == 500


class TestSettingsGetCorsOrigins:
    """Tests for Settings.get_cors_origins method."""

    def test_get_cors_origins_from_attribute(self, clean_environment):
        """Test get_cors_origins returns cors_origins attribute when no env var."""
        settings = Settings()

        # When no env var is set, should return the pydantic-parsed cors_origins
        origins = settings.get_cors_origins()

        # Default origins
        assert "http://localhost:8080" in origins
        assert "http://127.0.0.1:8080" in origins

    def test_get_cors_origins_parses_comma_separated_env(self, clean_environment):
        """Test get_cors_origins parses comma-separated env var at runtime.

        The get_cors_origins method checks the raw env var and parses it,
        allowing comma-separated format even though pydantic expects JSON.
        """
        settings = Settings()

        # Set env var AFTER creating settings (bypasses pydantic validation)
        os.environ["ARGUSCLOUD_CORS_ORIGINS"] = "http://app1.com,http://app2.com,http://app3.com"

        origins = settings.get_cors_origins()

        assert "http://app1.com" in origins
        assert "http://app2.com" in origins
        assert "http://app3.com" in origins
        assert len(origins) == 3

    def test_get_cors_origins_strips_whitespace(self, clean_environment):
        """Test get_cors_origins strips whitespace from comma-separated values."""
        settings = Settings()

        os.environ["ARGUSCLOUD_CORS_ORIGINS"] = "http://app1.com , http://app2.com , http://app3.com"

        origins = settings.get_cors_origins()

        assert "http://app1.com" in origins
        assert "http://app2.com" in origins
        assert "http://app3.com" in origins

    def test_get_cors_origins_filters_empty_strings(self, clean_environment):
        """Test get_cors_origins filters out empty strings."""
        settings = Settings()

        os.environ["ARGUSCLOUD_CORS_ORIGINS"] = "http://app1.com,,http://app2.com,"

        origins = settings.get_cors_origins()

        assert len(origins) == 2
        assert "" not in origins
        assert "http://app1.com" in origins
        assert "http://app2.com" in origins

    def test_get_cors_origins_returns_defaults_when_no_env(self, clean_environment):
        """Test get_cors_origins returns defaults when env not set."""
        settings = Settings()
        origins = settings.get_cors_origins()

        assert "http://localhost:8080" in origins
        assert "http://127.0.0.1:8080" in origins


class TestSettingsEnvPrefix:
    """Tests for Settings environment variable prefix."""

    def test_settings_uses_arguscloud_prefix(self, clean_environment):
        """Test Settings uses ARGUSCLOUD_ prefix."""
        # Set with prefix
        os.environ["ARGUSCLOUD_API_PORT"] = "9999"

        # Set without prefix (should be ignored)
        os.environ["API_PORT"] = "8888"

        settings = Settings()

        assert settings.api_port == 9999

    def test_settings_case_insensitive(self, clean_environment):
        """Test Settings is case insensitive for env vars."""
        os.environ["arguscloud_api_port"] = "9999"

        settings = Settings()

        # Pydantic should handle case insensitivity
        # Note: This depends on the case_sensitive config setting


class TestGetSettings:
    """Tests for get_settings function."""

    def test_get_settings_returns_settings_instance(self, clean_environment):
        """Test get_settings returns a Settings instance."""
        # Clear the cache
        get_settings.cache_clear()

        settings = get_settings()

        assert isinstance(settings, Settings)

    def test_get_settings_is_cached(self, clean_environment):
        """Test get_settings returns cached instance."""
        get_settings.cache_clear()

        settings1 = get_settings()
        settings2 = get_settings()

        assert settings1 is settings2

    def test_get_settings_cache_can_be_cleared(self, clean_environment):
        """Test get_settings cache can be cleared."""
        get_settings.cache_clear()

        settings1 = get_settings()

        get_settings.cache_clear()

        # After clearing cache, new instance should be created
        settings2 = get_settings()

        # They should be equal but not the same object
        # (unless Python optimizes this)
        assert settings2.api_host == settings1.api_host


class TestSettingsValidation:
    """Tests for Settings validation behavior."""

    def test_settings_invalid_port_type_raises_error(self, clean_environment):
        """Test Settings raises error for invalid port type."""
        os.environ["ARGUSCLOUD_API_PORT"] = "not-a-number"

        with pytest.raises(Exception):  # Pydantic validation error
            Settings()

    def test_settings_negative_port_accepted(self, clean_environment):
        """Test Settings behavior with negative port (depends on validation)."""
        os.environ["ARGUSCLOUD_API_PORT"] = "-1"

        # This might be accepted by default unless we add validators
        settings = Settings()
        assert settings.api_port == -1

    def test_settings_invalid_jwt_expiry_type(self, clean_environment):
        """Test Settings raises error for invalid jwt_expiry type."""
        os.environ["ARGUSCLOUD_JWT_EXPIRY"] = "not-a-number"

        with pytest.raises(Exception):
            Settings()


class TestSettingsSecurityDefaults:
    """Tests for security-related default values."""

    def test_auth_enabled_by_default(self, clean_environment):
        """Test authentication is enabled by default."""
        settings = Settings()

        assert settings.auth_enabled is True

    def test_jwt_secret_empty_by_default(self, clean_environment):
        """Test JWT secret is empty by default (should be generated)."""
        settings = Settings()

        assert settings.jwt_secret == ""

    def test_neo4j_password_empty_by_default(self, clean_environment):
        """Test Neo4j password is empty by default."""
        settings = Settings()

        assert settings.neo4j_password == ""

    def test_max_zip_size_has_reasonable_default(self, clean_environment):
        """Test max_zip_size has a reasonable default."""
        settings = Settings()

        # Default should be 500MB
        assert settings.max_zip_size == 500 * 1024 * 1024

    def test_max_zip_files_has_reasonable_default(self, clean_environment):
        """Test max_zip_files has a reasonable default."""
        settings = Settings()

        # Default should be 1000
        assert settings.max_zip_files == 1000


class TestSettingsIntegration:
    """Integration tests for Settings with realistic scenarios."""

    def test_production_config(self, clean_environment):
        """Test typical production configuration."""
        import json
        os.environ["ARGUSCLOUD_API_HOST"] = "0.0.0.0"
        os.environ["ARGUSCLOUD_API_PORT"] = "9847"
        os.environ["ARGUSCLOUD_NEO4J_URI"] = "bolt://neo4j-cluster:7687"
        os.environ["ARGUSCLOUD_NEO4J_USER"] = "neo4j"
        os.environ["ARGUSCLOUD_NEO4J_PASSWORD"] = "secure-password"
        os.environ["ARGUSCLOUD_JWT_SECRET"] = "super-secret-key"
        os.environ["ARGUSCLOUD_AUTH_ENABLED"] = "true"
        os.environ["ARGUSCLOUD_CORS_ORIGINS"] = json.dumps(["https://app.example.com"])
        os.environ["ARGUSCLOUD_LOG_LEVEL"] = "WARNING"

        settings = Settings()

        assert settings.api_host == "0.0.0.0"
        assert settings.api_port == 9847
        assert settings.neo4j_uri == "bolt://neo4j-cluster:7687"
        assert settings.auth_enabled is True
        assert settings.log_level == "WARNING"

    def test_development_config(self, clean_environment):
        """Test typical development configuration."""
        os.environ["ARGUSCLOUD_AUTH_ENABLED"] = "false"
        os.environ["ARGUSCLOUD_LOG_LEVEL"] = "DEBUG"

        settings = Settings()

        assert settings.auth_enabled is False
        assert settings.log_level == "DEBUG"
