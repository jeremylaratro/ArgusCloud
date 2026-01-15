"""Pytest configuration and shared fixtures for ArgusCloud tests.

This module provides common fixtures used across multiple test modules,
including mock Neo4j drivers, AWS sessions, and shared test data.
"""

from __future__ import annotations

import os
import pytest
from typing import Any, Dict, Generator, List
from unittest.mock import MagicMock, patch


# ============================================================================
# Custom Pytest Markers
# ============================================================================

def pytest_configure(config):
    """Register custom markers for test categorization."""
    config.addinivalue_line(
        "markers", "integration: marks tests requiring external services (Neo4j, AWS)"
    )
    config.addinivalue_line(
        "markers", "security: marks security-related tests"
    )
    config.addinivalue_line(
        "markers", "slow: marks tests that take a long time to run"
    )
    config.addinivalue_line(
        "markers", "aws: marks tests requiring AWS credentials or moto mocks"
    )


# ============================================================================
# Neo4j Mock Fixtures
# ============================================================================

@pytest.fixture
def mock_neo4j_driver() -> MagicMock:
    """Create a mock Neo4j driver with session context manager.

    Returns:
        Mock driver with properly configured session().run() chain
    """
    driver = MagicMock()
    session = MagicMock()

    # Configure context manager for 'with driver.session() as session:'
    driver.session.return_value.__enter__ = MagicMock(return_value=session)
    driver.session.return_value.__exit__ = MagicMock(return_value=None)

    return driver


@pytest.fixture
def mock_neo4j_session(mock_neo4j_driver: MagicMock) -> MagicMock:
    """Get the mock session from a mock driver.

    Args:
        mock_neo4j_driver: Mock Neo4j driver

    Returns:
        The session mock from the driver
    """
    return mock_neo4j_driver.session.return_value.__enter__.return_value


def create_neo4j_record(**kwargs) -> MagicMock:
    """Helper to create a mock Neo4j record.

    Args:
        **kwargs: Key-value pairs to return from record[key]

    Returns:
        Mock record that supports both __getitem__ and .data()
    """
    record = MagicMock()
    record.__getitem__ = lambda self, key: kwargs.get(key)
    record.data.return_value = kwargs
    return record


# ============================================================================
# AWS Mock Fixtures
# ============================================================================

@pytest.fixture
def mock_boto3_session() -> MagicMock:
    """Create a mock boto3 Session.

    Returns:
        Mock boto3.Session with client() method
    """
    session = MagicMock()
    session.client.return_value = MagicMock()
    session.region_name = "us-east-1"
    return session


@pytest.fixture
def valid_aws_credentials() -> Dict[str, str]:
    """Provide valid-format AWS credentials for testing.

    These are syntactically valid but not real credentials.

    Returns:
        Dict with access_key, secret_key, and optional fields
    """
    return {
        "access_key": "AKIAIOSFODNN7EXAMPLE",
        "secret_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "session_token": None,
        "region": "us-east-1",
    }


@pytest.fixture
def valid_sts_credentials() -> Dict[str, str]:
    """Provide valid-format STS temporary credentials.

    Returns:
        Dict with temporary credential fields
    """
    return {
        "access_key": "ASIAIOSFODNN7EXAMPLE",
        "secret_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "session_token": "FwoGZXIvYXdzEBYaDFake+Session+Token+Example==",
        "region": "us-west-2",
    }


@pytest.fixture
def mock_sts_client() -> MagicMock:
    """Create a mock STS client with GetCallerIdentity response.

    Returns:
        Mock STS client
    """
    client = MagicMock()
    client.get_caller_identity.return_value = {
        "UserId": "AIDAEXAMPLEUSERID",
        "Account": "123456789012",
        "Arn": "arn:aws:iam::123456789012:user/testuser"
    }
    return client


# ============================================================================
# Flask App Fixtures
# ============================================================================

@pytest.fixture
def app_no_auth(mock_neo4j_driver: MagicMock) -> Generator[Any, None, None]:
    """Create Flask test app with authentication disabled.

    Args:
        mock_neo4j_driver: Mock Neo4j driver

    Yields:
        Configured Flask application
    """
    from arguscloud.api.server import create_app
    from arguscloud.api.auth import AuthConfig

    with patch("arguscloud.api.server.get_driver", return_value=mock_neo4j_driver):
        config = AuthConfig(enabled=False)
        app = create_app(
            "bolt://localhost:7687",
            "neo4j",
            "password",
            auth_config=config
        )
        app.config["TESTING"] = True
        yield app


@pytest.fixture
def client_no_auth(app_no_auth) -> Generator[Any, None, None]:
    """Create test client with authentication disabled.

    Args:
        app_no_auth: Flask app without auth

    Yields:
        Flask test client
    """
    with app_no_auth.test_client() as client:
        yield client


@pytest.fixture
def app_with_auth(mock_neo4j_driver: MagicMock) -> Generator[Any, None, None]:
    """Create Flask test app with authentication enabled.

    Args:
        mock_neo4j_driver: Mock Neo4j driver

    Yields:
        Configured Flask application with API_KEY stored in config
    """
    from arguscloud.api.server import create_app
    from arguscloud.api.auth import AuthConfig, generate_api_key

    api_key, stored_hash = generate_api_key()

    with patch("arguscloud.api.server.get_driver", return_value=mock_neo4j_driver):
        config = AuthConfig(api_keys={"testuser": stored_hash})
        app = create_app(
            "bolt://localhost:7687",
            "neo4j",
            "password",
            auth_config=config
        )
        app.config["TESTING"] = True
        app.config["API_KEY"] = api_key
        yield app


@pytest.fixture
def client_with_auth(app_with_auth) -> Generator[Any, None, None]:
    """Create test client with authentication enabled.

    Args:
        app_with_auth: Flask app with auth

    Yields:
        Flask test client
    """
    with app_with_auth.test_client() as client:
        yield client


@pytest.fixture
def auth_headers(app_with_auth) -> Dict[str, str]:
    """Get authorization headers for authenticated requests.

    Args:
        app_with_auth: Flask app with auth (contains API_KEY)

    Returns:
        Dict with Authorization header
    """
    return {"X-API-Key": app_with_auth.config["API_KEY"]}


# ============================================================================
# Test Data Fixtures
# ============================================================================

@pytest.fixture
def sample_nodes() -> List[Dict[str, Any]]:
    """Provide sample node data for testing.

    Returns:
        List of node dictionaries
    """
    return [
        {
            "id": "arn:aws:iam::123456789012:role/AdminRole",
            "type": "Role",
            "provider": "aws",
            "properties": {
                "RoleName": "AdminRole",
                "Arn": "arn:aws:iam::123456789012:role/AdminRole",
                "CreateDate": "2024-01-01T00:00:00Z",
            }
        },
        {
            "id": "arn:aws:iam::123456789012:user/alice",
            "type": "User",
            "provider": "aws",
            "properties": {
                "UserName": "alice",
                "Arn": "arn:aws:iam::123456789012:user/alice",
                "CreateDate": "2024-01-01T00:00:00Z",
            }
        },
        {
            "id": "arn:aws:s3:::my-bucket",
            "type": "S3Bucket",
            "provider": "aws",
            "properties": {
                "BucketName": "my-bucket",
                "CreationDate": "2024-01-01T00:00:00Z",
            }
        },
    ]


@pytest.fixture
def sample_edges() -> List[Dict[str, Any]]:
    """Provide sample edge data for testing.

    Returns:
        List of edge dictionaries
    """
    return [
        {
            "src": "arn:aws:iam::123456789012:user/alice",
            "dst": "arn:aws:iam::123456789012:role/AdminRole",
            "type": "CanAssume",
            "properties": {}
        },
        {
            "src": "arn:aws:iam::123456789012:user/alice",
            "dst": "arn:aws:iam::123456789012:role/AdminRole",
            "type": "AttackPath",
            "properties": {
                "severity": "high",
                "rule": "PrivilegeEscalation",
                "description": "User can assume admin role"
            }
        },
    ]


@pytest.fixture
def sample_profile_data(sample_nodes: List[Dict], sample_edges: List[Dict]) -> Dict[str, Any]:
    """Provide sample profile data for testing.

    Args:
        sample_nodes: Sample node data
        sample_edges: Sample edge data

    Returns:
        Dict with profile name, nodes, edges, and meta
    """
    return {
        "name": "test-profile",
        "nodes": sample_nodes,
        "edges": sample_edges,
        "meta": {
            "node_count": len(sample_nodes),
            "edge_count": len(sample_edges),
        }
    }


@pytest.fixture
def sample_attack_paths() -> List[Dict[str, Any]]:
    """Provide sample attack path data for testing.

    Returns:
        List of attack path edge dictionaries
    """
    return [
        {
            "src": "arn:aws:iam::123456789012:user/alice",
            "dst": "arn:aws:iam::123456789012:role/AdminRole",
            "type": "AttackPath",
            "properties": {
                "severity": "critical",
                "rule": "AdminAccess",
                "description": "Direct admin access path"
            }
        },
        {
            "src": "arn:aws:iam::123456789012:role/DevRole",
            "dst": "arn:aws:s3:::sensitive-bucket",
            "type": "AttackPath",
            "properties": {
                "severity": "high",
                "rule": "DataExfiltration",
                "description": "Role can access sensitive data"
            }
        },
        {
            "src": "arn:aws:iam::123456789012:user/bob",
            "dst": "arn:aws:lambda::123456789012:function:admin-func",
            "type": "AttackPath",
            "properties": {
                "severity": "medium",
                "rule": "LambdaInvoke",
                "description": "User can invoke privileged function"
            }
        },
    ]


# ============================================================================
# Environment Fixtures
# ============================================================================

@pytest.fixture
def clean_environment():
    """Fixture that cleans ArgusCloud environment variables.

    Removes ARGUSCLOUD_* env vars before test and restores after.
    """
    # Save current env vars
    saved = {k: v for k, v in os.environ.items() if k.startswith("ARGUSCLOUD_")}

    # Clear them
    for key in saved:
        del os.environ[key]

    yield

    # Restore
    os.environ.update(saved)


@pytest.fixture
def mock_settings():
    """Fixture that provides a mock Settings object.

    Yields:
        Mock settings with default values
    """
    settings = MagicMock()
    settings.api_host = "0.0.0.0"
    settings.api_port = 9847
    settings.neo4j_uri = "bolt://localhost:7687"
    settings.neo4j_user = "neo4j"
    settings.neo4j_password = "testpassword"
    settings.jwt_secret = "test-secret-key"
    settings.jwt_expiry = 3600
    settings.auth_enabled = False
    settings.cors_origins = ["http://localhost:8080"]
    settings.max_query_limit = 10000
    settings.default_query_limit = 500
    settings.log_level = "INFO"
    settings.get_cors_origins.return_value = ["http://localhost:8080"]

    return settings
