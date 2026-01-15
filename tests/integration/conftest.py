"""Pytest configuration for integration tests.

This module provides fixtures for integration testing with real
Neo4j database instances using testcontainers.
"""

from __future__ import annotations

import os
import pytest
from typing import Generator, Any

# Check if testcontainers is available
try:
    from testcontainers.neo4j import Neo4jContainer
    HAS_TESTCONTAINERS = True
except ImportError:
    HAS_TESTCONTAINERS = False
    Neo4jContainer = None

from neo4j import GraphDatabase


# Skip all integration tests if testcontainers not available
pytestmark = pytest.mark.skipif(
    not HAS_TESTCONTAINERS,
    reason="testcontainers not installed (pip install testcontainers)"
)


@pytest.fixture(scope="session")
def neo4j_container() -> Generator[Any, None, None]:
    """Start a Neo4j container for the test session.

    This fixture starts a Neo4j container that persists for the
    entire test session, reducing startup overhead.

    Yields:
        Neo4jContainer instance with connection details
    """
    if not HAS_TESTCONTAINERS:
        pytest.skip("testcontainers not available")

    container = Neo4jContainer("neo4j:5.15")
    container.with_env("NEO4J_AUTH", "neo4j/testpassword")

    try:
        container.start()
        yield container
    finally:
        container.stop()


@pytest.fixture(scope="session")
def neo4j_driver(neo4j_container: Any) -> Generator[Any, None, None]:
    """Create a Neo4j driver connected to the test container.

    Args:
        neo4j_container: Running Neo4j container

    Yields:
        Configured Neo4j driver
    """
    uri = neo4j_container.get_connection_url()
    driver = GraphDatabase.driver(
        uri,
        auth=("neo4j", "testpassword")
    )

    try:
        # Wait for database to be ready
        with driver.session() as session:
            session.run("RETURN 1")
        yield driver
    finally:
        driver.close()


@pytest.fixture
def clean_database(neo4j_driver: Any) -> Generator[Any, None, None]:
    """Clean the database before and after each test.

    This ensures test isolation by removing all nodes and
    relationships.

    Args:
        neo4j_driver: Neo4j driver instance

    Yields:
        The neo4j driver (for convenience)
    """
    # Clean before test
    with neo4j_driver.session() as session:
        session.run("MATCH (n) DETACH DELETE n")

    yield neo4j_driver

    # Clean after test
    with neo4j_driver.session() as session:
        session.run("MATCH (n) DETACH DELETE n")


@pytest.fixture
def test_app(neo4j_container: Any) -> Generator[Any, None, None]:
    """Create a Flask test app connected to the test Neo4j container.

    Args:
        neo4j_container: Running Neo4j container

    Yields:
        Flask test client
    """
    from arguscloud.api.server import create_app
    from arguscloud.api.auth import AuthConfig

    uri = neo4j_container.get_connection_url()

    # Create app with auth disabled for testing
    app = create_app(
        uri=uri,
        user="neo4j",
        password="testpassword",
        auth_config=AuthConfig(enabled=False)
    )
    app.config["TESTING"] = True

    with app.test_client() as client:
        yield client


@pytest.fixture
def test_app_with_auth(neo4j_container: Any) -> Generator[Any, None, None]:
    """Create a Flask test app with authentication enabled.

    Args:
        neo4j_container: Running Neo4j container

    Yields:
        Tuple of (Flask test client, API key, key hash)
    """
    from arguscloud.api.server import create_app
    from arguscloud.api.auth import AuthConfig, generate_api_key

    uri = neo4j_container.get_connection_url()

    # Generate test API key
    api_key, key_hash = generate_api_key(prefix="test")

    # Create app with auth enabled
    app = create_app(
        uri=uri,
        user="neo4j",
        password="testpassword",
        auth_config=AuthConfig(
            enabled=True,
            api_keys={key_hash: "integration-test-key"}
        )
    )
    app.config["TESTING"] = True

    with app.test_client() as client:
        yield client, api_key, key_hash


@pytest.fixture
def sample_graph_data(clean_database: Any) -> dict:
    """Insert sample graph data for testing.

    Args:
        clean_database: Neo4j driver with clean database

    Returns:
        Dictionary with inserted node and edge IDs
    """
    driver = clean_database

    with driver.session() as session:
        # Create sample nodes
        session.run("""
            CREATE (r:Resource {
                id: 'arn:aws:iam::123456789012:role/AdminRole',
                type: 'Role',
                provider: 'aws',
                profile: 'test-profile',
                RoleName: 'AdminRole'
            })
        """)

        session.run("""
            CREATE (u:Resource {
                id: 'arn:aws:iam::123456789012:user/alice',
                type: 'User',
                provider: 'aws',
                profile: 'test-profile',
                UserName: 'alice'
            })
        """)

        session.run("""
            CREATE (b:Resource {
                id: 'arn:aws:s3:::my-bucket',
                type: 'S3Bucket',
                provider: 'aws',
                profile: 'test-profile',
                BucketName: 'my-bucket'
            })
        """)

        # Create relationships
        session.run("""
            MATCH (u:Resource {id: 'arn:aws:iam::123456789012:user/alice'})
            MATCH (r:Resource {id: 'arn:aws:iam::123456789012:role/AdminRole'})
            CREATE (u)-[:REL {type: 'CanAssume'}]->(r)
        """)

        session.run("""
            MATCH (u:Resource {id: 'arn:aws:iam::123456789012:user/alice'})
            MATCH (r:Resource {id: 'arn:aws:iam::123456789012:role/AdminRole'})
            CREATE (u)-[:REL {
                type: 'AttackPath',
                severity: 'high',
                rule: 'PrivilegeEscalation',
                description: 'User can assume admin role'
            }]->(r)
        """)

        # Create profile metadata
        session.run("""
            CREATE (p:Profile {
                name: 'test-profile',
                created_at: datetime(),
                updated_at: datetime(),
                node_count: 3,
                edge_count: 2
            })
        """)

    return {
        "nodes": [
            "arn:aws:iam::123456789012:role/AdminRole",
            "arn:aws:iam::123456789012:user/alice",
            "arn:aws:s3:::my-bucket",
        ],
        "edges": 2,
        "profile": "test-profile",
    }
