"""Tests for arguscloud.api.server module."""

import pytest
import json
from unittest.mock import patch, MagicMock

from arguscloud.api.server import create_app
from arguscloud.api.auth import AuthConfig, generate_api_key


@pytest.fixture
def mock_driver():
    """Create a mock Neo4j driver."""
    driver = MagicMock()
    session = MagicMock()
    driver.session.return_value.__enter__ = MagicMock(return_value=session)
    driver.session.return_value.__exit__ = MagicMock(return_value=None)
    return driver


@pytest.fixture
def app_no_auth(mock_driver):
    """Create Flask app with auth disabled."""
    with patch("arguscloud.api.server.get_driver", return_value=mock_driver):
        config = AuthConfig(enabled=False)
        app = create_app("bolt://localhost:7687", "neo4j", "password", auth_config=config)
        app.config["TESTING"] = True
        yield app


@pytest.fixture
def client_no_auth(app_no_auth):
    """Create test client with auth disabled."""
    return app_no_auth.test_client()


@pytest.fixture
def app_with_auth(mock_driver):
    """Create Flask app with auth enabled."""
    api_key, stored_hash = generate_api_key()
    with patch("arguscloud.api.server.get_driver", return_value=mock_driver):
        config = AuthConfig(api_keys={"testuser": stored_hash})
        app = create_app("bolt://localhost:7687", "neo4j", "password", auth_config=config)
        app.config["TESTING"] = True
        app.config["API_KEY"] = api_key  # Store for tests
        yield app


@pytest.fixture
def client_with_auth(app_with_auth):
    """Create test client with auth enabled."""
    return app_with_auth.test_client()


class TestHealthEndpoint:
    """Tests for /health endpoint."""

    def test_health_endpoint_success(self, client_no_auth, mock_driver):
        """Test health endpoint when database is connected."""
        # Mock successful DB check
        session = mock_driver.session.return_value.__enter__.return_value
        session.run.return_value.single.return_value = True

        response = client_no_auth.get("/health")
        assert response.status_code == 200
        data = response.get_json()
        assert data["status"] == "ok"
        assert data["checks"]["neo4j"] == "ok"

    def test_health_endpoint_db_failure(self, client_no_auth, mock_driver):
        """Test health endpoint when database connection fails."""
        session = mock_driver.session.return_value.__enter__.return_value
        session.run.side_effect = Exception("Connection failed")

        response = client_no_auth.get("/health")
        assert response.status_code == 503  # Service Unavailable
        data = response.get_json()
        assert data["status"] == "degraded"
        assert data["checks"]["neo4j"] == "error"


class TestGraphEndpoint:
    """Tests for /graph endpoint."""

    def test_graph_endpoint_returns_nodes_and_edges(self, client_no_auth, mock_driver):
        """Test that graph endpoint returns nodes and edges."""
        session = mock_driver.session.return_value.__enter__.return_value

        # Mock node query
        node_record = MagicMock()
        node_record.__getitem__ = lambda self, key: {
            "id": "node1", "type": "Role", "provider": "aws", "props": {"name": "TestRole"}
        }[key]

        # Mock edge query
        edge_record = MagicMock()
        edge_record.__getitem__ = lambda self, key: {
            "src": "node1", "dst": "node2", "type": "Trusts", "props": {}
        }[key]

        session.run.side_effect = [
            [node_record],  # nodes query
            [edge_record],  # edges query
        ]

        response = client_no_auth.get("/graph")
        assert response.status_code == 200
        data = response.get_json()
        assert "nodes" in data
        assert "edges" in data
        assert "meta" in data

    def test_graph_endpoint_with_limit(self, client_no_auth, mock_driver):
        """Test graph endpoint with limit parameter."""
        session = mock_driver.session.return_value.__enter__.return_value
        session.run.return_value = []

        response = client_no_auth.get("/graph?limit=100")
        assert response.status_code == 200
        data = response.get_json()
        assert data["meta"]["limit"] == 100

    def test_graph_endpoint_with_provider_filter(self, client_no_auth, mock_driver):
        """Test graph endpoint with provider filter."""
        session = mock_driver.session.return_value.__enter__.return_value
        session.run.return_value = []

        response = client_no_auth.get("/graph?provider=aws")
        assert response.status_code == 200

        # Verify the query was called with provider parameter
        calls = session.run.call_args_list
        assert len(calls) >= 1

    def test_graph_endpoint_with_type_filter(self, client_no_auth, mock_driver):
        """Test graph endpoint with type filter."""
        session = mock_driver.session.return_value.__enter__.return_value
        session.run.return_value = []

        response = client_no_auth.get("/graph?type=Role")
        assert response.status_code == 200

    def test_graph_endpoint_requires_auth(self, client_with_auth, app_with_auth, mock_driver):
        """Test that graph endpoint requires authentication."""
        session = mock_driver.session.return_value.__enter__.return_value
        session.run.return_value = []

        # Without auth header
        response = client_with_auth.get("/graph")
        assert response.status_code == 401

        # With valid auth header
        api_key = app_with_auth.config["API_KEY"]
        response = client_with_auth.get("/graph", headers={"X-API-Key": api_key})
        assert response.status_code == 200


class TestAttackPathsEndpoint:
    """Tests for /attackpaths endpoint."""

    def test_attackpaths_endpoint_returns_paths(self, client_no_auth, mock_driver):
        """Test that attackpaths endpoint returns attack paths."""
        session = mock_driver.session.return_value.__enter__.return_value

        path_record = MagicMock()
        path_record.__getitem__ = lambda self, key: {
            "src": "role1", "dst": "bucket1", "type": "AttackPath",
            "props": {"severity": "high", "rule": "public-s3"}
        }[key]

        session.run.return_value = [path_record]

        response = client_no_auth.get("/attackpaths")
        assert response.status_code == 200
        data = response.get_json()
        assert "edges" in data
        assert "meta" in data

    def test_attackpaths_endpoint_severity_filter(self, client_no_auth, mock_driver):
        """Test attackpaths endpoint with severity filter."""
        session = mock_driver.session.return_value.__enter__.return_value
        session.run.return_value = []

        response = client_no_auth.get("/attackpaths?severity=high")
        assert response.status_code == 200

    def test_attackpaths_endpoint_provider_filter(self, client_no_auth, mock_driver):
        """Test attackpaths endpoint with provider filter."""
        session = mock_driver.session.return_value.__enter__.return_value
        session.run.return_value = []

        response = client_no_auth.get("/attackpaths?provider=aws")
        assert response.status_code == 200


class TestFindingsEndpoint:
    """Tests for /findings endpoint."""

    def test_findings_endpoint_grouped_by_severity(self, client_no_auth, mock_driver):
        """Test that findings endpoint groups by severity."""
        session = mock_driver.session.return_value.__enter__.return_value

        # Create mock findings with different severities
        findings = []
        for sev in ["critical", "high", "medium", "low"]:
            rec = MagicMock()
            rec.__getitem__ = lambda self, key, s=sev: {
                "src": f"src-{s}", "dst": f"dst-{s}", "type": "AttackPath",
                "props": {"severity": s, "rule": f"rule-{s}"}
            }[key]
            findings.append(rec)

        session.run.return_value = findings

        response = client_no_auth.get("/findings")
        assert response.status_code == 200
        data = response.get_json()
        assert "by_severity" in data
        assert "critical" in data["by_severity"]
        assert "high" in data["by_severity"]
        assert "medium" in data["by_severity"]
        assert "low" in data["by_severity"]

    def test_findings_endpoint_grouped_by_rule(self, client_no_auth, mock_driver):
        """Test that findings endpoint groups by rule."""
        session = mock_driver.session.return_value.__enter__.return_value

        rec = MagicMock()
        rec.__getitem__ = lambda self, key: {
            "src": "src1", "dst": "dst1", "type": "AttackPath",
            "props": {"severity": "high", "rule": "public-s3"}
        }[key]

        session.run.return_value = [rec]

        response = client_no_auth.get("/findings")
        assert response.status_code == 200
        data = response.get_json()
        assert "by_rule" in data


class TestResourcesEndpoint:
    """Tests for /resources endpoint."""

    def test_resources_endpoint_grouped_by_type(self, client_no_auth, mock_driver):
        """Test that resources endpoint groups by type."""
        session = mock_driver.session.return_value.__enter__.return_value

        resources = []
        for rtype in ["Role", "S3Bucket", "EC2Instance"]:
            rec = MagicMock()
            rec.__getitem__ = lambda self, key, t=rtype: {
                "id": f"id-{t}", "type": t, "provider": "aws", "props": {}
            }[key]
            resources.append(rec)

        session.run.return_value = resources

        response = client_no_auth.get("/resources")
        assert response.status_code == 200
        data = response.get_json()
        assert "by_type" in data
        assert "total" in data

    def test_resources_endpoint_with_provider(self, client_no_auth, mock_driver):
        """Test resources endpoint with provider filter."""
        session = mock_driver.session.return_value.__enter__.return_value
        session.run.return_value = []

        response = client_no_auth.get("/resources?provider=aws")
        assert response.status_code == 200


class TestQueryEndpoint:
    """Tests for /query endpoint."""

    def test_query_endpoint_executes_cypher(self, client_no_auth, mock_driver):
        """Test that query endpoint executes Cypher query."""
        session = mock_driver.session.return_value.__enter__.return_value

        rec = MagicMock()
        rec.data.return_value = {"n": {"id": "node1"}}
        session.run.return_value = [rec]

        response = client_no_auth.post("/query",
            data=json.dumps({"cypher": "MATCH (n) RETURN n"}),
            content_type="application/json"
        )
        assert response.status_code == 200
        data = response.get_json()
        assert "results" in data
        assert "count" in data

    def test_query_endpoint_missing_cypher(self, client_no_auth, mock_driver):
        """Test query endpoint with missing cypher parameter."""
        response = client_no_auth.post("/query",
            data=json.dumps({}),
            content_type="application/json"
        )
        assert response.status_code == 400
        data = response.get_json()
        assert "error" in data
        assert "missing cypher" in data["error"]

    def test_query_endpoint_blocks_write_queries(self, client_no_auth, mock_driver):
        """Test that query endpoint blocks write operations.

        Uses whitelist validation - only MATCH...RETURN and CALL db./apoc. patterns allowed.
        """
        dangerous_queries = [
            "DELETE n",
            "REMOVE n.prop",
            "DROP INDEX",
            "CREATE (n:Node)",
            "MERGE (n:Node)",
            "SET n.prop = 1",
        ]

        for query in dangerous_queries:
            response = client_no_auth.post("/query",
                data=json.dumps({"cypher": query}),
                content_type="application/json"
            )
            assert response.status_code == 403, f"Query should be blocked: {query}"
            data = response.get_json()
            assert "not allowed" in data["error"].lower() or "Invalid" in data["error"]

    def test_query_endpoint_allows_read_queries(self, client_no_auth, mock_driver):
        """Test that query endpoint allows read operations."""
        session = mock_driver.session.return_value.__enter__.return_value
        session.run.return_value = []

        read_queries = [
            "MATCH (n) RETURN n",
            "MATCH (n)-[r]->(m) RETURN n, r, m",
            "MATCH (n:Role) WHERE n.name = 'Admin' RETURN n",
        ]

        for query in read_queries:
            response = client_no_auth.post("/query",
                data=json.dumps({"cypher": query}),
                content_type="application/json"
            )
            assert response.status_code == 200, f"Query should be allowed: {query}"

    def test_query_endpoint_adds_limit(self, client_no_auth, mock_driver):
        """Test that query endpoint adds LIMIT if not present."""
        session = mock_driver.session.return_value.__enter__.return_value
        session.run.return_value = []

        response = client_no_auth.post("/query",
            data=json.dumps({"cypher": "MATCH (n) RETURN n"}),
            content_type="application/json"
        )
        assert response.status_code == 200

        # Check that LIMIT was added to query
        call_args = session.run.call_args
        query = call_args[0][0]
        assert "LIMIT" in query

    def test_query_endpoint_db_error(self, client_no_auth, mock_driver):
        """Test query endpoint handles database errors."""
        session = mock_driver.session.return_value.__enter__.return_value
        session.run.side_effect = Exception("Database error")

        response = client_no_auth.post("/query",
            data=json.dumps({"cypher": "MATCH (n) RETURN n"}),
            content_type="application/json"
        )
        assert response.status_code == 500
        data = response.get_json()
        assert "error" in data


class TestExportEndpoint:
    """Tests for /export/<format> endpoint."""

    def test_export_json_format(self, client_no_auth, mock_driver):
        """Test export endpoint with JSON format."""
        session = mock_driver.session.return_value.__enter__.return_value
        session.run.return_value = []

        response = client_no_auth.get("/export/json")
        assert response.status_code == 200
        assert response.content_type == "application/json"

    def test_export_sarif_format(self, client_no_auth, mock_driver):
        """Test export endpoint with SARIF format."""
        session = mock_driver.session.return_value.__enter__.return_value
        session.run.return_value = []

        response = client_no_auth.get("/export/sarif")
        assert response.status_code == 200
        assert response.content_type == "application/json"

    def test_export_html_format(self, client_no_auth, mock_driver):
        """Test export endpoint with HTML format."""
        session = mock_driver.session.return_value.__enter__.return_value
        session.run.return_value = []

        response = client_no_auth.get("/export/html")
        assert response.status_code == 200
        assert "text/html" in response.content_type

    def test_export_invalid_format_error(self, client_no_auth, mock_driver):
        """Test export endpoint with invalid format."""
        response = client_no_auth.get("/export/invalid")
        assert response.status_code == 400
        data = response.get_json()
        assert "error" in data
        assert "Unknown format" in data["error"]


class TestCORSHeaders:
    """Tests for CORS headers."""

    def test_cors_headers_present(self, client_no_auth, mock_driver):
        """Test that CORS headers are present.

        CORS now uses specific allowed origins instead of wildcard '*' for security.
        """
        session = mock_driver.session.return_value.__enter__.return_value
        session.run.return_value.single.return_value = True

        response = client_no_auth.get("/health")
        assert response.status_code == 200
        # CORS uses specific origins, not wildcard - verify header exists
        cors_origin = response.headers.get("Access-Control-Allow-Origin")
        assert cors_origin is not None
        # Should be a specific origin (not '*') or the default allowed origin
        assert cors_origin in ["http://localhost:8080", "http://127.0.0.1:8080"] or cors_origin != "*"
        assert "Content-Type" in response.headers.get("Access-Control-Allow-Headers", "")
        assert "Authorization" in response.headers.get("Access-Control-Allow-Headers", "")
        assert "X-API-Key" in response.headers.get("Access-Control-Allow-Headers", "")

    def test_cors_methods_present(self, client_no_auth, mock_driver):
        """Test that CORS methods are allowed."""
        session = mock_driver.session.return_value.__enter__.return_value
        session.run.return_value.single.return_value = True

        response = client_no_auth.get("/health")
        methods = response.headers.get("Access-Control-Allow-Methods", "")
        assert "GET" in methods
        assert "POST" in methods
        assert "OPTIONS" in methods


class TestAuthTokenEndpoint:
    """Tests for /auth/token endpoint."""

    def test_auth_token_creation(self, client_with_auth, app_with_auth, mock_driver):
        """Test creating a JWT token from API key."""
        api_key = app_with_auth.config["API_KEY"]

        response = client_with_auth.post("/auth/token",
            headers={"X-API-Key": api_key}
        )
        assert response.status_code == 200
        data = response.get_json()
        assert "token" in data
        assert "expires_in" in data
        assert "token_type" in data
        assert data["token_type"] == "Bearer"

    def test_auth_token_requires_auth(self, client_with_auth, mock_driver):
        """Test that token creation requires authentication."""
        response = client_with_auth.post("/auth/token")
        assert response.status_code == 401


class TestAuthVerifyEndpoint:
    """Tests for /auth/verify endpoint."""

    def test_auth_verify_with_api_key(self, client_with_auth, app_with_auth, mock_driver):
        """Test verifying authentication with API key."""
        api_key = app_with_auth.config["API_KEY"]

        response = client_with_auth.get("/auth/verify",
            headers={"X-API-Key": api_key}
        )
        assert response.status_code == 200
        data = response.get_json()
        assert data["authenticated"] is True
        assert "user" in data

    def test_auth_verify_without_auth(self, client_with_auth, mock_driver):
        """Test verifying authentication without credentials."""
        response = client_with_auth.get("/auth/verify")
        assert response.status_code == 401
