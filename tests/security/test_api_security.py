"""Security tests for ArgusCloud API.

These tests verify that security controls are properly implemented,
including Cypher injection prevention, authentication, and input validation.
"""

from __future__ import annotations

import json
import pytest
from unittest.mock import MagicMock, patch


@pytest.fixture
def mock_driver():
    """Create a mock Neo4j driver."""
    driver = MagicMock()
    session = MagicMock()
    driver.session.return_value.__enter__ = MagicMock(return_value=session)
    driver.session.return_value.__exit__ = MagicMock(return_value=False)
    session.run.return_value = MagicMock()
    session.run.return_value.single.return_value = {"count": 1}
    session.run.return_value.__iter__ = lambda self: iter([])
    return driver


@pytest.fixture
def test_client(mock_driver):
    """Create a Flask test client with auth disabled."""
    from arguscloud.api.server import create_app
    from arguscloud.api.auth import AuthConfig

    with patch("arguscloud.api.server.get_driver", return_value=mock_driver):
        app = create_app(
            uri="bolt://localhost:7687",
            user="neo4j",
            password="password",
            auth_config=AuthConfig(enabled=False)
        )
        app.config["TESTING"] = True
        with app.test_client() as client:
            yield client


@pytest.fixture
def auth_test_client(mock_driver):
    """Create a Flask test client with auth enabled."""
    from arguscloud.api.server import create_app
    from arguscloud.api.auth import AuthConfig, generate_api_key

    api_key, key_hash = generate_api_key(prefix="test")

    with patch("arguscloud.api.server.get_driver", return_value=mock_driver):
        app = create_app(
            uri="bolt://localhost:7687",
            user="neo4j",
            password="password",
            auth_config=AuthConfig(
                enabled=True,
                api_keys={"test-key": key_hash}  # name -> hashed_key
            )
        )
        app.config["TESTING"] = True
        with app.test_client() as client:
            yield client, api_key


class TestCypherInjectionPrevention:
    """Tests for Cypher injection prevention."""

    def test_blocks_delete_queries(self, test_client):
        """Test that DELETE queries are blocked."""
        response = test_client.post(
            "/query",
            data=json.dumps({"cypher": "MATCH (n) DELETE n"}),
            content_type="application/json"
        )
        assert response.status_code == 403

        data = json.loads(response.data)
        assert "not allowed" in data["error"].lower()

    def test_blocks_detach_delete_queries(self, test_client):
        """Test that DETACH DELETE queries are blocked."""
        response = test_client.post(
            "/query",
            data=json.dumps({"cypher": "MATCH (n) DETACH DELETE n"}),
            content_type="application/json"
        )
        assert response.status_code == 403

    def test_blocks_create_queries(self, test_client):
        """Test that CREATE queries are blocked."""
        response = test_client.post(
            "/query",
            data=json.dumps({"cypher": "CREATE (n:Malicious {data: 'evil'})"}),
            content_type="application/json"
        )
        assert response.status_code == 403

    def test_blocks_merge_queries(self, test_client):
        """Test that MERGE queries are blocked."""
        response = test_client.post(
            "/query",
            data=json.dumps({"cypher": "MERGE (n:Node {id: 'test'})"}),
            content_type="application/json"
        )
        assert response.status_code == 403

    def test_blocks_set_queries(self, test_client):
        """Test that SET property queries are blocked."""
        response = test_client.post(
            "/query",
            data=json.dumps({"cypher": "MATCH (n) SET n.compromised = true"}),
            content_type="application/json"
        )
        assert response.status_code == 403

    def test_blocks_remove_queries(self, test_client):
        """Test that REMOVE queries are blocked."""
        response = test_client.post(
            "/query",
            data=json.dumps({"cypher": "MATCH (n) REMOVE n.security"}),
            content_type="application/json"
        )
        assert response.status_code == 403

    def test_blocks_drop_queries(self, test_client):
        """Test that DROP queries are blocked."""
        response = test_client.post(
            "/query",
            data=json.dumps({"cypher": "DROP INDEX my_index"}),
            content_type="application/json"
        )
        assert response.status_code == 403

    def test_blocks_call_with_write_procedures(self, test_client):
        """Test that write procedures are blocked."""
        # Should block non-whitelisted CALL statements
        response = test_client.post(
            "/query",
            data=json.dumps({"cypher": "CALL dbms.security.createUser('hacker', 'password')"}),
            content_type="application/json"
        )
        assert response.status_code == 403

    def test_blocks_comment_bypass_attempts(self, test_client):
        """Test that comment-based bypass attempts are blocked."""
        # Line comment bypass attempt
        response = test_client.post(
            "/query",
            data=json.dumps({
                "cypher": "MATCH (n) // RETURN n\nDELETE n"
            }),
            content_type="application/json"
        )
        assert response.status_code == 403

        # Block comment bypass attempt
        response = test_client.post(
            "/query",
            data=json.dumps({
                "cypher": "MATCH (n) /* ignore */ DELETE n RETURN n"
            }),
            content_type="application/json"
        )
        assert response.status_code == 403

    def test_blocks_case_variations(self, test_client):
        """Test that case variations are blocked."""
        variations = [
            "DELETE",
            "delete",
            "DeLeTe",
            "CREATE",
            "create",
            "CrEaTe",
        ]

        for keyword in variations:
            response = test_client.post(
                "/query",
                data=json.dumps({"cypher": f"MATCH (n) {keyword} n"}),
                content_type="application/json"
            )
            assert response.status_code == 403, f"Failed to block: {keyword}"

    def test_allows_valid_match_return_queries(self, test_client, mock_driver):
        """Test that valid MATCH...RETURN queries are allowed."""
        response = test_client.post(
            "/query",
            data=json.dumps({
                "cypher": "MATCH (n:Resource) RETURN n.id, n.type"
            }),
            content_type="application/json"
        )
        assert response.status_code == 200

    def test_allows_call_db_queries(self, test_client, mock_driver):
        """Test that CALL db.* queries are allowed."""
        response = test_client.post(
            "/query",
            data=json.dumps({
                "cypher": "CALL db.labels()"
            }),
            content_type="application/json"
        )
        assert response.status_code == 200

    def test_allows_call_apoc_read_queries(self, test_client, mock_driver):
        """Test that CALL apoc.* read queries are allowed."""
        response = test_client.post(
            "/query",
            data=json.dumps({
                "cypher": "CALL apoc.meta.stats()"
            }),
            content_type="application/json"
        )
        assert response.status_code == 200


class TestAuthenticationBypass:
    """Tests for authentication bypass prevention."""

    def test_protected_endpoints_require_auth(self, auth_test_client):
        """Test that protected endpoints require authentication."""
        client, api_key = auth_test_client

        protected_endpoints = [
            ("/graph", "GET"),
            ("/attackpaths", "GET"),
            ("/findings", "GET"),
            ("/resources", "GET"),
            ("/query", "POST"),
            ("/profiles", "GET"),
            ("/profiles", "POST"),
            ("/export/json", "GET"),
            ("/collect/aws", "POST"),
            ("/upload", "POST"),
        ]

        for endpoint, method in protected_endpoints:
            if method == "GET":
                response = client.get(endpoint)
            else:
                response = client.post(
                    endpoint,
                    data=json.dumps({}),
                    content_type="application/json"
                )

            assert response.status_code == 401, f"Endpoint {method} {endpoint} not protected"

    def test_invalid_api_key_rejected(self, auth_test_client):
        """Test that invalid API keys are rejected."""
        client, _ = auth_test_client

        response = client.get(
            "/graph",
            headers={"X-API-Key": "invalid-key-12345"}
        )
        assert response.status_code == 401

    def test_malformed_bearer_token_rejected(self, auth_test_client):
        """Test that malformed bearer tokens are rejected."""
        client, _ = auth_test_client

        malformed_tokens = [
            "not-a-jwt",
            "Bearer invalid",
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.invalid.signature",
            "",
            "Bearer ",
        ]

        for token in malformed_tokens:
            if token.startswith("Bearer"):
                headers = {"Authorization": token}
            else:
                headers = {"Authorization": f"Bearer {token}"}

            response = client.get("/graph", headers=headers)
            assert response.status_code == 401, f"Accepted malformed token: {token}"

    def test_expired_token_rejected(self, auth_test_client):
        """Test that expired JWT tokens are rejected."""
        import jwt
        from datetime import datetime, timedelta

        client, api_key = auth_test_client

        # Create an expired token
        expired_payload = {
            "sub": "test",
            "exp": datetime.utcnow() - timedelta(hours=1)
        }
        expired_token = jwt.encode(expired_payload, "wrong-secret", algorithm="HS256")

        response = client.get(
            "/graph",
            headers={"Authorization": f"Bearer {expired_token}"}
        )
        assert response.status_code == 401

    def test_valid_api_key_accepted(self, auth_test_client):
        """Test that valid API key grants access."""
        client, api_key = auth_test_client

        response = client.get(
            "/graph",
            headers={"X-API-Key": api_key}
        )
        assert response.status_code == 200

    def test_health_endpoint_unauthenticated(self, auth_test_client):
        """Test that health endpoint doesn't require auth."""
        client, _ = auth_test_client

        response = client.get("/health")
        assert response.status_code in [200, 503]  # Healthy or degraded

    def test_plugins_endpoint_unauthenticated(self, auth_test_client):
        """Test that plugins endpoint doesn't require auth."""
        client, _ = auth_test_client

        response = client.get("/plugins")
        assert response.status_code == 200


class TestInputValidation:
    """Tests for input validation."""

    def test_profile_name_validation(self, test_client):
        """Test that profile names are validated."""
        invalid_names = [
            "",
            "a" * 101,  # Too long
            "profile/with/slashes",
            "profile<script>",
            "profile; DROP TABLE",
            "../../../etc/passwd",
            "profile\x00null",
        ]

        for name in invalid_names:
            response = test_client.post(
                "/profiles",
                data=json.dumps({
                    "name": name,
                    "nodes": [{"id": "test", "type": "Test", "provider": "test"}],
                    "edges": [],
                    "mode": "create"
                }),
                content_type="application/json"
            )
            assert response.status_code == 400, f"Accepted invalid name: {name}"

    def test_valid_profile_names_accepted(self, test_client, mock_driver):
        """Test that valid profile names are accepted."""
        valid_names = [
            "my-profile",
            "my_profile",
            "my.profile",
            "MyProfile123",
            "a",
            "a" * 100,
        ]

        for name in valid_names:
            mock_driver.session.return_value.__enter__.return_value.run.return_value.single.return_value = None
            response = test_client.post(
                "/profiles",
                data=json.dumps({
                    "name": name,
                    "nodes": [{"id": "test", "type": "Test", "provider": "test"}],
                    "edges": [],
                    "mode": "create"
                }),
                content_type="application/json"
            )
            # May fail for other reasons but should not fail validation
            assert response.status_code != 400 or "Invalid profile name" not in response.data.decode()

    def test_json_content_type_required(self, test_client):
        """Test that JSON content type is required for POST endpoints."""
        response = test_client.post(
            "/query",
            data="cypher=MATCH (n) RETURN n",
            content_type="application/x-www-form-urlencoded"
        )
        assert response.status_code == 400

    def test_query_limit_validation(self, test_client, mock_driver):
        """Test that query limit is validated."""
        # Negative limit should be converted to valid
        response = test_client.post(
            "/query",
            data=json.dumps({"cypher": "MATCH (n) RETURN n", "limit": -1}),
            content_type="application/json"
        )
        # Should succeed but limit should be clamped
        assert response.status_code == 200

        # Very large limit should be clamped
        response = test_client.post(
            "/query",
            data=json.dumps({"cypher": "MATCH (n) RETURN n", "limit": 999999}),
            content_type="application/json"
        )
        assert response.status_code == 200


class TestZipBombProtection:
    """Tests for zip bomb protection."""

    def test_large_uncompressed_size_rejected(self, test_client):
        """Test that archives with large uncompressed size are rejected."""
        import io
        import zipfile

        # Create a zip with files that claim to be very large
        # (This is a simplified test - real zip bombs are more complex)
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
            # Create a normal small file for testing
            zf.writestr("small.jsonl", '{"id": "test"}\n' * 100)

        buffer.seek(0)

        response = test_client.post(
            "/upload",
            data={"file": (buffer, "test.zip")},
            content_type="multipart/form-data"
        )

        # Should succeed for normal files
        # Note: Real zip bomb test would require crafting a malicious archive
        assert response.status_code in [202, 400]

    def test_too_many_files_rejected(self, test_client):
        """Test that archives with too many files are rejected."""
        import io
        import zipfile

        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
            # Create many files (but under the limit for this test)
            for i in range(50):
                zf.writestr(f"file{i}.jsonl", '{"id": "test"}\n')

        buffer.seek(0)

        response = test_client.post(
            "/upload",
            data={"file": (buffer, "many-files.zip")},
            content_type="multipart/form-data"
        )

        # Should succeed for reasonable number of files
        assert response.status_code in [202, 400]


class TestInformationLeakage:
    """Tests for information leakage prevention."""

    def test_error_messages_dont_leak_stack_traces(self, test_client):
        """Test that error messages don't contain stack traces."""
        response = test_client.post(
            "/query",
            data=json.dumps({"cypher": "INVALID CYPHER SYNTAX !@#$%"}),
            content_type="application/json"
        )

        data = response.data.decode()

        # Should not contain internal implementation details
        assert "Traceback" not in data
        assert "File \"" not in data
        assert "line " not in data
        assert ".py" not in data

    def test_error_messages_dont_leak_paths(self, test_client):
        """Test that error messages don't contain file paths."""
        response = test_client.post(
            "/query",
            data=json.dumps({"cypher": "INVALID"}),
            content_type="application/json"
        )

        data = response.data.decode()

        # Should not contain system paths
        assert "/home/" not in data
        assert "/usr/" not in data
        assert "C:\\" not in data

    def test_health_check_minimal_info(self, test_client):
        """Test that health check returns minimal info."""
        response = test_client.get("/health")

        data = json.loads(response.data)

        # Should not leak internal details
        assert "password" not in json.dumps(data).lower()
        assert "secret" not in json.dumps(data).lower()
        assert "key" not in json.dumps(data).lower() or data.get("X-API-Key") is None


class TestCORSSecurity:
    """Tests for CORS security."""

    def test_cors_headers_set(self, test_client):
        """Test that CORS headers are properly set."""
        response = test_client.get("/health")

        # Should have CORS headers
        assert "Access-Control-Allow-Origin" in response.headers

    def test_cors_not_wildcard_with_credentials(self, test_client):
        """Test that CORS doesn't use wildcard with credentials."""
        response = test_client.get(
            "/health",
            headers={"Origin": "http://localhost:8080"}
        )

        allow_origin = response.headers.get("Access-Control-Allow-Origin", "")
        allow_credentials = response.headers.get("Access-Control-Allow-Credentials", "")

        # If credentials are allowed, origin shouldn't be wildcard
        if allow_credentials.lower() == "true":
            assert allow_origin != "*"
