"""Integration tests for ArgusCloud API.

These tests verify the full API stack with a real Neo4j database
using testcontainers.
"""

from __future__ import annotations

import json
import pytest

# All tests in this module require testcontainers
pytestmark = pytest.mark.integration


class TestHealthEndpointIntegration:
    """Integration tests for the health endpoint."""

    def test_health_with_real_database(self, test_app):
        """Test health check with real Neo4j connection."""
        response = test_app.get("/health")
        assert response.status_code == 200

        data = json.loads(response.data)
        assert data["status"] == "ok"
        assert data["checks"]["neo4j"] == "ok"
        assert "version" in data


class TestGraphEndpointIntegration:
    """Integration tests for the graph endpoint."""

    def test_graph_returns_real_data(self, test_app, sample_graph_data):
        """Test graph endpoint returns data from database."""
        response = test_app.get("/graph")
        assert response.status_code == 200

        data = json.loads(response.data)
        assert "nodes" in data
        assert "edges" in data
        assert len(data["nodes"]) == 3  # Role, User, S3Bucket

    def test_graph_with_provider_filter(self, test_app, sample_graph_data):
        """Test graph endpoint filters by provider."""
        response = test_app.get("/graph?provider=aws")
        assert response.status_code == 200

        data = json.loads(response.data)
        assert len(data["nodes"]) == 3

        # All should be AWS
        for node in data["nodes"]:
            assert node["provider"] == "aws"

    def test_graph_with_type_filter(self, test_app, sample_graph_data):
        """Test graph endpoint filters by node type."""
        response = test_app.get("/graph?type=Role")
        assert response.status_code == 200

        data = json.loads(response.data)
        assert len(data["nodes"]) == 1
        assert data["nodes"][0]["type"] == "Role"

    def test_graph_with_limit(self, test_app, sample_graph_data):
        """Test graph endpoint respects limit parameter."""
        response = test_app.get("/graph?limit=1")
        assert response.status_code == 200

        data = json.loads(response.data)
        assert len(data["nodes"]) <= 1


class TestAttackPathsIntegration:
    """Integration tests for attack paths endpoint."""

    def test_attackpaths_returns_findings(self, test_app, sample_graph_data):
        """Test attack paths endpoint returns findings from database."""
        response = test_app.get("/attackpaths")
        assert response.status_code == 200

        data = json.loads(response.data)
        assert "edges" in data
        assert len(data["edges"]) == 1
        assert data["edges"][0]["properties"]["severity"] == "high"

    def test_attackpaths_severity_filter(self, test_app, sample_graph_data):
        """Test attack paths filters by severity."""
        response = test_app.get("/attackpaths?severity=high")
        assert response.status_code == 200

        data = json.loads(response.data)
        assert len(data["edges"]) == 1

        response = test_app.get("/attackpaths?severity=critical")
        data = json.loads(response.data)
        assert len(data["edges"]) == 0


class TestFindingsIntegration:
    """Integration tests for findings summary endpoint."""

    def test_findings_summary(self, test_app, sample_graph_data):
        """Test findings endpoint aggregates correctly."""
        response = test_app.get("/findings")
        assert response.status_code == 200

        data = json.loads(response.data)
        assert data["total"] == 1
        assert data["by_severity"]["high"] == 1
        assert "PrivilegeEscalation" in data["by_rule"]


class TestResourcesIntegration:
    """Integration tests for resources endpoint."""

    def test_resources_summary(self, test_app, sample_graph_data):
        """Test resources endpoint aggregates correctly."""
        response = test_app.get("/resources")
        assert response.status_code == 200

        data = json.loads(response.data)
        assert data["total"] == 3
        assert data["by_type"]["Role"] == 1
        assert data["by_type"]["User"] == 1
        assert data["by_type"]["S3Bucket"] == 1


class TestQueryEndpointIntegration:
    """Integration tests for custom query endpoint."""

    def test_custom_query_execution(self, test_app, sample_graph_data):
        """Test custom Cypher query execution."""
        response = test_app.post(
            "/query",
            data=json.dumps({
                "cypher": "MATCH (n:Resource) RETURN n.id AS id, n.type AS type",
                "limit": 10
            }),
            content_type="application/json"
        )
        assert response.status_code == 200

        data = json.loads(response.data)
        assert data["count"] == 3

    def test_query_with_parameters(self, test_app, sample_graph_data):
        """Test query with type filter."""
        response = test_app.post(
            "/query",
            data=json.dumps({
                "cypher": "MATCH (n:Resource) WHERE n.type = 'Role' RETURN n.id",
                "limit": 10
            }),
            content_type="application/json"
        )
        assert response.status_code == 200

        data = json.loads(response.data)
        assert data["count"] == 1


class TestProfilesIntegration:
    """Integration tests for profile management."""

    def test_list_profiles(self, test_app, sample_graph_data):
        """Test listing profiles from database."""
        response = test_app.get("/profiles")
        assert response.status_code == 200

        data = json.loads(response.data)
        assert "profiles" in data
        # sample_graph_data creates a profile
        assert len(data["profiles"]) >= 1

    def test_create_and_get_profile(self, test_app, clean_database):
        """Test creating and retrieving a profile."""
        # Create profile
        create_response = test_app.post(
            "/profiles",
            data=json.dumps({
                "name": "integration-test-profile",
                "nodes": [
                    {
                        "id": "test-node-1",
                        "type": "TestNode",
                        "provider": "test",
                        "properties": {"name": "Test Node 1"}
                    }
                ],
                "edges": [],
                "mode": "create"
            }),
            content_type="application/json"
        )
        assert create_response.status_code == 200

        create_data = json.loads(create_response.data)
        assert create_data["success"] is True
        assert create_data["node_count"] == 1

        # Get profile
        get_response = test_app.get("/profiles/integration-test-profile")
        assert get_response.status_code == 200

        get_data = json.loads(get_response.data)
        assert get_data["name"] == "integration-test-profile"
        assert len(get_data["nodes"]) == 1

    def test_profile_overwrite_mode(self, test_app, clean_database):
        """Test profile overwrite mode."""
        # Create initial profile
        test_app.post(
            "/profiles",
            data=json.dumps({
                "name": "overwrite-test",
                "nodes": [{"id": "node-1", "type": "Type1", "provider": "test"}],
                "edges": [],
                "mode": "create"
            }),
            content_type="application/json"
        )

        # Overwrite with new data
        response = test_app.post(
            "/profiles",
            data=json.dumps({
                "name": "overwrite-test",
                "nodes": [
                    {"id": "node-2", "type": "Type2", "provider": "test"},
                    {"id": "node-3", "type": "Type3", "provider": "test"}
                ],
                "edges": [],
                "mode": "overwrite"
            }),
            content_type="application/json"
        )
        assert response.status_code == 200

        # Verify overwrite worked
        get_response = test_app.get("/profiles/overwrite-test")
        get_data = json.loads(get_response.data)
        assert len(get_data["nodes"]) == 2

    def test_delete_profile(self, test_app, sample_graph_data):
        """Test deleting a profile."""
        # Create a profile to delete
        test_app.post(
            "/profiles",
            data=json.dumps({
                "name": "to-delete",
                "nodes": [{"id": "temp", "type": "Temp", "provider": "test"}],
                "edges": [],
                "mode": "create"
            }),
            content_type="application/json"
        )

        # Delete it
        response = test_app.delete("/profiles/to-delete")
        assert response.status_code == 200

        data = json.loads(response.data)
        assert data["success"] is True

        # Verify it's gone (will return empty nodes)
        get_response = test_app.get("/profiles/to-delete")
        get_data = json.loads(get_response.data)
        assert len(get_data["nodes"]) == 0

    def test_rename_profile(self, test_app, clean_database):
        """Test renaming a profile."""
        # Create profile
        test_app.post(
            "/profiles",
            data=json.dumps({
                "name": "original-name",
                "nodes": [{"id": "node", "type": "Type", "provider": "test"}],
                "edges": [],
                "mode": "create"
            }),
            content_type="application/json"
        )

        # Rename it
        response = test_app.post(
            "/profiles/original-name/rename",
            data=json.dumps({"new_name": "new-name"}),
            content_type="application/json"
        )
        assert response.status_code == 200

        data = json.loads(response.data)
        assert data["success"] is True
        assert data["new_name"] == "new-name"


class TestExportIntegration:
    """Integration tests for export endpoint."""

    def test_export_json(self, test_app, sample_graph_data):
        """Test JSON export with real data."""
        response = test_app.get("/export/json")
        assert response.status_code == 200
        assert response.content_type == "application/json"

        data = json.loads(response.data)
        assert "findings" in data or "nodes" in data

    def test_export_sarif(self, test_app, sample_graph_data):
        """Test SARIF export with real data."""
        response = test_app.get("/export/sarif")
        assert response.status_code == 200
        assert response.content_type == "application/json"

        data = json.loads(response.data)
        assert "$schema" in data
        assert "runs" in data

    def test_export_html(self, test_app, sample_graph_data):
        """Test HTML export with real data."""
        response = test_app.get("/export/html")
        assert response.status_code == 200
        assert response.content_type == "text/html"
        assert b"<!DOCTYPE html>" in response.data or b"<html" in response.data


class TestAuthenticationIntegration:
    """Integration tests for authentication."""

    def test_authenticated_endpoint(self, test_app_with_auth):
        """Test accessing protected endpoint with API key."""
        client, api_key, _ = test_app_with_auth

        # Without auth should fail
        response = client.get("/graph")
        assert response.status_code == 401

        # With API key should succeed
        response = client.get(
            "/graph",
            headers={"X-API-Key": api_key}
        )
        assert response.status_code == 200

    def test_jwt_token_flow(self, test_app_with_auth):
        """Test JWT token creation and usage."""
        client, api_key, _ = test_app_with_auth

        # Get a token
        response = client.post(
            "/auth/token",
            headers={"X-API-Key": api_key}
        )
        assert response.status_code == 200

        data = json.loads(response.data)
        token = data["token"]

        # Use token to access protected endpoint
        response = client.get(
            "/graph",
            headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 200
