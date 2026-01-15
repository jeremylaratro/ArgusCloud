"""Tests for arguscloud.repositories module.

This module tests the Neo4j repository implementation including
node/edge queries, profile management, and database operations.
"""

from __future__ import annotations

import pytest
from unittest.mock import MagicMock, patch
from typing import Any, Dict, List

from arguscloud.repositories.base import GraphRepository, NodeFilter, ProfileData
from arguscloud.repositories.neo4j_repository import Neo4jGraphRepository


class TestNodeFilter:
    """Tests for NodeFilter dataclass."""

    def test_node_filter_defaults(self):
        """Test NodeFilter with default values."""
        filters = NodeFilter()

        assert filters.provider is None
        assert filters.node_type is None
        assert filters.limit == 500
        assert filters.profile is None

    def test_node_filter_custom_values(self):
        """Test NodeFilter with custom values."""
        filters = NodeFilter(
            provider="aws",
            node_type="Role",
            limit=100,
            profile="test-profile"
        )

        assert filters.provider == "aws"
        assert filters.node_type == "Role"
        assert filters.limit == 100
        assert filters.profile == "test-profile"


class TestProfileData:
    """Tests for ProfileData dataclass."""

    def test_profile_data_defaults(self):
        """Test ProfileData with default values."""
        profile = ProfileData(name="test")

        assert profile.name == "test"
        assert profile.nodes == []
        assert profile.edges == []
        assert profile.meta == {}

    def test_profile_data_with_data(self, sample_nodes, sample_edges):
        """Test ProfileData with actual data."""
        profile = ProfileData(
            name="test-profile",
            nodes=sample_nodes,
            edges=sample_edges,
            meta={"node_count": 3}
        )

        assert profile.name == "test-profile"
        assert len(profile.nodes) == 3
        assert len(profile.edges) == 2
        assert profile.meta["node_count"] == 3


class TestNeo4jGraphRepository:
    """Tests for Neo4jGraphRepository implementation."""

    @pytest.fixture
    def repository(self, mock_neo4j_driver: MagicMock) -> Neo4jGraphRepository:
        """Create repository with mock driver."""
        return Neo4jGraphRepository(mock_neo4j_driver)

    @pytest.fixture
    def mock_session(self, mock_neo4j_driver: MagicMock) -> MagicMock:
        """Get mock session from driver."""
        return mock_neo4j_driver.session.return_value.__enter__.return_value

    # ========================================================================
    # get_nodes() tests
    # ========================================================================

    def test_get_nodes_returns_node_list(
        self,
        repository: Neo4jGraphRepository,
        mock_session: MagicMock
    ):
        """Test get_nodes returns formatted node list."""
        # Setup mock records
        mock_record = MagicMock()
        mock_record.__getitem__ = lambda self, key: {
            "id": "arn:aws:iam::123456789012:role/TestRole",
            "type": "Role",
            "provider": "aws",
            "props": {"RoleName": "TestRole"}
        }.get(key)

        mock_session.run.return_value = [mock_record]

        # Execute
        filters = NodeFilter(limit=100)
        nodes = repository.get_nodes(filters)

        # Assert
        assert len(nodes) == 1
        assert nodes[0]["id"] == "arn:aws:iam::123456789012:role/TestRole"
        assert nodes[0]["type"] == "Role"
        assert nodes[0]["provider"] == "aws"
        assert nodes[0]["properties"]["RoleName"] == "TestRole"

    def test_get_nodes_with_provider_filter(
        self,
        repository: Neo4jGraphRepository,
        mock_session: MagicMock
    ):
        """Test get_nodes applies provider filter."""
        mock_session.run.return_value = []

        filters = NodeFilter(provider="aws", limit=100)
        repository.get_nodes(filters)

        # Check that query contains provider filter
        call_args = mock_session.run.call_args
        query = call_args[0][0]
        assert "n.provider = $provider" in query

    def test_get_nodes_with_type_filter(
        self,
        repository: Neo4jGraphRepository,
        mock_session: MagicMock
    ):
        """Test get_nodes applies node type filter."""
        mock_session.run.return_value = []

        filters = NodeFilter(node_type="Role", limit=100)
        repository.get_nodes(filters)

        call_args = mock_session.run.call_args
        query = call_args[0][0]
        assert "n.type = $type" in query

    def test_get_nodes_with_profile_filter(
        self,
        repository: Neo4jGraphRepository,
        mock_session: MagicMock
    ):
        """Test get_nodes applies profile filter."""
        mock_session.run.return_value = []

        filters = NodeFilter(profile="test-profile", limit=100)
        repository.get_nodes(filters)

        call_args = mock_session.run.call_args
        query = call_args[0][0]
        assert "n.profile = $profile" in query

    def test_get_nodes_empty_result(
        self,
        repository: Neo4jGraphRepository,
        mock_session: MagicMock
    ):
        """Test get_nodes returns empty list when no results."""
        mock_session.run.return_value = []

        nodes = repository.get_nodes(NodeFilter())

        assert nodes == []

    # ========================================================================
    # get_edges() tests
    # ========================================================================

    def test_get_edges_returns_edge_list(
        self,
        repository: Neo4jGraphRepository,
        mock_session: MagicMock
    ):
        """Test get_edges returns formatted edge list."""
        mock_record = MagicMock()
        mock_record.__getitem__ = lambda self, key: {
            "src": "arn:aws:iam::123456789012:user/alice",
            "dst": "arn:aws:iam::123456789012:role/TestRole",
            "type": "CanAssume",
            "props": {}
        }.get(key)

        mock_session.run.return_value = [mock_record]

        edges = repository.get_edges(NodeFilter())

        assert len(edges) == 1
        assert edges[0]["src"] == "arn:aws:iam::123456789012:user/alice"
        assert edges[0]["dst"] == "arn:aws:iam::123456789012:role/TestRole"
        assert edges[0]["type"] == "CanAssume"

    def test_get_edges_with_provider_filter(
        self,
        repository: Neo4jGraphRepository,
        mock_session: MagicMock
    ):
        """Test get_edges applies provider filter."""
        mock_session.run.return_value = []

        filters = NodeFilter(provider="aws")
        repository.get_edges(filters)

        call_args = mock_session.run.call_args
        query = call_args[0][0]
        assert "provider" in query.lower()

    # ========================================================================
    # get_attack_paths() tests
    # ========================================================================

    def test_get_attack_paths_returns_paths(
        self,
        repository: Neo4jGraphRepository,
        mock_session: MagicMock
    ):
        """Test get_attack_paths returns attack path edges."""
        mock_record = MagicMock()
        mock_record.__getitem__ = lambda self, key: {
            "src": "arn:aws:iam::123456789012:user/alice",
            "dst": "arn:aws:iam::123456789012:role/AdminRole",
            "type": "AttackPath",
            "props": {"severity": "critical", "rule": "AdminAccess"}
        }.get(key)

        mock_session.run.return_value = [mock_record]

        paths = repository.get_attack_paths()

        assert len(paths) == 1
        assert paths[0]["type"] == "AttackPath"
        assert paths[0]["properties"]["severity"] == "critical"

    def test_get_attack_paths_with_severity_filter(
        self,
        repository: Neo4jGraphRepository,
        mock_session: MagicMock
    ):
        """Test get_attack_paths filters by severity."""
        mock_session.run.return_value = []

        repository.get_attack_paths(severity="critical")

        call_args = mock_session.run.call_args
        query = call_args[0][0]
        assert "r.severity = $severity" in query

    def test_get_attack_paths_orders_by_severity(
        self,
        repository: Neo4jGraphRepository,
        mock_session: MagicMock
    ):
        """Test get_attack_paths orders results by severity."""
        mock_session.run.return_value = []

        repository.get_attack_paths()

        call_args = mock_session.run.call_args
        query = call_args[0][0]
        assert "ORDER BY" in query
        assert "critical" in query.lower()

    # ========================================================================
    # Profile management tests
    # ========================================================================

    def test_list_profiles_returns_profiles(
        self,
        repository: Neo4jGraphRepository,
        mock_session: MagicMock
    ):
        """Test list_profiles returns profile metadata."""
        # Mock profile query
        profile_record = MagicMock()
        profile_record.__getitem__ = lambda self, key: {
            "name": "test-profile",
            "node_count": 10,
            "created_at": "2024-01-01T00:00:00Z",
            "updated_at": "2024-01-02T00:00:00Z"
        }.get(key)

        # Mock edge count query
        edge_record = MagicMock()
        edge_record.__getitem__ = lambda self, key: {"edge_count": 5}.get(key)

        mock_session.run.side_effect = [
            [profile_record],  # First call for profiles
            MagicMock(single=lambda: edge_record)  # Second call for edge count
        ]

        profiles = repository.list_profiles()

        assert len(profiles) == 1
        assert profiles[0]["name"] == "test-profile"
        assert profiles[0]["node_count"] == 10

    def test_get_profile_returns_profile_data(
        self,
        repository: Neo4jGraphRepository,
        mock_session: MagicMock
    ):
        """Test get_profile returns ProfileData for existing profile."""
        # Mock existence check
        count_record = MagicMock()
        count_record.__getitem__ = lambda self, key: {"count": 1}.get(key)

        # Mock node query
        node_record = MagicMock()
        node_record.__getitem__ = lambda self, key: {
            "id": "arn:aws:iam::123456789012:role/TestRole",
            "type": "Role",
            "provider": "aws",
            "props": {"RoleName": "TestRole"}
        }.get(key)

        # Mock edge query
        edge_record = MagicMock()
        edge_record.__getitem__ = lambda self, key: {
            "src": "arn:aws:iam::123456789012:user/alice",
            "dst": "arn:aws:iam::123456789012:role/TestRole",
            "type": "CanAssume",
            "props": {}
        }.get(key)

        mock_session.run.side_effect = [
            MagicMock(single=lambda: count_record),  # Check exists
            [node_record],  # Get nodes
            [edge_record],  # Get edges
        ]

        profile = repository.get_profile("test-profile")

        assert profile is not None
        assert profile.name == "test-profile"
        assert len(profile.nodes) == 1
        assert len(profile.edges) == 1

    def test_get_profile_returns_none_for_missing(
        self,
        repository: Neo4jGraphRepository,
        mock_session: MagicMock
    ):
        """Test get_profile returns None for non-existent profile."""
        count_record = MagicMock()
        count_record.__getitem__ = lambda self, key: {"count": 0}.get(key)

        mock_session.run.return_value = MagicMock(single=lambda: count_record)

        profile = repository.get_profile("nonexistent")

        assert profile is None

    def test_save_profile_creates_new_profile(
        self,
        repository: Neo4jGraphRepository,
        mock_session: MagicMock,
        sample_nodes,
        sample_edges
    ):
        """Test save_profile creates a new profile."""
        # Mock existence check - profile doesn't exist
        count_record = MagicMock()
        count_record.__getitem__ = lambda self, key: {"count": 0}.get(key)

        mock_session.run.return_value = MagicMock(single=lambda: count_record)

        result = repository.save_profile(
            "new-profile",
            sample_nodes,
            sample_edges,
            mode="create"
        )

        assert result["success"] is True
        assert result["name"] == "new-profile"
        assert result["node_count"] == len(sample_nodes)
        assert result["edge_count"] == len(sample_edges)

    def test_save_profile_raises_for_existing_in_create_mode(
        self,
        repository: Neo4jGraphRepository,
        mock_session: MagicMock,
        sample_nodes,
        sample_edges
    ):
        """Test save_profile raises error when profile exists in create mode."""
        count_record = MagicMock()
        count_record.__getitem__ = lambda self, key: {"count": 1}.get(key)

        mock_session.run.return_value = MagicMock(single=lambda: count_record)

        with pytest.raises(ValueError, match="already exists"):
            repository.save_profile(
                "existing-profile",
                sample_nodes,
                sample_edges,
                mode="create"
            )

    def test_delete_profile_removes_profile(
        self,
        repository: Neo4jGraphRepository,
        mock_session: MagicMock
    ):
        """Test delete_profile removes existing profile."""
        count_record = MagicMock()
        count_record.__getitem__ = lambda self, key: {"count": 1}.get(key)

        mock_session.run.return_value = MagicMock(single=lambda: count_record)

        result = repository.delete_profile("test-profile")

        assert result is True
        # Verify delete query was called
        assert mock_session.run.call_count >= 2

    def test_delete_profile_returns_false_for_missing(
        self,
        repository: Neo4jGraphRepository,
        mock_session: MagicMock
    ):
        """Test delete_profile returns False for non-existent profile."""
        count_record = MagicMock()
        count_record.__getitem__ = lambda self, key: {"count": 0}.get(key)

        mock_session.run.return_value = MagicMock(single=lambda: count_record)

        result = repository.delete_profile("nonexistent")

        assert result is False

    # ========================================================================
    # Health and utility tests
    # ========================================================================

    def test_health_check_returns_true_when_healthy(
        self,
        repository: Neo4jGraphRepository,
        mock_session: MagicMock
    ):
        """Test health_check returns True when database is accessible."""
        mock_session.run.return_value = MagicMock()

        result = repository.health_check()

        assert result is True

    def test_health_check_returns_false_on_error(
        self,
        repository: Neo4jGraphRepository,
        mock_session: MagicMock
    ):
        """Test health_check returns False when database fails."""
        mock_session.run.side_effect = Exception("Connection failed")

        result = repository.health_check()

        assert result is False

    def test_get_stats_returns_counts(
        self,
        repository: Neo4jGraphRepository,
        mock_session: MagicMock
    ):
        """Test get_stats returns node, edge, and profile counts."""
        def single_result(value):
            result = MagicMock()
            result.__getitem__ = lambda self, key: {"count": value}.get(key)
            return MagicMock(single=lambda: result)

        mock_session.run.side_effect = [
            single_result(100),  # Nodes
            single_result(50),   # Edges
            single_result(5),    # Profiles
        ]

        stats = repository.get_stats()

        assert stats["node_count"] == 100
        assert stats["edge_count"] == 50
        assert stats["profile_count"] == 5
