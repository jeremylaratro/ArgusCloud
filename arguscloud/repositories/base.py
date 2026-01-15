"""Abstract base classes for ArgusCloud repositories.

This module defines the interfaces for data access, allowing
different database implementations to be swapped without
changing the API layer.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class NodeFilter:
    """Filter criteria for node queries.

    Attributes:
        provider: Filter by cloud provider (e.g., 'aws', 'gcp')
        node_type: Filter by node type (e.g., 'Role', 'S3Bucket')
        limit: Maximum number of results to return
        profile: Filter by profile name
    """

    provider: Optional[str] = None
    node_type: Optional[str] = None
    limit: int = 500
    profile: Optional[str] = None


@dataclass
class ProfileData:
    """Container for profile data.

    Attributes:
        name: Profile name
        nodes: List of node dictionaries
        edges: List of edge dictionaries
        meta: Additional metadata
    """

    name: str
    nodes: List[Dict[str, Any]] = field(default_factory=list)
    edges: List[Dict[str, Any]] = field(default_factory=list)
    meta: Dict[str, Any] = field(default_factory=dict)


class GraphRepository(ABC):
    """Abstract base class for graph data access.

    This interface defines all database operations needed by the
    ArgusCloud API. Implementations can be created for Neo4j,
    in-memory testing, or other graph databases.

    Example:
        >>> repo = Neo4jGraphRepository(driver)
        >>> nodes = repo.get_nodes(NodeFilter(provider='aws', limit=100))
        >>> health = repo.health_check()
    """

    @abstractmethod
    def get_nodes(self, filters: NodeFilter) -> List[Dict[str, Any]]:
        """Get nodes matching the given filters.

        Args:
            filters: Filter criteria for the query

        Returns:
            List of node dictionaries with id, type, provider, properties
        """
        pass

    @abstractmethod
    def get_edges(self, filters: NodeFilter) -> List[Dict[str, Any]]:
        """Get edges matching the given filters.

        Args:
            filters: Filter criteria for the query

        Returns:
            List of edge dictionaries with src, dst, type, properties
        """
        pass

    @abstractmethod
    def get_attack_paths(
        self,
        severity: Optional[str] = None,
        provider: Optional[str] = None,
        limit: int = 500,
    ) -> List[Dict[str, Any]]:
        """Get attack path edges.

        Args:
            severity: Filter by severity level (critical, high, medium, low)
            provider: Filter by cloud provider
            limit: Maximum number of results

        Returns:
            List of attack path edge dictionaries
        """
        pass

    @abstractmethod
    def get_findings_summary(
        self,
        provider: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Get aggregated findings summary.

        Args:
            provider: Filter by cloud provider

        Returns:
            Dictionary with by_severity, by_rule, and top findings
        """
        pass

    @abstractmethod
    def get_resources_summary(
        self,
        provider: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Get aggregated resources summary.

        Args:
            provider: Filter by cloud provider

        Returns:
            Dictionary with total count and by_type breakdown
        """
        pass

    @abstractmethod
    def execute_read_query(
        self,
        cypher: str,
        params: Optional[Dict[str, Any]] = None,
    ) -> List[Dict[str, Any]]:
        """Execute a validated read-only Cypher query.

        Args:
            cypher: The Cypher query to execute
            params: Optional query parameters

        Returns:
            List of result dictionaries

        Raises:
            ValueError: If the query is not allowed
        """
        pass

    # Profile operations

    @abstractmethod
    def list_profiles(self) -> List[Dict[str, Any]]:
        """List all profiles with metadata.

        Returns:
            List of profile summary dictionaries
        """
        pass

    @abstractmethod
    def get_profile(self, name: str) -> Optional[ProfileData]:
        """Get a specific profile by name.

        Args:
            name: Profile name

        Returns:
            ProfileData if found, None otherwise
        """
        pass

    @abstractmethod
    def save_profile(
        self,
        name: str,
        nodes: List[Dict[str, Any]],
        edges: List[Dict[str, Any]],
        mode: str = "create",
    ) -> Dict[str, Any]:
        """Save profile data to the database.

        Args:
            name: Profile name
            nodes: List of node dictionaries
            edges: List of edge dictionaries
            mode: Save mode ('create', 'overwrite', 'merge')

        Returns:
            Dictionary with success status and counts

        Raises:
            ValueError: If profile exists and mode is 'create'
        """
        pass

    @abstractmethod
    def delete_profile(self, name: str) -> bool:
        """Delete a profile by name.

        Args:
            name: Profile name to delete

        Returns:
            True if deleted, False if not found
        """
        pass

    @abstractmethod
    def rename_profile(self, old_name: str, new_name: str) -> bool:
        """Rename a profile.

        Args:
            old_name: Current profile name
            new_name: New profile name

        Returns:
            True if renamed successfully

        Raises:
            ValueError: If old_name not found or new_name exists
        """
        pass

    # Health and utility

    @abstractmethod
    def health_check(self) -> bool:
        """Check database connectivity.

        Returns:
            True if database is accessible, False otherwise
        """
        pass

    @abstractmethod
    def get_stats(self) -> Dict[str, Any]:
        """Get database statistics.

        Returns:
            Dictionary with node_count, edge_count, etc.
        """
        pass
