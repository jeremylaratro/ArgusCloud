"""Neo4j implementation of the GraphRepository interface.

This module provides the concrete implementation for Neo4j database
operations, encapsulating all Cypher queries and Neo4j-specific logic.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

from neo4j import Driver

from arguscloud.repositories.base import GraphRepository, NodeFilter, ProfileData

logger = logging.getLogger(__name__)


class Neo4jGraphRepository(GraphRepository):
    """Neo4j implementation of GraphRepository.

    This class encapsulates all Neo4j-specific database operations,
    providing a clean interface for the API layer.

    Attributes:
        driver: Neo4j driver instance
    """

    def __init__(self, driver: Driver):
        """Initialize the repository with a Neo4j driver.

        Args:
            driver: Configured Neo4j driver instance
        """
        self.driver = driver

    def get_nodes(self, filters: NodeFilter) -> List[Dict[str, Any]]:
        """Get nodes matching the given filters."""
        query = "MATCH (n) "
        params: Dict[str, Any] = {}
        conditions = []

        if filters.provider:
            conditions.append("n.provider = $provider")
            params["provider"] = filters.provider

        if filters.node_type:
            conditions.append("n.type = $type")
            params["type"] = filters.node_type

        if filters.profile:
            conditions.append("n.profile = $profile")
            params["profile"] = filters.profile

        if conditions:
            query += "WHERE " + " AND ".join(conditions) + " "

        query += f"""
        RETURN n.id AS id, n.type AS type,
               n.provider AS provider, properties(n) AS props
        LIMIT {filters.limit}
        """

        with self.driver.session() as session:
            result = session.run(query, params)
            return [
                {
                    "id": record["id"],
                    "type": record["type"],
                    "provider": record["provider"] or "unknown",
                    "properties": record["props"],
                }
                for record in result
            ]

    def get_edges(self, filters: NodeFilter) -> List[Dict[str, Any]]:
        """Get edges matching the given filters."""
        query = "MATCH (a)-[r]->(b) "
        params: Dict[str, Any] = {}
        conditions = []

        if filters.provider:
            conditions.append("(a.provider = $provider OR b.provider = $provider)")
            params["provider"] = filters.provider

        if filters.profile:
            conditions.append("(a.profile = $profile OR b.profile = $profile)")
            params["profile"] = filters.profile

        if conditions:
            query += "WHERE " + " AND ".join(conditions) + " "

        query += f"""
        RETURN a.id AS src, b.id AS dst, type(r) AS type, properties(r) AS props
        LIMIT {filters.limit}
        """

        with self.driver.session() as session:
            result = session.run(query, params)
            return [
                {
                    "src": record["src"],
                    "dst": record["dst"],
                    "type": record["type"],
                    "properties": record["props"],
                }
                for record in result
            ]

    def get_attack_paths(
        self,
        severity: Optional[str] = None,
        provider: Optional[str] = None,
        limit: int = 500,
    ) -> List[Dict[str, Any]]:
        """Get attack path edges."""
        query = "MATCH (a)-[r:AttackPath]->(b) "
        params: Dict[str, Any] = {}
        conditions = []

        if severity:
            conditions.append("r.severity = $severity")
            params["severity"] = severity

        if provider:
            conditions.append("(a.provider = $provider OR b.provider = $provider)")
            params["provider"] = provider

        if conditions:
            query += "WHERE " + " AND ".join(conditions) + " "

        # Order by severity for consistent results
        query += """
        RETURN a.id AS src, b.id AS dst, 'AttackPath' AS type, properties(r) AS props
        ORDER BY
            CASE r.severity
                WHEN 'critical' THEN 1
                WHEN 'high' THEN 2
                WHEN 'medium' THEN 3
                WHEN 'low' THEN 4
                ELSE 5
            END
        """
        query += f"LIMIT {limit}"

        with self.driver.session() as session:
            result = session.run(query, params)
            return [
                {
                    "src": record["src"],
                    "dst": record["dst"],
                    "type": record["type"],
                    "properties": record["props"],
                }
                for record in result
            ]

    def get_findings_summary(
        self,
        provider: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Get aggregated findings summary."""
        params: Dict[str, Any] = {}
        where_clause = ""

        if provider:
            where_clause = "WHERE a.provider = $provider OR b.provider = $provider"
            params["provider"] = provider

        # Get counts by severity
        severity_query = f"""
        MATCH (a)-[r:AttackPath]->(b)
        {where_clause}
        RETURN r.severity AS severity, count(*) AS count
        """

        # Get counts by rule
        rule_query = f"""
        MATCH (a)-[r:AttackPath]->(b)
        {where_clause}
        RETURN r.rule AS rule, count(*) AS count
        """

        # Get top critical/high findings
        top_findings_query = f"""
        MATCH (a)-[r:AttackPath]->(b)
        {where_clause}
        WHERE r.severity IN ['critical', 'high']
        RETURN a.id AS src, b.id AS dst, properties(r) AS props
        ORDER BY
            CASE r.severity
                WHEN 'critical' THEN 1
                WHEN 'high' THEN 2
            END
        LIMIT 20
        """

        with self.driver.session() as session:
            # Severity counts
            severity_result = session.run(severity_query, params)
            by_severity = {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
            }
            total = 0
            for record in severity_result:
                sev = record["severity"] or "unknown"
                count = record["count"]
                if sev in by_severity:
                    by_severity[sev] = count
                total += count

            # Rule counts
            rule_result = session.run(rule_query, params)
            by_rule = {}
            for record in rule_result:
                rule = record["rule"] or "unknown"
                by_rule[rule] = record["count"]

            # Top findings
            findings_result = session.run(top_findings_query, params)
            critical_findings = []
            high_findings = []
            for record in findings_result:
                finding = {
                    "src": record["src"],
                    "dst": record["dst"],
                    "properties": record["props"],
                }
                severity = record["props"].get("severity", "")
                if severity == "critical":
                    critical_findings.append(finding)
                elif severity == "high":
                    high_findings.append(finding)

            return {
                "total": total,
                "by_severity": by_severity,
                "by_rule": by_rule,
                "critical_findings": critical_findings[:10],
                "high_findings": high_findings[:10],
            }

    def get_resources_summary(
        self,
        provider: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Get aggregated resources summary."""
        params: Dict[str, Any] = {}
        where_clause = ""

        if provider:
            where_clause = "WHERE n.provider = $provider"
            params["provider"] = provider

        query = f"""
        MATCH (n)
        {where_clause}
        RETURN n.type AS type, count(*) AS count
        """

        with self.driver.session() as session:
            result = session.run(query, params)
            by_type = {}
            total = 0
            for record in result:
                node_type = record["type"] or "unknown"
                count = record["count"]
                by_type[node_type] = count
                total += count

            return {
                "total": total,
                "by_type": by_type,
            }

    def execute_read_query(
        self,
        cypher: str,
        params: Optional[Dict[str, Any]] = None,
    ) -> List[Dict[str, Any]]:
        """Execute a validated read-only Cypher query."""
        with self.driver.session() as session:
            result = session.run(cypher, params or {})
            return [record.data() for record in result]

    def list_profiles(self) -> List[Dict[str, Any]]:
        """List all profiles with metadata."""
        query = """
        MATCH (n)
        WHERE n.profile IS NOT NULL
        WITH n.profile AS name,
             count(*) AS node_count,
             min(n.created_at) AS created_at,
             max(n.updated_at) AS updated_at
        RETURN name, node_count, created_at, updated_at
        ORDER BY name
        """

        with self.driver.session() as session:
            result = session.run(query)
            profiles = []
            for record in result:
                profiles.append({
                    "name": record["name"],
                    "node_count": record["node_count"],
                    "created_at": record["created_at"],
                    "updated_at": record["updated_at"],
                })

            # Get edge counts separately
            for profile in profiles:
                edge_query = """
                MATCH (a)-[r]->(b)
                WHERE a.profile = $name OR b.profile = $name
                RETURN count(r) AS edge_count
                """
                edge_result = session.run(edge_query, {"name": profile["name"]})
                edge_record = edge_result.single()
                profile["edge_count"] = edge_record["edge_count"] if edge_record else 0

            return profiles

    def get_profile(self, name: str) -> Optional[ProfileData]:
        """Get a specific profile by name."""
        # Check if profile exists
        check_query = """
        MATCH (n {profile: $name})
        RETURN count(n) AS count
        """

        with self.driver.session() as session:
            check_result = session.run(check_query, {"name": name})
            check_record = check_result.single()
            if not check_record or check_record["count"] == 0:
                return None

            # Get nodes
            nodes_query = """
            MATCH (n {profile: $name})
            RETURN n.id AS id, n.type AS type, n.provider AS provider, properties(n) AS props
            """
            nodes_result = session.run(nodes_query, {"name": name})
            nodes = [
                {
                    "id": record["id"],
                    "type": record["type"],
                    "provider": record["provider"] or "unknown",
                    "properties": record["props"],
                }
                for record in nodes_result
            ]

            # Get edges
            edges_query = """
            MATCH (a {profile: $name})-[r]->(b)
            RETURN a.id AS src, b.id AS dst, type(r) AS type, properties(r) AS props
            """
            edges_result = session.run(edges_query, {"name": name})
            edges = [
                {
                    "src": record["src"],
                    "dst": record["dst"],
                    "type": record["type"],
                    "properties": record["props"],
                }
                for record in edges_result
            ]

            return ProfileData(
                name=name,
                nodes=nodes,
                edges=edges,
                meta={
                    "node_count": len(nodes),
                    "edge_count": len(edges),
                },
            )

    def save_profile(
        self,
        name: str,
        nodes: List[Dict[str, Any]],
        edges: List[Dict[str, Any]],
        mode: str = "create",
    ) -> Dict[str, Any]:
        """Save profile data to the database."""
        now = datetime.utcnow().isoformat()

        with self.driver.session() as session:
            # Check if profile exists
            check_query = """
            MATCH (n {profile: $name})
            RETURN count(n) AS count
            """
            check_result = session.run(check_query, {"name": name})
            check_record = check_result.single()
            exists = check_record and check_record["count"] > 0

            if mode == "create" and exists:
                raise ValueError(f"Profile '{name}' already exists")

            if mode == "overwrite" and exists:
                # Delete existing profile data
                delete_query = """
                MATCH (n {profile: $name})
                DETACH DELETE n
                """
                session.run(delete_query, {"name": name})

            # Insert nodes
            node_count = 0
            for node in nodes:
                node_query = """
                MERGE (n {id: $id})
                SET n += $props,
                    n.profile = $profile,
                    n.type = $type,
                    n.provider = $provider,
                    n.created_at = COALESCE(n.created_at, $now),
                    n.updated_at = $now
                """
                props = node.get("properties", {})
                session.run(
                    node_query,
                    {
                        "id": node["id"],
                        "props": props,
                        "profile": name,
                        "type": node.get("type", "unknown"),
                        "provider": node.get("provider", "unknown"),
                        "now": now,
                    },
                )
                node_count += 1

            # Insert edges
            edge_count = 0
            for edge in edges:
                edge_type = edge.get("type", "RELATES_TO")
                edge_query = f"""
                MATCH (a {{id: $src}}), (b {{id: $dst}})
                MERGE (a)-[r:{edge_type}]->(b)
                SET r += $props
                """
                session.run(
                    edge_query,
                    {
                        "src": edge["src"],
                        "dst": edge["dst"],
                        "props": edge.get("properties", {}),
                    },
                )
                edge_count += 1

            return {
                "success": True,
                "name": name,
                "node_count": node_count,
                "edge_count": edge_count,
                "mode": mode,
            }

    def delete_profile(self, name: str) -> bool:
        """Delete a profile by name."""
        with self.driver.session() as session:
            # Check if exists
            check_query = """
            MATCH (n {profile: $name})
            RETURN count(n) AS count
            """
            check_result = session.run(check_query, {"name": name})
            check_record = check_result.single()
            if not check_record or check_record["count"] == 0:
                return False

            # Delete
            delete_query = """
            MATCH (n {profile: $name})
            DETACH DELETE n
            """
            session.run(delete_query, {"name": name})
            return True

    def rename_profile(self, old_name: str, new_name: str) -> bool:
        """Rename a profile."""
        with self.driver.session() as session:
            # Check old exists
            check_old = session.run(
                "MATCH (n {profile: $name}) RETURN count(n) AS count",
                {"name": old_name},
            )
            old_record = check_old.single()
            if not old_record or old_record["count"] == 0:
                raise ValueError(f"Profile '{old_name}' not found")

            # Check new doesn't exist
            check_new = session.run(
                "MATCH (n {profile: $name}) RETURN count(n) AS count",
                {"name": new_name},
            )
            new_record = check_new.single()
            if new_record and new_record["count"] > 0:
                raise ValueError(f"Profile '{new_name}' already exists")

            # Rename
            rename_query = """
            MATCH (n {profile: $old_name})
            SET n.profile = $new_name
            """
            session.run(rename_query, {"old_name": old_name, "new_name": new_name})
            return True

    def health_check(self) -> bool:
        """Check database connectivity."""
        try:
            with self.driver.session() as session:
                session.run("RETURN 1")
            return True
        except Exception as e:
            logger.warning(f"Health check failed: {type(e).__name__}")
            return False

    def get_stats(self) -> Dict[str, Any]:
        """Get database statistics."""
        with self.driver.session() as session:
            node_result = session.run("MATCH (n) RETURN count(n) AS count")
            node_count = node_result.single()["count"]

            edge_result = session.run("MATCH ()-[r]->() RETURN count(r) AS count")
            edge_count = edge_result.single()["count"]

            profile_result = session.run(
                "MATCH (n) WHERE n.profile IS NOT NULL "
                "RETURN count(DISTINCT n.profile) AS count"
            )
            profile_count = profile_result.single()["count"]

            return {
                "node_count": node_count,
                "edge_count": edge_count,
                "profile_count": profile_count,
            }
