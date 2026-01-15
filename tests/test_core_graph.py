"""Tests for arguscloud.core.graph module."""

import pytest
from arguscloud.core.graph import (
    Node,
    Edge,
    AttackPath,
    GraphData,
    Severity,
    CloudProvider,
)


class TestSeverity:
    """Tests for Severity enum."""

    def test_severity_values(self):
        """Verify severity enum has expected values."""
        assert Severity.CRITICAL.value == "critical"
        assert Severity.HIGH.value == "high"
        assert Severity.MEDIUM.value == "medium"
        assert Severity.LOW.value == "low"
        assert Severity.INFO.value == "info"

    def test_severity_is_string_enum(self):
        """Severity should be usable as string."""
        assert str(Severity.HIGH) == "Severity.HIGH"
        assert Severity.HIGH == "high"


class TestCloudProvider:
    """Tests for CloudProvider enum."""

    def test_cloud_provider_values(self):
        """Verify cloud provider enum has expected values."""
        assert CloudProvider.AWS.value == "aws"
        assert CloudProvider.GCP.value == "gcp"
        assert CloudProvider.AZURE.value == "azure"


class TestNode:
    """Tests for Node dataclass."""

    def test_node_creation_minimal(self):
        """Test creating a node with minimal required fields."""
        node = Node(id="test-id", type="TestType")
        assert node.id == "test-id"
        assert node.type == "TestType"
        assert node.properties == {}
        assert node.provider == CloudProvider.AWS
        assert node.tags == {}

    def test_node_creation_full(self):
        """Test creating a node with all fields."""
        node = Node(
            id="arn:aws:s3:::bucket",
            type="S3Bucket",
            properties={"name": "bucket", "encrypted": True},
            provider=CloudProvider.AWS,
            tags={"env": "prod"},
        )
        assert node.id == "arn:aws:s3:::bucket"
        assert node.type == "S3Bucket"
        assert node.properties["name"] == "bucket"
        assert node.properties["encrypted"] is True
        assert node.provider == CloudProvider.AWS
        assert node.tags["env"] == "prod"

    def test_node_to_dict(self):
        """Test node serialization to dictionary."""
        node = Node(
            id="test-id",
            type="TestType",
            properties={"key": "value"},
            provider=CloudProvider.GCP,
            tags={"tag1": "val1"},
        )
        d = node.to_dict()
        assert d["id"] == "test-id"
        assert d["type"] == "TestType"
        assert d["properties"] == {"key": "value"}
        assert d["provider"] == "gcp"
        assert d["tags"] == {"tag1": "val1"}

    def test_node_from_dict(self):
        """Test node deserialization from dictionary."""
        data = {
            "id": "node-1",
            "type": "Role",
            "properties": {"is_admin": True},
            "provider": "aws",
            "tags": {"team": "security"},
        }
        node = Node.from_dict(data)
        assert node.id == "node-1"
        assert node.type == "Role"
        assert node.properties["is_admin"] is True
        assert node.provider == CloudProvider.AWS
        assert node.tags["team"] == "security"

    def test_node_from_dict_minimal(self):
        """Test node deserialization with minimal fields."""
        data = {"id": "minimal", "type": "Basic"}
        node = Node.from_dict(data)
        assert node.id == "minimal"
        assert node.type == "Basic"
        assert node.properties == {}
        assert node.provider == CloudProvider.AWS

    def test_node_from_dict_with_provider_enum(self):
        """Test node deserialization when provider is already enum."""
        data = {
            "id": "test",
            "type": "Type",
            "provider": CloudProvider.AZURE,
        }
        node = Node.from_dict(data)
        assert node.provider == CloudProvider.AZURE


class TestEdge:
    """Tests for Edge dataclass."""

    def test_edge_creation_minimal(self):
        """Test creating an edge with minimal required fields."""
        edge = Edge(src="node-1", dst="node-2", type="Connects")
        assert edge.src == "node-1"
        assert edge.dst == "node-2"
        assert edge.type == "Connects"
        assert edge.properties == {}
        assert edge.provider == CloudProvider.AWS

    def test_edge_creation_full(self):
        """Test creating an edge with all fields."""
        edge = Edge(
            src="role-arn",
            dst="user-arn",
            type="Trusts",
            properties={"source": "trust-policy"},
            provider=CloudProvider.AWS,
        )
        assert edge.src == "role-arn"
        assert edge.dst == "user-arn"
        assert edge.type == "Trusts"
        assert edge.properties["source"] == "trust-policy"
        assert edge.provider == CloudProvider.AWS

    def test_edge_to_dict(self):
        """Test edge serialization to dictionary."""
        edge = Edge(
            src="src",
            dst="dst",
            type="EdgeType",
            properties={"weight": 1},
            provider=CloudProvider.GCP,
        )
        d = edge.to_dict()
        assert d["src"] == "src"
        assert d["dst"] == "dst"
        assert d["type"] == "EdgeType"
        assert d["properties"]["weight"] == 1
        assert d["provider"] == "gcp"

    def test_edge_from_dict(self):
        """Test edge deserialization from dictionary."""
        data = {
            "src": "a",
            "dst": "b",
            "type": "Link",
            "properties": {"label": "connects"},
            "provider": "azure",
        }
        edge = Edge.from_dict(data)
        assert edge.src == "a"
        assert edge.dst == "b"
        assert edge.type == "Link"
        assert edge.properties["label"] == "connects"
        assert edge.provider == CloudProvider.AZURE

    def test_edge_from_dict_minimal(self):
        """Test edge deserialization with minimal fields."""
        data = {"src": "s", "dst": "d", "type": "T"}
        edge = Edge.from_dict(data)
        assert edge.src == "s"
        assert edge.dst == "d"
        assert edge.properties == {}


class TestAttackPath:
    """Tests for AttackPath dataclass."""

    def test_attack_path_creation(self):
        """Test creating an attack path finding."""
        path = AttackPath(
            src="resource-1",
            dst="internet",
            rule_id="public-s3",
            severity=Severity.HIGH,
            description="S3 bucket is public",
            remediation="Block public access",
        )
        assert path.src == "resource-1"
        assert path.dst == "internet"
        assert path.type == "AttackPath"
        assert path.rule_id == "public-s3"
        assert path.severity == Severity.HIGH
        assert path.description == "S3 bucket is public"
        assert path.remediation == "Block public access"

    def test_attack_path_post_init_sets_properties(self):
        """Attack path should populate properties from attributes."""
        path = AttackPath(
            src="src",
            dst="dst",
            rule_id="test-rule",
            severity=Severity.MEDIUM,
            description="Test finding",
            remediation="Fix it",
        )
        assert path.properties["rule"] == "test-rule"
        assert path.properties["severity"] == "medium"
        assert path.properties["description"] == "Test finding"
        assert path.properties["remediation"] == "Fix it"

    def test_attack_path_without_remediation(self):
        """Attack path without remediation should not have it in properties."""
        path = AttackPath(
            src="src",
            dst="dst",
            rule_id="test-rule",
            severity=Severity.LOW,
            description="Test",
        )
        assert "remediation" not in path.properties or path.properties.get("remediation") is None

    def test_attack_path_default_values(self):
        """Test attack path with default values."""
        path = AttackPath(src="s", dst="d")
        assert path.type == "AttackPath"
        assert path.rule_id == ""
        assert path.severity == Severity.INFO
        assert path.description == ""
        assert path.remediation is None

    def test_attack_path_type_always_set_to_attackpath(self):
        """Test that type is always set to AttackPath regardless of input."""
        path = AttackPath(src="s", dst="d", type="SomeOtherType")
        assert path.type == "AttackPath"


class TestGraphData:
    """Tests for GraphData container."""

    def test_graph_data_creation_empty(self):
        """Test creating empty graph data."""
        graph = GraphData()
        assert graph.nodes == []
        assert graph.edges == []

    def test_graph_data_add_node(self):
        """Test adding nodes to graph."""
        graph = GraphData()
        node = Node(id="n1", type="Type1")
        graph.add_node(node)
        assert len(graph.nodes) == 1
        assert graph.nodes[0].id == "n1"

    def test_graph_data_add_edge(self):
        """Test adding edges to graph."""
        graph = GraphData()
        edge = Edge(src="a", dst="b", type="Connects")
        graph.add_edge(edge)
        assert len(graph.edges) == 1
        assert graph.edges[0].src == "a"

    def test_graph_data_merge(self):
        """Test merging two graphs."""
        graph1 = GraphData(
            nodes=[Node(id="n1", type="T1")],
            edges=[Edge(src="a", dst="b", type="E1")],
        )
        graph2 = GraphData(
            nodes=[Node(id="n2", type="T2")],
            edges=[Edge(src="c", dst="d", type="E2")],
        )
        graph1.merge(graph2)
        assert len(graph1.nodes) == 2
        assert len(graph1.edges) == 2
        node_ids = [n.id for n in graph1.nodes]
        assert "n1" in node_ids
        assert "n2" in node_ids

    def test_graph_data_deduplicate_nodes(self):
        """Test deduplication of nodes by ID."""
        graph = GraphData(
            nodes=[
                Node(id="dup", type="Type1", properties={"v": 1}),
                Node(id="dup", type="Type1", properties={"v": 2}),
                Node(id="unique", type="Type2"),
            ]
        )
        graph.deduplicate()
        assert len(graph.nodes) == 2
        node_ids = [n.id for n in graph.nodes]
        assert "dup" in node_ids
        assert "unique" in node_ids

    def test_graph_data_deduplicate_edges(self):
        """Test deduplication of edges by (src, dst, type)."""
        graph = GraphData(
            edges=[
                Edge(src="a", dst="b", type="E1"),
                Edge(src="a", dst="b", type="E1", properties={"dup": True}),
                Edge(src="a", dst="b", type="E2"),
            ]
        )
        graph.deduplicate()
        assert len(graph.edges) == 2

    def test_graph_data_to_dict(self):
        """Test serialization of graph to dictionary."""
        graph = GraphData(
            nodes=[Node(id="n1", type="T1")],
            edges=[Edge(src="a", dst="b", type="E1")],
        )
        d = graph.to_dict()
        assert "nodes" in d
        assert "edges" in d
        assert len(d["nodes"]) == 1
        assert len(d["edges"]) == 1
        assert d["nodes"][0]["id"] == "n1"

    def test_graph_data_from_dict(self):
        """Test deserialization of graph from dictionary."""
        data = {
            "nodes": [{"id": "n1", "type": "T1", "provider": "aws"}],
            "edges": [{"src": "a", "dst": "b", "type": "E1", "provider": "gcp"}],
        }
        graph = GraphData.from_dict(data)
        assert len(graph.nodes) == 1
        assert len(graph.edges) == 1
        assert graph.nodes[0].id == "n1"
        assert graph.edges[0].provider == CloudProvider.GCP

    def test_graph_data_from_dict_empty(self):
        """Test deserialization of empty graph."""
        graph = GraphData.from_dict({})
        assert graph.nodes == []
        assert graph.edges == []

    def test_graph_data_large_graph_handling(self):
        """Test handling of large graphs."""
        graph = GraphData()
        # Add 1000 nodes
        for i in range(1000):
            graph.add_node(Node(id=f"node-{i}", type="TestType"))
        # Add 5000 edges
        for i in range(5000):
            graph.add_edge(Edge(src=f"node-{i % 1000}", dst=f"node-{(i + 1) % 1000}", type="Connects"))

        assert len(graph.nodes) == 1000
        assert len(graph.edges) == 5000

        # Test serialization/deserialization roundtrip
        d = graph.to_dict()
        restored = GraphData.from_dict(d)
        assert len(restored.nodes) == 1000
        assert len(restored.edges) == 5000

    def test_graph_data_merge_preserves_order(self):
        """Test that merge preserves order of nodes and edges."""
        graph1 = GraphData(
            nodes=[Node(id="n1", type="T1"), Node(id="n2", type="T2")],
            edges=[Edge(src="a", dst="b", type="E1")],
        )
        graph2 = GraphData(
            nodes=[Node(id="n3", type="T3")],
            edges=[Edge(src="c", dst="d", type="E2")],
        )
        graph1.merge(graph2)

        assert graph1.nodes[0].id == "n1"
        assert graph1.nodes[1].id == "n2"
        assert graph1.nodes[2].id == "n3"

    def test_graph_data_serialization_roundtrip(self):
        """Test complete serialization/deserialization roundtrip."""
        original = GraphData(
            nodes=[
                Node(id="n1", type="Role", properties={"is_admin": True}, provider=CloudProvider.AWS, tags={"env": "prod"}),
                Node(id="n2", type="S3Bucket", properties={"public": False}, provider=CloudProvider.AWS),
            ],
            edges=[
                Edge(src="n1", dst="n2", type="CanAccess", properties={"level": "read"}, provider=CloudProvider.AWS),
            ],
        )

        # Roundtrip
        d = original.to_dict()
        restored = GraphData.from_dict(d)

        # Verify nodes
        assert len(restored.nodes) == 2
        assert restored.nodes[0].properties["is_admin"] is True
        assert restored.nodes[0].tags["env"] == "prod"

        # Verify edges
        assert len(restored.edges) == 1
        assert restored.edges[0].properties["level"] == "read"

    def test_graph_data_deduplicate_keeps_first(self):
        """Test that deduplicate keeps the first occurrence of duplicates."""
        graph = GraphData(
            nodes=[
                Node(id="dup", type="Type1", properties={"version": 1}),
                Node(id="dup", type="Type1", properties={"version": 2}),
            ]
        )
        graph.deduplicate()
        assert len(graph.nodes) == 1
        # Should keep the first one (version 1)
        assert graph.nodes[0].properties["version"] == 1

    def test_graph_data_empty_merge(self):
        """Test merging empty graphs."""
        graph1 = GraphData()
        graph2 = GraphData()
        graph1.merge(graph2)
        assert len(graph1.nodes) == 0
        assert len(graph1.edges) == 0

    def test_graph_data_merge_into_empty(self):
        """Test merging into empty graph."""
        graph1 = GraphData()
        graph2 = GraphData(
            nodes=[Node(id="n1", type="T1")],
            edges=[Edge(src="a", dst="b", type="E1")],
        )
        graph1.merge(graph2)
        assert len(graph1.nodes) == 1
        assert len(graph1.edges) == 1


class TestNodeEdgeCases:
    """Additional edge case tests for Node."""

    def test_node_with_complex_properties(self):
        """Test node with nested complex properties."""
        node = Node(
            id="complex",
            type="Complex",
            properties={
                "list": [1, 2, 3],
                "nested": {"a": {"b": "c"}},
                "bool": True,
                "null": None,
            }
        )
        d = node.to_dict()
        assert d["properties"]["list"] == [1, 2, 3]
        assert d["properties"]["nested"]["a"]["b"] == "c"

        restored = Node.from_dict(d)
        assert restored.properties["list"] == [1, 2, 3]
        assert restored.properties["nested"]["a"]["b"] == "c"

    def test_node_with_empty_strings(self):
        """Test node with empty string values."""
        node = Node(id="", type="")
        assert node.id == ""
        assert node.type == ""

    def test_node_with_special_characters(self):
        """Test node with special characters in ID."""
        special_ids = [
            "arn:aws:s3:::bucket/key*",
            "resource:with:colons",
            "id with spaces",
            "id-with-dashes_and_underscores",
        ]
        for special_id in special_ids:
            node = Node(id=special_id, type="Test")
            d = node.to_dict()
            restored = Node.from_dict(d)
            assert restored.id == special_id


class TestEdgeEdgeCases:
    """Additional edge case tests for Edge."""

    def test_edge_self_reference(self):
        """Test edge that points to itself."""
        edge = Edge(src="node1", dst="node1", type="SelfRef")
        assert edge.src == edge.dst

    def test_edge_with_complex_properties(self):
        """Test edge with nested complex properties."""
        edge = Edge(
            src="a",
            dst="b",
            type="Test",
            properties={
                "conditions": [{"key": "value"}],
                "metadata": {"timestamp": "2024-01-01"},
            }
        )
        d = edge.to_dict()
        restored = Edge.from_dict(d)
        assert restored.properties["conditions"][0]["key"] == "value"


class TestAttackPathEdgeCases:
    """Additional edge case tests for AttackPath."""

    def test_attack_path_all_severities(self):
        """Test attack paths with all severity levels."""
        for severity in Severity:
            path = AttackPath(
                src="src",
                dst="dst",
                rule_id=f"rule-{severity.value}",
                severity=severity,
                description=f"Finding with {severity.value} severity",
            )
            assert path.severity == severity
            assert path.properties["severity"] == severity.value

    def test_attack_path_properties_include_all_fields(self):
        """Test that attack path properties include all relevant fields."""
        path = AttackPath(
            src="src",
            dst="dst",
            rule_id="test-rule",
            severity=Severity.HIGH,
            description="Test description",
            remediation="Test remediation",
        )

        assert "rule" in path.properties
        assert "severity" in path.properties
        assert "description" in path.properties
        assert "remediation" in path.properties

        assert path.properties["rule"] == "test-rule"
        assert path.properties["severity"] == "high"
        assert path.properties["description"] == "Test description"
        assert path.properties["remediation"] == "Test remediation"
