"""Graph data structures for nodes and edges."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional
from enum import Enum


class Severity(str, Enum):
    """Attack path severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class CloudProvider(str, Enum):
    """Supported cloud providers."""
    AWS = "aws"
    GCP = "gcp"
    AZURE = "azure"


@dataclass
class Node:
    """Represents a cloud resource node in the graph."""
    id: str
    type: str
    properties: Dict[str, Any] = field(default_factory=dict)
    provider: CloudProvider = CloudProvider.AWS
    tags: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert node to dictionary for serialization."""
        d = asdict(self)
        d["provider"] = self.provider.value
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Node":
        """Create node from dictionary."""
        provider = data.get("provider", "aws")
        if isinstance(provider, str):
            provider = CloudProvider(provider)
        return cls(
            id=data["id"],
            type=data["type"],
            properties=data.get("properties", {}),
            provider=provider,
            tags=data.get("tags", {}),
        )


@dataclass
class Edge:
    """Represents a relationship between nodes."""
    src: str
    dst: str
    type: str
    properties: Dict[str, Any] = field(default_factory=dict)
    provider: CloudProvider = CloudProvider.AWS

    def to_dict(self) -> Dict[str, Any]:
        """Convert edge to dictionary for serialization."""
        d = asdict(self)
        d["provider"] = self.provider.value
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Edge":
        """Create edge from dictionary."""
        provider = data.get("provider", "aws")
        if isinstance(provider, str):
            provider = CloudProvider(provider)
        return cls(
            src=data["src"],
            dst=data["dst"],
            type=data["type"],
            properties=data.get("properties", {}),
            provider=provider,
        )


@dataclass
class AttackPath(Edge):
    """Specialized edge representing a security finding."""
    type: str = "AttackPath"
    rule_id: str = ""
    severity: Severity = Severity.INFO
    description: str = ""
    remediation: Optional[str] = None

    def __post_init__(self):
        self.type = "AttackPath"
        self.properties.update({
            "rule": self.rule_id,
            "severity": self.severity.value,
            "description": self.description,
        })
        if self.remediation:
            self.properties["remediation"] = self.remediation


@dataclass
class GraphData:
    """Container for graph nodes and edges."""
    nodes: List[Node] = field(default_factory=list)
    edges: List[Edge] = field(default_factory=list)

    def add_node(self, node: Node) -> None:
        """Add a node to the graph."""
        self.nodes.append(node)

    def add_edge(self, edge: Edge) -> None:
        """Add an edge to the graph."""
        self.edges.append(edge)

    def merge(self, other: "GraphData") -> None:
        """Merge another graph into this one."""
        self.nodes.extend(other.nodes)
        self.edges.extend(other.edges)

    def deduplicate(self) -> None:
        """Remove duplicate nodes and edges."""
        seen_nodes: Dict[str, Node] = {}
        for node in self.nodes:
            if node.id not in seen_nodes:
                seen_nodes[node.id] = node
        self.nodes = list(seen_nodes.values())

        seen_edges: set = set()
        unique_edges: List[Edge] = []
        for edge in self.edges:
            key = (edge.src, edge.dst, edge.type)
            if key not in seen_edges:
                seen_edges.add(key)
                unique_edges.append(edge)
        self.edges = unique_edges

    def to_dict(self) -> Dict[str, Any]:
        """Convert graph to dictionary."""
        return {
            "nodes": [n.to_dict() for n in self.nodes],
            "edges": [e.to_dict() for e in self.edges],
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "GraphData":
        """Create graph from dictionary."""
        return cls(
            nodes=[Node.from_dict(n) for n in data.get("nodes", [])],
            edges=[Edge.from_dict(e) for e in data.get("edges", [])],
        )
