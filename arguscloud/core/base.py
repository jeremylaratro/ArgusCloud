"""Base classes for collectors, normalizers, and rules."""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Tuple

from .graph import CloudProvider, Edge, GraphData, Node, Severity, AttackPath


log = logging.getLogger(__name__)


@dataclass
class CollectorResult:
    """Result from a collector run."""
    service: str
    status: str  # "ok", "error", "skipped"
    records: List[Dict[str, Any]] = field(default_factory=list)
    detail: str = ""
    error: Optional[Exception] = None


class BaseCollector(ABC):
    """Base class for cloud resource collectors."""

    provider: CloudProvider = CloudProvider.AWS
    name: str = ""
    description: str = ""
    services: List[str] = []

    def __init__(self, session: Any):
        """Initialize collector with a cloud session/credentials."""
        self.session = session
        self.log = logging.getLogger(f"{__name__}.{self.__class__.__name__}")

    @abstractmethod
    def collect(self) -> CollectorResult:
        """Collect resources from the cloud provider."""
        pass

    def _handle_error(self, service: str, exc: Exception) -> CollectorResult:
        """Handle collection errors uniformly."""
        self.log.warning(f"Collector {self.name} failed: {exc}")
        return CollectorResult(
            service=service,
            status="error",
            detail=str(exc),
            error=exc,
        )


class BaseNormalizer(ABC):
    """Base class for data normalizers."""

    provider: CloudProvider = CloudProvider.AWS
    name: str = ""
    description: str = ""
    input_type: str = ""  # e.g., "iam-roles", "s3", etc.

    def __init__(self):
        self.log = logging.getLogger(f"{__name__}.{self.__class__.__name__}")

    @abstractmethod
    def normalize(self, records: Iterable[Dict[str, Any]]) -> GraphData:
        """Convert raw records to graph nodes and edges."""
        pass

    def _create_node(
        self,
        id: str,
        type: str,
        properties: Optional[Dict[str, Any]] = None,
        tags: Optional[Dict[str, str]] = None,
    ) -> Node:
        """Helper to create a node with this normalizer's provider."""
        return Node(
            id=id,
            type=type,
            properties=properties or {},
            provider=self.provider,
            tags=tags or {},
        )

    def _create_edge(
        self,
        src: str,
        dst: str,
        type: str,
        properties: Optional[Dict[str, Any]] = None,
    ) -> Edge:
        """Helper to create an edge with this normalizer's provider."""
        return Edge(
            src=src,
            dst=dst,
            type=type,
            properties=properties or {},
            provider=self.provider,
        )


@dataclass
class RuleContext:
    """Context passed to security rules for evaluation."""
    nodes: List[Node]
    edges: List[Edge]
    provider: Optional[CloudProvider] = None

    def get_nodes_by_type(self, node_type: str) -> List[Node]:
        """Get all nodes of a specific type."""
        return [n for n in self.nodes if n.type == node_type]

    def get_edges_by_type(self, edge_type: str) -> List[Edge]:
        """Get all edges of a specific type."""
        return [e for e in self.edges if e.type == edge_type]

    def get_node_by_id(self, node_id: str) -> Optional[Node]:
        """Get a node by its ID."""
        for n in self.nodes:
            if n.id == node_id:
                return n
        return None


@dataclass
class RuleResult:
    """Result from a security rule evaluation."""
    rule_id: str
    description: str
    attack_paths: List[AttackPath] = field(default_factory=list)
    passed: bool = True

    @property
    def finding_count(self) -> int:
        return len(self.attack_paths)


class BaseRule(ABC):
    """Base class for security analysis rules."""

    provider: CloudProvider = CloudProvider.AWS
    rule_id: str = ""
    description: str = ""
    severity: Severity = Severity.MEDIUM
    tags: List[str] = []
    remediation: str = ""

    def __init__(self):
        self.log = logging.getLogger(f"{__name__}.{self.__class__.__name__}")

    @abstractmethod
    def evaluate(self, ctx: RuleContext) -> RuleResult:
        """Evaluate the rule against the graph context."""
        pass

    def _create_finding(
        self,
        src: str,
        dst: str,
        description: Optional[str] = None,
        severity: Optional[Severity] = None,
        remediation: Optional[str] = None,
    ) -> AttackPath:
        """Helper to create an attack path finding."""
        return AttackPath(
            src=src,
            dst=dst,
            type="AttackPath",
            rule_id=self.rule_id,
            severity=severity or self.severity,
            description=description or self.description,
            remediation=remediation or self.remediation,
            provider=self.provider,
        )


def extract_principals(policy_doc: Dict[str, Any]) -> List[str]:
    """Extract principal ARNs/identifiers from an IAM policy document."""
    principals: List[str] = []
    statements = policy_doc.get("Statement") or []

    if not isinstance(statements, list):
        statements = [statements]

    for stmt in statements:
        principal = stmt.get("Principal")
        if principal == "*":
            principals.append("*")
        elif isinstance(principal, dict):
            for key, val in principal.items():
                if isinstance(val, list):
                    principals.extend(val)
                else:
                    principals.append(val)
        elif principal:
            principals.append(str(principal))

    return principals


def is_admin_policy(policy_doc: Dict[str, Any]) -> bool:
    """Check if a policy document grants admin access (Allow * on *)."""
    statements = policy_doc.get("Statement") or []

    if not isinstance(statements, list):
        statements = [statements]

    for stmt in statements:
        if stmt.get("Effect") != "Allow":
            continue

        actions = stmt.get("Action")
        resources = stmt.get("Resource")

        action_star = actions == "*" or (isinstance(actions, list) and "*" in actions)
        resource_star = resources == "*" or (isinstance(resources, list) and "*" in resources)

        if action_star and resource_star:
            return True

    return False
