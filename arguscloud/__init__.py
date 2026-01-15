"""ArgusCloud - Multi-cloud security graph analytics.

A modular, extensible framework for cloud security analysis that:
- Collects resource data from multiple cloud providers (AWS, GCP, Azure)
- Normalizes data into a unified graph structure
- Detects security misconfigurations and attack paths
- Exports findings to multiple formats (JSON, SARIF, HTML)
"""

__version__ = "0.2.0"
__author__ = "Jeremy Laratro"

from arguscloud.core.graph import (
    Node,
    Edge,
    AttackPath,
    GraphData,
    Severity,
    CloudProvider,
)
from arguscloud.core.registry import collectors, normalizers, rules

__all__ = [
    # Version info
    "__version__",
    "__author__",
    # Core graph types
    "Node",
    "Edge",
    "AttackPath",
    "GraphData",
    "Severity",
    "CloudProvider",
    # Registries
    "collectors",
    "normalizers",
    "rules",
]
