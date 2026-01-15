"""JSON export format."""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any, Dict, List

from arguscloud.core.graph import GraphData, Edge


class JSONExporter:
    """Export ArgusCloud data to JSON format."""

    def __init__(self, graph: GraphData, attack_paths: List[Edge]):
        self.graph = graph
        self.attack_paths = attack_paths

    def export(self, pretty: bool = True) -> str:
        """Export to JSON string."""
        report = self._build_report()
        indent = 2 if pretty else None
        return json.dumps(report, indent=indent, default=str)

    def export_to_file(self, path: str, pretty: bool = True) -> None:
        """Export to a JSON file."""
        with open(path, "w") as f:
            f.write(self.export(pretty=pretty))

    def _build_report(self) -> Dict[str, Any]:
        """Build the report structure."""
        # Count resources by type
        resource_counts: Dict[str, int] = {}
        for node in self.graph.nodes:
            resource_counts[node.type] = resource_counts.get(node.type, 0) + 1

        # Count findings by severity
        severity_counts: Dict[str, int] = {}
        for edge in self.attack_paths:
            sev = edge.properties.get("severity", "unknown")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        return {
            "metadata": {
                "tool": "ArgusCloud",
                "version": "0.2.0",
                "generated_at": datetime.utcnow().isoformat() + "Z",
            },
            "summary": {
                "total_nodes": len(self.graph.nodes),
                "total_edges": len(self.graph.edges),
                "total_findings": len(self.attack_paths),
                "resource_counts": resource_counts,
                "severity_counts": severity_counts,
            },
            "findings": [
                {
                    "rule_id": e.properties.get("rule", "unknown"),
                    "severity": e.properties.get("severity", "unknown"),
                    "description": e.properties.get("description", ""),
                    "remediation": e.properties.get("remediation"),
                    "source": e.src,
                    "target": e.dst,
                    "properties": e.properties,
                }
                for e in self.attack_paths
            ],
            "nodes": [n.to_dict() for n in self.graph.nodes],
            "edges": [e.to_dict() for e in self.graph.edges],
        }
