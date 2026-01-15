"""SARIF (Static Analysis Results Interchange Format) export.

SARIF is a standard format for security tool output, supported by GitHub,
Azure DevOps, and many other CI/CD platforms.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any, Dict, List

from arguscloud.core.graph import GraphData, Edge


class SARIFExporter:
    """Export ArgusCloud findings to SARIF format for CI/CD integration."""

    SARIF_VERSION = "2.1.0"
    SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"

    SEVERITY_MAP = {
        "critical": "error",
        "high": "error",
        "medium": "warning",
        "low": "note",
        "info": "note",
    }

    SEVERITY_SCORE = {
        "critical": 10.0,
        "high": 8.0,
        "medium": 5.0,
        "low": 2.0,
        "info": 0.0,
    }

    def __init__(self, graph: GraphData, attack_paths: List[Edge]):
        self.graph = graph
        self.attack_paths = attack_paths
        self._rules: Dict[str, Dict] = {}

    def export(self, pretty: bool = True) -> str:
        """Export to SARIF JSON string."""
        sarif = self._build_sarif()
        indent = 2 if pretty else None
        return json.dumps(sarif, indent=indent, default=str)

    def export_to_file(self, path: str, pretty: bool = True) -> None:
        """Export to a SARIF file."""
        with open(path, "w") as f:
            f.write(self.export(pretty=pretty))

    def _build_sarif(self) -> Dict[str, Any]:
        """Build the SARIF document structure."""
        results = []

        for idx, edge in enumerate(self.attack_paths):
            rule_id = edge.properties.get("rule", f"arguscloud-{idx}")
            severity = edge.properties.get("severity", "medium")

            # Register rule if not seen
            if rule_id not in self._rules:
                self._rules[rule_id] = {
                    "id": rule_id,
                    "name": rule_id.replace("-", " ").title(),
                    "shortDescription": {
                        "text": edge.properties.get("description", rule_id)
                    },
                    "fullDescription": {
                        "text": edge.properties.get("description", rule_id)
                    },
                    "help": {
                        "text": edge.properties.get("remediation", "Review and remediate this finding.")
                    },
                    "defaultConfiguration": {
                        "level": self.SEVERITY_MAP.get(severity, "warning")
                    },
                    "properties": {
                        "security-severity": str(self.SEVERITY_SCORE.get(severity, 5.0))
                    }
                }

            result = {
                "ruleId": rule_id,
                "level": self.SEVERITY_MAP.get(severity, "warning"),
                "message": {
                    "text": edge.properties.get("description", "Security finding")
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": edge.src,
                                "uriBaseId": "CLOUDRESOURCE"
                            }
                        },
                        "logicalLocations": [
                            {
                                "fullyQualifiedName": edge.src,
                                "kind": "resource"
                            }
                        ]
                    }
                ],
                "relatedLocations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": edge.dst,
                                "uriBaseId": "CLOUDRESOURCE"
                            }
                        },
                        "message": {
                            "text": f"Target: {edge.dst}"
                        }
                    }
                ],
                "properties": {
                    "severity": severity,
                    "provider": edge.provider.value if hasattr(edge, 'provider') else "aws",
                }
            }

            # Add remediation if available
            if edge.properties.get("remediation"):
                result["fixes"] = [
                    {
                        "description": {
                            "text": edge.properties["remediation"]
                        }
                    }
                ]

            results.append(result)

        return {
            "$schema": self.SARIF_SCHEMA,
            "version": self.SARIF_VERSION,
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "ArgusCloud",
                            "version": "0.2.0",
                            "informationUri": "https://github.com/jeremylaratro/cloudhound",
                            "rules": list(self._rules.values())
                        }
                    },
                    "results": results,
                    "invocations": [
                        {
                            "executionSuccessful": True,
                            "endTimeUtc": datetime.utcnow().isoformat() + "Z"
                        }
                    ],
                    "originalUriBaseIds": {
                        "CLOUDRESOURCE": {
                            "uri": "cloud://",
                            "description": {
                                "text": "Cloud resource identifier"
                            }
                        }
                    }
                }
            ]
        }
