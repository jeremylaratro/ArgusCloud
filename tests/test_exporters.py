"""Tests for arguscloud.exporters module."""

import json
import os
import tempfile
import pytest
from arguscloud.core.graph import Node, Edge, AttackPath, GraphData, Severity, CloudProvider
from arguscloud.exporters.json_export import JSONExporter
from arguscloud.exporters.sarif import SARIFExporter


class TestJSONExporter:
    """Tests for JSON exporter."""

    @pytest.fixture
    def sample_graph(self):
        """Create a sample graph for testing."""
        return GraphData(
            nodes=[
                Node(id="bucket-1", type="S3Bucket", properties={"name": "data"}),
                Node(id="role-1", type="Role", properties={"is_admin": True}),
            ],
            edges=[
                Edge(src="role-1", dst="bucket-1", type="CanAccess"),
            ],
        )

    @pytest.fixture
    def sample_findings(self):
        """Create sample attack path findings."""
        return [
            AttackPath(
                src="bucket-1",
                dst="internet",
                rule_id="public-s3",
                severity=Severity.HIGH,
                description="S3 bucket is public",
                remediation="Block public access",
            ),
            AttackPath(
                src="role-1",
                dst="*",
                rule_id="open-trust",
                severity=Severity.MEDIUM,
                description="Role trusts everyone",
            ),
        ]

    def test_export_returns_valid_json(self, sample_graph, sample_findings):
        """Test that export returns valid JSON."""
        exporter = JSONExporter(sample_graph, sample_findings)
        result = exporter.export()
        data = json.loads(result)
        assert isinstance(data, dict)

    def test_export_contains_metadata(self, sample_graph, sample_findings):
        """Test that export contains metadata section."""
        exporter = JSONExporter(sample_graph, sample_findings)
        data = json.loads(exporter.export())

        assert "metadata" in data
        assert data["metadata"]["tool"] == "ArgusCloud"
        assert "version" in data["metadata"]
        assert "generated_at" in data["metadata"]

    def test_export_contains_summary(self, sample_graph, sample_findings):
        """Test that export contains summary section."""
        exporter = JSONExporter(sample_graph, sample_findings)
        data = json.loads(exporter.export())

        assert "summary" in data
        assert data["summary"]["total_nodes"] == 2
        assert data["summary"]["total_edges"] == 1
        assert data["summary"]["total_findings"] == 2

    def test_export_contains_resource_counts(self, sample_graph, sample_findings):
        """Test that export contains resource counts."""
        exporter = JSONExporter(sample_graph, sample_findings)
        data = json.loads(exporter.export())

        resource_counts = data["summary"]["resource_counts"]
        assert resource_counts["S3Bucket"] == 1
        assert resource_counts["Role"] == 1

    def test_export_contains_severity_counts(self, sample_graph, sample_findings):
        """Test that export contains severity counts."""
        exporter = JSONExporter(sample_graph, sample_findings)
        data = json.loads(exporter.export())

        severity_counts = data["summary"]["severity_counts"]
        assert severity_counts["high"] == 1
        assert severity_counts["medium"] == 1

    def test_export_contains_findings(self, sample_graph, sample_findings):
        """Test that export contains findings list."""
        exporter = JSONExporter(sample_graph, sample_findings)
        data = json.loads(exporter.export())

        assert "findings" in data
        assert len(data["findings"]) == 2

        finding = data["findings"][0]
        assert "rule_id" in finding
        assert "severity" in finding
        assert "description" in finding
        assert "source" in finding
        assert "target" in finding

    def test_export_contains_nodes_and_edges(self, sample_graph, sample_findings):
        """Test that export contains nodes and edges."""
        exporter = JSONExporter(sample_graph, sample_findings)
        data = json.loads(exporter.export())

        assert "nodes" in data
        assert "edges" in data
        assert len(data["nodes"]) == 2
        assert len(data["edges"]) == 1

    def test_export_pretty_formatting(self, sample_graph, sample_findings):
        """Test pretty vs compact formatting."""
        exporter = JSONExporter(sample_graph, sample_findings)

        pretty = exporter.export(pretty=True)
        compact = exporter.export(pretty=False)

        # Pretty should have newlines and indentation
        assert "\n" in pretty
        # Compact should not have indentation
        assert "\n" not in compact

    def test_export_to_file(self, sample_graph, sample_findings):
        """Test exporting to a file."""
        exporter = JSONExporter(sample_graph, sample_findings)

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            path = f.name

        try:
            exporter.export_to_file(path)
            with open(path) as f:
                data = json.load(f)
            assert data["summary"]["total_findings"] == 2
        finally:
            os.unlink(path)

    def test_export_empty_graph(self):
        """Test exporting empty graph and findings."""
        exporter = JSONExporter(GraphData(), [])
        data = json.loads(exporter.export())

        assert data["summary"]["total_nodes"] == 0
        assert data["summary"]["total_findings"] == 0
        assert data["findings"] == []


class TestSARIFExporter:
    """Tests for SARIF exporter."""

    @pytest.fixture
    def sample_graph(self):
        """Create a sample graph for testing."""
        return GraphData(
            nodes=[
                Node(id="bucket-1", type="S3Bucket", properties={"name": "data"}),
            ],
        )

    @pytest.fixture
    def sample_findings(self):
        """Create sample attack path findings."""
        return [
            AttackPath(
                src="bucket-1",
                dst="internet",
                rule_id="aws-s3-public",
                severity=Severity.HIGH,
                description="S3 bucket is publicly accessible",
                remediation="Enable Block Public Access",
            ),
            AttackPath(
                src="bucket-2",
                dst="internet",
                rule_id="aws-s3-public",
                severity=Severity.HIGH,
                description="S3 bucket is publicly accessible",
            ),
        ]

    def test_export_returns_valid_json(self, sample_graph, sample_findings):
        """Test that export returns valid JSON."""
        exporter = SARIFExporter(sample_graph, sample_findings)
        result = exporter.export()
        data = json.loads(result)
        assert isinstance(data, dict)

    def test_export_contains_sarif_version(self, sample_graph, sample_findings):
        """Test that export contains SARIF version."""
        exporter = SARIFExporter(sample_graph, sample_findings)
        data = json.loads(exporter.export())

        assert data["version"] == "2.1.0"
        assert "$schema" in data

    def test_export_contains_runs(self, sample_graph, sample_findings):
        """Test that export contains runs array."""
        exporter = SARIFExporter(sample_graph, sample_findings)
        data = json.loads(exporter.export())

        assert "runs" in data
        assert len(data["runs"]) == 1

    def test_export_contains_tool_info(self, sample_graph, sample_findings):
        """Test that export contains tool information."""
        exporter = SARIFExporter(sample_graph, sample_findings)
        data = json.loads(exporter.export())

        tool = data["runs"][0]["tool"]["driver"]
        assert tool["name"] == "ArgusCloud"
        assert "version" in tool
        assert "informationUri" in tool

    def test_export_contains_rules(self, sample_graph, sample_findings):
        """Test that export contains rule definitions."""
        exporter = SARIFExporter(sample_graph, sample_findings)
        data = json.loads(exporter.export())

        rules = data["runs"][0]["tool"]["driver"]["rules"]
        assert len(rules) >= 1  # At least one unique rule

        rule = rules[0]
        assert "id" in rule
        assert "shortDescription" in rule
        assert "help" in rule

    def test_export_contains_results(self, sample_graph, sample_findings):
        """Test that export contains results."""
        exporter = SARIFExporter(sample_graph, sample_findings)
        data = json.loads(exporter.export())

        results = data["runs"][0]["results"]
        assert len(results) == 2

        result = results[0]
        assert "ruleId" in result
        assert "level" in result
        assert "message" in result
        assert "locations" in result

    def test_severity_mapping(self, sample_graph):
        """Test severity to level mapping."""
        findings = [
            AttackPath(
                src="res1", dst="internet",
                rule_id="critical-rule", severity=Severity.CRITICAL,
            ),
            AttackPath(
                src="res2", dst="internet",
                rule_id="high-rule", severity=Severity.HIGH,
            ),
            AttackPath(
                src="res3", dst="internet",
                rule_id="medium-rule", severity=Severity.MEDIUM,
            ),
            AttackPath(
                src="res4", dst="internet",
                rule_id="low-rule", severity=Severity.LOW,
            ),
            AttackPath(
                src="res5", dst="internet",
                rule_id="info-rule", severity=Severity.INFO,
            ),
        ]
        exporter = SARIFExporter(sample_graph, findings)
        data = json.loads(exporter.export())

        results = data["runs"][0]["results"]
        levels = [r["level"] for r in results]

        assert "error" in levels  # CRITICAL and HIGH map to error
        assert "warning" in levels  # MEDIUM maps to warning
        assert "note" in levels  # LOW and INFO map to note

    def test_export_contains_locations(self, sample_graph, sample_findings):
        """Test that results contain location information."""
        exporter = SARIFExporter(sample_graph, sample_findings)
        data = json.loads(exporter.export())

        result = data["runs"][0]["results"][0]
        location = result["locations"][0]

        assert "physicalLocation" in location
        assert "artifactLocation" in location["physicalLocation"]
        assert "logicalLocations" in location

    def test_export_contains_related_locations(self, sample_graph, sample_findings):
        """Test that results contain related location (target)."""
        exporter = SARIFExporter(sample_graph, sample_findings)
        data = json.loads(exporter.export())

        result = data["runs"][0]["results"][0]
        assert "relatedLocations" in result
        assert len(result["relatedLocations"]) >= 1

    def test_export_contains_fixes(self, sample_graph, sample_findings):
        """Test that results with remediation contain fixes."""
        exporter = SARIFExporter(sample_graph, sample_findings)
        data = json.loads(exporter.export())

        # First finding has remediation
        result = data["runs"][0]["results"][0]
        assert "fixes" in result
        assert len(result["fixes"]) == 1

    def test_export_contains_invocations(self, sample_graph, sample_findings):
        """Test that export contains invocation metadata."""
        exporter = SARIFExporter(sample_graph, sample_findings)
        data = json.loads(exporter.export())

        invocations = data["runs"][0]["invocations"]
        assert len(invocations) == 1
        assert invocations[0]["executionSuccessful"] is True
        assert "endTimeUtc" in invocations[0]

    def test_export_to_file(self, sample_graph, sample_findings):
        """Test exporting to a file."""
        exporter = SARIFExporter(sample_graph, sample_findings)

        with tempfile.NamedTemporaryFile(mode="w", suffix=".sarif", delete=False) as f:
            path = f.name

        try:
            exporter.export_to_file(path)
            with open(path) as f:
                data = json.load(f)
            assert data["version"] == "2.1.0"
        finally:
            os.unlink(path)

    def test_export_empty_findings(self, sample_graph):
        """Test exporting with no findings."""
        exporter = SARIFExporter(sample_graph, [])
        data = json.loads(exporter.export())

        results = data["runs"][0]["results"]
        rules = data["runs"][0]["tool"]["driver"]["rules"]
        assert len(results) == 0
        assert len(rules) == 0

    def test_deduplication_of_rules(self, sample_graph, sample_findings):
        """Test that rules are deduplicated."""
        exporter = SARIFExporter(sample_graph, sample_findings)
        data = json.loads(exporter.export())

        rules = data["runs"][0]["tool"]["driver"]["rules"]
        # Both findings have same rule_id, should only be one rule
        assert len(rules) == 1

    def test_security_severity_property(self, sample_graph, sample_findings):
        """Test that rules have security-severity property."""
        exporter = SARIFExporter(sample_graph, sample_findings)
        data = json.loads(exporter.export())

        rule = data["runs"][0]["tool"]["driver"]["rules"][0]
        assert "properties" in rule
        assert "security-severity" in rule["properties"]
