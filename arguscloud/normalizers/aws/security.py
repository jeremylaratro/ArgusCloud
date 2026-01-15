"""AWS Security service normalizers."""

from __future__ import annotations

from typing import Any, Dict, Iterable

from arguscloud.core.graph import CloudProvider, GraphData, Node
from arguscloud.core.registry import normalizers


@normalizers.normalizer(
    name="cloudtrail",
    provider="aws",
    description="Normalize CloudTrail trails to graph",
    input_type="cloudtrail",
)
def normalize_cloudtrail(records: Iterable[Dict[str, Any]]) -> GraphData:
    """Convert CloudTrail trails to nodes."""
    graph = GraphData()
    trail_statuses = {}

    for rec in records:
        # Collect trail status info
        if rec.get("TrailStatus"):
            name = rec.get("Name")
            if name:
                trail_statuses[name] = rec["TrailStatus"]

        # Process trail definitions
        if rec.get("Trails"):
            for trail in rec["Trails"]:
                name = trail.get("Name")
                if not name:
                    continue

                status = trail_statuses.get(name, {})
                node_id = f"cloudtrail:{name}"

                graph.add_node(Node(
                    id=node_id,
                    type="CloudTrailTrail",
                    properties={
                        "name": name,
                        "home_region": trail.get("HomeRegion"),
                        "is_multi_region": trail.get("IsMultiRegionTrail"),
                        "is_organization_trail": trail.get("IsOrganizationTrail"),
                        "s3_bucket": trail.get("S3BucketName"),
                        "log_file_validation": trail.get("LogFileValidationEnabled"),
                        "kms_key_id": trail.get("KMSKeyId"),
                        "is_logging": status.get("IsLogging"),
                        "latest_delivery_time": str(status.get("LatestDeliveryTime", "")),
                    },
                    provider=CloudProvider.AWS,
                ))

    return graph


@normalizers.normalizer(
    name="guardduty",
    provider="aws",
    description="Normalize GuardDuty detectors to graph",
    input_type="guardduty",
)
def normalize_guardduty(records: Iterable[Dict[str, Any]]) -> GraphData:
    """Convert GuardDuty detectors to nodes."""
    graph = GraphData()

    for rec in records:
        det_id = rec.get("Detector")
        info = rec.get("Info") or {}
        if not det_id:
            continue

        graph.add_node(Node(
            id=f"guardduty:{det_id}",
            type="GuardDutyDetector",
            properties={
                "status": info.get("Status"),
                "finding_publishing_frequency": info.get("FindingPublishingFrequency"),
                "high_severity_findings": rec.get("HighSeverityFindings", 0),
                "service_role": info.get("ServiceRole"),
            },
            provider=CloudProvider.AWS,
        ))

    return graph


@normalizers.normalizer(
    name="securityhub",
    provider="aws",
    description="Normalize Security Hub findings to graph",
    input_type="securityhub",
)
def normalize_securityhub(records: Iterable[Dict[str, Any]]) -> GraphData:
    """Convert Security Hub data to nodes."""
    graph = GraphData()

    for rec in records:
        if rec.get("Hub"):
            hub = rec["Hub"]
            hub_arn = hub.get("HubArn")
            if hub_arn:
                graph.add_node(Node(
                    id=hub_arn,
                    type="SecurityHub",
                    properties={
                        "subscribed_at": str(hub.get("SubscribedAt", "")),
                        "auto_enable_controls": hub.get("AutoEnableControls"),
                    },
                    provider=CloudProvider.AWS,
                ))

        if rec.get("Findings"):
            for finding in rec["Findings"]:
                finding_id = finding.get("Id")
                if not finding_id:
                    continue

                severity = finding.get("Severity", {})

                graph.add_node(Node(
                    id=finding_id,
                    type="SecurityFinding",
                    properties={
                        "title": finding.get("Title"),
                        "description": finding.get("Description"),
                        "severity_label": severity.get("Label"),
                        "severity_score": severity.get("Normalized"),
                        "product": finding.get("ProductArn"),
                        "status": finding.get("Workflow", {}).get("Status"),
                        "compliance_status": finding.get("Compliance", {}).get("Status"),
                        "resource_type": finding.get("Resources", [{}])[0].get("Type") if finding.get("Resources") else None,
                        "resource_id": finding.get("Resources", [{}])[0].get("Id") if finding.get("Resources") else None,
                    },
                    provider=CloudProvider.AWS,
                ))

        if rec.get("EnabledStandards"):
            for std in rec["EnabledStandards"]:
                std_arn = std.get("StandardsSubscriptionArn")
                if std_arn:
                    graph.add_node(Node(
                        id=std_arn,
                        type="SecurityStandard",
                        properties={
                            "standards_arn": std.get("StandardsArn"),
                            "status": std.get("StandardsStatus"),
                        },
                        provider=CloudProvider.AWS,
                    ))

    return graph
