"""Tests for arguscloud.normalizers.aws.security module (CloudTrail, GuardDuty, SecurityHub)."""

import pytest
from arguscloud.normalizers.aws.security import (
    normalize_cloudtrail,
    normalize_guardduty,
    normalize_securityhub,
)
from arguscloud.core.graph import CloudProvider


class TestNormalizeCloudTrail:
    """Tests for CloudTrail trail normalization."""

    def test_normalize_empty_records(self):
        """Test normalizing empty records."""
        graph = normalize_cloudtrail([])
        assert len(graph.nodes) == 0
        assert len(graph.edges) == 0

    def test_normalize_basic_trail(self):
        """Test normalizing a basic CloudTrail trail."""
        records = [
            {
                "Trails": [
                    {
                        "Name": "my-trail",
                        "HomeRegion": "us-east-1",
                        "S3BucketName": "cloudtrail-logs-bucket",
                        "IsMultiRegionTrail": False,
                        "IsOrganizationTrail": False,
                        "LogFileValidationEnabled": True,
                    }
                ]
            }
        ]
        graph = normalize_cloudtrail(records)
        assert len(graph.nodes) == 1
        node = graph.nodes[0]
        assert node.id == "cloudtrail:my-trail"
        assert node.type == "CloudTrailTrail"
        assert node.properties["name"] == "my-trail"
        assert node.properties["home_region"] == "us-east-1"
        assert node.properties["s3_bucket"] == "cloudtrail-logs-bucket"
        assert node.properties["is_multi_region"] is False
        assert node.properties["is_organization_trail"] is False
        assert node.properties["log_file_validation"] is True
        assert node.provider == CloudProvider.AWS

    def test_trail_with_status(self):
        """Test trail with status information merged."""
        records = [
            {
                "Name": "my-trail",
                "TrailStatus": {
                    "IsLogging": True,
                    "LatestDeliveryTime": "2024-01-15T10:30:00Z",
                },
            },
            {
                "Trails": [
                    {
                        "Name": "my-trail",
                        "HomeRegion": "us-east-1",
                        "S3BucketName": "logs-bucket",
                    }
                ]
            },
        ]
        graph = normalize_cloudtrail(records)
        node = graph.nodes[0]
        assert node.properties["is_logging"] is True
        assert node.properties["latest_delivery_time"] == "2024-01-15T10:30:00Z"

    def test_trail_not_logging(self):
        """Test trail that is not actively logging."""
        records = [
            {
                "Name": "stopped-trail",
                "TrailStatus": {
                    "IsLogging": False,
                    "LatestDeliveryTime": "2024-01-01T00:00:00Z",
                },
            },
            {
                "Trails": [
                    {
                        "Name": "stopped-trail",
                        "HomeRegion": "us-east-1",
                    }
                ]
            },
        ]
        graph = normalize_cloudtrail(records)
        node = graph.nodes[0]
        assert node.properties["is_logging"] is False

    def test_multi_region_trail(self):
        """Test multi-region trail."""
        records = [
            {
                "Trails": [
                    {
                        "Name": "global-trail",
                        "HomeRegion": "us-east-1",
                        "IsMultiRegionTrail": True,
                        "IsOrganizationTrail": False,
                    }
                ]
            }
        ]
        graph = normalize_cloudtrail(records)
        node = graph.nodes[0]
        assert node.properties["is_multi_region"] is True
        assert node.properties["is_organization_trail"] is False

    def test_organization_trail(self):
        """Test organization-wide trail."""
        records = [
            {
                "Trails": [
                    {
                        "Name": "org-trail",
                        "HomeRegion": "us-east-1",
                        "IsMultiRegionTrail": True,
                        "IsOrganizationTrail": True,
                    }
                ]
            }
        ]
        graph = normalize_cloudtrail(records)
        node = graph.nodes[0]
        assert node.properties["is_multi_region"] is True
        assert node.properties["is_organization_trail"] is True

    def test_trail_with_kms_encryption(self):
        """Test trail with KMS encryption."""
        records = [
            {
                "Trails": [
                    {
                        "Name": "encrypted-trail",
                        "HomeRegion": "us-east-1",
                        "S3BucketName": "logs-bucket",
                        "KMSKeyId": "arn:aws:kms:us-east-1:123456789012:key/abcd1234",
                    }
                ]
            }
        ]
        graph = normalize_cloudtrail(records)
        node = graph.nodes[0]
        assert node.properties["kms_key_id"] == "arn:aws:kms:us-east-1:123456789012:key/abcd1234"

    def test_trail_without_name_skipped(self):
        """Test that trails without name are skipped."""
        records = [
            {
                "Trails": [
                    {
                        "HomeRegion": "us-east-1",
                        "S3BucketName": "logs-bucket",
                    }
                ]
            }
        ]
        graph = normalize_cloudtrail(records)
        assert len(graph.nodes) == 0

    def test_trail_status_without_name_ignored(self):
        """Test that trail status without name is ignored."""
        records = [
            {
                "TrailStatus": {
                    "IsLogging": True,
                }
            }
        ]
        graph = normalize_cloudtrail(records)
        assert len(graph.nodes) == 0

    def test_multiple_trails(self):
        """Test normalizing multiple trails."""
        records = [
            {
                "Name": "trail-1",
                "TrailStatus": {"IsLogging": True},
            },
            {
                "Name": "trail-2",
                "TrailStatus": {"IsLogging": False},
            },
            {
                "Trails": [
                    {"Name": "trail-1", "HomeRegion": "us-east-1"},
                    {"Name": "trail-2", "HomeRegion": "us-west-2"},
                ]
            },
        ]
        graph = normalize_cloudtrail(records)
        assert len(graph.nodes) == 2

        trail_names = [n.properties["name"] for n in graph.nodes]
        assert "trail-1" in trail_names
        assert "trail-2" in trail_names

    def test_trail_missing_status(self):
        """Test trail without status information."""
        records = [
            {
                "Trails": [
                    {
                        "Name": "no-status-trail",
                        "HomeRegion": "us-east-1",
                    }
                ]
            }
        ]
        graph = normalize_cloudtrail(records)
        node = graph.nodes[0]
        assert node.properties["is_logging"] is None
        assert node.properties["latest_delivery_time"] == ""


class TestNormalizeGuardDuty:
    """Tests for GuardDuty detector normalization."""

    def test_normalize_empty_records(self):
        """Test normalizing empty records."""
        graph = normalize_guardduty([])
        assert len(graph.nodes) == 0
        assert len(graph.edges) == 0

    def test_normalize_basic_detector(self):
        """Test normalizing a basic GuardDuty detector."""
        records = [
            {
                "Detector": "abc123def456",
                "Info": {
                    "Status": "ENABLED",
                    "FindingPublishingFrequency": "FIFTEEN_MINUTES",
                    "ServiceRole": "arn:aws:iam::123456789012:role/guardduty-role",
                },
            }
        ]
        graph = normalize_guardduty(records)
        assert len(graph.nodes) == 1
        node = graph.nodes[0]
        assert node.id == "guardduty:abc123def456"
        assert node.type == "GuardDutyDetector"
        assert node.properties["status"] == "ENABLED"
        assert node.properties["finding_publishing_frequency"] == "FIFTEEN_MINUTES"
        assert node.properties["service_role"] == "arn:aws:iam::123456789012:role/guardduty-role"
        assert node.provider == CloudProvider.AWS

    def test_detector_with_findings_count(self):
        """Test detector with high severity findings count."""
        records = [
            {
                "Detector": "det123",
                "Info": {"Status": "ENABLED"},
                "HighSeverityFindings": 5,
            }
        ]
        graph = normalize_guardduty(records)
        node = graph.nodes[0]
        assert node.properties["high_severity_findings"] == 5

    def test_detector_no_findings(self):
        """Test detector with no high severity findings."""
        records = [
            {
                "Detector": "det123",
                "Info": {"Status": "ENABLED"},
            }
        ]
        graph = normalize_guardduty(records)
        node = graph.nodes[0]
        assert node.properties["high_severity_findings"] == 0

    def test_detector_disabled(self):
        """Test disabled detector."""
        records = [
            {
                "Detector": "det123",
                "Info": {"Status": "DISABLED"},
            }
        ]
        graph = normalize_guardduty(records)
        node = graph.nodes[0]
        assert node.properties["status"] == "DISABLED"

    def test_detector_without_id_skipped(self):
        """Test that detector without ID is skipped."""
        records = [
            {
                "Info": {"Status": "ENABLED"},
                "HighSeverityFindings": 0,
            }
        ]
        graph = normalize_guardduty(records)
        assert len(graph.nodes) == 0

    def test_detector_without_info(self):
        """Test detector without Info dictionary."""
        records = [
            {
                "Detector": "det123",
            }
        ]
        graph = normalize_guardduty(records)
        node = graph.nodes[0]
        assert node.properties["status"] is None
        assert node.properties["finding_publishing_frequency"] is None
        assert node.properties["service_role"] is None

    def test_multiple_detectors(self):
        """Test normalizing multiple detectors."""
        records = [
            {
                "Detector": "det1",
                "Info": {"Status": "ENABLED"},
            },
            {
                "Detector": "det2",
                "Info": {"Status": "ENABLED"},
            },
        ]
        graph = normalize_guardduty(records)
        assert len(graph.nodes) == 2


class TestNormalizeSecurityHub:
    """Tests for Security Hub normalization."""

    def test_normalize_empty_records(self):
        """Test normalizing empty records."""
        graph = normalize_securityhub([])
        assert len(graph.nodes) == 0
        assert len(graph.edges) == 0

    def test_normalize_hub(self):
        """Test normalizing Security Hub."""
        records = [
            {
                "Hub": {
                    "HubArn": "arn:aws:securityhub:us-east-1:123456789012:hub/default",
                    "SubscribedAt": "2024-01-01T00:00:00Z",
                    "AutoEnableControls": True,
                }
            }
        ]
        graph = normalize_securityhub(records)
        assert len(graph.nodes) == 1
        node = graph.nodes[0]
        assert node.id == "arn:aws:securityhub:us-east-1:123456789012:hub/default"
        assert node.type == "SecurityHub"
        assert node.properties["auto_enable_controls"] is True
        assert node.provider == CloudProvider.AWS

    def test_hub_without_arn_skipped(self):
        """Test that hub without ARN is skipped."""
        records = [
            {
                "Hub": {
                    "SubscribedAt": "2024-01-01T00:00:00Z",
                    "AutoEnableControls": True,
                }
            }
        ]
        graph = normalize_securityhub(records)
        assert len(graph.nodes) == 0

    def test_normalize_finding(self):
        """Test normalizing Security Hub finding."""
        records = [
            {
                "Findings": [
                    {
                        "Id": "arn:aws:securityhub:us-east-1:123456789012:finding/abc123",
                        "Title": "S3 bucket is public",
                        "Description": "The S3 bucket allows public access",
                        "Severity": {"Label": "HIGH", "Normalized": 70},
                        "ProductArn": "arn:aws:securityhub:us-east-1::product/aws/config",
                        "Workflow": {"Status": "NEW"},
                        "Compliance": {"Status": "FAILED"},
                        "Resources": [
                            {"Type": "AwsS3Bucket", "Id": "my-bucket"}
                        ],
                    }
                ]
            }
        ]
        graph = normalize_securityhub(records)
        assert len(graph.nodes) == 1
        node = graph.nodes[0]
        assert node.type == "SecurityFinding"
        assert node.properties["title"] == "S3 bucket is public"
        assert node.properties["severity_label"] == "HIGH"
        assert node.properties["severity_score"] == 70
        assert node.properties["status"] == "NEW"
        assert node.properties["compliance_status"] == "FAILED"
        assert node.properties["resource_type"] == "AwsS3Bucket"
        assert node.properties["resource_id"] == "my-bucket"

    def test_finding_without_id_skipped(self):
        """Test that finding without ID is skipped."""
        records = [
            {
                "Findings": [
                    {
                        "Title": "Some finding",
                        "Severity": {"Label": "MEDIUM"},
                    }
                ]
            }
        ]
        graph = normalize_securityhub(records)
        assert len(graph.nodes) == 0

    def test_finding_without_resources(self):
        """Test finding without resources."""
        records = [
            {
                "Findings": [
                    {
                        "Id": "finding-1",
                        "Title": "Generic finding",
                        "Severity": {"Label": "LOW"},
                    }
                ]
            }
        ]
        graph = normalize_securityhub(records)
        node = graph.nodes[0]
        assert node.properties["resource_type"] is None
        assert node.properties["resource_id"] is None

    def test_finding_with_empty_resources(self):
        """Test finding with empty resources list."""
        records = [
            {
                "Findings": [
                    {
                        "Id": "finding-1",
                        "Title": "Generic finding",
                        "Resources": [],
                    }
                ]
            }
        ]
        graph = normalize_securityhub(records)
        node = graph.nodes[0]
        assert node.properties["resource_type"] is None
        assert node.properties["resource_id"] is None

    def test_normalize_enabled_standards(self):
        """Test normalizing enabled security standards."""
        records = [
            {
                "EnabledStandards": [
                    {
                        "StandardsSubscriptionArn": "arn:aws:securityhub:us-east-1:123456789012:subscription/cis-aws-foundations-benchmark/v/1.2.0",
                        "StandardsArn": "arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.2.0",
                        "StandardsStatus": "READY",
                    }
                ]
            }
        ]
        graph = normalize_securityhub(records)
        assert len(graph.nodes) == 1
        node = graph.nodes[0]
        assert node.type == "SecurityStandard"
        assert node.properties["status"] == "READY"

    def test_standard_without_arn_skipped(self):
        """Test that standard without ARN is skipped."""
        records = [
            {
                "EnabledStandards": [
                    {
                        "StandardsArn": "arn:aws:securityhub:::ruleset/aws-foundational-security-best-practices/v/1.0.0",
                        "StandardsStatus": "READY",
                    }
                ]
            }
        ]
        graph = normalize_securityhub(records)
        assert len(graph.nodes) == 0

    def test_all_components(self):
        """Test normalizing hub, findings, and standards together."""
        records = [
            {
                "Hub": {
                    "HubArn": "arn:aws:securityhub:us-east-1:123456789012:hub/default",
                    "AutoEnableControls": True,
                },
                "Findings": [
                    {
                        "Id": "finding-1",
                        "Title": "Finding 1",
                        "Severity": {"Label": "HIGH"},
                    },
                    {
                        "Id": "finding-2",
                        "Title": "Finding 2",
                        "Severity": {"Label": "MEDIUM"},
                    },
                ],
                "EnabledStandards": [
                    {
                        "StandardsSubscriptionArn": "arn:aws:securityhub:us-east-1:123456789012:subscription/std1",
                        "StandardsStatus": "READY",
                    },
                ],
            }
        ]
        graph = normalize_securityhub(records)

        hub_nodes = [n for n in graph.nodes if n.type == "SecurityHub"]
        finding_nodes = [n for n in graph.nodes if n.type == "SecurityFinding"]
        standard_nodes = [n for n in graph.nodes if n.type == "SecurityStandard"]

        assert len(hub_nodes) == 1
        assert len(finding_nodes) == 2
        assert len(standard_nodes) == 1

    def test_multiple_findings(self):
        """Test normalizing multiple findings."""
        records = [
            {
                "Findings": [
                    {"Id": "finding-1", "Title": "Finding 1", "Severity": {"Label": "HIGH"}},
                    {"Id": "finding-2", "Title": "Finding 2", "Severity": {"Label": "MEDIUM"}},
                    {"Id": "finding-3", "Title": "Finding 3", "Severity": {"Label": "LOW"}},
                ]
            }
        ]
        graph = normalize_securityhub(records)
        assert len(graph.nodes) == 3
