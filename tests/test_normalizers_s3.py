"""Tests for arguscloud.normalizers.aws.s3 module."""

import pytest
from arguscloud.normalizers.aws.s3 import normalize_s3
from arguscloud.core.graph import CloudProvider


class TestNormalizeS3:
    """Tests for S3 bucket normalization."""

    def test_normalize_empty_records(self):
        """Test normalizing empty records."""
        graph = normalize_s3([])
        assert len(graph.nodes) == 0
        assert len(graph.edges) == 0

    def test_normalize_basic_bucket(self):
        """Test normalizing a basic S3 bucket."""
        records = [
            {
                "Bucket": {
                    "Name": "my-bucket",
                    "CreationDate": "2024-01-01T00:00:00Z",
                },
                "Location": "us-east-1",
            }
        ]
        graph = normalize_s3(records)
        assert len(graph.nodes) == 1
        bucket = graph.nodes[0]
        assert bucket.id == "arn:aws:s3:::my-bucket"
        assert bucket.type == "S3Bucket"
        assert bucket.properties["name"] == "my-bucket"
        assert bucket.properties["region"] == "us-east-1"
        assert bucket.provider == CloudProvider.AWS

    def test_normalize_public_bucket(self):
        """Test normalizing a public bucket."""
        records = [
            {
                "Bucket": {"Name": "public-bucket"},
                "PolicyStatus": {"PolicyStatus": {"IsPublic": True}},
            }
        ]
        graph = normalize_s3(records)
        bucket = graph.nodes[0]
        assert bucket.properties["is_public"] is True

    def test_normalize_bucket_with_public_access_block(self):
        """Test normalizing bucket with public access block."""
        records = [
            {
                "Bucket": {"Name": "blocked-bucket"},
                "PublicAccessBlock": {
                    "BlockPublicAcls": True,
                    "IgnorePublicAcls": True,
                    "BlockPublicPolicy": True,
                    "RestrictPublicBuckets": True,
                },
            }
        ]
        graph = normalize_s3(records)
        bucket = graph.nodes[0]
        assert bucket.properties["public_access_blocked"] is True

    def test_normalize_bucket_partial_public_access_block(self):
        """Test normalizing bucket with partial public access block."""
        records = [
            {
                "Bucket": {"Name": "partial-block"},
                "PublicAccessBlock": {
                    "BlockPublicAcls": True,
                    "IgnorePublicAcls": False,
                    "BlockPublicPolicy": True,
                    "RestrictPublicBuckets": True,
                },
            }
        ]
        graph = normalize_s3(records)
        bucket = graph.nodes[0]
        assert bucket.properties["public_access_blocked"] is False

    def test_normalize_encrypted_bucket(self):
        """Test normalizing an encrypted bucket."""
        records = [
            {
                "Bucket": {"Name": "encrypted-bucket"},
                "Encryption": {
                    "Rules": [
                        {
                            "ApplyServerSideEncryptionByDefault": {
                                "SSEAlgorithm": "aws:kms"
                            }
                        }
                    ]
                },
            }
        ]
        graph = normalize_s3(records)
        bucket = graph.nodes[0]
        assert bucket.properties["encrypted"] is True

    def test_normalize_unencrypted_bucket(self):
        """Test normalizing an unencrypted bucket."""
        records = [
            {
                "Bucket": {"Name": "unencrypted-bucket"},
                "Encryption": {},
            }
        ]
        graph = normalize_s3(records)
        bucket = graph.nodes[0]
        assert bucket.properties["encrypted"] is False

    def test_normalize_versioned_bucket(self):
        """Test normalizing a versioned bucket."""
        records = [
            {
                "Bucket": {"Name": "versioned-bucket"},
                "Versioning": {"Status": "Enabled"},
            }
        ]
        graph = normalize_s3(records)
        bucket = graph.nodes[0]
        assert bucket.properties["versioning_enabled"] is True

    def test_normalize_unversioned_bucket(self):
        """Test normalizing an unversioned bucket."""
        records = [
            {
                "Bucket": {"Name": "unversioned-bucket"},
                "Versioning": {"Status": "Suspended"},
            }
        ]
        graph = normalize_s3(records)
        bucket = graph.nodes[0]
        assert bucket.properties["versioning_enabled"] is False

    def test_normalize_bucket_with_logging(self):
        """Test normalizing bucket with logging enabled."""
        records = [
            {
                "Bucket": {"Name": "logged-bucket"},
                "Logging": {"TargetBucket": "log-bucket"},
            }
        ]
        graph = normalize_s3(records)
        bucket = graph.nodes[0]
        assert bucket.properties["logging_enabled"] is True

    def test_normalize_bucket_without_logging(self):
        """Test normalizing bucket without logging."""
        records = [
            {
                "Bucket": {"Name": "no-logging-bucket"},
            }
        ]
        graph = normalize_s3(records)
        bucket = graph.nodes[0]
        assert bucket.properties["logging_enabled"] is False

    def test_normalize_bucket_with_policy(self):
        """Test normalizing bucket with bucket policy."""
        records = [
            {
                "Bucket": {"Name": "policy-bucket"},
                "Policy": {
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": "*",
                            "Action": "s3:GetObject",
                            "Resource": "arn:aws:s3:::policy-bucket/*",
                        }
                    ]
                },
            }
        ]
        graph = normalize_s3(records)

        # Should have bucket and policy nodes
        bucket_nodes = [n for n in graph.nodes if n.type == "S3Bucket"]
        policy_nodes = [n for n in graph.nodes if n.type == "ResourcePolicy"]
        assert len(bucket_nodes) == 1
        assert len(policy_nodes) == 1

        # Should have policy edges
        policy_edges = [e for e in graph.edges if e.type == "ResourcePolicy"]
        assert len(policy_edges) == 1
        assert policy_edges[0].src == "arn:aws:s3:::policy-bucket"
        assert policy_edges[0].dst == "arn:aws:s3:::policy-bucket:policy"

        # Should have principal edges
        principal_edges = [e for e in graph.edges if e.type == "PolicyPrincipal"]
        assert len(principal_edges) == 1
        assert principal_edges[0].dst == "*"

    def test_normalize_bucket_with_multi_principal_policy(self):
        """Test normalizing bucket policy with multiple principals."""
        records = [
            {
                "Bucket": {"Name": "multi-principal"},
                "Policy": {
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {
                                "AWS": [
                                    "arn:aws:iam::111111111111:root",
                                    "arn:aws:iam::222222222222:root",
                                ]
                            },
                            "Action": "s3:*",
                            "Resource": "*",
                        }
                    ]
                },
            }
        ]
        graph = normalize_s3(records)
        principal_edges = [e for e in graph.edges if e.type == "PolicyPrincipal"]
        assert len(principal_edges) == 2

    def test_skip_bucket_without_name(self):
        """Test that buckets without name are skipped."""
        records = [{"Bucket": {}}]
        graph = normalize_s3(records)
        assert len(graph.nodes) == 0

    def test_normalize_bucket_default_location(self):
        """Test bucket without location defaults to us-east-1."""
        records = [
            {
                "Bucket": {"Name": "default-region"},
            }
        ]
        graph = normalize_s3(records)
        bucket = graph.nodes[0]
        assert bucket.properties["region"] == "us-east-1"
