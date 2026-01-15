"""Tests for arguscloud.rules.aws.ec2 module."""

import pytest
from arguscloud.core.graph import Node, Severity
from arguscloud.core.base import RuleContext
from arguscloud.rules.aws.ec2 import (
    rule_open_security_group,
    rule_imds_exposure,
    rule_public_snapshot,
    rule_public_ami,
    rule_unencrypted_snapshot,
)


class TestRuleOpenSecurityGroup:
    """Tests for the open security group rule."""

    def test_open_sg_detected(self):
        """Test detecting security group open to internet."""
        nodes = [
            Node(
                id="sg-123",
                type="SecurityGroup",
                properties={"name": "web-sg", "has_open_ingress": True},
            )
        ]
        ctx = RuleContext(nodes=nodes, edges=[])

        result = rule_open_security_group(ctx)
        assert result.passed is False
        assert result.finding_count == 1
        assert result.attack_paths[0].severity == Severity.MEDIUM
        assert result.attack_paths[0].dst == "internet"

    def test_closed_sg_passes(self):
        """Test no finding for closed security group."""
        nodes = [
            Node(
                id="sg-123",
                type="SecurityGroup",
                properties={"name": "private-sg", "has_open_ingress": False},
            )
        ]
        ctx = RuleContext(nodes=nodes, edges=[])

        result = rule_open_security_group(ctx)
        assert result.passed is True

    def test_multiple_sgs(self):
        """Test detecting multiple open security groups."""
        nodes = [
            Node(id="sg-1", type="SecurityGroup", properties={"has_open_ingress": True}),
            Node(id="sg-2", type="SecurityGroup", properties={"has_open_ingress": False}),
            Node(id="sg-3", type="SecurityGroup", properties={"has_open_ingress": True}),
        ]
        ctx = RuleContext(nodes=nodes, edges=[])

        result = rule_open_security_group(ctx)
        assert result.finding_count == 2


class TestRuleImdsExposure:
    """Tests for the IMDS exposure rule."""

    def test_imds_exposure_detected(self):
        """Test detecting public instance with IAM role."""
        nodes = [
            Node(
                id="i-123",
                type="EC2Instance",
                properties={
                    "public_ip": "1.2.3.4",
                    "iam_instance_profile": "arn:aws:iam::123:instance-profile/MyRole",
                    "imds_v2_required": False,
                },
            )
        ]
        ctx = RuleContext(nodes=nodes, edges=[])

        result = rule_imds_exposure(ctx)
        assert result.passed is False
        assert result.finding_count == 1
        # Without IMDSv2, severity should be HIGH
        assert result.attack_paths[0].severity == Severity.HIGH

    def test_imds_exposure_with_v2_medium(self):
        """Test that IMDSv2 required reduces severity to MEDIUM."""
        nodes = [
            Node(
                id="i-123",
                type="EC2Instance",
                properties={
                    "public_ip": "1.2.3.4",
                    "iam_instance_profile": "arn:aws:iam::123:instance-profile/MyRole",
                    "imds_v2_required": True,
                },
            )
        ]
        ctx = RuleContext(nodes=nodes, edges=[])

        result = rule_imds_exposure(ctx)
        assert result.finding_count == 1
        assert result.attack_paths[0].severity == Severity.MEDIUM

    def test_private_instance_passes(self):
        """Test no finding for private instance with role."""
        nodes = [
            Node(
                id="i-123",
                type="EC2Instance",
                properties={
                    "public_ip": None,
                    "iam_instance_profile": "arn:aws:iam::123:instance-profile/MyRole",
                },
            )
        ]
        ctx = RuleContext(nodes=nodes, edges=[])

        result = rule_imds_exposure(ctx)
        assert result.passed is True

    def test_public_instance_no_role_passes(self):
        """Test no finding for public instance without role."""
        nodes = [
            Node(
                id="i-123",
                type="EC2Instance",
                properties={
                    "public_ip": "1.2.3.4",
                    "iam_instance_profile": None,
                },
            )
        ]
        ctx = RuleContext(nodes=nodes, edges=[])

        result = rule_imds_exposure(ctx)
        assert result.passed is True


class TestRulePublicSnapshot:
    """Tests for the public snapshot rule."""

    def test_public_snapshot_detected(self):
        """Test detecting a public snapshot."""
        nodes = [
            Node(
                id="snap-123",
                type="Snapshot",
                properties={"is_public": True},
            )
        ]
        ctx = RuleContext(nodes=nodes, edges=[])

        result = rule_public_snapshot(ctx)
        assert result.passed is False
        assert result.finding_count == 1
        assert result.attack_paths[0].severity == Severity.HIGH

    def test_private_snapshot_passes(self):
        """Test no finding for private snapshot."""
        nodes = [
            Node(
                id="snap-123",
                type="Snapshot",
                properties={"is_public": False},
            )
        ]
        ctx = RuleContext(nodes=nodes, edges=[])

        result = rule_public_snapshot(ctx)
        assert result.passed is True


class TestRulePublicAmi:
    """Tests for the public AMI rule."""

    def test_public_ami_detected(self):
        """Test detecting a public AMI."""
        nodes = [
            Node(
                id="ami-123",
                type="AMI",
                properties={"name": "my-ami", "public": True},
            )
        ]
        ctx = RuleContext(nodes=nodes, edges=[])

        result = rule_public_ami(ctx)
        assert result.passed is False
        assert result.finding_count == 1
        assert result.attack_paths[0].severity == Severity.MEDIUM

    def test_private_ami_passes(self):
        """Test no finding for private AMI."""
        nodes = [
            Node(
                id="ami-123",
                type="AMI",
                properties={"name": "my-ami", "public": False},
            )
        ]
        ctx = RuleContext(nodes=nodes, edges=[])

        result = rule_public_ami(ctx)
        assert result.passed is True


class TestRuleUnencryptedSnapshot:
    """Tests for the unencrypted snapshot rule."""

    def test_unencrypted_snapshot_detected(self):
        """Test detecting an unencrypted snapshot."""
        nodes = [
            Node(
                id="snap-123",
                type="Snapshot",
                properties={"encrypted": False},
            )
        ]
        ctx = RuleContext(nodes=nodes, edges=[])

        result = rule_unencrypted_snapshot(ctx)
        assert result.passed is False
        assert result.finding_count == 1
        assert result.attack_paths[0].severity == Severity.MEDIUM

    def test_encrypted_snapshot_passes(self):
        """Test no finding for encrypted snapshot."""
        nodes = [
            Node(
                id="snap-123",
                type="Snapshot",
                properties={"encrypted": True},
            )
        ]
        ctx = RuleContext(nodes=nodes, edges=[])

        result = rule_unencrypted_snapshot(ctx)
        assert result.passed is True

    def test_snapshot_without_encrypted_field(self):
        """Test handling of snapshot without encrypted field."""
        nodes = [
            Node(
                id="snap-123",
                type="Snapshot",
                properties={},
            )
        ]
        ctx = RuleContext(nodes=nodes, edges=[])

        result = rule_unencrypted_snapshot(ctx)
        # Should pass because encrypted is not explicitly False
        assert result.passed is True
