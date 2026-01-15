"""Tests for arguscloud.rules.aws.logging module."""

import pytest
from arguscloud.core.graph import Node, Severity
from arguscloud.core.base import RuleContext
from arguscloud.rules.aws.logging import (
    rule_missing_cloudtrail,
    rule_cloudtrail_not_logging,
    rule_missing_guardduty,
    rule_missing_config,
    rule_cloudwatch_no_retention,
)


class TestRuleMissingCloudtrail:
    """Tests for the missing CloudTrail rule."""

    def test_missing_cloudtrail_detected(self):
        """Test detecting account without CloudTrail."""
        nodes = [
            Node(id="account:123456789012", type="Account", properties={})
        ]
        ctx = RuleContext(nodes=nodes, edges=[])

        result = rule_missing_cloudtrail(ctx)
        assert result.passed is False
        assert result.finding_count == 1
        assert result.attack_paths[0].severity == Severity.HIGH

    def test_cloudtrail_present_and_logging(self):
        """Test no finding when CloudTrail is logging."""
        nodes = [
            Node(id="account:123456789012", type="Account", properties={}),
            Node(
                id="trail-1",
                type="CloudTrailTrail",
                properties={"is_logging": True},
            ),
        ]
        ctx = RuleContext(nodes=nodes, edges=[])

        result = rule_missing_cloudtrail(ctx)
        assert result.passed is True

    def test_cloudtrail_present_but_not_logging(self):
        """Test finding when CloudTrail exists but not logging."""
        nodes = [
            Node(id="account:123456789012", type="Account", properties={}),
            Node(
                id="trail-1",
                type="CloudTrailTrail",
                properties={"is_logging": False},
            ),
        ]
        ctx = RuleContext(nodes=nodes, edges=[])

        result = rule_missing_cloudtrail(ctx)
        assert result.passed is False

    def test_multiple_trails_one_logging(self):
        """Test passes when at least one trail is logging."""
        nodes = [
            Node(id="account:123", type="Account"),
            Node(id="trail-1", type="CloudTrailTrail", properties={"is_logging": False}),
            Node(id="trail-2", type="CloudTrailTrail", properties={"is_logging": True}),
        ]
        ctx = RuleContext(nodes=nodes, edges=[])

        result = rule_missing_cloudtrail(ctx)
        assert result.passed is True


class TestRuleCloudtrailNotLogging:
    """Tests for the CloudTrail not logging rule."""

    def test_cloudtrail_not_logging_detected(self):
        """Test detecting disabled CloudTrail trail."""
        nodes = [
            Node(
                id="trail-1",
                type="CloudTrailTrail",
                properties={"name": "main-trail", "is_logging": False},
            )
        ]
        ctx = RuleContext(nodes=nodes, edges=[])

        result = rule_cloudtrail_not_logging(ctx)
        assert result.passed is False
        assert result.finding_count == 1
        assert result.attack_paths[0].severity == Severity.HIGH

    def test_cloudtrail_logging_passes(self):
        """Test no finding when CloudTrail is logging."""
        nodes = [
            Node(
                id="trail-1",
                type="CloudTrailTrail",
                properties={"name": "main-trail", "is_logging": True},
            )
        ]
        ctx = RuleContext(nodes=nodes, edges=[])

        result = rule_cloudtrail_not_logging(ctx)
        assert result.passed is True

    def test_multiple_trails(self):
        """Test detecting multiple disabled trails."""
        nodes = [
            Node(id="trail-1", type="CloudTrailTrail", properties={"is_logging": False}),
            Node(id="trail-2", type="CloudTrailTrail", properties={"is_logging": True}),
            Node(id="trail-3", type="CloudTrailTrail", properties={"is_logging": False}),
        ]
        ctx = RuleContext(nodes=nodes, edges=[])

        result = rule_cloudtrail_not_logging(ctx)
        assert result.finding_count == 2


class TestRuleMissingGuardduty:
    """Tests for the missing GuardDuty rule."""

    def test_missing_guardduty_detected(self):
        """Test detecting account without GuardDuty."""
        nodes = [
            Node(id="account:123456789012", type="Account", properties={})
        ]
        ctx = RuleContext(nodes=nodes, edges=[])

        result = rule_missing_guardduty(ctx)
        assert result.passed is False
        assert result.finding_count == 1
        assert result.attack_paths[0].severity == Severity.MEDIUM

    def test_guardduty_present(self):
        """Test no finding when GuardDuty is enabled."""
        nodes = [
            Node(id="account:123456789012", type="Account", properties={}),
            Node(id="detector-1", type="GuardDutyDetector", properties={}),
        ]
        ctx = RuleContext(nodes=nodes, edges=[])

        result = rule_missing_guardduty(ctx)
        assert result.passed is True

    def test_no_account_no_finding(self):
        """Test no finding when there's no account node."""
        nodes = [
            Node(id="role-1", type="Role", properties={})
        ]
        ctx = RuleContext(nodes=nodes, edges=[])

        result = rule_missing_guardduty(ctx)
        assert result.passed is True


class TestRuleMissingConfig:
    """Tests for the missing AWS Config rule."""

    def test_missing_config_detected(self):
        """Test detecting account without AWS Config."""
        nodes = [
            Node(id="account:123456789012", type="Account", properties={})
        ]
        ctx = RuleContext(nodes=nodes, edges=[])

        result = rule_missing_config(ctx)
        assert result.passed is False
        assert result.finding_count == 1
        assert result.attack_paths[0].severity == Severity.LOW

    def test_config_present_and_recording(self):
        """Test no finding when Config is recording."""
        nodes = [
            Node(id="account:123456789012", type="Account", properties={}),
            Node(
                id="recorder-1",
                type="ConfigRecorder",
                properties={"recording": True},
            ),
        ]
        ctx = RuleContext(nodes=nodes, edges=[])

        result = rule_missing_config(ctx)
        assert result.passed is True

    def test_config_present_not_recording(self):
        """Test finding when Config exists but not recording."""
        nodes = [
            Node(id="account:123456789012", type="Account", properties={}),
            Node(
                id="recorder-1",
                type="ConfigRecorder",
                properties={"recording": False},
            ),
        ]
        ctx = RuleContext(nodes=nodes, edges=[])

        result = rule_missing_config(ctx)
        assert result.passed is False


class TestRuleCloudwatchNoRetention:
    """Tests for the CloudWatch Log Group without retention rule."""

    def test_no_retention_detected(self):
        """Test detecting log group without retention."""
        nodes = [
            Node(
                id="/aws/lambda/my-func",
                type="LogGroup",
                properties={"retention": None},
            )
        ]
        ctx = RuleContext(nodes=nodes, edges=[])

        result = rule_cloudwatch_no_retention(ctx)
        assert result.passed is False
        assert result.finding_count == 1
        assert result.attack_paths[0].severity == Severity.LOW

    def test_with_retention_passes(self):
        """Test no finding for log group with retention."""
        nodes = [
            Node(
                id="/aws/lambda/my-func",
                type="LogGroup",
                properties={"retention": 30},
            )
        ]
        ctx = RuleContext(nodes=nodes, edges=[])

        result = rule_cloudwatch_no_retention(ctx)
        assert result.passed is True

    def test_multiple_log_groups(self):
        """Test detecting multiple log groups without retention."""
        nodes = [
            Node(id="log-1", type="LogGroup", properties={"retention": None}),
            Node(id="log-2", type="LogGroup", properties={"retention": 7}),
            Node(id="log-3", type="LogGroup", properties={"retention": None}),
        ]
        ctx = RuleContext(nodes=nodes, edges=[])

        result = rule_cloudwatch_no_retention(ctx)
        assert result.finding_count == 2
