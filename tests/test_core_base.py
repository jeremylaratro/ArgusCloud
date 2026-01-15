"""Tests for arguscloud.core.base module."""

import pytest
from arguscloud.core.graph import (
    Node,
    Edge,
    AttackPath,
    GraphData,
    Severity,
    CloudProvider,
)
from arguscloud.core.base import (
    CollectorResult,
    BaseCollector,
    BaseNormalizer,
    BaseRule,
    RuleContext,
    RuleResult,
    extract_principals,
    is_admin_policy,
)


class TestCollectorResult:
    """Tests for CollectorResult dataclass."""

    def test_collector_result_ok(self):
        """Test creating a successful collector result."""
        result = CollectorResult(
            service="iam",
            status="ok",
            records=[{"Role": {"Arn": "arn:aws:iam::123:role/test"}}],
        )
        assert result.service == "iam"
        assert result.status == "ok"
        assert len(result.records) == 1
        assert result.detail == ""
        assert result.error is None

    def test_collector_result_error(self):
        """Test creating an error collector result."""
        exc = Exception("Access denied")
        result = CollectorResult(
            service="s3",
            status="error",
            detail="Access denied",
            error=exc,
        )
        assert result.status == "error"
        assert result.detail == "Access denied"
        assert result.error is exc
        assert result.records == []

    def test_collector_result_skipped(self):
        """Test creating a skipped collector result."""
        result = CollectorResult(
            service="organizations",
            status="skipped",
            detail="Not in org",
        )
        assert result.status == "skipped"
        assert result.detail == "Not in org"


class TestRuleContext:
    """Tests for RuleContext dataclass."""

    @pytest.fixture
    def sample_context(self):
        """Create a sample context with nodes and edges."""
        nodes = [
            Node(id="role1", type="Role", properties={"is_admin": True}),
            Node(id="role2", type="Role", properties={"is_admin": False}),
            Node(id="user1", type="User", properties={"name": "alice"}),
            Node(id="bucket1", type="S3Bucket", properties={"name": "data"}),
        ]
        edges = [
            Edge(src="role1", dst="user1", type="Trusts"),
            Edge(src="role2", dst="*", type="Trusts"),
            Edge(src="user1", dst="bucket1", type="CanAccess"),
        ]
        return RuleContext(nodes=nodes, edges=edges)

    def test_rule_context_creation(self, sample_context):
        """Test creating a rule context."""
        assert len(sample_context.nodes) == 4
        assert len(sample_context.edges) == 3

    def test_get_nodes_by_type(self, sample_context):
        """Test filtering nodes by type."""
        roles = sample_context.get_nodes_by_type("Role")
        assert len(roles) == 2
        assert all(n.type == "Role" for n in roles)

        users = sample_context.get_nodes_by_type("User")
        assert len(users) == 1
        assert users[0].id == "user1"

        nonexistent = sample_context.get_nodes_by_type("Lambda")
        assert len(nonexistent) == 0

    def test_get_edges_by_type(self, sample_context):
        """Test filtering edges by type."""
        trust_edges = sample_context.get_edges_by_type("Trusts")
        assert len(trust_edges) == 2
        assert all(e.type == "Trusts" for e in trust_edges)

        access_edges = sample_context.get_edges_by_type("CanAccess")
        assert len(access_edges) == 1

        nonexistent = sample_context.get_edges_by_type("NonExistent")
        assert len(nonexistent) == 0

    def test_get_node_by_id(self, sample_context):
        """Test getting a node by ID."""
        role = sample_context.get_node_by_id("role1")
        assert role is not None
        assert role.type == "Role"
        assert role.properties["is_admin"] is True

        nonexistent = sample_context.get_node_by_id("nonexistent")
        assert nonexistent is None

    def test_rule_context_with_provider(self):
        """Test rule context with provider filter."""
        ctx = RuleContext(nodes=[], edges=[], provider=CloudProvider.GCP)
        assert ctx.provider == CloudProvider.GCP


class TestRuleResult:
    """Tests for RuleResult dataclass."""

    def test_rule_result_passed(self):
        """Test creating a passed rule result."""
        result = RuleResult(
            rule_id="test-rule",
            description="Test rule passed",
            passed=True,
        )
        assert result.rule_id == "test-rule"
        assert result.passed is True
        assert result.attack_paths == []
        assert result.finding_count == 0

    def test_rule_result_with_findings(self):
        """Test creating a rule result with findings."""
        findings = [
            AttackPath(src="a", dst="b", rule_id="test", severity=Severity.HIGH),
            AttackPath(src="c", dst="d", rule_id="test", severity=Severity.MEDIUM),
        ]
        result = RuleResult(
            rule_id="test-rule",
            description="Test rule",
            attack_paths=findings,
            passed=False,
        )
        assert result.passed is False
        assert result.finding_count == 2
        assert len(result.attack_paths) == 2


class TestExtractPrincipals:
    """Tests for extract_principals function."""

    def test_extract_wildcard_principal(self):
        """Test extracting wildcard principal."""
        policy = {
            "Statement": [
                {"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject"}
            ]
        }
        principals = extract_principals(policy)
        assert "*" in principals

    def test_extract_aws_principal(self):
        """Test extracting AWS principal."""
        policy = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": "arn:aws:iam::123456789012:root"},
                    "Action": "sts:AssumeRole",
                }
            ]
        }
        principals = extract_principals(policy)
        assert "arn:aws:iam::123456789012:root" in principals

    def test_extract_multiple_principals(self):
        """Test extracting multiple AWS principals."""
        policy = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": [
                            "arn:aws:iam::111111111111:root",
                            "arn:aws:iam::222222222222:root",
                        ]
                    },
                    "Action": "sts:AssumeRole",
                }
            ]
        }
        principals = extract_principals(policy)
        assert len(principals) == 2
        assert "arn:aws:iam::111111111111:root" in principals
        assert "arn:aws:iam::222222222222:root" in principals

    def test_extract_service_principal(self):
        """Test extracting service principal."""
        policy = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "lambda.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ]
        }
        principals = extract_principals(policy)
        assert "lambda.amazonaws.com" in principals

    def test_extract_multiple_services(self):
        """Test extracting multiple service principals."""
        policy = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "Service": ["ec2.amazonaws.com", "lambda.amazonaws.com"]
                    },
                    "Action": "sts:AssumeRole",
                }
            ]
        }
        principals = extract_principals(policy)
        assert "ec2.amazonaws.com" in principals
        assert "lambda.amazonaws.com" in principals

    def test_extract_from_multiple_statements(self):
        """Test extracting principals from multiple statements."""
        policy = {
            "Statement": [
                {"Effect": "Allow", "Principal": "*"},
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": "arn:aws:iam::123:role/test"},
                },
            ]
        }
        principals = extract_principals(policy)
        assert "*" in principals
        assert "arn:aws:iam::123:role/test" in principals

    def test_extract_empty_policy(self):
        """Test extracting from empty policy."""
        principals = extract_principals({})
        assert principals == []

    def test_extract_no_statements(self):
        """Test extracting from policy with no statements."""
        policy = {"Version": "2012-10-17"}
        principals = extract_principals(policy)
        assert principals == []

    def test_extract_single_statement_not_list(self):
        """Test extracting when Statement is not a list."""
        policy = {
            "Statement": {
                "Effect": "Allow",
                "Principal": "*",
                "Action": "s3:*",
            }
        }
        principals = extract_principals(policy)
        assert "*" in principals

    def test_extract_mixed_principal_types(self):
        """Test extracting mixed AWS and Service principals."""
        policy = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": "arn:aws:iam::123:root",
                        "Service": "ecs-tasks.amazonaws.com",
                    },
                    "Action": "sts:AssumeRole",
                }
            ]
        }
        principals = extract_principals(policy)
        assert "arn:aws:iam::123:root" in principals
        assert "ecs-tasks.amazonaws.com" in principals


class TestIsAdminPolicy:
    """Tests for is_admin_policy function."""

    def test_admin_policy_star_star(self):
        """Test detecting admin policy with Action: * and Resource: *."""
        policy = {
            "Statement": [
                {"Effect": "Allow", "Action": "*", "Resource": "*"}
            ]
        }
        assert is_admin_policy(policy) is True

    def test_admin_policy_list_with_star(self):
        """Test detecting admin when * is in action list."""
        policy = {
            "Statement": [
                {"Effect": "Allow", "Action": ["s3:*", "*"], "Resource": "*"}
            ]
        }
        assert is_admin_policy(policy) is True

    def test_admin_policy_resource_list_with_star(self):
        """Test detecting admin when * is in resource list."""
        policy = {
            "Statement": [
                {"Effect": "Allow", "Action": "*", "Resource": ["arn:aws:s3:::bucket", "*"]}
            ]
        }
        assert is_admin_policy(policy) is True

    def test_not_admin_limited_action(self):
        """Test non-admin policy with limited actions."""
        policy = {
            "Statement": [
                {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}
            ]
        }
        assert is_admin_policy(policy) is False

    def test_not_admin_limited_resource(self):
        """Test non-admin policy with limited resources."""
        policy = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "*",
                    "Resource": "arn:aws:s3:::my-bucket/*",
                }
            ]
        }
        assert is_admin_policy(policy) is False

    def test_not_admin_deny_effect(self):
        """Test that Deny statements are not considered admin."""
        policy = {
            "Statement": [
                {"Effect": "Deny", "Action": "*", "Resource": "*"}
            ]
        }
        assert is_admin_policy(policy) is False

    def test_empty_policy(self):
        """Test empty policy is not admin."""
        assert is_admin_policy({}) is False

    def test_no_statements(self):
        """Test policy with no statements is not admin."""
        policy = {"Version": "2012-10-17"}
        assert is_admin_policy(policy) is False

    def test_single_statement_not_list(self):
        """Test when Statement is a dict not a list."""
        policy = {
            "Statement": {"Effect": "Allow", "Action": "*", "Resource": "*"}
        }
        assert is_admin_policy(policy) is True

    def test_multiple_statements_one_admin(self):
        """Test that any admin statement is detected."""
        policy = {
            "Statement": [
                {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"},
                {"Effect": "Allow", "Action": "*", "Resource": "*"},
            ]
        }
        assert is_admin_policy(policy) is True
