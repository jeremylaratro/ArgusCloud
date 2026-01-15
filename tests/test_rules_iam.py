"""Tests for arguscloud.rules.aws.iam module."""

import pytest
from arguscloud.core.graph import Node, Edge, Severity
from arguscloud.core.base import RuleContext
from arguscloud.rules.aws.iam import (
    rule_open_trust,
    rule_assume_role_chain,
    rule_user_no_mfa,
    rule_user_multiple_keys,
)


class TestRuleOpenTrust:
    """Tests for the open trust policy rule."""

    def test_open_trust_detected(self):
        """Test detecting a role with wildcard trust."""
        nodes = [Node(id="role1", type="Role")]
        edges = [Edge(src="role1", dst="*", type="Trusts")]
        ctx = RuleContext(nodes=nodes, edges=edges)

        result = rule_open_trust(ctx)
        assert result.passed is False
        assert result.finding_count == 1
        assert result.attack_paths[0].rule_id == "aws-iam-open-trust"
        assert result.attack_paths[0].severity == Severity.HIGH

    def test_open_trust_not_detected_with_specific_principal(self):
        """Test no finding for specific principal."""
        nodes = [Node(id="role1", type="Role")]
        edges = [
            Edge(src="role1", dst="arn:aws:iam::123:root", type="Trusts")
        ]
        ctx = RuleContext(nodes=nodes, edges=edges)

        result = rule_open_trust(ctx)
        assert result.passed is True
        assert result.finding_count == 0

    def test_open_trust_multiple_roles(self):
        """Test detecting multiple roles with wildcard trust."""
        nodes = [
            Node(id="role1", type="Role"),
            Node(id="role2", type="Role"),
        ]
        edges = [
            Edge(src="role1", dst="*", type="Trusts"),
            Edge(src="role2", dst="*", type="Trusts"),
        ]
        ctx = RuleContext(nodes=nodes, edges=edges)

        result = rule_open_trust(ctx)
        assert result.finding_count == 2

    def test_open_trust_ignores_non_trust_edges(self):
        """Test that non-Trusts edges are ignored."""
        nodes = [Node(id="role1", type="Role")]
        edges = [Edge(src="role1", dst="*", type="AttachedPolicy")]
        ctx = RuleContext(nodes=nodes, edges=edges)

        result = rule_open_trust(ctx)
        assert result.passed is True


class TestRuleAssumeRoleChain:
    """Tests for the assume role chain detection rule."""

    def test_assume_role_chain_detected(self):
        """Test detecting trust chain leading to admin role."""
        nodes = [
            Node(id="user1", type="User"),
            Node(id="role1", type="Role", properties={"is_admin": False}),
            Node(id="admin-role", type="Role", properties={"is_admin": True}),
        ]
        edges = [
            Edge(src="role1", dst="user1", type="Trusts"),
            Edge(src="admin-role", dst="role1", type="Trusts"),
        ]
        ctx = RuleContext(nodes=nodes, edges=edges)

        result = rule_assume_role_chain(ctx)
        assert result.passed is False
        assert result.finding_count >= 1

    def test_assume_role_chain_not_detected_no_admin(self):
        """Test no finding when no admin role in chain."""
        nodes = [
            Node(id="user1", type="User"),
            Node(id="role1", type="Role", properties={"is_admin": False}),
            Node(id="role2", type="Role", properties={"is_admin": False}),
        ]
        edges = [
            Edge(src="role1", dst="user1", type="Trusts"),
            Edge(src="role2", dst="role1", type="Trusts"),
        ]
        ctx = RuleContext(nodes=nodes, edges=edges)

        result = rule_assume_role_chain(ctx)
        assert result.passed is True

    def test_assume_role_chain_ignores_wildcard(self):
        """Test that wildcard principals are filtered from chain analysis."""
        nodes = [
            Node(id="admin-role", type="Role", properties={"is_admin": True}),
        ]
        edges = [
            Edge(src="admin-role", dst="*", type="Trusts"),
        ]
        ctx = RuleContext(nodes=nodes, edges=edges)

        result = rule_assume_role_chain(ctx)
        assert result.passed is True

    def test_assume_role_chain_direct_trust(self):
        """Test direct trust to admin role."""
        nodes = [
            Node(id="user1", type="User"),
            Node(id="admin-role", type="Role", properties={"is_admin": True}),
        ]
        edges = [
            Edge(src="admin-role", dst="user1", type="Trusts"),
        ]
        ctx = RuleContext(nodes=nodes, edges=edges)

        result = rule_assume_role_chain(ctx)
        assert result.passed is False


class TestRuleUserNoMfa:
    """Tests for the user without MFA rule."""

    def test_user_no_mfa_detected(self):
        """Test detecting user with console access but no MFA."""
        nodes = [
            Node(
                id="user1",
                type="User",
                properties={
                    "name": "alice",
                    "has_console_access": True,
                    "has_mfa": False,
                },
            )
        ]
        ctx = RuleContext(nodes=nodes, edges=[])

        result = rule_user_no_mfa(ctx)
        assert result.passed is False
        assert result.finding_count == 1
        assert result.attack_paths[0].severity == Severity.HIGH

    def test_user_with_mfa_passes(self):
        """Test no finding for user with MFA."""
        nodes = [
            Node(
                id="user1",
                type="User",
                properties={
                    "name": "alice",
                    "has_console_access": True,
                    "has_mfa": True,
                },
            )
        ]
        ctx = RuleContext(nodes=nodes, edges=[])

        result = rule_user_no_mfa(ctx)
        assert result.passed is True

    def test_user_no_console_access_passes(self):
        """Test no finding for user without console access."""
        nodes = [
            Node(
                id="user1",
                type="User",
                properties={
                    "name": "api-user",
                    "has_console_access": False,
                    "has_mfa": False,
                },
            )
        ]
        ctx = RuleContext(nodes=nodes, edges=[])

        result = rule_user_no_mfa(ctx)
        assert result.passed is True

    def test_ignores_non_user_nodes(self):
        """Test that non-User nodes are ignored."""
        nodes = [
            Node(
                id="role1",
                type="Role",
                properties={"has_console_access": True, "has_mfa": False},
            )
        ]
        ctx = RuleContext(nodes=nodes, edges=[])

        result = rule_user_no_mfa(ctx)
        assert result.passed is True


class TestRuleUserMultipleKeys:
    """Tests for the user with multiple access keys rule."""

    def test_multiple_keys_detected(self):
        """Test detecting user with multiple active keys."""
        nodes = [
            Node(
                id="user1",
                type="User",
                properties={"name": "alice", "active_access_keys": 2},
            )
        ]
        ctx = RuleContext(nodes=nodes, edges=[])

        result = rule_user_multiple_keys(ctx)
        assert result.passed is False
        assert result.finding_count == 1
        assert result.attack_paths[0].severity == Severity.MEDIUM

    def test_single_key_passes(self):
        """Test no finding for user with single key."""
        nodes = [
            Node(
                id="user1",
                type="User",
                properties={"name": "alice", "active_access_keys": 1},
            )
        ]
        ctx = RuleContext(nodes=nodes, edges=[])

        result = rule_user_multiple_keys(ctx)
        assert result.passed is True

    def test_no_keys_passes(self):
        """Test no finding for user with no active keys."""
        nodes = [
            Node(
                id="user1",
                type="User",
                properties={"name": "alice", "active_access_keys": 0},
            )
        ]
        ctx = RuleContext(nodes=nodes, edges=[])

        result = rule_user_multiple_keys(ctx)
        assert result.passed is True

    def test_multiple_users(self):
        """Test detecting multiple users with multiple keys."""
        nodes = [
            Node(id="user1", type="User", properties={"active_access_keys": 2}),
            Node(id="user2", type="User", properties={"active_access_keys": 1}),
            Node(id="user3", type="User", properties={"active_access_keys": 3}),
        ]
        ctx = RuleContext(nodes=nodes, edges=[])

        result = rule_user_multiple_keys(ctx)
        assert result.finding_count == 2
