"""Tests for arguscloud.core.registry module."""

import pytest
from arguscloud.core.registry import (
    BaseRegistry,
    CollectorRegistry,
    NormalizerRegistry,
    RuleRegistry,
)


class TestBaseRegistry:
    """Tests for BaseRegistry class."""

    def test_registry_creation(self):
        """Test creating a registry."""
        registry = CollectorRegistry()
        assert len(registry) == 0

    def test_register_item(self):
        """Test registering an item."""
        registry = CollectorRegistry()

        def my_collector():
            pass

        registry.register(
            name="test",
            item=my_collector,
            provider="aws",
            description="Test collector",
        )
        assert len(registry) == 1
        assert "aws:test" in registry

    def test_get_item(self):
        """Test getting an item by name and provider."""
        registry = CollectorRegistry()

        def my_collector():
            return "collected"

        registry.register(name="iam", item=my_collector, provider="aws")
        retrieved = registry.get("iam", provider="aws")
        assert retrieved is my_collector
        assert retrieved() == "collected"

    def test_get_nonexistent(self):
        """Test getting nonexistent item returns None."""
        registry = CollectorRegistry()
        result = registry.get("nonexistent", provider="aws")
        assert result is None

    def test_get_all(self):
        """Test getting all items."""
        registry = CollectorRegistry()
        registry.register(name="a", item=lambda: 1, provider="aws")
        registry.register(name="b", item=lambda: 2, provider="aws")
        registry.register(name="c", item=lambda: 3, provider="gcp")

        all_items = registry.get_all()
        assert len(all_items) == 3

    def test_get_all_filtered_by_provider(self):
        """Test getting all items filtered by provider."""
        registry = CollectorRegistry()
        registry.register(name="a", item=lambda: 1, provider="aws")
        registry.register(name="b", item=lambda: 2, provider="aws")
        registry.register(name="c", item=lambda: 3, provider="gcp")

        aws_items = registry.get_all(provider="aws")
        assert len(aws_items) == 2
        assert all(k.startswith("aws:") for k in aws_items.keys())

        gcp_items = registry.get_all(provider="gcp")
        assert len(gcp_items) == 1

    def test_list_names(self):
        """Test listing registered names."""
        registry = CollectorRegistry()
        registry.register(name="iam", item=lambda: None, provider="aws")
        registry.register(name="s3", item=lambda: None, provider="aws")
        registry.register(name="compute", item=lambda: None, provider="gcp")

        names = registry.list_names()
        assert len(names) == 3
        assert "iam" in names
        assert "s3" in names
        assert "compute" in names

    def test_list_names_filtered(self):
        """Test listing names filtered by provider."""
        registry = CollectorRegistry()
        registry.register(name="iam", item=lambda: None, provider="aws")
        registry.register(name="s3", item=lambda: None, provider="aws")
        registry.register(name="compute", item=lambda: None, provider="gcp")

        aws_names = registry.list_names(provider="aws")
        assert len(aws_names) == 2
        assert "iam" in aws_names
        assert "s3" in aws_names
        assert "compute" not in aws_names

    def test_get_metadata(self):
        """Test getting metadata for an item."""
        registry = CollectorRegistry()
        registry.register(
            name="test",
            item=lambda: None,
            provider="aws",
            description="Test description",
            services=["iam", "sts"],
        )

        metadata = registry.get_metadata("test", provider="aws")
        assert metadata is not None
        assert metadata["name"] == "test"
        assert metadata["provider"] == "aws"
        assert metadata["description"] == "Test description"
        assert metadata["services"] == ["iam", "sts"]

    def test_get_metadata_nonexistent(self):
        """Test getting metadata for nonexistent item."""
        registry = CollectorRegistry()
        metadata = registry.get_metadata("nonexistent")
        assert metadata is None

    def test_contains(self):
        """Test checking if key exists in registry."""
        registry = CollectorRegistry()
        registry.register(name="test", item=lambda: None, provider="aws")

        assert "aws:test" in registry
        assert "aws:nonexistent" not in registry

    def test_register_returns_item(self):
        """Test that register returns the registered item."""
        registry = CollectorRegistry()

        def my_func():
            return 42

        result = registry.register(name="test", item=my_func, provider="aws")
        assert result is my_func


class TestCollectorRegistry:
    """Tests for CollectorRegistry class."""

    def test_collector_decorator(self):
        """Test the collector decorator."""
        registry = CollectorRegistry()

        @registry.collector(
            name="iam",
            provider="aws",
            description="Collect IAM resources",
            services=["iam"],
        )
        def collect_iam():
            return {"roles": []}

        # Function should still be callable
        assert collect_iam() == {"roles": []}

        # Should be registered
        assert "aws:iam" in registry
        retrieved = registry.get("iam", provider="aws")
        assert retrieved is collect_iam

    def test_collector_decorator_default_provider(self):
        """Test collector decorator with default provider."""
        registry = CollectorRegistry()

        @registry.collector(name="test")
        def collect_test():
            pass

        assert "aws:test" in registry


class TestNormalizerRegistry:
    """Tests for NormalizerRegistry class."""

    def test_normalizer_decorator(self):
        """Test the normalizer decorator."""
        registry = NormalizerRegistry()

        @registry.normalizer(
            name="iam-roles",
            provider="aws",
            description="Normalize IAM roles",
            input_type="iam-roles",
        )
        def normalize_roles(records):
            return {"nodes": [], "edges": []}

        # Function should still be callable
        result = normalize_roles([])
        assert result == {"nodes": [], "edges": []}

        # Should be registered
        assert "aws:iam-roles" in registry
        metadata = registry.get_metadata("iam-roles", provider="aws")
        assert metadata["input_type"] == "iam-roles"

    def test_normalizer_decorator_default_values(self):
        """Test normalizer decorator with default values."""
        registry = NormalizerRegistry()

        @registry.normalizer(name="test")
        def normalize_test(records):
            pass

        assert "aws:test" in registry
        metadata = registry.get_metadata("test")
        assert metadata["input_type"] == ""


class TestRuleRegistry:
    """Tests for RuleRegistry class."""

    def test_rule_decorator(self):
        """Test the rule decorator."""
        registry = RuleRegistry()

        @registry.rule(
            rule_id="public-s3",
            provider="aws",
            description="Detect public S3 buckets",
            severity="high",
            tags=["s3", "data-exposure"],
        )
        def check_public_s3(ctx):
            return {"rule_id": "public-s3", "findings": []}

        # Function should still be callable
        result = check_public_s3(None)
        assert result["rule_id"] == "public-s3"

        # Should be registered
        assert "aws:public-s3" in registry
        metadata = registry.get_metadata("public-s3", provider="aws")
        assert metadata["severity"] == "high"
        assert "s3" in metadata["tags"]

    def test_rule_decorator_default_values(self):
        """Test rule decorator with default values."""
        registry = RuleRegistry()

        @registry.rule(rule_id="test-rule")
        def check_test(ctx):
            pass

        assert "aws:test-rule" in registry
        metadata = registry.get_metadata("test-rule")
        assert metadata["severity"] == "medium"
        assert metadata["tags"] == []


class TestRegistryIsolation:
    """Tests to ensure registries don't interfere with each other."""

    def test_separate_registries(self):
        """Test that each registry type is independent."""
        collectors = CollectorRegistry()
        normalizers = NormalizerRegistry()
        rules = RuleRegistry()

        collectors.register(name="test", item=lambda: "collector", provider="aws")
        normalizers.register(name="test", item=lambda: "normalizer", provider="aws")
        rules.register(name="test", item=lambda: "rule", provider="aws")

        assert collectors.get("test")() == "collector"
        assert normalizers.get("test")() == "normalizer"
        assert rules.get("test")() == "rule"

    def test_provider_isolation(self):
        """Test that different providers are isolated within registry."""
        registry = CollectorRegistry()
        registry.register(name="compute", item=lambda: "aws", provider="aws")
        registry.register(name="compute", item=lambda: "gcp", provider="gcp")

        assert registry.get("compute", provider="aws")() == "aws"
        assert registry.get("compute", provider="gcp")() == "gcp"
        assert len(registry) == 2
