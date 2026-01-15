"""Tests for arguscloud.plugins module.

This module tests the plugin system including discovery, loading,
unloading, and lifecycle management.
"""

from __future__ import annotations

import pytest
from unittest.mock import MagicMock, patch, PropertyMock
from typing import List

from arguscloud.plugins.base import Plugin, PluginInfo, VALID_PACKAGE_NAME_PATTERN
from arguscloud.plugins.registry import (
    PluginRegistry,
    get_registry,
    discover_plugins,
    load_plugins,
)


class TestPluginInfo:
    """Tests for PluginInfo dataclass."""

    def test_plugin_info_required_fields(self):
        """Test PluginInfo with required fields only."""
        info = PluginInfo(
            name="test-plugin",
            version="1.0.0",
            description="A test plugin"
        )

        assert info.name == "test-plugin"
        assert info.version == "1.0.0"
        assert info.description == "A test plugin"
        assert info.author == ""  # Default
        assert info.dependencies == []  # Default
        assert info.homepage == ""  # Default

    def test_plugin_info_all_fields(self):
        """Test PluginInfo with all fields."""
        info = PluginInfo(
            name="advanced-plugin",
            version="2.0.0",
            description="An advanced plugin",
            author="Test Author",
            dependencies=["requests>=2.0.0", "pyyaml"],
            homepage="https://example.com/plugin"
        )

        assert info.name == "advanced-plugin"
        assert info.author == "Test Author"
        assert len(info.dependencies) == 2
        assert info.homepage == "https://example.com/plugin"


class TestValidPackageNamePattern:
    """Tests for package name validation pattern."""

    def test_pattern_matches_simple_name(self):
        """Test pattern matches simple package names."""
        assert VALID_PACKAGE_NAME_PATTERN.match("requests") is not None
        assert VALID_PACKAGE_NAME_PATTERN.match("flask") is not None

    def test_pattern_matches_name_with_hyphen(self):
        """Test pattern matches names with hyphens."""
        assert VALID_PACKAGE_NAME_PATTERN.match("flask-cors") is not None
        assert VALID_PACKAGE_NAME_PATTERN.match("pyjwt") is not None

    def test_pattern_matches_name_with_underscore(self):
        """Test pattern matches names with underscores."""
        assert VALID_PACKAGE_NAME_PATTERN.match("pydantic_settings") is not None

    def test_pattern_matches_name_with_numbers(self):
        """Test pattern matches names with numbers."""
        assert VALID_PACKAGE_NAME_PATTERN.match("oauth2") is not None
        assert VALID_PACKAGE_NAME_PATTERN.match("s3transfer") is not None

    def test_pattern_rejects_names_starting_with_number(self):
        """Test pattern rejects names starting with numbers."""
        assert VALID_PACKAGE_NAME_PATTERN.match("2to3") is None

    def test_pattern_rejects_names_with_special_chars(self):
        """Test pattern rejects names with special characters."""
        assert VALID_PACKAGE_NAME_PATTERN.match("my.package") is None
        assert VALID_PACKAGE_NAME_PATTERN.match("my@package") is None


class MockPlugin(Plugin):
    """Mock plugin implementation for testing."""

    def __init__(self, name: str = "mock-plugin", version: str = "1.0.0", dependencies: List[str] = None):
        self._name = name
        self._version = version
        self._dependencies = dependencies or []
        self.loaded = False
        self.unloaded = False
        self.routes_registered = False
        self.cli_registered = False

    @property
    def info(self) -> PluginInfo:
        return PluginInfo(
            name=self._name,
            version=self._version,
            description="A mock plugin for testing",
            dependencies=self._dependencies
        )

    def on_load(self) -> None:
        self.loaded = True

    def on_unload(self) -> None:
        self.unloaded = True

    def register_routes(self, app) -> None:
        self.routes_registered = True

    def register_cli(self, subparsers) -> None:
        self.cli_registered = True


class TestPlugin:
    """Tests for Plugin base class."""

    def test_plugin_check_dependencies_empty(self):
        """Test check_dependencies with no dependencies."""
        plugin = MockPlugin()

        missing = plugin.check_dependencies()

        assert missing == []

    def test_plugin_check_dependencies_installed(self):
        """Test check_dependencies with installed dependencies."""
        plugin = MockPlugin(dependencies=["pytest"])

        # pytest should be installed in test environment
        missing = plugin.check_dependencies()

        assert missing == []

    def test_plugin_check_dependencies_missing(self):
        """Test check_dependencies with missing dependency."""
        plugin = MockPlugin(dependencies=["nonexistent_package_12345"])

        missing = plugin.check_dependencies()

        assert len(missing) == 1
        assert "nonexistent_package_12345" in missing

    def test_plugin_check_dependencies_parses_version_specs(self):
        """Test check_dependencies parses version specifiers."""
        plugin = MockPlugin(dependencies=["pytest>=7.0.0"])

        # Should parse out the version and check just the package
        missing = plugin.check_dependencies()

        assert missing == []

    def test_plugin_sanitize_package_name_simple(self):
        """Test _sanitize_package_name with simple name."""
        plugin = MockPlugin()

        result = plugin._sanitize_package_name("requests")

        assert result == "requests"

    def test_plugin_sanitize_package_name_with_version(self):
        """Test _sanitize_package_name strips version."""
        plugin = MockPlugin()

        assert plugin._sanitize_package_name("requests>=2.0.0") == "requests"
        assert plugin._sanitize_package_name("flask==2.0.0") == "flask"
        assert plugin._sanitize_package_name("pyjwt<3.0.0") == "pyjwt"

    def test_plugin_sanitize_package_name_converts_hyphen(self):
        """Test _sanitize_package_name converts hyphens to underscores."""
        plugin = MockPlugin()

        result = plugin._sanitize_package_name("flask-cors")

        assert result == "flask_cors"

    def test_plugin_sanitize_package_name_handles_extras(self):
        """Test _sanitize_package_name handles package extras."""
        plugin = MockPlugin()

        result = plugin._sanitize_package_name("pydantic[email]")

        assert result == "pydantic"

    def test_plugin_sanitize_package_name_rejects_invalid(self):
        """Test _sanitize_package_name rejects invalid names."""
        plugin = MockPlugin()

        result = plugin._sanitize_package_name("123invalid")

        assert result is None

    def test_plugin_repr(self):
        """Test Plugin __repr__."""
        plugin = MockPlugin(name="test-plugin", version="1.2.3")

        repr_str = repr(plugin)

        assert "test-plugin" in repr_str
        assert "1.2.3" in repr_str

    def test_plugin_default_methods(self):
        """Test Plugin default method implementations."""
        plugin = MockPlugin()

        # These should not raise
        plugin.on_load()
        plugin.on_unload()

        # Default implementations should return empty lists
        assert plugin.get_ui_scripts() == []
        assert plugin.get_ui_styles() == []


class TestPluginRegistry:
    """Tests for PluginRegistry class."""

    @pytest.fixture
    def registry(self) -> PluginRegistry:
        """Create a fresh registry instance."""
        return PluginRegistry()

    def test_registry_initial_state(self, registry: PluginRegistry):
        """Test registry is empty on creation."""
        assert registry.plugins == {}
        assert registry.plugin_count == 0
        assert registry.load_errors == {}

    def test_registry_discover_returns_list(self, registry: PluginRegistry):
        """Test discover returns list of plugin names."""
        with patch("importlib.metadata.entry_points") as mock_eps:
            mock_eps.return_value = []

            result = registry.discover()

            assert isinstance(result, list)

    def test_registry_discover_loads_entry_points(self, registry: PluginRegistry):
        """Test discover loads plugins from entry points."""
        mock_ep = MagicMock()
        mock_ep.name = "test-plugin"
        mock_ep.load.return_value = MockPlugin

        with patch("importlib.metadata.entry_points") as mock_eps:
            mock_eps.return_value = [mock_ep]

            result = registry.discover()

            assert "test-plugin" in result

    def test_registry_discover_records_invalid_plugins(self, registry: PluginRegistry):
        """Test discover records errors for invalid plugins."""
        mock_ep = MagicMock()
        mock_ep.name = "bad-plugin"
        mock_ep.load.side_effect = ImportError("Module not found")

        with patch("importlib.metadata.entry_points") as mock_eps:
            mock_eps.return_value = [mock_ep]

            registry.discover()

            assert "bad-plugin" in registry.load_errors

    def test_registry_load_creates_plugin_instance(self, registry: PluginRegistry):
        """Test load creates and initializes plugin instance."""
        registry._discovered["test-plugin"] = MockPlugin

        plugin = registry.load("test-plugin")

        assert plugin is not None
        assert plugin.loaded is True
        assert "test-plugin" in registry.plugins

    def test_registry_load_returns_existing(self, registry: PluginRegistry):
        """Test load returns existing plugin if already loaded."""
        registry._discovered["test-plugin"] = MockPlugin
        plugin1 = registry.load("test-plugin")
        plugin2 = registry.load("test-plugin")

        assert plugin1 is plugin2

    def test_registry_load_returns_none_for_undiscovered(self, registry: PluginRegistry):
        """Test load returns None for undiscovered plugin."""
        result = registry.load("nonexistent")

        assert result is None

    def test_registry_load_checks_dependencies(self, registry: PluginRegistry):
        """Test load checks plugin dependencies."""

        class PluginWithMissingDep(MockPlugin):
            @property
            def info(self):
                return PluginInfo(
                    name="dep-plugin",
                    version="1.0.0",
                    description="Plugin with missing dep",
                    dependencies=["nonexistent_pkg_12345"]
                )

        registry._discovered["dep-plugin"] = PluginWithMissingDep

        result = registry.load("dep-plugin")

        assert result is None
        assert "dep-plugin" in registry.load_errors
        assert "Missing dependencies" in registry.load_errors["dep-plugin"]

    def test_registry_load_records_initialization_errors(self, registry: PluginRegistry):
        """Test load records errors during plugin initialization."""

        class FailingPlugin(MockPlugin):
            def on_load(self):
                raise RuntimeError("Init failed")

        registry._discovered["failing-plugin"] = FailingPlugin

        result = registry.load("failing-plugin")

        assert result is None
        assert "failing-plugin" in registry.load_errors

    def test_registry_load_all_loads_discovered(self, registry: PluginRegistry):
        """Test load_all loads all discovered plugins."""
        registry._discovered["plugin-1"] = MockPlugin
        registry._discovered["plugin-2"] = MockPlugin

        count = registry.load_all()

        assert count == 2
        assert registry.plugin_count == 2

    def test_registry_load_all_calls_discover_if_empty(self, registry: PluginRegistry):
        """Test load_all calls discover if nothing discovered."""
        with patch.object(registry, "discover") as mock_discover:
            mock_discover.return_value = []

            registry.load_all()

            mock_discover.assert_called_once()

    def test_registry_unload_removes_plugin(self, registry: PluginRegistry):
        """Test unload removes plugin from registry."""
        registry._discovered["test-plugin"] = MockPlugin
        plugin = registry.load("test-plugin")

        result = registry.unload("test-plugin")

        assert result is True
        assert plugin.unloaded is True
        assert "test-plugin" not in registry.plugins

    def test_registry_unload_returns_false_for_missing(self, registry: PluginRegistry):
        """Test unload returns False for unloaded plugin."""
        result = registry.unload("nonexistent")

        assert result is False

    def test_registry_unload_handles_errors(self, registry: PluginRegistry):
        """Test unload handles errors during on_unload."""

        class FailingUnloadPlugin(MockPlugin):
            def on_unload(self):
                raise RuntimeError("Unload failed")

        registry._discovered["failing-plugin"] = FailingUnloadPlugin
        registry.load("failing-plugin")

        # Should not raise
        result = registry.unload("failing-plugin")

        assert result is True

    def test_registry_register_routes(self, registry: PluginRegistry):
        """Test register_routes calls plugin.register_routes."""
        registry._discovered["test-plugin"] = MockPlugin
        registry.load("test-plugin")

        mock_app = MagicMock()
        registry.register_routes(mock_app)

        plugin = registry.plugins["test-plugin"]
        assert plugin.routes_registered is True

    def test_registry_register_cli(self, registry: PluginRegistry):
        """Test register_cli calls plugin.register_cli."""
        registry._discovered["test-plugin"] = MockPlugin
        registry.load("test-plugin")

        mock_subparsers = MagicMock()
        registry.register_cli(mock_subparsers)

        plugin = registry.plugins["test-plugin"]
        assert plugin.cli_registered is True

    def test_registry_get_ui_assets(self, registry: PluginRegistry):
        """Test get_ui_assets collects assets from plugins."""

        class PluginWithAssets(MockPlugin):
            def get_ui_scripts(self):
                return ["console.log('test');"]

            def get_ui_styles(self):
                return [".test { color: red; }"]

        registry._discovered["assets-plugin"] = PluginWithAssets
        registry.load("assets-plugin")

        assets = registry.get_ui_assets()

        assert len(assets["scripts"]) == 1
        assert len(assets["styles"]) == 1

    def test_registry_get_plugin_info(self, registry: PluginRegistry):
        """Test get_plugin_info returns plugin metadata."""
        registry._discovered["test-plugin"] = MockPlugin
        registry.load("test-plugin")

        info_list = registry.get_plugin_info()

        assert len(info_list) == 1
        assert info_list[0]["name"] == "mock-plugin"
        assert info_list[0]["version"] == "1.0.0"

    def test_registry_repr(self, registry: PluginRegistry):
        """Test registry __repr__."""
        registry._discovered["plugin-1"] = MockPlugin
        registry.load("plugin-1")

        repr_str = repr(registry)

        assert "plugins=1" in repr_str
        assert "discovered=1" in repr_str


class TestGetRegistry:
    """Tests for get_registry singleton function."""

    def test_get_registry_returns_instance(self):
        """Test get_registry returns PluginRegistry instance."""
        with patch("arguscloud.plugins.registry._registry", None):
            registry = get_registry()

            assert isinstance(registry, PluginRegistry)

    def test_get_registry_returns_same_instance(self):
        """Test get_registry returns same instance on multiple calls."""
        with patch("arguscloud.plugins.registry._registry", None):
            registry1 = get_registry()
            registry2 = get_registry()

            assert registry1 is registry2


class TestDiscoverPlugins:
    """Tests for discover_plugins convenience function."""

    def test_discover_plugins_uses_registry(self):
        """Test discover_plugins uses global registry."""
        with patch("arguscloud.plugins.registry.get_registry") as mock_get:
            mock_registry = MagicMock()
            mock_registry.discover.return_value = ["plugin-1"]
            mock_get.return_value = mock_registry

            result = discover_plugins()

            mock_registry.discover.assert_called_once()
            assert result == ["plugin-1"]


class TestLoadPlugins:
    """Tests for load_plugins convenience function."""

    def test_load_plugins_uses_registry(self):
        """Test load_plugins uses global registry."""
        with patch("arguscloud.plugins.registry.get_registry") as mock_get:
            mock_registry = MagicMock()
            mock_registry.load_all.return_value = 2
            mock_get.return_value = mock_registry

            result = load_plugins()

            mock_registry.load_all.assert_called_once()
            assert result == 2


class TestPluginLifecycle:
    """Integration tests for plugin lifecycle."""

    def test_full_plugin_lifecycle(self):
        """Test complete plugin lifecycle: discover -> load -> use -> unload."""
        registry = PluginRegistry()

        # Simulate discovery
        registry._discovered["lifecycle-test"] = MockPlugin

        # Load
        plugin = registry.load("lifecycle-test")
        assert plugin is not None
        assert plugin.loaded is True
        assert registry.plugin_count == 1

        # Use
        mock_app = MagicMock()
        registry.register_routes(mock_app)
        assert plugin.routes_registered is True

        # Get info
        info = registry.get_plugin_info()
        assert len(info) == 1

        # Unload
        result = registry.unload("lifecycle-test")
        assert result is True
        assert plugin.unloaded is True
        assert registry.plugin_count == 0
