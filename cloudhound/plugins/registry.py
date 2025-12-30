"""Plugin discovery and registration for CloudHound."""

from __future__ import annotations

import logging
import sys
from typing import Dict, List, Optional, TYPE_CHECKING

from .base import Plugin, PluginInfo

if TYPE_CHECKING:
    from flask import Flask
    import argparse

logger = logging.getLogger(__name__)


class PluginRegistry:
    """Registry for managing CloudHound plugins.

    This class handles plugin discovery, loading, and lifecycle management.
    Plugins are discovered via Python entry_points.

    Usage:
        registry = PluginRegistry()
        registry.discover()  # Find all installed plugins
        registry.load_all()  # Load and initialize plugins

        # Get plugin info
        for plugin in registry.plugins.values():
            print(plugin.info.name, plugin.info.version)

        # Register with Flask
        registry.register_routes(app)
    """

    def __init__(self):
        self._plugins: Dict[str, Plugin] = {}
        self._discovered: Dict[str, type] = {}
        self._load_errors: Dict[str, str] = {}

    @property
    def plugins(self) -> Dict[str, Plugin]:
        """Return loaded plugins."""
        return self._plugins.copy()

    @property
    def plugin_count(self) -> int:
        """Return number of loaded plugins."""
        return len(self._plugins)

    @property
    def load_errors(self) -> Dict[str, str]:
        """Return any errors encountered during loading."""
        return self._load_errors.copy()

    def discover(self) -> List[str]:
        """Discover available plugins via entry_points.

        Looks for plugins registered under 'cloudhound.plugins' entry point.

        Returns:
            List of discovered plugin names
        """
        self._discovered.clear()

        # Use importlib.metadata for Python 3.9+
        try:
            if sys.version_info >= (3, 10):
                from importlib.metadata import entry_points
                eps = entry_points(group="cloudhound.plugins")
            else:
                from importlib.metadata import entry_points
                all_eps = entry_points()
                eps = all_eps.get("cloudhound.plugins", [])
        except Exception as e:
            logger.warning(f"Failed to load entry_points: {e}")
            return []

        for ep in eps:
            try:
                plugin_class = ep.load()
                if isinstance(plugin_class, type) and issubclass(plugin_class, Plugin):
                    self._discovered[ep.name] = plugin_class
                    logger.debug(f"Discovered plugin: {ep.name}")
                else:
                    logger.warning(f"Entry point {ep.name} is not a valid Plugin class")
            except Exception as e:
                logger.warning(f"Failed to load plugin {ep.name}: {e}")
                self._load_errors[ep.name] = str(e)

        return list(self._discovered.keys())

    def load(self, name: str) -> Optional[Plugin]:
        """Load a specific plugin by name.

        Args:
            name: Plugin name (entry point name)

        Returns:
            Plugin instance or None if loading failed
        """
        if name in self._plugins:
            return self._plugins[name]

        if name not in self._discovered:
            logger.error(f"Plugin {name} not discovered. Call discover() first.")
            return None

        plugin_class = self._discovered[name]

        try:
            plugin = plugin_class()

            # Check dependencies
            missing = plugin.check_dependencies()
            if missing:
                self._load_errors[name] = f"Missing dependencies: {', '.join(missing)}"
                logger.warning(f"Plugin {name} has missing dependencies: {missing}")
                return None

            # Initialize plugin
            plugin.on_load()
            self._plugins[name] = plugin
            logger.info(f"Loaded plugin: {plugin.info.name} v{plugin.info.version}")
            return plugin

        except Exception as e:
            self._load_errors[name] = str(e)
            logger.error(f"Failed to load plugin {name}: {e}")
            return None

    def load_all(self) -> int:
        """Load all discovered plugins.

        Returns:
            Number of successfully loaded plugins
        """
        if not self._discovered:
            self.discover()

        loaded = 0
        for name in self._discovered:
            if self.load(name):
                loaded += 1

        return loaded

    def unload(self, name: str) -> bool:
        """Unload a plugin.

        Args:
            name: Plugin name to unload

        Returns:
            True if unloaded, False if not found
        """
        if name not in self._plugins:
            return False

        try:
            self._plugins[name].on_unload()
        except Exception as e:
            logger.warning(f"Error during plugin {name} unload: {e}")

        del self._plugins[name]
        return True

    def register_routes(self, app: "Flask") -> None:
        """Register all plugin routes with Flask app.

        Args:
            app: Flask application instance
        """
        for name, plugin in self._plugins.items():
            try:
                plugin.register_routes(app)
                logger.debug(f"Registered routes for plugin: {name}")
            except Exception as e:
                logger.error(f"Failed to register routes for {name}: {e}")

    def register_cli(self, subparsers: "argparse._SubParsersAction") -> None:
        """Register all plugin CLI commands.

        Args:
            subparsers: Argparse subparsers from main CLI
        """
        for name, plugin in self._plugins.items():
            try:
                plugin.register_cli(subparsers)
                logger.debug(f"Registered CLI commands for plugin: {name}")
            except Exception as e:
                logger.error(f"Failed to register CLI for {name}: {e}")

    def get_ui_assets(self) -> Dict[str, List[str]]:
        """Get UI scripts and styles from all plugins.

        Returns:
            Dict with 'scripts' and 'styles' lists
        """
        scripts = []
        styles = []

        for plugin in self._plugins.values():
            try:
                scripts.extend(plugin.get_ui_scripts())
                styles.extend(plugin.get_ui_styles())
            except Exception as e:
                logger.error(f"Failed to get UI assets from {plugin.info.name}: {e}")

        return {"scripts": scripts, "styles": styles}

    def get_plugin_info(self) -> List[Dict]:
        """Get info about all loaded plugins.

        Returns:
            List of plugin info dicts
        """
        return [
            {
                "name": plugin.info.name,
                "version": plugin.info.version,
                "description": plugin.info.description,
                "author": plugin.info.author,
                "homepage": plugin.info.homepage,
            }
            for plugin in self._plugins.values()
        ]

    def __repr__(self) -> str:
        return f"<PluginRegistry plugins={len(self._plugins)} discovered={len(self._discovered)}>"


# Global registry instance
_registry: Optional[PluginRegistry] = None


def get_registry() -> PluginRegistry:
    """Get the global plugin registry instance."""
    global _registry
    if _registry is None:
        _registry = PluginRegistry()
    return _registry


def discover_plugins() -> List[str]:
    """Discover available plugins.

    Returns:
        List of discovered plugin names
    """
    return get_registry().discover()


def load_plugins() -> int:
    """Load all discovered plugins.

    Returns:
        Number of loaded plugins
    """
    return get_registry().load_all()
