"""CloudHound Plugin System.

This module provides a plugin architecture for extending CloudHound with
optional features like scheduled scans, multi-cloud support, and more.

Plugins are discovered via Python entry_points and loaded at startup.
Each plugin can register API routes, CLI commands, and UI components.

Example plugin setup.py:
    entry_points={
        'cloudhound.plugins': [
            'scheduler = cloudhound_scheduler:SchedulerPlugin',
        ],
    }
"""

from .base import Plugin, PluginInfo
from .registry import PluginRegistry, discover_plugins, load_plugins

__all__ = [
    "Plugin",
    "PluginInfo",
    "PluginRegistry",
    "discover_plugins",
    "load_plugins",
]
