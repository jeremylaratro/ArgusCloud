"""Base plugin class for ArgusCloud extensions."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
import importlib.util
import logging
import re
from typing import Any, Callable, Dict, List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from flask import Flask
    import argparse

logger = logging.getLogger(__name__)

# Valid package name pattern (PEP 508 compliant)
VALID_PACKAGE_NAME_PATTERN = re.compile(r'^[a-zA-Z][a-zA-Z0-9_-]*$')


@dataclass
class PluginInfo:
    """Metadata about a plugin."""
    name: str
    version: str
    description: str
    author: str = ""
    dependencies: List[str] = field(default_factory=list)
    homepage: str = ""


class Plugin(ABC):
    """Base class for ArgusCloud plugins.

    Plugins can extend ArgusCloud with:
    - Additional API endpoints
    - CLI commands
    - UI components (via JavaScript injection)
    - Custom collectors, normalizers, and rules

    Example implementation:

        class SchedulerPlugin(Plugin):
            @property
            def info(self) -> PluginInfo:
                return PluginInfo(
                    name="scheduler",
                    version="1.0.0",
                    description="Scheduled scan support for ArgusCloud",
                    author="ArgusCloud Team",
                    dependencies=["apscheduler>=3.10.0"]
                )

            def register_routes(self, app: Flask) -> None:
                @app.route("/schedules")
                def list_schedules():
                    return jsonify({"schedules": []})

            def register_cli(self, subparsers) -> None:
                parser = subparsers.add_parser("schedule", help="Manage scheduled scans")
                parser.add_argument("action", choices=["list", "create", "delete"])

            def on_load(self) -> None:
                print("Scheduler plugin loaded")
    """

    @property
    @abstractmethod
    def info(self) -> PluginInfo:
        """Return plugin metadata."""
        pass

    def register_routes(self, app: "Flask") -> None:
        """Register Flask API routes.

        Override this to add custom endpoints to the API server.

        Args:
            app: Flask application instance
        """
        pass

    def register_cli(self, subparsers: "argparse._SubParsersAction") -> None:
        """Register CLI subcommands.

        Override this to add commands to the arguscloud CLI.

        Args:
            subparsers: Argparse subparsers object from main CLI
        """
        pass

    def get_ui_scripts(self) -> List[str]:
        """Return JavaScript code to inject into the UI.

        Override this to add UI components or modify behavior.
        Each string is executed as JavaScript in the browser.

        Returns:
            List of JavaScript code strings
        """
        return []

    def get_ui_styles(self) -> List[str]:
        """Return CSS styles to inject into the UI.

        Override this to add custom styling.

        Returns:
            List of CSS code strings
        """
        return []

    def on_load(self) -> None:
        """Called when the plugin is loaded.

        Override this for initialization tasks like:
        - Database migrations
        - Resource setup
        - Configuration validation
        """
        pass

    def on_unload(self) -> None:
        """Called when the plugin is unloaded.

        Override this for cleanup tasks.
        """
        pass

    def _sanitize_package_name(self, dep: str) -> Optional[str]:
        """Sanitize and validate package name from dependency string.

        Args:
            dep: Dependency string (e.g., "apscheduler>=3.10.0")

        Returns:
            Sanitized package name or None if invalid
        """
        # Parse dependency string
        pkg_name = dep.split(">=")[0].split("==")[0].split("<")[0].split("[")[0].strip()

        # Validate package name format
        if not VALID_PACKAGE_NAME_PATTERN.match(pkg_name):
            logger.warning(f"Invalid package name format: {pkg_name}")
            return None

        # Convert hyphens to underscores for import
        return pkg_name.replace("-", "_")

    def check_dependencies(self) -> List[str]:
        """Check if plugin dependencies are satisfied.

        Returns:
            List of missing dependency names (empty if all satisfied)
        """
        missing = []
        for dep in self.info.dependencies:
            pkg_name = self._sanitize_package_name(dep)
            if not pkg_name:
                # Skip invalid package names
                continue

            # Use importlib.util.find_spec for safer checking
            spec = importlib.util.find_spec(pkg_name)
            if spec is None:
                missing.append(dep)
        return missing

    def __repr__(self) -> str:
        return f"<Plugin {self.info.name} v{self.info.version}>"
