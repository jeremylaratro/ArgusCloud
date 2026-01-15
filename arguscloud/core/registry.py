"""Registry patterns for collectors, normalizers, and rules."""

from __future__ import annotations

import logging
from typing import Callable, Dict, List, Optional, Type, TypeVar, Generic
from abc import ABC

log = logging.getLogger(__name__)

T = TypeVar("T")


class BaseRegistry(Generic[T], ABC):
    """Base registry for plugin-style components."""

    def __init__(self, name: str):
        self._name = name
        self._items: Dict[str, T] = {}
        self._metadata: Dict[str, Dict] = {}

    def register(
        self,
        name: str,
        item: T,
        provider: str = "aws",
        description: str = "",
        **metadata
    ) -> T:
        """Register an item with the registry."""
        key = f"{provider}:{name}"
        self._items[key] = item
        self._metadata[key] = {
            "name": name,
            "provider": provider,
            "description": description,
            **metadata,
        }
        log.debug(f"Registered {self._name}: {key}")
        return item

    def get(self, name: str, provider: str = "aws") -> Optional[T]:
        """Get an item by name and provider."""
        return self._items.get(f"{provider}:{name}")

    def get_all(self, provider: Optional[str] = None) -> Dict[str, T]:
        """Get all items, optionally filtered by provider."""
        if provider is None:
            return dict(self._items)
        return {k: v for k, v in self._items.items() if k.startswith(f"{provider}:")}

    def list_names(self, provider: Optional[str] = None) -> List[str]:
        """List all registered names."""
        items = self.get_all(provider)
        return [self._metadata[k]["name"] for k in items.keys()]

    def get_metadata(self, name: str, provider: str = "aws") -> Optional[Dict]:
        """Get metadata for an item."""
        return self._metadata.get(f"{provider}:{name}")

    def __contains__(self, key: str) -> bool:
        return key in self._items

    def __len__(self) -> int:
        return len(self._items)


class CollectorRegistry(BaseRegistry[Callable]):
    """Registry for cloud resource collectors."""

    def __init__(self):
        super().__init__("collector")

    def collector(
        self,
        name: str,
        provider: str = "aws",
        description: str = "",
        services: Optional[List[str]] = None,
    ):
        """Decorator to register a collector function."""
        def decorator(func: Callable) -> Callable:
            self.register(
                name=name,
                item=func,
                provider=provider,
                description=description,
                services=services or [],
            )
            return func
        return decorator


class NormalizerRegistry(BaseRegistry[Callable]):
    """Registry for data normalizers."""

    def __init__(self):
        super().__init__("normalizer")

    def normalizer(
        self,
        name: str,
        provider: str = "aws",
        description: str = "",
        input_type: str = "",
    ):
        """Decorator to register a normalizer function."""
        def decorator(func: Callable) -> Callable:
            self.register(
                name=name,
                item=func,
                provider=provider,
                description=description,
                input_type=input_type,
            )
            return func
        return decorator


class RuleRegistry(BaseRegistry[Callable]):
    """Registry for security analysis rules."""

    def __init__(self):
        super().__init__("rule")

    def rule(
        self,
        rule_id: str,
        provider: str = "aws",
        description: str = "",
        severity: str = "medium",
        tags: Optional[List[str]] = None,
    ):
        """Decorator to register a security rule."""
        def decorator(func: Callable) -> Callable:
            self.register(
                name=rule_id,
                item=func,
                provider=provider,
                description=description,
                severity=severity,
                tags=tags or [],
            )
            return func
        return decorator


# Global registries
collectors = CollectorRegistry()
normalizers = NormalizerRegistry()
rules = RuleRegistry()
