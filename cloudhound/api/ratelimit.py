"""Rate limiting for CloudHound API.

This module provides rate limiting using flask-limiter to protect
the API from abuse and ensure fair resource usage.
"""

from __future__ import annotations

import logging
import os
from typing import Optional

from flask import Flask, request, jsonify

logger = logging.getLogger(__name__)

# Check if flask-limiter is available
try:
    from flask_limiter import Limiter
    from flask_limiter.util import get_remote_address
    HAS_LIMITER = True
except ImportError:
    HAS_LIMITER = False
    Limiter = None
    logger.info("flask-limiter not installed, rate limiting disabled")


# Default rate limits
DEFAULT_LIMITS = {
    "default": "1000/hour",           # Default limit for all endpoints
    "query": "100/minute",            # /query endpoint
    "collect": "10/hour",             # /collect/aws endpoint
    "upload": "20/hour",              # /upload endpoint
    "export": "60/hour",              # /export/<format> endpoint
    "auth": "20/minute",              # /auth/* endpoints
}


def get_rate_limit_key() -> str:
    """Get the key used for rate limiting.

    Uses API key if present, otherwise falls back to IP address.

    Returns:
        Rate limit key string
    """
    # Try to use API key as the identifier
    api_key = request.headers.get("X-API-Key")
    if api_key:
        return f"apikey:{api_key[:16]}"

    # Try to use JWT subject
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        # Use first 16 chars of token as identifier
        token = auth_header[7:]
        return f"token:{token[:16]}"

    # Fall back to IP address
    return f"ip:{get_remote_address()}"


def init_rate_limiting(
    app: Flask,
    storage_uri: Optional[str] = None,
    enabled: bool = True
) -> Optional[Limiter]:
    """Initialize rate limiting for a Flask application.

    Args:
        app: Flask application instance
        storage_uri: Storage backend URI (e.g., redis://localhost:6379)
                    If not provided, uses in-memory storage.
        enabled: Whether rate limiting is enabled

    Returns:
        Limiter instance or None if disabled/unavailable
    """
    if not HAS_LIMITER:
        logger.warning("Rate limiting not available - install flask-limiter")
        return None

    if not enabled:
        logger.info("Rate limiting disabled by configuration")
        return None

    # Get storage URI from environment if not provided
    if storage_uri is None:
        storage_uri = os.environ.get("CLOUDHOUND_RATELIMIT_STORAGE", "memory://")

    # Get default limit from environment
    default_limit = os.environ.get(
        "CLOUDHOUND_RATELIMIT_DEFAULT",
        DEFAULT_LIMITS["default"]
    )

    # Initialize limiter
    limiter = Limiter(
        key_func=get_rate_limit_key,
        app=app,
        default_limits=[default_limit],
        storage_uri=storage_uri,
        strategy="fixed-window",
        headers_enabled=True,  # Add rate limit headers to responses
    )

    # Add custom error handler
    @app.errorhandler(429)
    def rate_limit_exceeded(e):
        """Handle rate limit exceeded errors."""
        return jsonify({
            "error": "Rate limit exceeded",
            "message": str(e.description),
            "retry_after": e.retry_after if hasattr(e, "retry_after") else None
        }), 429

    logger.info(f"Rate limiting initialized with storage: {storage_uri}")
    return limiter


def get_endpoint_limit(endpoint: str) -> str:
    """Get the rate limit for a specific endpoint.

    Args:
        endpoint: Endpoint name (e.g., "query", "collect")

    Returns:
        Rate limit string (e.g., "100/minute")
    """
    return os.environ.get(
        f"CLOUDHOUND_RATELIMIT_{endpoint.upper()}",
        DEFAULT_LIMITS.get(endpoint, DEFAULT_LIMITS["default"])
    )


class RateLimitConfig:
    """Configuration for rate limiting.

    Attributes:
        enabled: Whether rate limiting is enabled
        storage_uri: Backend storage URI
        default_limit: Default rate limit for all endpoints
        endpoint_limits: Per-endpoint rate limits
    """

    def __init__(
        self,
        enabled: bool = True,
        storage_uri: Optional[str] = None,
        default_limit: Optional[str] = None,
        endpoint_limits: Optional[dict] = None,
    ):
        """Initialize rate limit configuration.

        Args:
            enabled: Whether rate limiting is enabled
            storage_uri: Backend storage URI
            default_limit: Default rate limit
            endpoint_limits: Per-endpoint rate limits
        """
        self.enabled = enabled
        self.storage_uri = storage_uri or os.environ.get(
            "CLOUDHOUND_RATELIMIT_STORAGE",
            "memory://"
        )
        self.default_limit = default_limit or os.environ.get(
            "CLOUDHOUND_RATELIMIT_DEFAULT",
            DEFAULT_LIMITS["default"]
        )
        self.endpoint_limits = endpoint_limits or {}

        # Merge with defaults
        for key, value in DEFAULT_LIMITS.items():
            if key not in self.endpoint_limits:
                env_key = f"CLOUDHOUND_RATELIMIT_{key.upper()}"
                self.endpoint_limits[key] = os.environ.get(env_key, value)

    @classmethod
    def from_env(cls) -> "RateLimitConfig":
        """Create configuration from environment variables.

        Returns:
            RateLimitConfig instance
        """
        enabled = os.environ.get("CLOUDHOUND_RATELIMIT_ENABLED", "true").lower() == "true"
        return cls(enabled=enabled)

    def get_limit(self, endpoint: str) -> str:
        """Get rate limit for an endpoint.

        Args:
            endpoint: Endpoint name

        Returns:
            Rate limit string
        """
        return self.endpoint_limits.get(endpoint, self.default_limit)


def apply_rate_limits(app: Flask, limiter: Limiter, config: RateLimitConfig) -> None:
    """Apply rate limits to specific endpoints.

    This should be called after routes are registered to apply
    per-endpoint rate limits.

    Args:
        app: Flask application
        limiter: Limiter instance
        config: Rate limit configuration
    """
    if not HAS_LIMITER or limiter is None:
        return

    # Define endpoint patterns and their limits
    endpoint_patterns = {
        "query": ["/query"],
        "collect": ["/collect/aws"],
        "upload": ["/upload"],
        "export": ["/export/json", "/export/sarif", "/export/html"],
        "auth": ["/auth/token", "/auth/verify"],
    }

    # Apply limits using limiter.limit decorator
    # Note: This approach works with existing routes
    for limit_name, endpoints in endpoint_patterns.items():
        limit_value = config.get_limit(limit_name)
        for endpoint in endpoints:
            # Find and decorate the endpoint
            for rule in app.url_map.iter_rules():
                if rule.rule == endpoint:
                    view_func = app.view_functions.get(rule.endpoint)
                    if view_func:
                        # Apply limit
                        decorated = limiter.limit(limit_value)(view_func)
                        app.view_functions[rule.endpoint] = decorated
                        logger.debug(f"Applied rate limit {limit_value} to {endpoint}")


def create_limiter_decorators(limiter: Optional[Limiter]) -> dict:
    """Create rate limit decorators for use in routes.

    Args:
        limiter: Limiter instance

    Returns:
        Dictionary of decorator functions
    """
    if limiter is None or not HAS_LIMITER:
        # Return no-op decorators
        def noop(f):
            return f
        return {
            "query": noop,
            "collect": noop,
            "upload": noop,
            "export": noop,
            "auth": noop,
        }

    return {
        "query": limiter.limit(get_endpoint_limit("query")),
        "collect": limiter.limit(get_endpoint_limit("collect")),
        "upload": limiter.limit(get_endpoint_limit("upload")),
        "export": limiter.limit(get_endpoint_limit("export")),
        "auth": limiter.limit(get_endpoint_limit("auth")),
    }
