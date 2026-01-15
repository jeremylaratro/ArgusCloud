"""API authentication for ArgusCloud server.

Supports two authentication methods:
1. API Key authentication (header: X-API-Key)
2. JWT Bearer token authentication (header: Authorization: Bearer <token>)
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
from datetime import datetime, timedelta, timezone
from functools import wraps
from typing import Any, Callable, Dict, Optional, Tuple

import jwt
from flask import request, jsonify, g, current_app


# Default settings
DEFAULT_API_KEY_LENGTH = 32
DEFAULT_JWT_EXPIRY = 3600  # 1 hour
JWT_ALGORITHM = "HS256"


def generate_api_key(prefix: str = "ch") -> Tuple[str, str]:
    """Generate a new API key.

    Returns:
        Tuple of (api_key, hashed_key) - store the hashed_key, give user the api_key
    """
    raw_key = secrets.token_urlsafe(DEFAULT_API_KEY_LENGTH)
    api_key = f"{prefix}_{raw_key}"
    hashed_key = hashlib.sha256(api_key.encode()).hexdigest()
    return api_key, hashed_key


def validate_api_key(api_key: str, stored_hash: str) -> bool:
    """Validate an API key against a stored hash."""
    computed_hash = hashlib.sha256(api_key.encode()).hexdigest()
    return hmac.compare_digest(computed_hash, stored_hash)


def create_jwt_token(
    payload: Dict[str, Any],
    secret: str,
    expiry_seconds: int = DEFAULT_JWT_EXPIRY
) -> str:
    """Create a JWT token using PyJWT library.

    Args:
        payload: Data to encode in the token
        secret: Secret key for signing
        expiry_seconds: Token expiry time in seconds

    Returns:
        Encoded JWT token string
    """
    # Create a copy to avoid modifying the original
    token_payload = payload.copy()

    # Add standard JWT claims
    now = datetime.now(timezone.utc)
    token_payload["exp"] = now + timedelta(seconds=expiry_seconds)
    token_payload["iat"] = now

    return jwt.encode(token_payload, secret, algorithm=JWT_ALGORITHM)


def verify_jwt_token(token: str, secret: str) -> Optional[Dict[str, Any]]:
    """Verify and decode a JWT token using PyJWT library.

    Args:
        token: JWT token string to verify
        secret: Secret key used for signing

    Returns:
        Decoded payload if valid, None if invalid
    """
    try:
        # PyJWT handles signature verification, expiry checking, and decoding
        payload = jwt.decode(
            token,
            secret,
            algorithms=[JWT_ALGORITHM],
            options={"require": ["exp", "iat"]}
        )
        return payload
    except jwt.ExpiredSignatureError:
        # Token has expired
        return None
    except jwt.InvalidTokenError:
        # Invalid token (bad signature, malformed, etc.)
        return None


class AuthConfig:
    """Authentication configuration."""

    def __init__(
        self,
        enabled: bool = True,
        api_keys: Optional[Dict[str, str]] = None,  # name -> hashed_key
        jwt_secret: Optional[str] = None,
        allow_anonymous_health: bool = True,
        allow_anonymous_read: bool = False,
    ):
        self.enabled = enabled
        self.api_keys = api_keys or {}
        self.jwt_secret = jwt_secret or os.environ.get("ARGUSCLOUD_JWT_SECRET", secrets.token_hex(32))
        self.allow_anonymous_health = allow_anonymous_health
        self.allow_anonymous_read = allow_anonymous_read

    @classmethod
    def from_env(cls) -> "AuthConfig":
        """Create config from environment variables."""
        enabled = os.environ.get("ARGUSCLOUD_AUTH_ENABLED", "true").lower() == "true"

        # Load API keys from environment (comma-separated name:hash pairs)
        api_keys = {}
        api_keys_env = os.environ.get("ARGUSCLOUD_API_KEYS", "")
        if api_keys_env:
            for pair in api_keys_env.split(","):
                if ":" in pair:
                    name, hashed = pair.split(":", 1)
                    api_keys[name.strip()] = hashed.strip()

        return cls(
            enabled=enabled,
            api_keys=api_keys,
            jwt_secret=os.environ.get("ARGUSCLOUD_JWT_SECRET"),
            allow_anonymous_health=os.environ.get("ARGUSCLOUD_ALLOW_ANON_HEALTH", "true").lower() == "true",
            allow_anonymous_read=os.environ.get("ARGUSCLOUD_ALLOW_ANON_READ", "false").lower() == "true",
        )


def get_auth_config() -> AuthConfig:
    """Get auth config from Flask app or create default."""
    if hasattr(current_app, "auth_config"):
        return current_app.auth_config
    return AuthConfig.from_env()


def authenticate_request() -> Optional[Dict[str, Any]]:
    """Authenticate the current request.

    Returns:
        User info dict if authenticated, None otherwise
    """
    config = get_auth_config()

    # Check API key header
    api_key = request.headers.get("X-API-Key")
    if api_key:
        for name, stored_hash in config.api_keys.items():
            if validate_api_key(api_key, stored_hash):
                return {"type": "api_key", "name": name}

    # Check Bearer token
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        token = auth_header[7:]
        payload = verify_jwt_token(token, config.jwt_secret)
        if payload:
            return {"type": "jwt", "payload": payload}

    return None


def require_auth(f: Optional[Callable] = None, *, allow_read: bool = False):
    """Decorator to require authentication on a route.

    Args:
        allow_read: If True, allows anonymous access when ARGUSCLOUD_ALLOW_ANON_READ is set

    Usage:
        @app.route("/protected")
        @require_auth
        def protected_route():
            return jsonify({"user": g.user})

        @app.route("/data")
        @require_auth(allow_read=True)
        def read_data():
            return jsonify({"data": [...]})
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            config = get_auth_config()

            # Skip auth if disabled
            if not config.enabled:
                g.user = {"type": "anonymous", "auth_disabled": True}
                return func(*args, **kwargs)

            # Allow anonymous read access if configured
            if allow_read and config.allow_anonymous_read:
                g.user = {"type": "anonymous", "read_only": True}
                return func(*args, **kwargs)

            # Authenticate
            user = authenticate_request()
            if user is None:
                return jsonify({
                    "error": "Unauthorized",
                    "message": "Valid API key or JWT token required"
                }), 401

            g.user = user
            return func(*args, **kwargs)

        return wrapper

    if f is not None:
        return decorator(f)
    return decorator


def init_auth(app, config: Optional[AuthConfig] = None):
    """Initialize authentication on a Flask app.

    Args:
        app: Flask application instance
        config: Optional AuthConfig, defaults to loading from environment
    """
    app.auth_config = config or AuthConfig.from_env()

    @app.route("/auth/token", methods=["POST"])
    def create_token():
        """Create a JWT token from API key authentication."""
        user = authenticate_request()
        if user is None:
            return jsonify({"error": "Unauthorized"}), 401

        # Create JWT with user info
        payload = {
            "sub": user.get("name", "api_user"),
            "type": user.get("type"),
        }

        token = create_jwt_token(payload, app.auth_config.jwt_secret)
        return jsonify({
            "token": token,
            "expires_in": DEFAULT_JWT_EXPIRY,
            "token_type": "Bearer"
        })

    @app.route("/auth/verify", methods=["GET"])
    @require_auth
    def verify_token():
        """Verify the current authentication."""
        return jsonify({
            "authenticated": True,
            "user": g.user
        })
