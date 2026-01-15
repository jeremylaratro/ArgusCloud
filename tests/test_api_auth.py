"""Tests for arguscloud.api.auth module."""

import pytest
import time
from unittest.mock import patch, MagicMock

from arguscloud.api.auth import (
    generate_api_key,
    validate_api_key,
    create_jwt_token,
    verify_jwt_token,
    AuthConfig,
    authenticate_request,
    require_auth,
)


class TestGenerateApiKey:
    """Tests for API key generation."""

    def test_generate_api_key_format(self):
        """Test that generated API key has correct format."""
        api_key, hashed = generate_api_key()
        assert api_key.startswith("ch_")
        assert len(hashed) == 64  # SHA256 hex digest

    def test_generate_api_key_with_prefix(self):
        """Test API key generation with custom prefix."""
        api_key, hashed = generate_api_key(prefix="test")
        assert api_key.startswith("test_")

    def test_generate_api_key_uniqueness(self):
        """Test that generated keys are unique."""
        keys = set()
        for _ in range(100):
            api_key, _ = generate_api_key()
            assert api_key not in keys
            keys.add(api_key)

    def test_generate_api_key_hash_is_deterministic(self):
        """Test that hashing the same key gives same result."""
        api_key, hashed1 = generate_api_key()
        # Manually hash the key again
        import hashlib
        hashed2 = hashlib.sha256(api_key.encode()).hexdigest()
        assert hashed1 == hashed2


class TestValidateApiKey:
    """Tests for API key validation."""

    def test_validate_api_key_success(self):
        """Test validating a correct API key."""
        api_key, stored_hash = generate_api_key()
        assert validate_api_key(api_key, stored_hash) is True

    def test_validate_api_key_failure_wrong_key(self):
        """Test validating an incorrect API key."""
        _, stored_hash = generate_api_key()
        wrong_key = "ch_wrong_key_12345"
        assert validate_api_key(wrong_key, stored_hash) is False

    def test_validate_api_key_failure_modified_hash(self):
        """Test validating against a modified hash."""
        api_key, _ = generate_api_key()
        wrong_hash = "a" * 64
        assert validate_api_key(api_key, wrong_hash) is False

    def test_validate_api_key_empty_values(self):
        """Test validating with empty values."""
        api_key, stored_hash = generate_api_key()
        assert validate_api_key("", stored_hash) is False
        assert validate_api_key(api_key, "") is False


class TestJWTToken:
    """Tests for JWT token creation and verification."""

    def test_create_jwt_token_structure(self):
        """Test that JWT token has correct structure."""
        token = create_jwt_token({"user": "test"}, "secret")
        parts = token.split(".")
        assert len(parts) == 3  # header.payload.signature

    def test_verify_jwt_token_success(self):
        """Test verifying a valid JWT token."""
        payload = {"user": "testuser", "role": "admin"}
        secret = "my_secret_key"
        token = create_jwt_token(payload, secret)

        verified = verify_jwt_token(token, secret)
        assert verified is not None
        assert verified["user"] == "testuser"
        assert verified["role"] == "admin"
        assert "exp" in verified
        assert "iat" in verified

    def test_verify_jwt_token_expired(self):
        """Test verifying an expired JWT token."""
        payload = {"user": "testuser"}
        secret = "secret"
        # Create token that expired 10 seconds ago
        token = create_jwt_token(payload, secret, expiry_seconds=-10)

        verified = verify_jwt_token(token, secret)
        assert verified is None

    def test_verify_jwt_token_invalid_signature(self):
        """Test verifying a JWT token with wrong secret."""
        payload = {"user": "testuser"}
        token = create_jwt_token(payload, "secret1")

        verified = verify_jwt_token(token, "secret2")
        assert verified is None

    def test_verify_jwt_token_malformed(self):
        """Test verifying a malformed JWT token."""
        assert verify_jwt_token("invalid_token", "secret") is None
        assert verify_jwt_token("only.two", "secret") is None
        assert verify_jwt_token("too.many.parts.here", "secret") is None

    def test_verify_jwt_token_tampered_payload(self):
        """Test verifying a JWT with tampered payload."""
        import base64
        import json

        payload = {"user": "testuser", "role": "user"}
        secret = "secret"
        token = create_jwt_token(payload, secret)

        # Tamper with the payload
        parts = token.split(".")
        fake_payload = {"user": "admin", "role": "admin", "exp": int(time.time()) + 3600, "iat": int(time.time())}
        fake_payload_b64 = base64.urlsafe_b64encode(json.dumps(fake_payload).encode()).decode().rstrip("=")
        tampered_token = f"{parts[0]}.{fake_payload_b64}.{parts[2]}"

        verified = verify_jwt_token(tampered_token, secret)
        assert verified is None

    def test_jwt_token_expiry_default(self):
        """Test that JWT token has correct default expiry."""
        payload = {"user": "testuser"}
        token = create_jwt_token(payload, "secret")

        verified = verify_jwt_token(token, "secret")
        assert verified is not None
        # Default expiry is 3600 seconds
        assert verified["exp"] - verified["iat"] == 3600

    def test_jwt_token_custom_expiry(self):
        """Test JWT token with custom expiry."""
        payload = {"user": "testuser"}
        token = create_jwt_token(payload, "secret", expiry_seconds=7200)

        verified = verify_jwt_token(token, "secret")
        assert verified is not None
        assert verified["exp"] - verified["iat"] == 7200


class TestAuthConfig:
    """Tests for AuthConfig class."""

    def test_auth_config_defaults(self):
        """Test AuthConfig default values."""
        config = AuthConfig()
        assert config.enabled is True
        assert config.api_keys == {}
        assert config.jwt_secret is not None
        assert config.allow_anonymous_health is True
        assert config.allow_anonymous_read is False

    def test_auth_config_disabled(self):
        """Test AuthConfig with auth disabled."""
        config = AuthConfig(enabled=False)
        assert config.enabled is False

    def test_auth_config_with_api_keys(self):
        """Test AuthConfig with API keys."""
        api_keys = {"key1": "hash1", "key2": "hash2"}
        config = AuthConfig(api_keys=api_keys)
        assert config.api_keys == api_keys

    def test_auth_config_allow_anonymous_read(self):
        """Test AuthConfig with anonymous read enabled."""
        config = AuthConfig(allow_anonymous_read=True)
        assert config.allow_anonymous_read is True

    def test_auth_config_from_env(self):
        """Test AuthConfig from environment variables."""
        with patch.dict("os.environ", {
            "ARGUSCLOUD_AUTH_ENABLED": "true",
            "ARGUSCLOUD_API_KEYS": "admin:abc123,reader:def456",
            "ARGUSCLOUD_JWT_SECRET": "test_secret",
            "ARGUSCLOUD_ALLOW_ANON_HEALTH": "true",
            "ARGUSCLOUD_ALLOW_ANON_READ": "false",
        }):
            config = AuthConfig.from_env()
            assert config.enabled is True
            assert config.api_keys == {"admin": "abc123", "reader": "def456"}
            assert config.jwt_secret == "test_secret"
            assert config.allow_anonymous_health is True
            assert config.allow_anonymous_read is False

    def test_auth_config_from_env_disabled(self):
        """Test AuthConfig from environment with auth disabled."""
        with patch.dict("os.environ", {
            "ARGUSCLOUD_AUTH_ENABLED": "false",
        }, clear=True):
            config = AuthConfig.from_env()
            assert config.enabled is False

    def test_auth_config_from_env_empty_keys(self):
        """Test AuthConfig from environment with empty API keys."""
        with patch.dict("os.environ", {
            "ARGUSCLOUD_API_KEYS": "",
        }, clear=True):
            config = AuthConfig.from_env()
            assert config.api_keys == {}


class TestAuthenticateRequest:
    """Tests for authenticate_request function using Flask test context."""

    def test_authenticate_request_api_key(self):
        """Test authenticating with API key."""
        from flask import Flask

        app = Flask(__name__)
        api_key, stored_hash = generate_api_key()
        config = AuthConfig(api_keys={"testuser": stored_hash})
        app.auth_config = config

        with app.test_request_context(headers={"X-API-Key": api_key}):
            result = authenticate_request()
            assert result is not None
            assert result["type"] == "api_key"
            assert result["name"] == "testuser"

    def test_authenticate_request_bearer_token(self):
        """Test authenticating with Bearer token."""
        from flask import Flask

        app = Flask(__name__)
        secret = "test_secret"
        token = create_jwt_token({"sub": "testuser"}, secret)
        config = AuthConfig(jwt_secret=secret)
        app.auth_config = config

        with app.test_request_context(headers={"Authorization": f"Bearer {token}"}):
            result = authenticate_request()
            assert result is not None
            assert result["type"] == "jwt"
            assert result["payload"]["sub"] == "testuser"

    def test_authenticate_request_no_auth(self):
        """Test authenticating with no credentials."""
        from flask import Flask

        app = Flask(__name__)
        config = AuthConfig(api_keys={})
        app.auth_config = config

        with app.test_request_context():
            result = authenticate_request()
            assert result is None

    def test_authenticate_request_invalid_api_key(self):
        """Test authenticating with invalid API key."""
        from flask import Flask

        app = Flask(__name__)
        _, stored_hash = generate_api_key()
        config = AuthConfig(api_keys={"user": stored_hash})
        app.auth_config = config

        with app.test_request_context(headers={"X-API-Key": "invalid_key"}):
            result = authenticate_request()
            assert result is None

    def test_authenticate_request_invalid_bearer_token(self):
        """Test authenticating with invalid Bearer token."""
        from flask import Flask

        app = Flask(__name__)
        config = AuthConfig(jwt_secret="secret")
        app.auth_config = config

        with app.test_request_context(headers={"Authorization": "Bearer invalid_token"}):
            result = authenticate_request()
            assert result is None


class TestRequireAuthDecorator:
    """Tests for require_auth decorator."""

    def test_require_auth_allows_valid_api_key(self):
        """Test that require_auth allows valid API key."""
        from flask import Flask, g, jsonify

        app = Flask(__name__)
        api_key, stored_hash = generate_api_key()
        config = AuthConfig(api_keys={"testuser": stored_hash})
        app.auth_config = config

        @app.route("/test")
        @require_auth
        def test_route():
            return jsonify({"user": g.user})

        with app.test_client() as client:
            response = client.get("/test", headers={"X-API-Key": api_key})
            assert response.status_code == 200
            data = response.get_json()
            assert data["user"]["type"] == "api_key"

    def test_require_auth_blocks_invalid_key(self):
        """Test that require_auth blocks invalid API key."""
        from flask import Flask

        app = Flask(__name__)
        config = AuthConfig(api_keys={"user": "some_hash"})
        app.auth_config = config

        @app.route("/test")
        @require_auth
        def test_route():
            return "ok"

        with app.test_client() as client:
            response = client.get("/test", headers={"X-API-Key": "invalid"})
            assert response.status_code == 401

    def test_require_auth_blocks_no_auth(self):
        """Test that require_auth blocks requests with no auth."""
        from flask import Flask

        app = Flask(__name__)
        config = AuthConfig()
        app.auth_config = config

        @app.route("/test")
        @require_auth
        def test_route():
            return "ok"

        with app.test_client() as client:
            response = client.get("/test")
            assert response.status_code == 401

    def test_require_auth_disabled_mode(self):
        """Test that require_auth allows when auth is disabled."""
        from flask import Flask, g, jsonify

        app = Flask(__name__)
        config = AuthConfig(enabled=False)
        app.auth_config = config

        @app.route("/test")
        @require_auth
        def test_route():
            return jsonify({"user": g.user})

        with app.test_client() as client:
            response = client.get("/test")
            assert response.status_code == 200
            data = response.get_json()
            assert data["user"]["auth_disabled"] is True

    def test_require_auth_allow_read(self):
        """Test require_auth with allow_read parameter."""
        from flask import Flask, g, jsonify

        app = Flask(__name__)
        config = AuthConfig(allow_anonymous_read=True)
        app.auth_config = config

        @app.route("/test")
        @require_auth(allow_read=True)
        def test_route():
            return jsonify({"user": g.user})

        with app.test_client() as client:
            response = client.get("/test")
            assert response.status_code == 200
            data = response.get_json()
            assert data["user"]["read_only"] is True

    def test_require_auth_allow_read_still_requires_auth_if_not_configured(self):
        """Test that allow_read still requires auth if not configured."""
        from flask import Flask

        app = Flask(__name__)
        config = AuthConfig(allow_anonymous_read=False)
        app.auth_config = config

        @app.route("/test")
        @require_auth(allow_read=True)
        def test_route():
            return "ok"

        with app.test_client() as client:
            response = client.get("/test")
            assert response.status_code == 401

    def test_require_auth_with_bearer_token(self):
        """Test require_auth with valid Bearer token."""
        from flask import Flask, g, jsonify

        app = Flask(__name__)
        secret = "test_secret"
        token = create_jwt_token({"sub": "testuser"}, secret)
        config = AuthConfig(jwt_secret=secret)
        app.auth_config = config

        @app.route("/test")
        @require_auth
        def test_route():
            return jsonify({"user": g.user})

        with app.test_client() as client:
            response = client.get("/test", headers={"Authorization": f"Bearer {token}"})
            assert response.status_code == 200
            data = response.get_json()
            assert data["user"]["type"] == "jwt"
