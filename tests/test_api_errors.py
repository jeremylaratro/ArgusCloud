"""Tests for arguscloud.api.errors module.

This module tests the standardized error handling classes and
decorators used across the API.
"""

from __future__ import annotations

import pytest
from unittest.mock import MagicMock, patch
from flask import Flask, jsonify

from arguscloud.api.errors import (
    APIError,
    ValidationError,
    NotFoundError,
    AuthenticationError,
    AuthorizationError,
    ConflictError,
    handle_api_errors,
    safe_endpoint,
)


class TestAPIError:
    """Tests for base APIError class."""

    def test_api_error_with_message_only(self):
        """Test APIError with just a message."""
        error = APIError("Something went wrong")

        assert error.message == "Something went wrong"
        assert error.status_code == 400  # Default
        assert error.details == {}

    def test_api_error_with_custom_status(self):
        """Test APIError with custom status code."""
        error = APIError("Not found", status_code=404)

        assert error.status_code == 404

    def test_api_error_with_details(self):
        """Test APIError with additional details."""
        error = APIError(
            "Invalid input",
            status_code=400,
            details={"field": "name", "reason": "too short"}
        )

        assert error.details["field"] == "name"
        assert error.details["reason"] == "too short"

    def test_api_error_to_response(self):
        """Test APIError conversion to Flask response."""
        app = Flask(__name__)

        with app.app_context():
            error = APIError("Test error", status_code=400)
            response, status_code = error.to_response()

            assert status_code == 400
            # Response should be a Flask Response object

    def test_api_error_to_response_includes_details(self):
        """Test APIError response includes details when present."""
        app = Flask(__name__)

        with app.app_context():
            error = APIError(
                "Validation failed",
                status_code=400,
                details={"field": "email"}
            )
            response, status_code = error.to_response()

            data = response.get_json()
            assert data["error"] == "Validation failed"
            assert data["details"]["field"] == "email"

    def test_api_error_str_representation(self):
        """Test APIError string representation."""
        error = APIError("Something went wrong")

        assert str(error) == "Something went wrong"


class TestValidationError:
    """Tests for ValidationError class."""

    def test_validation_error_defaults(self):
        """Test ValidationError with default values."""
        error = ValidationError("Invalid input")

        assert error.message == "Invalid input"
        assert error.status_code == 400
        assert error.details == {}

    def test_validation_error_with_field(self):
        """Test ValidationError with field specification."""
        error = ValidationError("Required field missing", field="name")

        assert error.status_code == 400
        assert error.details["field"] == "name"

    def test_validation_error_inherits_from_api_error(self):
        """Test ValidationError is an APIError."""
        error = ValidationError("Invalid")

        assert isinstance(error, APIError)


class TestNotFoundError:
    """Tests for NotFoundError class."""

    def test_not_found_error_with_resource_only(self):
        """Test NotFoundError with just resource name."""
        error = NotFoundError("Profile")

        assert error.message == "Profile not found"
        assert error.status_code == 404

    def test_not_found_error_with_identifier(self):
        """Test NotFoundError with resource and identifier."""
        error = NotFoundError("Profile", identifier="test-profile")

        assert error.message == "Profile 'test-profile' not found"
        assert error.status_code == 404

    def test_not_found_error_inherits_from_api_error(self):
        """Test NotFoundError is an APIError."""
        error = NotFoundError("Resource")

        assert isinstance(error, APIError)


class TestAuthenticationError:
    """Tests for AuthenticationError class."""

    def test_authentication_error_default_message(self):
        """Test AuthenticationError with default message."""
        error = AuthenticationError()

        assert error.message == "Authentication required"
        assert error.status_code == 401

    def test_authentication_error_custom_message(self):
        """Test AuthenticationError with custom message."""
        error = AuthenticationError("Invalid token")

        assert error.message == "Invalid token"
        assert error.status_code == 401

    def test_authentication_error_inherits_from_api_error(self):
        """Test AuthenticationError is an APIError."""
        error = AuthenticationError()

        assert isinstance(error, APIError)


class TestAuthorizationError:
    """Tests for AuthorizationError class."""

    def test_authorization_error_default_message(self):
        """Test AuthorizationError with default message."""
        error = AuthorizationError()

        assert error.message == "Permission denied"
        assert error.status_code == 403

    def test_authorization_error_custom_message(self):
        """Test AuthorizationError with custom message."""
        error = AuthorizationError("Insufficient privileges")

        assert error.message == "Insufficient privileges"
        assert error.status_code == 403

    def test_authorization_error_inherits_from_api_error(self):
        """Test AuthorizationError is an APIError."""
        error = AuthorizationError()

        assert isinstance(error, APIError)


class TestConflictError:
    """Tests for ConflictError class."""

    def test_conflict_error_with_message(self):
        """Test ConflictError with message."""
        error = ConflictError("Profile already exists")

        assert error.message == "Profile already exists"
        assert error.status_code == 409
        assert error.details == {}

    def test_conflict_error_with_resource(self):
        """Test ConflictError with resource specification."""
        error = ConflictError("Already exists", resource="profile")

        assert error.status_code == 409
        assert error.details["resource"] == "profile"

    def test_conflict_error_inherits_from_api_error(self):
        """Test ConflictError is an APIError."""
        error = ConflictError("Conflict")

        assert isinstance(error, APIError)


class TestHandleApiErrors:
    """Tests for handle_api_errors function."""

    @pytest.fixture
    def app(self):
        """Create Flask app for testing."""
        app = Flask(__name__)
        handle_api_errors(app)
        return app

    def test_handles_api_error(self, app):
        """Test handle_api_errors registers APIError handler."""

        @app.route("/test")
        def test_route():
            raise APIError("Test error", status_code=400)

        with app.test_client() as client:
            response = client.get("/test")

            assert response.status_code == 400
            data = response.get_json()
            assert data["error"] == "Test error"

    def test_handles_validation_error(self, app):
        """Test handle_api_errors handles ValidationError."""

        @app.route("/test")
        def test_route():
            raise ValidationError("Invalid", field="name")

        with app.test_client() as client:
            response = client.get("/test")

            assert response.status_code == 400

    def test_handles_not_found_error(self, app):
        """Test handle_api_errors handles NotFoundError."""

        @app.route("/test")
        def test_route():
            raise NotFoundError("Profile", "test")

        with app.test_client() as client:
            response = client.get("/test")

            assert response.status_code == 404

    def test_handles_generic_404(self, app):
        """Test handle_api_errors handles generic 404."""
        with app.test_client() as client:
            response = client.get("/nonexistent")

            assert response.status_code == 404
            data = response.get_json()
            assert data["error"] == "Not found"

    def test_handles_generic_400(self, app):
        """Test handle_api_errors handles generic 400."""

        @app.route("/test")
        def test_route():
            from werkzeug.exceptions import BadRequest
            raise BadRequest()

        with app.test_client() as client:
            response = client.get("/test")

            assert response.status_code == 400


class TestSafeEndpoint:
    """Tests for safe_endpoint decorator."""

    @pytest.fixture
    def app(self):
        """Create Flask app for testing."""
        return Flask(__name__)

    def test_safe_endpoint_passes_through_success(self, app):
        """Test safe_endpoint passes through successful responses."""

        @app.route("/test")
        @safe_endpoint("test operation")
        def test_route():
            return jsonify({"result": "success"})

        with app.test_client() as client:
            response = client.get("/test")

            assert response.status_code == 200
            data = response.get_json()
            assert data["result"] == "success"

    def test_safe_endpoint_passes_through_api_errors(self, app):
        """Test safe_endpoint lets APIError pass through."""
        handle_api_errors(app)

        @app.route("/test")
        @safe_endpoint("test operation")
        def test_route():
            raise NotFoundError("Resource")

        with app.test_client() as client:
            response = client.get("/test")

            assert response.status_code == 404

    def test_safe_endpoint_converts_value_error(self, app):
        """Test safe_endpoint converts ValueError to 400."""

        @app.route("/test")
        @safe_endpoint("test operation")
        def test_route():
            raise ValueError("Invalid value")

        with app.test_client() as client:
            response = client.get("/test")

            assert response.status_code == 400
            data = response.get_json()
            assert data["error"] == "Invalid value"

    def test_safe_endpoint_handles_unexpected_errors(self, app):
        """Test safe_endpoint handles unexpected errors with 500."""

        @app.route("/test")
        @safe_endpoint("test operation")
        def test_route():
            raise RuntimeError("Unexpected error")

        with app.test_client() as client:
            response = client.get("/test")

            assert response.status_code == 500
            data = response.get_json()
            assert "Error in test operation" in data["error"]

    def test_safe_endpoint_logs_unexpected_errors(self, app):
        """Test safe_endpoint logs unexpected errors."""

        @app.route("/test")
        @safe_endpoint("test operation")
        def test_route():
            raise RuntimeError("Unexpected error")

        with patch("arguscloud.api.errors.logger") as mock_logger:
            with app.test_client() as client:
                client.get("/test")

                # Should have logged an error
                mock_logger.error.assert_called()

    def test_safe_endpoint_logs_validation_warnings(self, app):
        """Test safe_endpoint logs validation errors as warnings."""

        @app.route("/test")
        @safe_endpoint("test operation")
        def test_route():
            raise ValueError("Invalid input")

        with patch("arguscloud.api.errors.logger") as mock_logger:
            with app.test_client() as client:
                client.get("/test")

                # Should have logged a warning
                mock_logger.warning.assert_called()

    def test_safe_endpoint_preserves_function_name(self, app):
        """Test safe_endpoint preserves decorated function name."""

        @safe_endpoint("test operation")
        def my_function():
            pass

        assert my_function.__name__ == "my_function"

    def test_safe_endpoint_works_with_arguments(self, app):
        """Test safe_endpoint works with route arguments."""

        @app.route("/test/<name>")
        @safe_endpoint("test operation")
        def test_route(name):
            return jsonify({"name": name})

        with app.test_client() as client:
            response = client.get("/test/alice")

            assert response.status_code == 200
            data = response.get_json()
            assert data["name"] == "alice"
