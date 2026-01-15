"""Standardized error handling for ArgusCloud API.

Provides consistent error responses and logging patterns
across all API endpoints.
"""

from __future__ import annotations

import logging
from functools import wraps
from typing import Any, Callable, Optional, Tuple

from flask import jsonify

logger = logging.getLogger(__name__)


class APIError(Exception):
    """Base exception for API errors.

    Usage:
        raise APIError("Resource not found", status_code=404)
        raise APIError("Invalid input", status_code=400, details={"field": "name"})
    """

    def __init__(
        self,
        message: str,
        status_code: int = 400,
        details: Optional[dict] = None
    ):
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.details = details or {}

    def to_response(self) -> Tuple[dict, int]:
        """Convert to Flask JSON response."""
        response = {"error": self.message}
        if self.details:
            response["details"] = self.details
        return jsonify(response), self.status_code


class ValidationError(APIError):
    """Raised for input validation failures."""

    def __init__(self, message: str, field: Optional[str] = None):
        details = {"field": field} if field else {}
        super().__init__(message, status_code=400, details=details)


class NotFoundError(APIError):
    """Raised when a requested resource is not found."""

    def __init__(self, resource: str, identifier: Optional[str] = None):
        message = f"{resource} not found"
        if identifier:
            message = f"{resource} '{identifier}' not found"
        super().__init__(message, status_code=404)


class AuthenticationError(APIError):
    """Raised for authentication failures."""

    def __init__(self, message: str = "Authentication required"):
        super().__init__(message, status_code=401)


class AuthorizationError(APIError):
    """Raised for authorization/permission failures."""

    def __init__(self, message: str = "Permission denied"):
        super().__init__(message, status_code=403)


class ConflictError(APIError):
    """Raised when a resource conflict occurs (e.g., duplicate name)."""

    def __init__(self, message: str, resource: Optional[str] = None):
        details = {"resource": resource} if resource else {}
        super().__init__(message, status_code=409, details=details)


def handle_api_errors(app):
    """Register error handlers with Flask app.

    Args:
        app: Flask application instance
    """

    @app.errorhandler(APIError)
    def handle_api_error(error: APIError):
        return error.to_response()

    @app.errorhandler(400)
    def handle_bad_request(error):
        return jsonify({"error": "Bad request"}), 400

    @app.errorhandler(404)
    def handle_not_found(error):
        return jsonify({"error": "Not found"}), 404

    @app.errorhandler(500)
    def handle_internal_error(error):
        logger.exception("Internal server error")
        return jsonify({"error": "Internal server error"}), 500


def safe_endpoint(operation_name: str):
    """Decorator for standardized error handling on API endpoints.

    Catches exceptions and converts them to appropriate API responses.

    Args:
        operation_name: Human-readable name for logging

    Usage:
        @app.route("/items")
        @safe_endpoint("list items")
        def list_items():
            ...
    """

    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs) -> Any:
            try:
                return func(*args, **kwargs)
            except APIError:
                # Let API errors pass through to be handled by Flask
                raise
            except ValueError as e:
                # Convert validation errors
                logger.warning(f"Validation error in {operation_name}: {e}")
                return jsonify({"error": str(e)}), 400
            except Exception as e:
                # Log unexpected errors but don't expose details
                logger.error(
                    f"Unexpected error in {operation_name}: {type(e).__name__}: {e}",
                    exc_info=True
                )
                return jsonify({"error": f"Error in {operation_name}"}), 500

        return wrapper

    return decorator
