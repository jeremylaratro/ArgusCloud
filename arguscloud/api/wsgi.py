"""WSGI entry point for ArgusCloud API.

This module creates a Flask application instance configured via environment
variables, suitable for use with gunicorn or other WSGI servers.

Usage with gunicorn:
    gunicorn arguscloud.api.wsgi:application

Environment Variables:
    ARGUSCLOUD_NEO4J_URI: Neo4j connection URI (default: bolt://localhost:7687)
    ARGUSCLOUD_NEO4J_USER: Neo4j username (default: neo4j)
    ARGUSCLOUD_NEO4J_PASSWORD: Neo4j password (default: letmein123)
    ARGUSCLOUD_AUTH_ENABLED: Enable authentication (default: true)
    ARGUSCLOUD_JWT_SECRET: JWT signing secret
    ARGUSCLOUD_JWT_EXPIRY: JWT expiry in seconds (default: 3600)
"""

import logging
import os
import sys

# Configure logging before importing application code
log_level = os.environ.get("ARGUSCLOUD_LOG_LEVEL", "INFO").upper()
logging.basicConfig(
    level=getattr(logging, log_level, logging.INFO),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    stream=sys.stdout
)

logger = logging.getLogger(__name__)

from .server import create_app
from .auth import AuthConfig


def get_app():
    """Create and configure the Flask application from environment variables."""
    # Neo4j configuration
    neo4j_uri = os.environ.get("ARGUSCLOUD_NEO4J_URI", "bolt://localhost:7687")
    neo4j_user = os.environ.get("ARGUSCLOUD_NEO4J_USER", "neo4j")
    neo4j_password = os.environ.get("ARGUSCLOUD_NEO4J_PASSWORD", "letmein123")

    # Authentication configuration
    auth_enabled = os.environ.get("ARGUSCLOUD_AUTH_ENABLED", "true").lower() == "true"
    jwt_secret = os.environ.get("ARGUSCLOUD_JWT_SECRET")
    jwt_expiry = int(os.environ.get("ARGUSCLOUD_JWT_EXPIRY", "3600"))

    auth_config = AuthConfig(
        enabled=auth_enabled,
        jwt_secret=jwt_secret,
        jwt_expiry=jwt_expiry
    )

    logger.info(f"Starting ArgusCloud API")
    logger.info(f"  Neo4j URI: {neo4j_uri}")
    logger.info(f"  Auth enabled: {auth_enabled}")
    logger.info(f"  Log level: {log_level}")

    return create_app(
        uri=neo4j_uri,
        user=neo4j_user,
        password=neo4j_password,
        auth_config=auth_config
    )


# Create the application instance for WSGI servers
application = get_app()

# Alias for convenience
app = application
