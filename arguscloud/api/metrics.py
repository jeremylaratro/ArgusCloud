"""Prometheus metrics for ArgusCloud API.

This module provides observability through Prometheus metrics,
tracking request counts, latencies, and error rates.
"""

from __future__ import annotations

import time
import logging
from functools import wraps
from typing import Any, Callable, Optional

from flask import Flask, Response, request, g

logger = logging.getLogger(__name__)

# Check if prometheus_client is available
try:
    from prometheus_client import (
        Counter,
        Histogram,
        Gauge,
        Info,
        generate_latest,
        CONTENT_TYPE_LATEST,
        CollectorRegistry,
        REGISTRY,
    )
    HAS_PROMETHEUS = True
except ImportError:
    HAS_PROMETHEUS = False
    logger.info("prometheus_client not installed, metrics disabled")


# Metrics definitions (only created if prometheus available)
if HAS_PROMETHEUS:
    # Request metrics
    REQUEST_COUNT = Counter(
        "arguscloud_http_requests_total",
        "Total HTTP requests",
        ["method", "endpoint", "status"]
    )

    REQUEST_LATENCY = Histogram(
        "arguscloud_http_request_duration_seconds",
        "HTTP request latency in seconds",
        ["method", "endpoint"],
        buckets=[0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]
    )

    REQUEST_IN_PROGRESS = Gauge(
        "arguscloud_http_requests_in_progress",
        "Number of HTTP requests currently being processed",
        ["method", "endpoint"]
    )

    # Database metrics
    DB_QUERY_COUNT = Counter(
        "arguscloud_db_queries_total",
        "Total database queries",
        ["operation", "status"]
    )

    DB_QUERY_LATENCY = Histogram(
        "arguscloud_db_query_duration_seconds",
        "Database query latency in seconds",
        ["operation"],
        buckets=[0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0]
    )

    # Collection metrics
    COLLECTION_COUNT = Counter(
        "arguscloud_collections_total",
        "Total collection jobs",
        ["provider", "status"]
    )

    COLLECTION_DURATION = Histogram(
        "arguscloud_collection_duration_seconds",
        "Collection job duration in seconds",
        ["provider"],
        buckets=[1.0, 5.0, 10.0, 30.0, 60.0, 120.0, 300.0, 600.0]
    )

    # Resource metrics
    RESOURCES_COLLECTED = Counter(
        "arguscloud_resources_collected_total",
        "Total resources collected",
        ["provider", "resource_type"]
    )

    # Error metrics
    ERROR_COUNT = Counter(
        "arguscloud_errors_total",
        "Total errors",
        ["type", "endpoint"]
    )

    # Application info
    APP_INFO = Info(
        "arguscloud",
        "ArgusCloud application information"
    )


def init_metrics(app: Flask, version: str = "0.2.0") -> None:
    """Initialize metrics for a Flask application.

    This sets up request timing middleware and the /metrics endpoint.

    Args:
        app: Flask application instance
        version: Application version string
    """
    if not HAS_PROMETHEUS:
        logger.warning("Prometheus metrics not available - install prometheus_client")
        return

    # Set application info
    APP_INFO.info({
        "version": version,
        "name": "arguscloud",
    })

    @app.before_request
    def before_request() -> None:
        """Record request start time."""
        g.start_time = time.time()
        endpoint = _get_endpoint_label()
        REQUEST_IN_PROGRESS.labels(
            method=request.method,
            endpoint=endpoint
        ).inc()

    @app.after_request
    def after_request(response: Response) -> Response:
        """Record request metrics."""
        endpoint = _get_endpoint_label()

        # Record latency
        if hasattr(g, "start_time"):
            latency = time.time() - g.start_time
            REQUEST_LATENCY.labels(
                method=request.method,
                endpoint=endpoint
            ).observe(latency)

        # Record request count
        REQUEST_COUNT.labels(
            method=request.method,
            endpoint=endpoint,
            status=response.status_code
        ).inc()

        # Decrement in-progress gauge
        REQUEST_IN_PROGRESS.labels(
            method=request.method,
            endpoint=endpoint
        ).dec()

        return response

    @app.route("/metrics")
    def metrics() -> Response:
        """Expose Prometheus metrics endpoint.

        Returns:
            Prometheus metrics in text format
        """
        return Response(
            generate_latest(REGISTRY),
            mimetype=CONTENT_TYPE_LATEST
        )


def _get_endpoint_label() -> str:
    """Get a normalized endpoint label for metrics.

    This normalizes variable parts of URLs to avoid high cardinality.

    Returns:
        Normalized endpoint string
    """
    # Use the matched rule if available
    if request.url_rule:
        return request.url_rule.rule

    # Fall back to path, but normalize common patterns
    path = request.path

    # Normalize job IDs
    import re
    path = re.sub(
        r"/collect/[a-f0-9-]{36}",
        "/collect/{job_id}",
        path
    )
    path = re.sub(
        r"/upload/[a-f0-9-]{36}",
        "/upload/{job_id}",
        path
    )

    # Normalize profile names
    path = re.sub(
        r"/profiles/[^/]+",
        "/profiles/{name}",
        path
    )

    return path


def track_db_query(operation: str) -> Callable:
    """Decorator to track database query metrics.

    Args:
        operation: Name of the database operation

    Returns:
        Decorator function
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            if not HAS_PROMETHEUS:
                return func(*args, **kwargs)

            start_time = time.time()
            try:
                result = func(*args, **kwargs)
                DB_QUERY_COUNT.labels(operation=operation, status="success").inc()
                return result
            except Exception as e:
                DB_QUERY_COUNT.labels(operation=operation, status="error").inc()
                raise
            finally:
                latency = time.time() - start_time
                DB_QUERY_LATENCY.labels(operation=operation).observe(latency)

        return wrapper
    return decorator


def track_collection(provider: str, status: str, duration: float) -> None:
    """Track a collection job completion.

    Args:
        provider: Cloud provider (aws, gcp, azure)
        status: Job status (success, failed, cancelled)
        duration: Duration in seconds
    """
    if not HAS_PROMETHEUS:
        return

    COLLECTION_COUNT.labels(provider=provider, status=status).inc()
    COLLECTION_DURATION.labels(provider=provider).observe(duration)


def track_resources_collected(provider: str, resource_type: str, count: int = 1) -> None:
    """Track resources collected.

    Args:
        provider: Cloud provider
        resource_type: Type of resource
        count: Number of resources
    """
    if not HAS_PROMETHEUS:
        return

    RESOURCES_COLLECTED.labels(
        provider=provider,
        resource_type=resource_type
    ).inc(count)


def track_error(error_type: str, endpoint: Optional[str] = None) -> None:
    """Track an error occurrence.

    Args:
        error_type: Type of error
        endpoint: API endpoint where error occurred
    """
    if not HAS_PROMETHEUS:
        return

    ERROR_COUNT.labels(
        type=error_type,
        endpoint=endpoint or "unknown"
    ).inc()


class MetricsContext:
    """Context manager for timing operations.

    Example:
        >>> with MetricsContext("db_query", "get_nodes"):
        ...     result = session.run(query)
    """

    def __init__(self, category: str, operation: str):
        """Initialize the context.

        Args:
            category: Metric category (e.g., "db_query")
            operation: Specific operation name
        """
        self.category = category
        self.operation = operation
        self.start_time: Optional[float] = None

    def __enter__(self) -> "MetricsContext":
        """Enter the context and start timing."""
        self.start_time = time.time()
        return self

    def __exit__(
        self,
        exc_type: Optional[type],
        exc_val: Optional[Exception],
        exc_tb: Any
    ) -> bool:
        """Exit the context and record metrics."""
        if not HAS_PROMETHEUS or self.start_time is None:
            return False

        duration = time.time() - self.start_time

        if self.category == "db_query":
            status = "error" if exc_type else "success"
            DB_QUERY_COUNT.labels(
                operation=self.operation,
                status=status
            ).inc()
            DB_QUERY_LATENCY.labels(operation=self.operation).observe(duration)

        return False  # Don't suppress exceptions
