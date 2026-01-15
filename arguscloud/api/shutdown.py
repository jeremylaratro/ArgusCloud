"""Graceful shutdown handling for ArgusCloud API.

This module provides graceful shutdown support for the API server,
ensuring in-flight requests complete and resources are properly cleaned up.
"""

from __future__ import annotations

import atexit
import logging
import signal
import sys
import threading
import time
from typing import Any, Callable, List, Optional

from flask import Flask

logger = logging.getLogger(__name__)


class GracefulShutdown:
    """Manages graceful shutdown of the application.

    This class handles SIGTERM and SIGINT signals, ensuring that:
    - In-flight requests are allowed to complete
    - Background jobs are cancelled
    - Database connections are closed
    - Resources are cleaned up

    Attributes:
        shutdown_event: Threading event signaling shutdown
        shutdown_timeout: Maximum seconds to wait for cleanup
        cleanup_handlers: List of cleanup functions to call
    """

    def __init__(self, timeout: int = 30):
        """Initialize graceful shutdown handler.

        Args:
            timeout: Maximum seconds to wait for graceful shutdown
        """
        self.shutdown_event = threading.Event()
        self.shutdown_timeout = timeout
        self.cleanup_handlers: List[Callable[[], None]] = []
        self._original_handlers: dict = {}
        self._in_flight_requests = 0
        self._lock = threading.Lock()

    def register_cleanup(self, handler: Callable[[], None]) -> None:
        """Register a cleanup handler to run on shutdown.

        Args:
            handler: Function to call during shutdown
        """
        self.cleanup_handlers.append(handler)

    def increment_requests(self) -> None:
        """Increment the in-flight request counter."""
        with self._lock:
            self._in_flight_requests += 1

    def decrement_requests(self) -> None:
        """Decrement the in-flight request counter."""
        with self._lock:
            self._in_flight_requests -= 1

    def get_in_flight_count(self) -> int:
        """Get the current number of in-flight requests.

        Returns:
            Number of requests being processed
        """
        with self._lock:
            return self._in_flight_requests

    def is_shutting_down(self) -> bool:
        """Check if shutdown has been initiated.

        Returns:
            True if shutdown is in progress
        """
        return self.shutdown_event.is_set()

    def _signal_handler(self, signum: int, frame: Any) -> None:
        """Handle shutdown signals.

        Args:
            signum: Signal number
            frame: Current stack frame
        """
        signal_name = signal.Signals(signum).name
        logger.info(f"Received {signal_name}, initiating graceful shutdown...")

        self.shutdown_event.set()
        self._shutdown()

    def _shutdown(self) -> None:
        """Perform the shutdown sequence."""
        start_time = time.time()

        # Wait for in-flight requests with timeout
        logger.info("Waiting for in-flight requests to complete...")
        while self.get_in_flight_count() > 0:
            elapsed = time.time() - start_time
            if elapsed > self.shutdown_timeout:
                logger.warning(
                    f"Shutdown timeout reached with {self.get_in_flight_count()} "
                    "requests still in flight"
                )
                break
            time.sleep(0.1)

        in_flight = self.get_in_flight_count()
        if in_flight == 0:
            logger.info("All in-flight requests completed")
        else:
            logger.warning(f"Proceeding with {in_flight} requests still in flight")

        # Run cleanup handlers
        logger.info(f"Running {len(self.cleanup_handlers)} cleanup handlers...")
        for handler in self.cleanup_handlers:
            try:
                handler()
            except Exception as e:
                logger.error(f"Cleanup handler failed: {type(e).__name__}: {e}")

        elapsed = time.time() - start_time
        logger.info(f"Graceful shutdown completed in {elapsed:.2f}s")

    def install_signal_handlers(self) -> None:
        """Install signal handlers for SIGTERM and SIGINT."""
        # Only install in main thread
        if threading.current_thread() is not threading.main_thread():
            logger.debug("Skipping signal handler installation in non-main thread")
            return

        # Store original handlers
        self._original_handlers[signal.SIGTERM] = signal.signal(
            signal.SIGTERM, self._signal_handler
        )
        self._original_handlers[signal.SIGINT] = signal.signal(
            signal.SIGINT, self._signal_handler
        )

        # Register atexit handler
        atexit.register(self._atexit_handler)

        logger.info("Signal handlers installed for graceful shutdown")

    def _atexit_handler(self) -> None:
        """Handle process exit."""
        if not self.shutdown_event.is_set():
            logger.debug("Running atexit cleanup")
            self.shutdown_event.set()
            for handler in self.cleanup_handlers:
                try:
                    handler()
                except Exception:
                    pass  # Ignore errors during atexit

    def restore_signal_handlers(self) -> None:
        """Restore original signal handlers."""
        for sig, handler in self._original_handlers.items():
            signal.signal(sig, handler)
        self._original_handlers.clear()


# Global shutdown handler instance
_shutdown_handler: Optional[GracefulShutdown] = None


def get_shutdown_handler() -> GracefulShutdown:
    """Get or create the global shutdown handler.

    Returns:
        GracefulShutdown instance
    """
    global _shutdown_handler
    if _shutdown_handler is None:
        _shutdown_handler = GracefulShutdown()
    return _shutdown_handler


def init_graceful_shutdown(
    app: Flask,
    driver: Optional[Any] = None,
    timeout: int = 30
) -> GracefulShutdown:
    """Initialize graceful shutdown for a Flask application.

    Args:
        app: Flask application instance
        driver: Neo4j driver to close on shutdown
        timeout: Maximum seconds to wait for shutdown

    Returns:
        GracefulShutdown instance
    """
    handler = get_shutdown_handler()
    handler.shutdown_timeout = timeout

    # Track in-flight requests
    @app.before_request
    def before_request() -> None:
        """Track request start."""
        if handler.is_shutting_down():
            # Return 503 during shutdown
            from flask import jsonify
            return jsonify({
                "error": "Service unavailable",
                "message": "Server is shutting down"
            }), 503
        handler.increment_requests()

    @app.after_request
    def after_request(response):
        """Track request completion."""
        handler.decrement_requests()
        return response

    # Register Neo4j driver cleanup
    if driver is not None:
        def close_driver():
            logger.info("Closing Neo4j driver...")
            try:
                driver.close()
                logger.info("Neo4j driver closed")
            except Exception as e:
                logger.error(f"Error closing Neo4j driver: {e}")

        handler.register_cleanup(close_driver)

    # Add health check for shutdown status
    @app.route("/ready")
    def readiness():
        """Kubernetes readiness probe endpoint."""
        from flask import jsonify
        if handler.is_shutting_down():
            return jsonify({"ready": False, "reason": "shutting_down"}), 503
        return jsonify({"ready": True})

    # Install signal handlers (only works in main thread)
    try:
        handler.install_signal_handlers()
    except ValueError:
        # Not in main thread, skip signal handling
        logger.debug("Skipping signal handlers (not main thread)")

    return handler


def register_cleanup(handler: Callable[[], None]) -> None:
    """Register a cleanup handler with the global shutdown handler.

    Args:
        handler: Function to call during shutdown
    """
    get_shutdown_handler().register_cleanup(handler)


def is_shutting_down() -> bool:
    """Check if the application is shutting down.

    Returns:
        True if shutdown is in progress
    """
    handler = get_shutdown_handler()
    return handler.is_shutting_down()


class ShutdownMiddleware:
    """WSGI middleware for graceful shutdown support.

    This middleware can be used with production WSGI servers
    like gunicorn to handle shutdown gracefully.
    """

    def __init__(self, app: Any, handler: Optional[GracefulShutdown] = None):
        """Initialize the middleware.

        Args:
            app: WSGI application
            handler: GracefulShutdown instance
        """
        self.app = app
        self.handler = handler or get_shutdown_handler()

    def __call__(self, environ: dict, start_response: Callable) -> Any:
        """Handle WSGI request.

        Args:
            environ: WSGI environment
            start_response: WSGI start_response callback

        Returns:
            Response iterator
        """
        if self.handler.is_shutting_down():
            status = "503 Service Unavailable"
            headers = [("Content-Type", "application/json")]
            start_response(status, headers)
            return [b'{"error": "Service unavailable", "message": "Server is shutting down"}']

        self.handler.increment_requests()
        try:
            return self.app(environ, start_response)
        finally:
            self.handler.decrement_requests()
