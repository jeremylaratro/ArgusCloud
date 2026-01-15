# ArgusCloud API Dockerfile
# Multi-stage production build for the ArgusCloud API server

# =============================================================================
# Stage 1: Builder - Install dependencies and build the package
# =============================================================================
FROM python:3.11-slim AS builder

# Set build-time environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# Create virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy dependency files first for better cache utilization
COPY pyproject.toml ./

# Install dependencies (including prod extras for gunicorn)
RUN pip install --upgrade pip setuptools wheel && \
    pip install ".[prod]"

# Copy application code
COPY cloudhound/ ./cloudhound/
COPY awshound/ ./awshound/
COPY cloudhound.py ./

# Install the application
RUN pip install --no-deps .

# =============================================================================
# Stage 2: Runtime - Minimal production image
# =============================================================================
FROM python:3.11-slim AS runtime

# Labels for container metadata
LABEL org.opencontainers.image.title="ArgusCloud API" \
      org.opencontainers.image.description="Cloud security graph analytics API server" \
      org.opencontainers.image.version="0.3.0" \
      org.opencontainers.image.vendor="ArgusCloud" \
      org.opencontainers.image.source="https://github.com/jeremylaratro/cloudhound"

# Runtime environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONFAULTHANDLER=1 \
    # Application defaults
    ARGUSCLOUD_API_HOST=0.0.0.0 \
    ARGUSCLOUD_API_PORT=9847 \
    ARGUSCLOUD_LOG_LEVEL=INFO \
    # Virtual environment path
    PATH="/opt/venv/bin:$PATH"

WORKDIR /app

# Install runtime dependencies (curl for healthcheck)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    tini \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Create non-root user for security
RUN groupadd --gid 1000 arguscloud && \
    useradd --uid 1000 --gid arguscloud --shell /bin/bash --create-home arguscloud

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv

# Copy application code (needed for some dynamic imports)
COPY --chown=arguscloud:arguscloud cloudhound/ ./cloudhound/
COPY --chown=arguscloud:arguscloud awshound/ ./awshound/
COPY --chown=arguscloud:arguscloud cloudhound.py ./

# Create data directory for uploads/exports
RUN mkdir -p /app/data && chown arguscloud:arguscloud /app/data

# Switch to non-root user
USER arguscloud

# Expose API port
EXPOSE 9847

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD curl -f http://localhost:9847/health || exit 1

# Use tini as init system for proper signal handling
ENTRYPOINT ["/usr/bin/tini", "--"]

# Run with gunicorn for production
# Uses wsgi.py which configures the app from environment variables
CMD ["gunicorn", \
     "--bind", "0.0.0.0:9847", \
     "--workers", "4", \
     "--threads", "2", \
     "--timeout", "120", \
     "--keep-alive", "5", \
     "--max-requests", "1000", \
     "--max-requests-jitter", "100", \
     "--access-logfile", "-", \
     "--error-logfile", "-", \
     "--capture-output", \
     "cloudhound.api.wsgi:application"]
