# ArgusCloud UI Dockerfile
# Serves the static web UI via nginx

# =============================================================================
# Stage 1: Build preparation (minimal - just copy static files)
# =============================================================================
FROM alpine:3.19 AS builder

WORKDIR /build

# Copy UI static files
COPY index.html ./
COPY css/ ./css/
COPY js/ ./js/

# Remove any development/sample files that shouldn't be in production
RUN rm -f *.jsonl sample_*.jsonl 2>/dev/null || true

# =============================================================================
# Stage 2: Production nginx image
# =============================================================================
FROM nginx:1.25-alpine AS runtime

# Labels for container metadata
LABEL org.opencontainers.image.title="ArgusCloud UI" \
      org.opencontainers.image.description="ArgusCloud web interface for cloud security visualization" \
      org.opencontainers.image.version="0.3.0" \
      org.opencontainers.image.vendor="ArgusCloud" \
      org.opencontainers.image.source="https://github.com/jeremylaratro/cloudhound"

# Remove default nginx config and content
RUN rm -rf /usr/share/nginx/html/* /etc/nginx/conf.d/default.conf

# Copy custom nginx configuration
COPY nginx.conf /etc/nginx/conf.d/default.conf

# Copy static files from builder
COPY --from=builder /build/ /usr/share/nginx/html/

# Create nginx cache directories with correct permissions
RUN mkdir -p /var/cache/nginx/client_temp \
             /var/cache/nginx/proxy_temp \
             /var/cache/nginx/fastcgi_temp \
             /var/cache/nginx/uwsgi_temp \
             /var/cache/nginx/scgi_temp && \
    chown -R nginx:nginx /var/cache/nginx && \
    chown -R nginx:nginx /var/run && \
    chown -R nginx:nginx /usr/share/nginx/html

# Use non-root user
USER nginx

# Expose HTTP port
EXPOSE 80

# Health check
HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
    CMD wget -q --spider http://localhost:80/ || exit 1

# nginx runs in foreground by default with this config
CMD ["nginx", "-g", "daemon off;"]
