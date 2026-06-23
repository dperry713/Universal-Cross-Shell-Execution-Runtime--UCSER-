# UCSER Production Dockerfile
# Multi-stage build for minimal image size and security

# Stage 1: Builder
FROM python:3.11-slim as builder

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Create virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy requirements and install
COPY requirements-pinned.txt .
RUN pip install --no-cache-dir --upgrade pip setuptools wheel && \
    pip install --no-cache-dir -r requirements-pinned.txt

# Stage 2: Runtime
FROM python:3.11-slim

# Install runtime dependencies only
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user for security
RUN groupadd -r ucser && useradd -r -g ucser ucser

# Set working directory
WORKDIR /app

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv

# Copy application code
COPY --chown=ucser:ucser . .

# Create necessary directories
RUN mkdir -p /app/logs /app/data /app/keys && \
    chown -R ucser:ucser /app

# Set environment variables
ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    APP_ENV=production

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Switch to non-root user
USER ucser

# Expose port
EXPOSE 8000

# Run application
CMD ["python", "-m", "api.cockpit"]

# Labels for metadata
LABEL maintainer="Dustin Perry <dustin@example.com>" \
      version="1.0.0" \
      description="UCSER - Universal Cross-Shell Execution Runtime" \
      org.opencontainers.image.source="https://github.com/dperry713/UCSER"
