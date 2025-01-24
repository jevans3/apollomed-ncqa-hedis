FROM python:3.9-slim

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    # HIPAA compliance: Set secure defaults
    PYTHON_HASHSEED=random \
    # Ensure TLS 1.2 or higher
    REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt

# Set working directory
WORKDIR /app

# Install system dependencies and security updates
RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    ca-certificates \
    # Required for encryption
    gnupg \
    openssl \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user with specific UID/GID for better security
RUN groupadd -g 10001 appgroup && \
    useradd -u 10000 -g appgroup -s /sbin/nologin -m appuser && \
    chown -R appuser:appgroup /app

# Copy requirements first for better caching
COPY --chown=appuser:appgroup requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Install security packages
RUN pip install --no-cache-dir \
    cryptography \
    pyOpenSSL \
    certifi \
    bandit \
    safety

# Copy application code
COPY --chown=appuser:appgroup . .

# Run security checks
RUN bandit -r /app -ll && \
    safety check

# Generate self-signed cert for HTTPS
RUN openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout /app/private.key -out /app/certificate.crt \
    -subj "/C=US/ST=CA/L=City/O=Organization/CN=localhost"

# Set appropriate permissions
RUN chmod 600 /app/private.key && \
    chmod 644 /app/certificate.crt && \
    chown -R appuser:appgroup /app

# Switch to non-root user
USER appuser

# Set up logging configuration
ENV LOG_LEVEL=INFO

# Health check with HTTPS
HEALTHCHECK --interval=30s --timeout=30s --start-period=5s --retries=3 \
    CMD curl -f --cacert /app/certificate.crt https://localhost:${PORT:-8000}/health || exit 1

# HIPAA Audit logging directory
RUN mkdir -p /app/audit_logs && \
    chown appuser:appgroup /app/audit_logs

EXPOSE ${PORT:-8000}

# Start with HTTPS enabled
CMD ["python", "src/main.py"]