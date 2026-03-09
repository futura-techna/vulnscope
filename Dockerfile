# Optimized Dockerfile for VulnScope API
# Designed for Render free tier deployment

FROM python:3.12-slim

WORKDIR /app

# Install minimal system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install uv for faster package management
RUN curl -LsSf https://astral.sh/uv/install.sh | sh
ENV PATH="/root/.local/bin:$PATH"

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies using uv (faster than pip)
RUN uv pip install --system --no-cache -r requirements.txt

# Copy source code
COPY src/ src/

# Create non-root user for security
RUN useradd --create-home --shell /bin/bash appuser && \
    chown -R appuser:appuser /app
USER appuser

# Expose port (Render sets PORT env var dynamically)
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:${PORT:-8000}/health || exit 1

# Default command - uses PORT environment variable from Render
CMD sh -c "uvicorn src.api.main:app --host 0.0.0.0 --port ${PORT:-8000}"