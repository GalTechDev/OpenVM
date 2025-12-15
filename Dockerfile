# OpenVM - Docker VM Manager
# Production Docker image

FROM python:3.11-slim

LABEL maintainer="Maxence Moreau"
LABEL description="OpenVM - Web-based Docker VM Manager with SSH Terminal"
LABEL version="1.0"

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    docker.io \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create app directory
WORKDIR /app

# Copy requirements first for caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create data directory for SQLite (will be mounted as volume)
RUN mkdir -p /app/data

# Expose port
EXPOSE 5000

# Environment variables
ENV FLASK_ENV=production
ENV PYTHONUNBUFFERED=1

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:5000/ || exit 1

# Database is auto-initialized on first run
# Admin account is created via /setup page on first access
CMD ["python", "web_app.py"]

