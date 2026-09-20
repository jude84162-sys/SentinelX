# SentinelX - Docker Image
# Cross-platform Blue Team Suite (Linux/WSL/Kali)
# Note: Android-specific modules (Termux:API) are not available in Docker.

FROM python:3.11-slim

LABEL org.opencontainers.image.title="SentinelX"
LABEL org.opencontainers.image.description="Modular Enterprise Blue Team Suite - Cross-platform security triage"
LABEL org.opencontainers.image.authors="jude84162-sys"
LABEL org.opencontainers.image.source="https://github.com/jude84162-sys/SentinelX"
LABEL org.opencontainers.image.licenses="MIT"

# Set working directory
WORKDIR /app

# Install system dependencies
# - procps: for ps, top (process listing utilities)
# - iproute2: for ss, ip (network tools)
# - net-tools: for netstat (fallback)
# - jq: for JSON processing
RUN apt-get update && apt-get install -y --no-install-recommends \
    procps \
    iproute2 \
    net-tools \
    jq \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create outputs directory
RUN mkdir -p outputs

# Default command: run full triage
ENTRYPOINT ["python", "SentinelX.py"]
CMD ["--triage-all"]
