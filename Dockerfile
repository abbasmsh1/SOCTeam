# ============================================================================
# Stage 1: Frontend Builder
# ============================================================================
FROM node:18-alpine AS frontend-builder

WORKDIR /app/frontend

# Copy package files for dependency installation
COPY frontend/package*.json ./

# Install dependencies (including devDependencies for build tools)
RUN npm ci

# Copy frontend source code
COPY frontend/ ./

# Build the frontend
RUN npm run build

# ============================================================================
# Stage 2: Python Runtime (Final Image)
# ============================================================================
FROM python:3.9-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app

# Set work directory
WORKDIR /app

# Install system dependencies
# libpcap-dev: for scapy/cicflowmeter
# gcc, g++, make: for compiling python packages
# net-tools, iputils-ping: for network troubleshooting
# tcpdump: for packet capture
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap-dev \
    gcc \
    g++ \
    make \
    net-tools \
    iputils-ping \
    tcpdump \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy and install Python dependencies
COPY Implementation/requirements.txt /app/Implementation/requirements.txt
RUN pip install --no-cache-dir -r Implementation/requirements.txt

# Copy the entire project structure
COPY . /app/

# Copy frontend build artifacts from the builder stage
COPY --from=frontend-builder /app/frontend/dist /app/frontend/dist

# Create necessary directories
RUN mkdir -p Implementation/logs \
    Implementation/Reports \
    Implementation/Data \
    Models

# Add a health check (optional)
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import sys; sys.exit(0)" || exit 1

# Expose ports
# 8000: Backend API (if using FastAPI/Flask)
# 5173: Frontend dev server (if needed)
EXPOSE 8000 5173

# Default command to run the main application
# Can be overridden in docker-compose.yml or docker run
CMD ["python", "-m", "Implementation.main", "--help"]

