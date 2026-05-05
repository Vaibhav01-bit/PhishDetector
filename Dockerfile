# Use Python 3.12 slim image as base
FROM python:3.12-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DEBIAN_FRONTEND=noninteractive

# Install system dependencies required by Playwright + Chromium + pyzbar + whois
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Playwright/Chromium dependencies
    wget gnupg ca-certificates \
    libnss3 libatk-bridge2.0-0 libdrm2 libxkbcommon0 \
    libxcomposite1 libxdamage1 libxrandr2 libgbm1 \
    libpango-1.0-0 libcairo2 libasound2 libxshmfence1 \
    libx11-xcb1 libxcb1 libx11-6 libxext6 libxfixes3 \
    libxi6 libxtst6 libglib2.0-0 libnspr4 libdbus-1-3 \
    libatspi2.0-0 libcups2 libcurl4 \
    # pyzbar dependencies
    libzbar0 \
    # whois dependencies
    whois \
    # Build tools
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt /app/requirements.txt
WORKDIR /app
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Install Playwright and download Chromium browser
RUN playwright install --with-deps chromium

# Copy application code
COPY . /app/

# Expose port (Cloud Run expects PORT env var, defaults to 8080)
ENV PORT=8080
EXPOSE 8080

# Run with gunicorn for production
CMD exec gunicorn --bind 0.0.0.0:$PORT --workers 1 --timeout 120 --access-logfile - --error-logfile - app:app
