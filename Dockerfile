# Dockerfile — versiondiff-sentinel
FROM python:3.11-slim

# Install system dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        unzip p7zip-full file libmagic1 binutils exiftool build-essential \
    && rm -rf /var/lib/apt/lists/*

# Create app directory
WORKDIR /app

# Copy requirements first for caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy project source
COPY ./src ./src

# Expose FastAPI port
EXPOSE 8000

# Default command
CMD ["uvicorn", "src.server.main:app", "--host", "0.0.0.0", "--port", "8000"]
