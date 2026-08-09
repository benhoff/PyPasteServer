# Use the official Python image as the base
FROM python:3.11-slim

ARG PYP_SERVER_VERSION=0.0.0
LABEL org.opencontainers.image.title="PyPasteServer" \
      org.opencontainers.image.version="$PYP_SERVER_VERSION"

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app
ENV DATABASE_URL=sqlite:////data/clipboard.db
ENV RUN_DATABASE_MIGRATIONS_ON_STARTUP=0

# Set work directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY high-level-server-requirements.txt requirements.txt
RUN pip install --upgrade pip
RUN pip install --no-cache-dir -r requirements.txt

# Copy the application code
COPY . /app/

# Declare a volume for the data directory
RUN mkdir -p /data
VOLUME ["/data"]

# Expose the port FastAPI is running on
EXPOSE 8001

# Command to run the FastAPI application with Gunicorn and Uvicorn workers
CMD ["sh", "-c", "alembic upgrade head && exec gunicorn server_app.main:app --worker-class server_app.worker.SyncUvicornWorker --bind 0.0.0.0:8001 --workers 4"]
