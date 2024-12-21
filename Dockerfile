# Use the official Python image as the base
FROM python:3.11-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

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

# Copy initial clipboard.db if it exists
COPY clipboard.db /app/clipboard.db

# Declare a volume for the data directory
VOLUME ["/app"]

# Expose the port FastAPI is running on
EXPOSE 8001

# Command to run the FastAPI application with Gunicorn and Uvicorn workers
CMD ["gunicorn", "server:app", "--worker-class", "uvicorn.workers.UvicornWorker", "--bind", "0.0.0.0:8001", "--workers", "4"]
