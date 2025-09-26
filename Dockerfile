FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    postgresql-client \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create non-root user
RUN useradd -m -u 1000 bmpuser && \
    chown -R bmpuser:bmpuser /app

USER bmpuser

# Expose BMP port and metrics port
EXPOSE 11019 9090

# Run the application
CMD ["python", "main.py"]