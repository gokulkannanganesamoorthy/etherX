# Base Image: Lightweight Python
FROM python:3.9-slim

# Environment Variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV APP_HOME=/app

# Work Directory
WORKDIR $APP_HOME

# Install System Dependencies (gcc for some python libs)
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Install Dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy Application Code
COPY . .

# Expose WAF Port
EXPOSE 8000

# Run Command (Production Mode with Gunicorn/Uvicorn workers)
CMD ["uvicorn", "waf:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "4"]
