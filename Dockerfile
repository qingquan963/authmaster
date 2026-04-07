FROM python:3.11-slim

WORKDIR /app

# Install system deps for some Python packages
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Python deps
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy app
COPY . .

# Run
CMD ["uvicorn", "main_sso:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
