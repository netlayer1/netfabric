FROM python:3.11-slim

WORKDIR /app

# Install system deps for Netmiko/cryptography
RUN apt-get update && apt-get install -y \
    gcc \
    libffi-dev \
    openssh-client \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Create data directories
RUN mkdir -p data/configs data/logs

EXPOSE 8000

CMD ["hypercorn", "backend.main:app", "--bind", "0.0.0.0:8000"]
